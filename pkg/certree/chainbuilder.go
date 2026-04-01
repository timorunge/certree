// ChainBuilder discovers all possible certificate trust paths.

package certree

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
)

// DefaultMaxDepth is the default maximum chain depth used by
// NewChainBuilder and NewAnalyzer when no explicit depth is configured.
const DefaultMaxDepth = 10

// maxTrustPaths is the maximum number of trust paths built per BuildChains
// call. This prevents combinatorial explosion when many certificates in the
// pool share the same subject/AKI (e.g., crafted cross-signed bundles).
const maxTrustPaths = 1000

// ChainBuilder builds certificate chains and discovers trust paths from a pool of certificates.
// It identifies end-entity certificates and recursively constructs all possible paths,
// which may terminate at trusted roots, untrusted self-signed certs, or incomplete chains.
// Cross-signed certificates with multiple trust paths are fully supported.
type ChainBuilder interface {
	// BuildChains builds all possible certificate chains from the given certificates.
	// It is safe for concurrent use on the same ChainBuilder instance -- each call
	// creates its own certificate index. The AIA fetcher is internally synchronized.
	BuildChains(ctx context.Context, certs []*Certificate, trustStore TrustStore) ([]*TrustPath, error)
}

// chainBuilderOptions configures chain building behavior.
type chainBuilderOptions struct {
	maxDepth       int
	aiaFetch       bool
	aiaForce       bool
	detectCircular bool
}

// ChainBuilderOption is a functional option for configuring ChainBuilder.
type ChainBuilderOption func(*defaultChainBuilder)

// WithMaxDepth sets the maximum chain depth (0 = unlimited, default 10).
// Depth is counted from the end-entity: depth=0 is the leaf, depth=1 is the first
// intermediate, depth=2 the second, and so on.
func WithMaxDepth(depth int) ChainBuilderOption {
	return func(cb *defaultChainBuilder) {
		cb.opts.maxDepth = depth
	}
}

// WithAIAFetch enables fetching missing intermediates via the AIA extension (default false).
// Requires network access; may slow down chain building.
func WithAIAFetch(fetch bool) ChainBuilderOption {
	return func(cb *defaultChainBuilder) {
		cb.opts.aiaFetch = fetch
	}
}

// WithAIAForce causes AIA fetches even when a local issuer is already found,
// discovering alternate trust paths through cross-signed intermediates (default false).
// Requires WithAIAFetch to also be enabled.
func WithAIAForce(force bool) ChainBuilderOption {
	return func(cb *defaultChainBuilder) {
		cb.opts.aiaForce = force
	}
}

// WithCircularDetection enables or disables circular reference detection (default true).
// When enabled, a certificate appearing more than once in a chain is reported as
// ErrorCircularReference.
func WithCircularDetection(detect bool) ChainBuilderOption {
	return func(cb *defaultChainBuilder) {
		cb.opts.detectCircular = detect
	}
}

// WithChainLogger sets the logger for the chain builder (default: discard logger).
func WithChainLogger(logger *slog.Logger) ChainBuilderOption {
	return func(cb *defaultChainBuilder) {
		if logger == nil {
			panic("certree: WithChainLogger called with nil logger")
		}
		cb.logger = logger
	}
}

// WithAIAFetcher sets the AIAFetcher used when WithAIAFetch is enabled (default: nil).
func WithAIAFetcher(fetcher AIAFetcher) ChainBuilderOption {
	return func(cb *defaultChainBuilder) {
		if fetcher == nil {
			panic("certree: WithAIAFetcher called with nil fetcher")
		}
		cb.aiaFetcher = fetcher
	}
}

// defaultChainBuilder implements ChainBuilder with recursive chain building.
type defaultChainBuilder struct {
	opts       chainBuilderOptions
	logger     *slog.Logger
	aiaFetcher AIAFetcher
}

// NewChainBuilder creates a new ChainBuilder with the given options.
// See With* options for configuration.
func NewChainBuilder(opts ...ChainBuilderOption) ChainBuilder {
	cb := &defaultChainBuilder{
		opts: chainBuilderOptions{
			maxDepth:       DefaultMaxDepth,
			detectCircular: true,
		},
		logger: NewLogger(),
	}

	for _, opt := range opts {
		opt(cb)
	}

	if cb.opts.aiaForce && !cb.opts.aiaFetch {
		cb.logger.Warn("WithAIAForce has no effect without WithAIAFetch(true)")
	}

	return cb
}

var _ ChainBuilder = (*defaultChainBuilder)(nil)

// BuildChains builds all possible certificate chains from the given certificates.
// It discovers ALL trust paths from end-entity certificates to trusted roots, supporting
// cross-signed certificates with multiple valid paths.
//
// Safe for concurrent use: each call creates its own index and visited map; the AIA
// fetcher is internally synchronized. Non-fatal conditions (circular references, depth
// exceeded, missing issuer, untrusted root) are reported in TrustPath.Errors and
// TrustPath.Warnings rather than as returned errors.
func (cb *defaultChainBuilder) BuildChains(ctx context.Context, certs []*Certificate, trustStore TrustStore) ([]*TrustPath, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("building certificate chains: %w", ctx.Err())
	default:
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided: %w", ErrEmptyInput)
	}

	cb.logger.Info("building certificate chains", "count", len(certs))

	index := newCertificateIndex(certs)

	// Detect duplicate certificates in the input pool.
	// Duplicates produce unhelpful redundant paths and indicate misconfigured
	// certificate bundles. Track them so warnings can be attached to paths
	// that contain any of the duplicate certificates.
	duplicateFingerprints := cb.detectDuplicates(certs)

	endEntities := cb.findEndEntities(certs, index)
	cb.logger.Debug("found end-entity certificates", "count", len(endEntities))

	// Build chains for each end-entity certificate.
	//
	// The end-entity loop is sequential within a single BuildChains call because
	// buildChain mutates the per-call certificateIndex (trust store issuers,
	// AIA-fetched certs). Concurrent BuildChains calls are safe because each
	// creates its own index and the shared AIA fetcher is mutex-protected.
	var allPaths []*TrustPath
	pathCount := 0
	for _, endEntity := range endEntities {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("building chain for %s: %w", endEntity.CommonName(), ctx.Err())
		default:
		}

		if pathCount >= maxTrustPaths {
			cb.logger.Warn("trust path limit reached, skipping remaining end-entities",
				"limit", maxTrustPaths, "endEntity", endEntity.CommonName())
			break
		}

		visited := make(map[string]struct{}, len(certs))
		paths := cb.buildChain(ctx, endEntity, index, trustStore, visited, 0, &pathCount)
		allPaths = append(allPaths, paths...)
	}

	// Surface context cancellation that occurred during recursive chain
	// building. buildChain returns partial results silently on cancel;
	// this check ensures the caller gets a clear error.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("building certificate chains: %w", err)
	}

	// Deduplicate paths with identical certificate sequences. This can happen
	// when trust store issuers produce paths equivalent to pool-based paths,
	// or when AIAForce discovers alternate paths that converge.
	allPaths = deduplicatePaths(allPaths)

	if len(duplicateFingerprints) > 0 {
		for _, path := range allPaths {
			for _, cert := range path.Certificates {
				if _, ok := duplicateFingerprints[certDedupKey(cert)]; ok {
					path.Warnings = append(path.Warnings, ValidationWarning{
						Certificate: cert,
						Type:        WarningDuplicateCertificate,
						Message:     "duplicate certificate in chain: " + cert.CommonName(),
					})
					break // one warning per path is sufficient
				}
			}
		}
	}

	cb.logger.Info("built certificate chains", "paths", len(allPaths))

	return allPaths, nil
}

// buildChain recursively builds all possible chains from a certificate.
//
//nolint:gocyclo,cyclop // recursive chain builder with multiple termination conditions
func (cb *defaultChainBuilder) buildChain(
	ctx context.Context,
	cert *Certificate,
	index *certificateIndex,
	trustStore TrustStore,
	visited map[string]struct{},
	depth int,
	pathCount *int,
) []*TrustPath {
	select {
	case <-ctx.Done():
		return nil // Context canceled; caller checks ctx.Err() in the loop.
	default:
	}

	if *pathCount >= maxTrustPaths {
		return nil
	}

	fingerprint := cert.FingerprintSHA256()

	if cb.opts.detectCircular {
		if _, ok := visited[fingerprint]; ok {
			cb.logger.Warn("circular reference detected", "cert", cert.CommonName(), "fingerprint", fingerprint)
			*pathCount++
			return []*TrustPath{{
				Certificates: []*Certificate{cert},
				Status:       PathIncomplete,
				Errors: []ValidationError{
					{Certificate: cert, Type: ErrorCircularReference, Message: "circular reference in certificate chain"},
				},
				Warnings: []ValidationWarning{},
			}}
		}
	}

	// Check depth limit (depth is 0-indexed, so if depth >= maxDepth, we've exceeded).
	if cb.opts.maxDepth > 0 && depth >= cb.opts.maxDepth {
		cb.logger.Warn("maximum chain depth exceeded", "cert", cert.CommonName(), "depth", depth, "maxDepth", cb.opts.maxDepth)
		*pathCount++
		return []*TrustPath{{
			Certificates: []*Certificate{cert},
			Status:       PathIncomplete,
			Errors: []ValidationError{
				{Certificate: cert, Type: ErrorDepthExceeded, Message: fmt.Sprintf("maximum chain depth of %d exceeded", cb.opts.maxDepth)},
			},
			Warnings: []ValidationWarning{},
		}}
	}

	// Mark as visited (backtrack after recursion to allow same cert in different paths).
	visited[fingerprint] = struct{}{}
	defer delete(visited, fingerprint)

	isTrusted := trustStore.IsTrusted(cert)
	trustedLocations := trustStore.TrustedLocations(cert)

	if isTrusted {
		// Use WithTrustedLocations (returns a copy) instead of the in-place
		// setTrustedLocations. The same *Certificate pointer may be shared
		// across multiple trust paths built concurrently by BatchAnalyzer;
		// mutating it in-place would be a data race.
		cert = cert.WithTrustedLocations(trustedLocations)
	}

	if cert.IsSelfSigned() {
		cb.logger.Debug("found self-signed certificate", "cert", cert.CommonName())

		if isTrusted {
			*pathCount++
			return []*TrustPath{{
				Certificates: []*Certificate{cert},
				Status:       PathTrusted,
				Errors:       []ValidationError{},
				Warnings:     []ValidationWarning{},
			}}
		}
		*pathCount++
		return []*TrustPath{{
			Certificates: []*Certificate{cert},
			Status:       PathUntrusted,
			Errors: []ValidationError{
				{Certificate: cert, Type: ErrorUntrustedRoot, Message: "self-signed certificate not in trust store"},
			},
			Warnings: []ValidationWarning{},
		}}
	}

	// If certificate is in trust store but not self-signed, treat it as a trusted root.
	// With AIAForce, also continue building to discover alternate paths via AIA.
	var trustedPaths []*TrustPath
	if isTrusted {
		cb.logger.Debug("found trusted certificate in trust store", "cert", cert.CommonName())
		trustedPath := NewTrustPath([]*Certificate{cert}, PathTrusted)
		*pathCount++
		if !cb.opts.aiaForce {
			return []*TrustPath{trustedPath}
		}
		trustedPaths = append(trustedPaths, trustedPath)
	}

	issuers := index.findIssuers(cert)

	// If no issuers found in the index, check the trust store. The server may
	// not have sent the root certificate, but it may be in the OS trust store.
	// This resolves incomplete chains for servers that send leaf + intermediate
	// but omit the root (e.g., Let's Encrypt chains where ISRG Root X1 is in
	// the system keychain but not sent by the server).
	if len(issuers) == 0 {
		trustStoreIssuers := trustStore.FindIssuers(cert)
		if len(trustStoreIssuers) > 0 {
			cb.logger.Debug("found issuers in trust store", "cert", cert.CommonName(), "count", len(trustStoreIssuers))
			// Add trust store issuers to the index so recursive calls can find them.
			for _, tsCert := range trustStoreIssuers {
				if _, ok := index.byFingerprint[certDedupKey(tsCert)]; ok {
					continue
				}
				index.all = append(index.all, tsCert)
				index.byFingerprint[certDedupKey(tsCert)] = struct{}{}
				subject := string(tsCert.Raw().RawSubject)
				index.bySubject[subject] = append(index.bySubject[subject], tsCert)
				if len(tsCert.Raw().SubjectKeyId) > 0 {
					ski := string(tsCert.Raw().SubjectKeyId)
					index.bySKI[ski] = append(index.bySKI[ski], tsCert)
				}
			}
			issuers = index.findIssuers(cert)
		}
	}

	// If no issuers found and AIA fetching is enabled, try to fetch via AIA.
	// If AIAForce is enabled, also fetch when issuers exist to discover alternate paths.
	shouldFetchAIA := cb.opts.aiaFetch && cb.aiaFetcher != nil &&
		(len(issuers) == 0 || cb.opts.aiaForce)
	if shouldFetchAIA {
		issuers = cb.tryAIAFetch(ctx, cert, index, issuers)
	}

	// If still no issuers found, mark chain as incomplete.
	// However, if the certificate is already trusted (saved in trustedPaths
	// during AIAForce exploration), the trusted path is valid per RFC 5280
	// Section 6.1: path validation terminates at a trust anchor regardless
	// of whether the anchor's own issuer is available.
	if len(issuers) == 0 {
		if len(trustedPaths) > 0 {
			return trustedPaths
		}
		cb.logger.Debug("no issuer found for certificate", "cert", cert.CommonName())
		*pathCount++
		return []*TrustPath{{
			Certificates: []*Certificate{cert},
			Status:       PathIncomplete,
			Errors:       []ValidationError{},
			Warnings: []ValidationWarning{
				{Certificate: cert, Type: WarningIncompleteChain, Message: "issuer certificate not found"},
			},
		}}
	}

	var allPaths []*TrustPath
	for _, issuer := range issuers {
		select {
		case <-ctx.Done():
			// Return partial results; BuildChains detects cancellation
			// via ctx.Err() after the top-level loop and returns an error.
			// Do NOT refactor BuildChains to skip that post-loop check.
			return trustedPaths
		default:
		}

		if *pathCount >= maxTrustPaths {
			break
		}

		issuerPaths := cb.buildChain(ctx, issuer, index, trustStore, visited, depth+1, pathCount)

		for _, issuerPath := range issuerPaths {
			certs := make([]*Certificate, 0, 1+len(issuerPath.Certificates))
			certs = append(certs, cert)
			certs = append(certs, issuerPath.Certificates...)

			newPath := NewTrustPath(certs, issuerPath.Status)
			// Copy error/warning slices when non-empty to avoid sharing
			// the underlying array with the issuer path.
			if len(issuerPath.Errors) > 0 {
				newPath.Errors = append([]ValidationError{}, issuerPath.Errors...)
			}
			if len(issuerPath.Warnings) > 0 {
				newPath.Warnings = append([]ValidationWarning{}, issuerPath.Warnings...)
			}
			allPaths = append(allPaths, newPath)
		}
	}

	// Include any trusted paths discovered before AIA exploration.
	allPaths = append(trustedPaths, allPaths...)

	return allPaths
}

// findEndEntities identifies certificates that are not issuing any other certificate.
// Self-signed certificates are correctly excluded because findIssuers returns the
// cert itself (subject matches issuer), so they are marked as issuers.
func (cb *defaultChainBuilder) findEndEntities(certs []*Certificate, index *certificateIndex) []*Certificate {
	isIssuer := make(map[*Certificate]struct{})

	for _, cert := range certs {
		issuers := index.findIssuers(cert)
		for _, issuer := range issuers {
			isIssuer[issuer] = struct{}{}
		}
	}

	var endEntities []*Certificate
	for _, cert := range certs {
		if _, ok := isIssuer[cert]; !ok {
			endEntities = append(endEntities, cert)
		}
	}

	// If no end-entities found (all certs issue each other), treat all as potential end-entities.
	// Note: MaxDepth prevents unbounded recursion, but branching factor grows with N.
	if len(endEntities) == 0 {
		cb.logger.Warn("no clear end-entity certificates found, treating all as potential end-entities")
		return certs
	}

	return endEntities
}

// tryAIAFetch attempts to fetch issuer certificates via AIA (Authority
// Information Access) and index them. Multiple AIA URLs may yield different
// cross-signed versions of the same CA key (same SPKI, different issuers).
// Returns an updated issuer list (re-queried from the index after successful
// fetches, or unchanged on failure).
func (cb *defaultChainBuilder) tryAIAFetch(ctx context.Context, cert *Certificate, index *certificateIndex, issuers []*Certificate) []*Certificate {
	cb.logger.Debug("attempting AIA fetch", "cert", cert.CommonName(), "existingIssuers", len(issuers))

	fetchedCerts, err := cb.aiaFetcher.FetchIssuers(ctx, cert)
	if err != nil {
		cb.logger.Warn("failed to fetch issuers via AIA", "cert", cert.CommonName(), "error", err)
		return issuers
	}

	added := 0
	for _, fetchedCert := range fetchedCerts {
		if !cb.aiaIssuerMatches(cert, fetchedCert) {
			cb.logger.Warn("excluding fetched certificate from path building due to issuer mismatch",
				"cert", cert.CommonName(),
				"fetched", fetchedCert.CommonName())
			continue
		}

		// Deduplicate by fingerprint: skip if this exact certificate is already indexed.
		if _, ok := index.byFingerprint[certDedupKey(fetchedCert)]; ok {
			cb.logger.Debug("AIA-fetched certificate already in index",
				"cert", cert.CommonName(), "fetched", fetchedCert.CommonName())
			continue
		}

		// Add fetched certificate to the index. Cross-signed certificates share
		// the same SPKI but have different fingerprints (different issuer signature),
		// so they are correctly indexed as separate entries.
		cb.logger.Info("indexing AIA-fetched issuer", "cert", cert.CommonName(), "issuer", fetchedCert.CommonName())
		index.all = append(index.all, fetchedCert)
		index.byFingerprint[certDedupKey(fetchedCert)] = struct{}{}
		subject := string(fetchedCert.Raw().RawSubject)
		index.bySubject[subject] = append(index.bySubject[subject], fetchedCert)
		if len(fetchedCert.Raw().SubjectKeyId) > 0 {
			ski := string(fetchedCert.Raw().SubjectKeyId)
			index.bySKI[ski] = append(index.bySKI[ski], fetchedCert)
		}
		added++
	}

	if added == 0 {
		return issuers
	}

	// Re-query issuers with the newly indexed certificates.
	return index.findIssuers(cert)
}

// aiaIssuerMatches validates that a fetched certificate matches the expected
// issuer based on AKI/SKI. Returns true if AKI/SKI are not both available
// (cannot validate) or if they match.
func (cb *defaultChainBuilder) aiaIssuerMatches(cert, fetched *Certificate) bool {
	if len(cert.Raw().AuthorityKeyId) == 0 || len(fetched.Raw().SubjectKeyId) == 0 {
		return true
	}
	if !bytes.Equal(cert.Raw().AuthorityKeyId, fetched.Raw().SubjectKeyId) {
		cb.logger.Warn("fetched certificate does not match expected issuer",
			"cert", cert.CommonName(),
			"fetched", fetched.CommonName(),
			"cert_aki", fmt.Sprintf("%x", cert.Raw().AuthorityKeyId),
			"fetched_ski", fmt.Sprintf("%x", fetched.Raw().SubjectKeyId))
		return false
	}
	return true
}

// detectDuplicates returns the set of certificate deduplication keys that
// appear more than once in certs. The returned map is nil when no duplicates
// are found.
func (cb *defaultChainBuilder) detectDuplicates(certs []*Certificate) map[string]struct{} {
	counts := make(map[string]int, len(certs))
	for _, cert := range certs {
		counts[certDedupKey(cert)]++
	}
	var dups map[string]struct{}
	for key, n := range counts {
		if n > 1 {
			if dups == nil {
				dups = make(map[string]struct{})
			}
			dups[key] = struct{}{}
			cb.logger.Warn("duplicate certificate detected in input pool", "key", key)
		}
	}
	return dups
}

// certificateIndex provides efficient certificate lookups.
type certificateIndex struct {
	bySubject     map[string][]*Certificate
	bySKI         map[string][]*Certificate
	byFingerprint map[string]struct{}
	all           []*Certificate
}

// certDedupKey returns a deduplication key for a certificate. It uses
// FingerprintSHA256() when available, falling back to the hex-encoded leading
// raw DER bytes for certificates created without NewCertificate (e.g., in
// tests that construct Certificate structs directly).
func certDedupKey(cert *Certificate) string {
	if fp := cert.FingerprintSHA256(); fp != "" {
		return fp
	}
	return fmt.Sprintf("raw:%x", cert.Raw().Raw[:min(pathKeyFallbackBytes, len(cert.Raw().Raw))])
}

// newCertificateIndex creates an index for efficient certificate lookups.
func newCertificateIndex(certs []*Certificate) *certificateIndex {
	// bySKI maps SubjectKeyId (raw bytes as string key, not hex-encoded) to
	// certificates. The raw-bytes key benefits from Go's m[string(bytes)]
	// zero-allocation optimization. This differs from defaultTrustStore.systemBySKI
	// which uses hex encoding; the two indexes are separate and never cross-queried.
	index := &certificateIndex{
		bySubject:     make(map[string][]*Certificate, len(certs)),
		bySKI:         make(map[string][]*Certificate, len(certs)),
		byFingerprint: make(map[string]struct{}, len(certs)),
		all:           certs,
	}

	for _, cert := range certs {
		// Index by raw ASN.1 subject bytes (avoids pkix.Name.String() allocations).
		subject := string(cert.Raw().RawSubject)
		index.bySubject[subject] = append(index.bySubject[subject], cert)

		if len(cert.Raw().SubjectKeyId) > 0 {
			ski := string(cert.Raw().SubjectKeyId)
			index.bySKI[ski] = append(index.bySKI[ski], cert)
		}

		index.byFingerprint[certDedupKey(cert)] = struct{}{}
	}

	return index
}

// findIssuers finds all potential issuers for a certificate.
func (index *certificateIndex) findIssuers(cert *Certificate) []*Certificate {
	var issuers []*Certificate

	// Go optimizes m[string(bytes)] to avoid allocation.
	if len(cert.Raw().AuthorityKeyId) > 0 {
		if candidates, ok := index.bySKI[string(cert.Raw().AuthorityKeyId)]; ok {
			issuers = append(issuers, candidates...)
		}
	}

	if len(issuers) == 0 {
		if candidates, ok := index.bySubject[string(cert.Raw().RawIssuer)]; ok {
			issuers = append(issuers, candidates...)
		}
	}

	return issuers
}

// deduplicatePaths removes trust paths that have identical certificate sequences
// and resolves prefix relationships between paths. Two paths are considered
// duplicates if they contain the same certificates in the same order (by
// fingerprint). When duplicates exist, the trusted variant is preferred.
//
// Prefix semantics (for each pair where shorter is a prefix of longer):
//   - Both trusted:             keep both -- each represents a distinct trust anchor.
//   - Shorter trusted, longer untrusted: remove longer -- it is noise from
//     AIAForce exploration past the trust anchor.
//   - Shorter untrusted, longer trusted: remove shorter -- the longer path is
//     strictly better.
//   - Both untrusted:           remove shorter -- the longer path is more complete.
func deduplicatePaths(paths []*TrustPath) []*TrustPath {
	if len(paths) <= 1 {
		return paths
	}

	unique := deduplicateExact(paths)
	return removePrefixPaths(unique)
}

// deduplicateExact removes paths with identical certificate fingerprint
// sequences, preferring trusted variants over untrusted ones.
func deduplicateExact(paths []*TrustPath) []*TrustPath {
	seen := make(map[string]int) // key -> index in result
	unique := make([]*TrustPath, 0, len(paths))

	for _, path := range paths {
		key := path.PathKey()
		if idx, exists := seen[key]; exists {
			// Prefer the trusted variant.
			if path.Status.IsTrusted() && !unique[idx].Status.IsTrusted() {
				unique[idx] = path
			}
			continue
		}
		seen[key] = len(unique)
		unique = append(unique, path)
	}

	return unique
}

// removePrefixPaths resolves prefix relationships between paths. For each pair
// where shorter is a strict prefix of longer, the outcome depends on trust.
// This is O(n^2) in the number of paths, which is acceptable because paths are
// bounded by maxTrustPaths and typically number in the low tens. For each pair:
//   - Both trusted:             keep both (distinct trust anchors).
//   - Shorter trusted, longer not: remove longer (untrusted AIAForce noise).
//   - Shorter not trusted:      remove shorter (longer is at least as good).
func removePrefixPaths(paths []*TrustPath) []*TrustPath {
	toRemove := make(map[int]struct{})

	for i, shorter := range paths {
		for j, longer := range paths {
			if i == j || len(longer.Certificates) <= len(shorter.Certificates) {
				continue
			}
			if !isPathPrefix(shorter, longer) {
				continue
			}

			shorterTrusted := shorter.Status.IsTrusted()
			longerTrusted := longer.Status.IsTrusted()

			switch {
			case shorterTrusted && longerTrusted:
				// Both end at genuine trust anchors -- keep both.
			case shorterTrusted && !longerTrusted:
				// Longer is an untrusted extension past the trust anchor -- remove it.
				toRemove[j] = struct{}{}
			default:
				// Shorter is untrusted; longer is at least as complete -- remove shorter.
				toRemove[i] = struct{}{}
			}
		}
	}

	if len(toRemove) == 0 {
		return paths
	}

	result := make([]*TrustPath, 0, len(paths)-len(toRemove))
	for i, path := range paths {
		if _, ok := toRemove[i]; !ok {
			result = append(result, path)
		}
	}
	return result
}

// isPathPrefix returns true if shorter's certificate sequence is a prefix of
// longer's certificate sequence (compared by SHA-256 fingerprint).
func isPathPrefix(shorter, longer *TrustPath) bool {
	if len(shorter.Certificates) >= len(longer.Certificates) {
		return false
	}
	for i, cert := range shorter.Certificates {
		if cert.FingerprintSHA256() != longer.Certificates[i].FingerprintSHA256() {
			return false
		}
	}
	return true
}

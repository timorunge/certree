// Trust store implementation for managing trusted root certificates.

package certree

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// TrustStore provides access to trusted root certificates from system and custom sources.
// It supports loading certificates from platform-specific system trust stores (macOS Keychain,
// Linux certificate directories, Windows Certificate Store) and custom PEM bundle files.
//
// The trust store maintains separate collections for system and custom roots, allowing
// precedence control when a certificate appears in both locations. This is useful for
// testing scenarios where you want to override system trust decisions.
//
// Thread-safety: All methods are safe for concurrent use.
type TrustStore interface {
	// IsTrusted checks if a certificate is in the trust store.
	// It returns true if the certificate is found in either the system trust store
	// or custom trust store (or both).
	//
	// The certificate is identified by its SHA-256 fingerprint, so certificates
	// with identical content are considered the same regardless of source.
	IsTrusted(cert *Certificate) bool

	// TrustedLocations returns all locations where the certificate is trusted.
	// For system certificates, "system" is returned. For custom certificates, the
	// actual file paths from which the certificate was loaded are returned (e.g.,
	// "/etc/ssl/custom-ca.crt"). If the certificate appears in multiple custom
	// bundles, all file paths are listed.
	//
	// The order reflects the configured precedence (see WithCustomRootsPrecedence).
	// Returns an empty slice if the certificate is not trusted.
	TrustedLocations(cert *Certificate) []string

	// LoadSystemRoots loads trusted root certificates from the system trust store.
	// The implementation is platform-specific:
	//   - macOS: Loads from SystemRootCertificates.keychain and System.keychain
	//   - Linux: Loads from standard certificate directories (/etc/ssl/certs, etc.)
	//   - Windows: Enumerates ROOT and AuthRoot stores via the Windows Crypto API
	//   - Other platforms: Returns error indicating unsupported platform
	//
	// This method is idempotent; subsequent calls are no-ops (the first successful
	// load is cached for the lifetime of the TrustStore instance).
	// Use WithSystemRootsPath to override the default system location.
	//
	// Returns an error if the system trust store cannot be accessed or parsed.
	LoadSystemRoots() error

	// LoadCustomRoots loads trusted root certificates from a custom PEM bundle file.
	// The file must contain one or more PEM-encoded certificates. Non-certificate
	// PEM blocks (e.g., private keys) are ignored.
	//
	// This method can be called multiple times with different files; certificates
	// are accumulated in the custom trust store. Duplicate certificates (same fingerprint)
	// are automatically deduplicated.
	//
	// Returns an error if the file cannot be read or contains no valid certificates.
	LoadCustomRoots(path string) error

	// FindIssuers returns trusted certificates that could be the issuer of cert.
	// It matches by Authority Key Identifier (AKI) to Subject Key Identifier (SKI)
	// when AKI is present, falling back to raw subject DN matching against the
	// certificate's raw issuer DN. This enables the chain builder to complete
	// chains when the server does not send the root certificate.
	//
	// Returns nil if no matching issuers are found in the trust store.
	// Thread-safe for concurrent access.
	FindIssuers(cert *Certificate) []*Certificate
}

// trustStoreOptions configures trust store behavior.
// These options control how certificates are loaded and which trust store
// takes precedence when a certificate appears in multiple locations.
type trustStoreOptions struct {
	// preferCustom determines precedence when a cert is in both stores.
	// If true, custom trust store takes precedence over system trust store.
	// If false (default), system trust store takes precedence.
	//
	// This affects the order returned by TrustedLocations and can be used
	// to override system trust decisions for testing or special configurations.
	preferCustom bool

	// systemRootsPath overrides the default system trust store path.
	// Empty string (default) uses platform-specific defaults:
	//   - macOS: SystemRootCertificates.keychain + System.keychain (MDM/admin CAs)
	//   - Linux: /etc/ssl/certs, /etc/pki/tls/certs, etc.
	//   - Windows: ROOT and AuthRoot stores (Windows Crypto API)
	//
	// Set this to load system roots from a non-standard location.
	systemRootsPath string
}

// TrustStoreOption is a functional option for configuring a TrustStore.
type TrustStoreOption func(*defaultTrustStore)

// WithCustomRootsPrecedence controls whether custom trust bundles take precedence over
// system roots when both contain the same certificate.
// Default: false (system roots take precedence).
func WithCustomRootsPrecedence(prefer bool) TrustStoreOption {
	return func(ts *defaultTrustStore) {
		ts.opts.preferCustom = prefer
	}
}

// WithSystemRootsPath sets a custom path for loading system root certificates.
// Default: platform-specific default location.
func WithSystemRootsPath(path string) TrustStoreOption {
	return func(ts *defaultTrustStore) {
		ts.opts.systemRootsPath = path
	}
}

// WithTrustStoreLogger sets the logger for the trust store.
// Default: no-op logger (silent).
//
// Panics if logger is nil (programmer error).
func WithTrustStoreLogger(logger *slog.Logger) TrustStoreOption {
	return func(ts *defaultTrustStore) {
		if logger == nil {
			panic("certree: WithTrustStoreLogger called with nil logger")
		}
		ts.logger = logger
	}
}

// defaultTrustStore implements the TrustStore interface.
// It maintains separate collections for system and custom root certificates,
// using SHA-256 fingerprints as keys for efficient lookup and deduplication.
//
// Custom certificates are tracked with their originating file paths so that
// TrustedLocations can return the actual bundle file paths (e.g.,
// "/etc/ssl/custom-ca.crt") instead of a generic "custom" label. When a
// certificate appears in multiple custom bundles, all file paths are recorded.
//
// All methods are protected by a read-write mutex for thread-safe concurrent access.
type defaultTrustStore struct {
	opts   trustStoreOptions
	logger *slog.Logger

	// mu protects concurrent access to all fields below.
	mu sync.RWMutex

	// systemRoots maps certificate fingerprints to certificates from system trust store.
	systemRoots map[string]*Certificate

	// systemBySKI maps SubjectKeyId (hex) to certificates from system trust store.
	// Used by FindIssuers for AKI-to-SKI issuer discovery. Multiple certificates
	// may share the same SKI, so the map stores a slice per SKI.
	systemBySKI map[string][]*Certificate

	// systemBySPKI maps SHA-256 of RawSubjectPublicKeyInfo (hex) to certificates
	// from the system trust store. Used by IsTrusted and TrustedLocations to
	// identify cross-signed variants that share the same public key. Unlike SKI,
	// SPKI comparison guarantees key equivalence because CAs cannot forge another
	// key's SubjectPublicKeyInfo.
	systemBySPKI map[string][]*Certificate

	// customCerts maps certificate fingerprints to certificates from custom trust bundles.
	customCerts map[string]*Certificate

	// customBySKI maps SubjectKeyId (hex) to certificates from custom trust bundles.
	// Used by FindIssuers for AKI-to-SKI issuer discovery. Multiple certificates
	// may share the same SKI, so the map stores a slice.
	customBySKI map[string][]*Certificate

	// customBySPKI maps SHA-256 of RawSubjectPublicKeyInfo (hex) to certificates
	// from custom trust bundles. Used by IsTrusted and TrustedLocations to
	// identify cross-signed variants that share the same public key.
	customBySPKI map[string][]*Certificate

	// systemBySubject maps raw ASN.1 subject bytes to certificates from the
	// system trust store. Used by FindIssuers to locate issuers by subject DN
	// when the chain builder cannot find them in the certificate index.
	systemBySubject map[string][]*Certificate

	// customBySubject maps raw ASN.1 subject bytes to certificates from custom
	// trust bundles. Used by FindIssuers alongside systemBySubject.
	customBySubject map[string][]*Certificate

	// customPaths maps certificate fingerprints to the list of file paths where
	// each custom certificate was loaded from. A certificate appearing in multiple
	// custom bundles will have multiple paths recorded.
	customPaths map[string][]string

	// systemLoaded is set after the first successful LoadSystemRoots call;
	// subsequent calls return immediately.
	systemLoaded bool
}

// NewTrustStore creates a new trust store with the given options.
// The trust store is initially empty; call LoadSystemRoots and/or LoadCustomRoots
// to populate it with trusted certificates.
func NewTrustStore(opts ...TrustStoreOption) TrustStore {
	ts := &defaultTrustStore{
		logger:          NewLogger(),
		systemRoots:     make(map[string]*Certificate),
		systemBySKI:     make(map[string][]*Certificate),
		systemBySPKI:    make(map[string][]*Certificate),
		systemBySubject: make(map[string][]*Certificate),
		customCerts:     make(map[string]*Certificate),
		customBySKI:     make(map[string][]*Certificate),
		customBySPKI:    make(map[string][]*Certificate),
		customBySubject: make(map[string][]*Certificate),
		customPaths:     make(map[string][]string),
	}

	for _, opt := range opts {
		opt(ts)
	}

	return ts
}

var _ TrustStore = (*defaultTrustStore)(nil)

// IsTrusted checks if a certificate is in the trust store.
// Returns true if the certificate is found in either system or custom trust store.
// Thread-safe for concurrent access.
func (ts *defaultTrustStore) IsTrusted(cert *Certificate) bool {
	if cert == nil {
		return false
	}

	ts.mu.RLock()
	defer ts.mu.RUnlock()

	fingerprint := cert.FingerprintSHA256()

	_, inSystem := ts.systemRoots[fingerprint]
	_, inCustom := ts.customCerts[fingerprint]

	if inSystem || inCustom {
		return true
	}

	// Check by SubjectPublicKeyInfo for cross-signed variants sharing the same key.
	// Unlike SubjectKeyId (an opaque value CAs can set arbitrarily per RFC 5280),
	// comparing the raw SPKI bytes guarantees the same public key -- the actual
	// invariant that cross-signing preserves.
	spki := cert.spkiSHA256
	if certs, ok := ts.systemBySPKI[spki]; ok && len(certs) > 0 {
		return true
	}
	if certs, ok := ts.customBySPKI[spki]; ok && len(certs) > 0 {
		return true
	}

	return false
}

// TrustedLocations returns all locations where the certificate is trusted.
// For system certificates, "system" is returned. For custom certificates, the
// actual file paths from which the certificate was loaded are returned.
// If the certificate appears in multiple custom bundles, all file paths are listed.
// The order of locations reflects the configured precedence (PreferCustom option).
// The returned slice is a fresh copy; callers may modify it freely.
// Thread-safe for concurrent access.
func (ts *defaultTrustStore) TrustedLocations(cert *Certificate) []string {
	if cert == nil {
		return []string{}
	}

	ts.mu.RLock()
	defer ts.mu.RUnlock()

	fingerprint := cert.FingerprintSHA256()

	_, inSystem := ts.systemRoots[fingerprint]
	paths, inCustom := ts.customPaths[fingerprint]

	inSystem, inCustom, paths = ts.resolveSPKILookups(cert, inSystem, inCustom, paths)

	return ts.assembleLocations(inSystem, inCustom, paths)
}

// FindIssuers returns trusted certificates whose subject matches the issuer of
// cert. It uses AKI-to-SKI matching when the certificate has an Authority Key
// Identifier, falling back to raw ASN.1 subject/issuer DN comparison. Results
// are deduplicated by fingerprint.
// Thread-safe for concurrent access.
func (ts *defaultTrustStore) FindIssuers(cert *Certificate) []*Certificate {
	if cert == nil {
		return nil
	}

	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if len(cert.Raw().AuthorityKeyId) > 0 {
		aki := HexEncodeUpper(cert.Raw().AuthorityKeyId)
		issuers := ts.collectBySKI(aki)
		if len(issuers) > 0 {
			return issuers
		}
	}

	// Fall back to raw subject DN matching.
	issuerDN := string(cert.Raw().RawIssuer)
	return ts.collectBySubject(issuerDN)
}

// collectBySKI gathers certificates from both system and custom stores that
// match the given SKI hex string, deduplicated by fingerprint.
func (ts *defaultTrustStore) collectBySKI(ski string) []*Certificate {
	return deduplicateCerts(ts.systemBySKI[ski], ts.customBySKI[ski])
}

// collectBySubject gathers certificates from both system and custom stores
// whose raw ASN.1 subject matches the given DN, deduplicated by fingerprint.
func (ts *defaultTrustStore) collectBySubject(subjectDN string) []*Certificate {
	return deduplicateCerts(ts.systemBySubject[subjectDN], ts.customBySubject[subjectDN])
}

// deduplicateCerts merges two certificate slices, deduplicating by SHA-256 fingerprint.
// Certificates from system appear before those from custom; duplicates are dropped.
func deduplicateCerts(system, custom []*Certificate) []*Certificate {
	seen := make(map[string]struct{}, len(system)+len(custom))
	result := make([]*Certificate, 0, len(system)+len(custom))
	for _, cert := range append(system, custom...) {
		fp := cert.FingerprintSHA256()
		if _, ok := seen[fp]; !ok {
			seen[fp] = struct{}{}
			result = append(result, cert)
		}
	}
	return result
}

// resolveSPKILookups extends fingerprint-based trust lookups with SPKI-based lookups.
// If the certificate was not found by fingerprint in either store, this method
// checks the SPKI maps for cross-signed variants sharing the same public key.
// When both stores already matched by fingerprint, SPKI lookup is skipped --
// cross-signed variants' file paths are not appended in that case because the
// primary cert's paths are already collected.
func (ts *defaultTrustStore) resolveSPKILookups(cert *Certificate, inSystem, inCustom bool, paths []string) (bool, bool, []string) {
	if (inSystem && inCustom) || len(cert.Raw().RawSubjectPublicKeyInfo) == 0 {
		return inSystem, inCustom, paths
	}

	spki := cert.spkiSHA256
	if !inSystem {
		if certs, ok := ts.systemBySPKI[spki]; ok && len(certs) > 0 {
			inSystem = true
		}
	}
	if !inCustom {
		if matched, ok := ts.customBySPKI[spki]; ok && len(matched) > 0 {
			inCustom = true
			for _, m := range matched {
				if p, exists := ts.customPaths[m.FingerprintSHA256()]; exists {
					paths = append(paths, p...)
				}
			}
		}
	}

	return inSystem, inCustom, paths
}

// assembleLocations builds the final location slice from system and custom trust matches.
func (ts *defaultTrustStore) assembleLocations(inSystem, inCustom bool, paths []string) []string {
	if !inSystem && !inCustom {
		return []string{}
	}

	locs := make([]string, 0, 1+len(paths))
	if ts.opts.preferCustom {
		if inCustom {
			locs = append(locs, paths...)
		}
		if inSystem {
			locs = append(locs, "system")
		}
	} else {
		if inSystem {
			locs = append(locs, "system")
		}
		if inCustom {
			locs = append(locs, paths...)
		}
	}
	return locs
}

// LoadSystemRoots loads trusted root certificates from the system trust store.
// This method delegates to platform-specific implementations (loadSystemRoots).
// Subsequent calls are no-ops; the system trust store is loaded once and cached
// for the lifetime of the trust store instance.
// Thread-safe for concurrent access.
func (ts *defaultTrustStore) LoadSystemRoots() error {
	// Fast path: check under read lock to avoid blocking concurrent readers.
	ts.mu.RLock()
	if ts.systemLoaded {
		ts.mu.RUnlock()
		return nil
	}
	ts.mu.RUnlock()

	// Acquire write lock for the entire load operation. This ensures
	// loadSystemRoots (which may shell out to security(1) on macOS) runs
	// at most once, even under concurrent calls.
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Double-check after acquiring write lock: another goroutine may have
	// loaded the roots while we were waiting.
	if ts.systemLoaded {
		return nil
	}

	// Platform-specific implementation (may execute external commands).
	certs, err := loadSystemRoots(ts.opts.systemRootsPath, ts.logger)
	if err != nil {
		return fmt.Errorf("loading system roots: %w", err)
	}

	for _, cert := range certs {
		fingerprint := cert.FingerprintSHA256()
		ts.systemRoots[fingerprint] = cert
		subject := string(cert.Raw().RawSubject)
		ts.systemBySubject[subject] = append(ts.systemBySubject[subject], cert)
		if len(cert.Raw().SubjectKeyId) > 0 {
			ski := HexEncodeUpper(cert.Raw().SubjectKeyId)
			ts.systemBySKI[ski] = append(ts.systemBySKI[ski], cert)
		}
		spki := cert.spkiSHA256
		ts.systemBySPKI[spki] = append(ts.systemBySPKI[spki], cert)
		ts.logger.Debug("loaded system root certificate",
			"subject", cert.CommonName(),
			"fingerprint", fingerprint,
		)
	}

	ts.logger.Info("loaded system root certificates", "count", len(certs))
	ts.systemLoaded = true
	return nil
}

// LoadCustomRoots loads trusted root certificates from a custom bundle file.
// Certificates are accumulated; calling this method multiple times with different
// files adds to the custom trust store. Duplicate certificates (same fingerprint)
// are deduplicated, but all originating file paths are tracked so that
// TrustedLocations returns the actual bundle paths.
// Thread-safe for concurrent access.
func (ts *defaultTrustStore) LoadCustomRoots(path string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	certs, err := loadCustomRoots(path)
	if err != nil {
		// loadCustomRoots may return a StructuredError from ParsePEMCertificates;
		// propagate it directly so the user message is specific.
		if se, ok := errors.AsType[*StructuredError](err); ok {
			return se
		}
		return NewStructuredError(
			fmt.Sprintf("could not load custom roots from %q", path),
			ErrFileReadFailed,
			err,
		)
	}

	for _, cert := range certs {
		fingerprint := cert.FingerprintSHA256()

		// The customCerts map is the authoritative dedup check. Index maps
		// (bySubject, bySKI, bySPKI) only need updates for new certs.
		if _, exists := ts.customCerts[fingerprint]; !exists {
			ts.customCerts[fingerprint] = cert

			subject := string(cert.Raw().RawSubject)
			ts.customBySubject[subject] = append(ts.customBySubject[subject], cert)

			if len(cert.Raw().SubjectKeyId) > 0 {
				ski := HexEncodeUpper(cert.Raw().SubjectKeyId)
				ts.customBySKI[ski] = append(ts.customBySKI[ski], cert)
			}

			spki := cert.spkiSHA256
			ts.customBySPKI[spki] = append(ts.customBySPKI[spki], cert)
		}

		// Track originating file paths even for duplicates.
		if !slices.Contains(ts.customPaths[fingerprint], path) {
			ts.customPaths[fingerprint] = append(ts.customPaths[fingerprint], path)
		}

		ts.logger.Debug("loaded custom root certificate",
			"subject", cert.CommonName(),
			"fingerprint", fingerprint,
			"source", path,
		)
	}

	ts.logger.Info("loaded custom root certificates", "count", len(certs), "source", path)
	return nil
}

// loadCustomRoots reads a PEM bundle file, validates it, and returns the parsed certificates.
func loadCustomRoots(path string) ([]*Certificate, error) {
	cleaned := filepath.Clean(path)

	if !filepath.IsAbs(cleaned) {
		return nil, NewStructuredError(
			fmt.Sprintf("trust bundle path %q must be absolute", cleaned),
			ErrInvalidInput, nil,
		)
	}

	info, err := os.Stat(cleaned)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, NewStructuredError(
				fmt.Sprintf("trust bundle %q not found", cleaned),
				ErrFileReadFailed, err,
			)
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, NewStructuredError(
				fmt.Sprintf("cannot read trust bundle %q: permission denied", cleaned),
				ErrFileReadFailed, err,
			)
		}
		return nil, NewStructuredError(
			fmt.Sprintf("cannot access trust bundle %q", cleaned),
			ErrFileReadFailed, err,
		)
	}
	if info.IsDir() {
		return nil, NewStructuredError(
			fmt.Sprintf("trust bundle path %q is a directory, expected a PEM file", cleaned),
			ErrInvalidInput, nil,
		)
	}
	if info.Size() > int64(maxParserInputSize) {
		return nil, NewStructuredError(
			fmt.Sprintf("trust bundle %q exceeds maximum size (%d bytes)", cleaned, maxParserInputSize),
			ErrFileTooLarge, nil,
		)
	}

	// #nosec G304 -- Path cleaned by filepath.Clean and verified by os.Stat above; user-provided trust bundle path.
	data, err := os.ReadFile(cleaned)
	if err != nil {
		return nil, NewStructuredError(
			fmt.Sprintf("cannot read trust bundle %q", cleaned),
			ErrFileReadFailed, err,
		)
	}

	source := CertificateSource{
		Type:     SourceTypeFile,
		Location: cleaned,
	}

	certs, err := ParsePEMCertificates(data, source, 0)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

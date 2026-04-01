// Simulator for certificate exclusion scenarios and trust path filtering.

package certree

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
)

// Simulator simulates certificate exclusion and injection scenarios to predict
// the impact of certificate changes on trust path validation.
//
// Not safe for concurrent use: ExcludeBy* and InjectCertificates mutate
// internal state. Create a separate Simulator per goroutine, or serialize calls.
type Simulator interface {
	// ExcludeByCommonName adds a Common Name exclusion criterion.
	// Certificates with a matching Common Name will be excluded from the
	// simulation. Supports exact matches, wildcard patterns via
	// path.Match (e.g. "*.example.com", "Intermediate*"), and
	// pipe-separated alternatives (e.g. "Old CA|Legacy*").
	// Returns the simulator for method chaining.
	ExcludeByCommonName(cn string) Simulator

	// ExcludeByFingerprint adds a fingerprint exclusion criterion.
	// Certificates with a matching SHA256 fingerprint will be excluded from
	// the simulation. Supports exact matches, wildcard patterns via
	// path.Match (e.g. "A1B2*"), and pipe-separated alternatives.
	// Returns the simulator for method chaining.
	ExcludeByFingerprint(fingerprint string) Simulator

	// ExcludeBySerial adds a serial number exclusion criterion.
	// Certificates with a matching serial number will be excluded from the
	// simulation. Supports exact matches, wildcard patterns via
	// path.Match (e.g. "1234*"), and pipe-separated alternatives.
	// Returns the simulator for method chaining.
	ExcludeBySerial(serial string) Simulator

	// InjectCertificates adds certificates to the simulation pool.
	// When Simulate is called, the injected certificates are merged with
	// the original analysis certificates and all trust paths are rebuilt
	// from scratch using the configured ChainBuilder and TrustStore.
	// Requires WithSimulatorChainBuilder and WithSimulatorTrustStore.
	// Returns the simulator for method chaining.
	InjectCertificates(certs []*Certificate) Simulator

	// Simulate performs the simulation on the given analysis.
	// When certificates have been injected, it rebuilds chains from the
	// merged certificate pool using the configured ChainBuilder and
	// TrustStore, then applies any exclusion filters.
	// When only exclusions are present, it filters existing trust paths.
	// Optionally re-validates paths if a validator is configured.
	//
	// Returns an error if:
	//   - The context is canceled
	//   - The analysis parameter is nil
	//   - Injection is used without ChainBuilder or TrustStore
	//   - Chain building fails (when injecting)
	//   - Validation fails (if validator is configured)
	Simulate(ctx context.Context, analysis *Analysis) (*Analysis, error)
}

// SimulatorOption is a functional option for configuring Simulator.
type SimulatorOption func(*defaultSimulator)

// WithSimulatorValidator sets a custom validator for the simulator.
// When set, the simulator re-validates rebuilt trust paths after exclusion.
func WithSimulatorValidator(validator Validator) SimulatorOption {
	return func(s *defaultSimulator) {
		if validator == nil {
			panic("certree: WithSimulatorValidator called with nil validator")
		}
		s.validator = validator
	}
}

// WithSimulatorLogger sets a custom logger for the simulator.
func WithSimulatorLogger(logger *slog.Logger) SimulatorOption {
	return func(s *defaultSimulator) {
		if logger == nil {
			panic("certree: WithSimulatorLogger called with nil logger")
		}
		s.logger = logger
	}
}

// WithSimulatorValidationOptions sets the validation options used when
// re-validating simulated paths. If not set, the simulator uses sensible
// defaults (signatures and expiry enabled, revocation disabled, 30-day expiry warning).
func WithSimulatorValidationOptions(opts ValidationOptions) SimulatorOption {
	return func(s *defaultSimulator) {
		s.validationOpts = &opts
	}
}

// WithSimulatorChainBuilder sets the chain builder used when injecting
// certificates. Required for InjectCertificates to rebuild trust paths
// from the merged certificate pool.
func WithSimulatorChainBuilder(chainBuilder ChainBuilder) SimulatorOption {
	return func(s *defaultSimulator) {
		if chainBuilder == nil {
			panic("certree: WithSimulatorChainBuilder called with nil chain builder")
		}
		s.chainBuilder = chainBuilder
	}
}

// WithSimulatorTrustStore sets the trust store used when injecting
// certificates. Required for InjectCertificates to rebuild trust paths.
func WithSimulatorTrustStore(trustStore TrustStore) SimulatorOption {
	return func(s *defaultSimulator) {
		if trustStore == nil {
			panic("certree: WithSimulatorTrustStore called with nil trust store")
		}
		s.trustStore = trustStore
	}
}

// defaultSimulator implements the Simulator interface.
type defaultSimulator struct {
	validationOpts *ValidationOptions
	logger         *slog.Logger
	validator      Validator

	// Chain building dependencies for injection mode.
	chainBuilder ChainBuilder
	trustStore   TrustStore

	excludedCNs          []string
	excludedFingerprints []string
	excludedSerials      []string

	// Injected certificates for rotation simulation.
	injectedCerts []*Certificate
}

// NewSimulator creates a new Simulator with the given options.
// By default no validator is configured, so re-validation is skipped.
func NewSimulator(opts ...SimulatorOption) Simulator {
	s := &defaultSimulator{
		excludedCNs:          []string{},
		excludedFingerprints: []string{},
		excludedSerials:      []string{},
		logger:               NewLogger(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

var _ Simulator = (*defaultSimulator)(nil)

// ExcludeByCommonName adds a Common Name exclusion criterion.
func (s *defaultSimulator) ExcludeByCommonName(cn string) Simulator {
	s.excludedCNs = append(s.excludedCNs, cn)
	s.logger.Debug("added common name exclusion", "cn", cn)
	return s
}

// ExcludeByFingerprint adds a fingerprint exclusion criterion.
func (s *defaultSimulator) ExcludeByFingerprint(fingerprint string) Simulator {
	s.excludedFingerprints = append(s.excludedFingerprints, fingerprint)
	s.logger.Debug("added fingerprint exclusion", "fingerprint", fingerprint)
	return s
}

// ExcludeBySerial adds a serial number exclusion criterion.
func (s *defaultSimulator) ExcludeBySerial(serial string) Simulator {
	s.excludedSerials = append(s.excludedSerials, serial)
	s.logger.Debug("added serial number exclusion", "serial", serial)
	return s
}

// InjectCertificates adds certificates to the simulation pool.
func (s *defaultSimulator) InjectCertificates(certs []*Certificate) Simulator {
	s.injectedCerts = append(s.injectedCerts, certs...)
	s.logger.Debug("injected certificates for simulation", "count", len(certs))
	return s
}

// Simulate performs the simulation on the given analysis.
// When certificates have been injected it rebuilds chains from the merged pool
// then applies exclusions; otherwise it filters existing trust paths in place.
func (s *defaultSimulator) Simulate(ctx context.Context, analysis *Analysis) (*Analysis, error) {
	select {
	case <-ctx.Done():
		return nil, NewStructuredError("simulation canceled", ErrContextCanceled, ctx.Err())
	default:
	}

	if analysis == nil {
		return nil, NewStructuredError("simulation requires a non-nil analysis", ErrNilArgument, nil)
	}

	s.logger.Info("starting simulation",
		"total_paths", len(analysis.TrustPaths),
		"injected_certs", len(s.injectedCerts),
		"excluded_cns", len(s.excludedCNs),
		"excluded_fingerprints", len(s.excludedFingerprints),
		"excluded_serials", len(s.excludedSerials),
	)

	var matchers exclusionMatchers
	if s.hasExclusions() {
		matchers = s.compileExclusionMatchers()
	}

	if len(s.injectedCerts) > 0 {
		return s.simulateWithInjection(ctx, analysis, matchers)
	}

	return s.simulateExclusionOnly(ctx, analysis, matchers)
}

// exclusionMatchers holds pre-compiled pattern matchers for certificate
// exclusion, keeping the simulator safe for concurrent Simulate calls.
type exclusionMatchers struct {
	cn     *PatternMatcher
	fp     *PatternMatcher
	serial *PatternMatcher
}

// compileExclusionMatchers builds immutable matchers from the configured exclusion criteria.
func (s *defaultSimulator) compileExclusionMatchers() exclusionMatchers {
	return exclusionMatchers{
		cn:     NewPatternMatcher(s.excludedCNs),
		fp:     NewPatternMatcher(s.excludedFingerprints),
		serial: NewPatternMatcher(s.excludedSerials),
	}
}

// simulateExclusionOnly filters existing paths without rebuilding chains.
func (s *defaultSimulator) simulateExclusionOnly(ctx context.Context, analysis *Analysis, matchers exclusionMatchers) (*Analysis, error) {
	var simulatedPaths []*TrustPath
	for _, path := range analysis.TrustPaths {
		simPath := s.simulatePath(path, matchers)
		if simPath != nil {
			simulatedPaths = append(simulatedPaths, simPath)
		}
	}

	if err := s.revalidate(ctx, simulatedPaths); err != nil {
		return nil, err
	}

	allCerts, _ := collectAllCertificates(analysis)
	filteredCerts := s.filterCertificates(allCerts, matchers)

	simulatedAnalysis := NewAnalysis(filteredCerts, simulatedPaths, analysis.Metadata.Source,
		WithSimulated(true))

	s.logger.Info("simulation complete",
		"simulated_paths", len(simulatedPaths),
		"trusted_paths", simulatedAnalysis.Metadata.TrustedPaths,
	)

	return simulatedAnalysis, nil
}

// simulateWithInjection merges injected certificates with the original pool,
// rebuilds all chains from scratch, applies exclusions, and marks injected
// certs in SimulationMetadata.
func (s *defaultSimulator) simulateWithInjection(ctx context.Context, analysis *Analysis, matchers exclusionMatchers) (*Analysis, error) {
	if s.chainBuilder == nil || s.trustStore == nil {
		return nil, NewStructuredError(
			"injection requires WithSimulatorChainBuilder and WithSimulatorTrustStore",
			ErrInvalidInput, nil,
		)
	}

	injectedFPs := make(map[string]struct{}, len(s.injectedCerts))
	for _, cert := range s.injectedCerts {
		injectedFPs[cert.FingerprintSHA256()] = struct{}{}
		s.logger.Debug("injecting certificate",
			"cn", cert.CommonName(),
			"fingerprint", cert.FingerprintSHA256(),
		)
	}

	// collectAllCertificates returns the seen-map so we extend it directly.
	mergedCerts, seen := collectAllCertificates(analysis)
	originalCount := len(mergedCerts)
	for _, cert := range s.injectedCerts {
		fp := cert.FingerprintSHA256()
		if _, ok := seen[fp]; !ok {
			seen[fp] = struct{}{}
			mergedCerts = append(mergedCerts, cert)
		}
	}

	s.logger.Info("rebuilding chains with injected certificates",
		"original_certs", originalCount,
		"injected_certs", len(s.injectedCerts),
		"merged_certs", len(mergedCerts),
	)

	rebuiltPaths, err := s.chainBuilder.BuildChains(ctx, mergedCerts, s.trustStore)
	if err != nil {
		return nil, NewStructuredError(
			"failed to rebuild certificate chains after injection",
			ErrChainBuildFailed,
			err,
		)
	}

	var simulatedPaths []*TrustPath
	hasExcl := s.hasExclusions()
	for _, path := range rebuiltPaths {
		if hasExcl {
			simPath := s.simulatePath(path, matchers)
			if simPath != nil {
				simulatedPaths = append(simulatedPaths, simPath)
			}
		} else {
			simulatedPaths = append(simulatedPaths, path)
		}
	}

	for _, path := range simulatedPaths {
		for _, cert := range path.Certificates {
			fp := cert.FingerprintSHA256()
			if _, ok := injectedFPs[fp]; ok {
				if path.SimulationMetadata == nil {
					path.SimulationMetadata = make(map[string]CertSimulationState)
				}
				state := path.SimulationMetadata[fp]
				state.IsInjected = true
				path.SimulationMetadata[fp] = state
			}
		}
	}

	if err := s.revalidate(ctx, simulatedPaths); err != nil {
		return nil, err
	}

	finalCerts := s.filterCertificates(mergedCerts, matchers)

	simulatedAnalysis := NewAnalysis(finalCerts, simulatedPaths, analysis.Metadata.Source,
		WithSimulated(true))

	s.logger.Info("injection simulation complete",
		"rebuilt_paths", len(rebuiltPaths),
		"simulated_paths", len(simulatedPaths),
		"trusted_paths", simulatedAnalysis.Metadata.TrustedPaths,
	)

	return simulatedAnalysis, nil
}

// hasExclusions reports whether any exclusion criteria have been configured.
func (s *defaultSimulator) hasExclusions() bool {
	return len(s.excludedCNs) > 0 || len(s.excludedFingerprints) > 0 ||
		len(s.excludedSerials) > 0
}

// revalidate runs the validator on simulated paths if one is configured.
func (s *defaultSimulator) revalidate(ctx context.Context, paths []*TrustPath) error {
	if s.validator == nil {
		return nil
	}
	var validationOpts ValidationOptions
	if s.validationOpts != nil {
		validationOpts = *s.validationOpts
	} else {
		validationOpts = ValidationOptions{
			VerifyExpiry:       true,
			ExpiryWarningDays:  DefaultExpiryWarningDays,
			VerifyHostname:     false,
			VerifyRevocation:   false,
			RevocationFailOpen: true,
			VerifySignatures:   true,
		}
	}
	if err := s.validator.Validate(ctx, paths, validationOpts); err != nil {
		return fmt.Errorf("validating simulated chains: %w", err)
	}
	return nil
}

// simulatePath applies exclusion rules to a single trust path. It retains ALL
// certificates from the original path for structural alignment. The excluded
// cert and every cert above it are recorded in SimulationMetadata so the display
// layer can dim them while keeping the tree shape identical to the original.
// Returns nil if the first cert (leaf) is excluded.
func (s *defaultSimulator) simulatePath(tp *TrustPath, matchers exclusionMatchers) *TrustPath {
	var certs []*Certificate
	excludedIdx := -1

	for i, cert := range tp.Certificates {
		if shouldExclude(cert, matchers) {
			if len(certs) == 0 {
				// Leaf itself was excluded -- drop the entire path.
				return nil
			}
			excludedIdx = i
			break
		}
		certs = append(certs, cert)
	}

	if excludedIdx == -1 {
		return &TrustPath{
			Certificates: certs,
			Status:       tp.Status,
			Errors:       slices.Clone(tp.Errors),
			Warnings:     slices.Clone(tp.Warnings),
		}
	}

	// Check if any cert below the excluded one (closer to the leaf) is
	// independently in the trust store. Per RFC 5280 Section 6, path
	// validation terminates at a trust anchor; anything above exists only
	// for legacy compatibility. A trusted cert below preserves the path.
	trustedBelowIdx := -1
	for i := excludedIdx - 1; i >= 0; i-- {
		if len(certs[i].Metadata().TrustedLocations) > 0 {
			trustedBelowIdx = i
			break
		}
	}

	excludedCert := tp.Certificates[excludedIdx]

	certs = append(certs, excludedCert)
	for i := excludedIdx + 1; i < len(tp.Certificates); i++ {
		certs = append(certs, tp.Certificates[i])
	}

	// Carry over warnings/errors only for certs below the excluded one;
	// exclusion/ghost state is communicated via SimulationMetadata.
	belowFingerprints := make(map[string]struct{}, excludedIdx)
	for i := range excludedIdx {
		belowFingerprints[tp.Certificates[i].FingerprintSHA256()] = struct{}{}
	}
	warnings := filterWarningsForCerts(tp.Warnings, belowFingerprints)
	filteredErrors := filterErrorsForCerts(tp.Errors, belowFingerprints)

	simMeta := make(map[string]CertSimulationState, 1+len(tp.Certificates)-excludedIdx-1)
	excludedState := simMeta[excludedCert.FingerprintSHA256()]
	excludedState.IsExcluded = true
	simMeta[excludedCert.FingerprintSHA256()] = excludedState
	for i := excludedIdx + 1; i < len(tp.Certificates); i++ {
		fp := tp.Certificates[i].FingerprintSHA256()
		ghostState := simMeta[fp]
		ghostState.IsGhosted = true
		// Mark certs above the break that are also explicitly excluded,
		// so IsExcluded returns true for all user-excluded certificates.
		if shouldExclude(tp.Certificates[i], matchers) {
			ghostState.IsExcluded = true
		}
		simMeta[fp] = ghostState
	}

	if trustedBelowIdx >= 0 {
		// A trusted cert below the excluded one serves as trust anchor,
		// keeping the path trusted regardless of the original status.
		return &TrustPath{
			Certificates:       certs,
			Status:             PathTrusted,
			Errors:             filteredErrors,
			Warnings:           warnings,
			SimulationMetadata: simMeta,
		}
	}

	// No trusted anchor below the excluded cert: exclusion breaks the chain.
	warnings = append(warnings, ValidationWarning{
		Certificate: excludedCert,
		Type:        WarningExcludedBySimulation,
		Message:     "certificate excluded by simulation",
	})
	for i := range excludedIdx {
		warnings = append(warnings, ValidationWarning{
			Certificate: certs[i],
			Type:        WarningExcludedBySimulation,
			Message:     "trust chain broken: dependent certificate excluded by simulation",
		})
	}
	return &TrustPath{
		Certificates:       certs,
		Status:             PathIncomplete,
		Errors:             filteredErrors,
		Warnings:           warnings,
		SimulationMetadata: simMeta,
	}
}

// filterCertificates returns a new slice containing only non-excluded certificates.
func (s *defaultSimulator) filterCertificates(certs []*Certificate, matchers exclusionMatchers) []*Certificate {
	filtered := make([]*Certificate, 0, len(certs))

	for _, cert := range certs {
		if shouldExclude(cert, matchers) {
			s.logger.Debug("excluding certificate",
				"cn", cert.CommonName(),
				"fingerprint", cert.FingerprintSHA256(),
				"serial", cert.SerialNumber(),
			)
			continue
		}
		filtered = append(filtered, cert)
	}

	return filtered
}

// shouldExclude checks if a certificate should be excluded based on the
// compiled exclusion matchers. Accepts matchers as a value to avoid shared
// mutable state on the simulator.
func shouldExclude(cert *Certificate, m exclusionMatchers) bool {
	return m.cn.Match(cert.CommonName()) ||
		m.fp.Match(cert.FingerprintSHA256()) ||
		m.serial.Match(cert.SerialNumber())
}

// filterWarningsForCerts returns warnings whose Certificate is nil (path-level)
// or matches one of the fingerprints in the keep set.
func filterWarningsForCerts(warnings []ValidationWarning, keep map[string]struct{}) []ValidationWarning {
	result := []ValidationWarning{}
	for _, w := range warnings {
		if w.Certificate == nil {
			result = append(result, w)
			continue
		}
		if _, ok := keep[w.Certificate.FingerprintSHA256()]; ok {
			result = append(result, w)
		}
	}
	return result
}

// filterErrorsForCerts returns errors whose Certificate is nil (path-level)
// or matches one of the fingerprints in the keep set. This prevents stale
// errors (referencing excluded or ghosted certificates) from persisting in
// simulated paths while preserving path-level errors without a certificate.
func filterErrorsForCerts(errors []ValidationError, keep map[string]struct{}) []ValidationError {
	result := []ValidationError{}
	for _, e := range errors {
		if e.Certificate == nil {
			result = append(result, e)
			continue
		}
		if _, ok := keep[e.Certificate.FingerprintSHA256()]; ok {
			result = append(result, e)
		}
	}
	return result
}

// collectAllCertificates returns all unique certificates from an analysis,
// including AIA-fetched certs that appear in trust paths but not in the
// parsed certificate list. Deduplicates by fingerprint. The returned map
// contains the fingerprints of all collected certificates, allowing callers
// to extend the set without a second dedup pass.
func collectAllCertificates(analysis *Analysis) ([]*Certificate, map[string]struct{}) {
	seen := make(map[string]struct{}, len(analysis.Certificates))
	all := make([]*Certificate, 0, len(analysis.Certificates))

	for _, cert := range analysis.Certificates {
		fp := cert.FingerprintSHA256()
		if _, ok := seen[fp]; !ok {
			seen[fp] = struct{}{}
			all = append(all, cert)
		}
	}

	for _, path := range analysis.TrustPaths {
		for _, cert := range path.Certificates {
			fp := cert.FingerprintSHA256()
			if _, ok := seen[fp]; !ok {
				seen[fp] = struct{}{}
				all = append(all, cert)
			}
		}
	}

	return all, seen
}

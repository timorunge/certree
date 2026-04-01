// Analyzer orchestration: parsing, chain building, validation, and trust path discovery.

package certree

import (
	"context"
	"fmt"
	"log/slog"
	"net"
)

// DefaultExpiryWarningDays is the number of days before expiry at which a
// warning is emitted, used as the default for ValidationOptions.ExpiryWarningDays
// when no explicit value is configured.
const DefaultExpiryWarningDays = 30

// Analyzer orchestrates certificate analysis by coordinating parsing, chain
// building, validation, and trust path discovery.
type Analyzer struct {
	parser         Parser
	chainBuilder   ChainBuilder
	validator      Validator
	trustStore     TrustStore
	logger         *slog.Logger
	validationOpts *ValidationOptions
	remoteOpts     *RemoteOptions
	sni            string
}

// AnalyzerOption configures the analyzer via functional options.
type AnalyzerOption func(*Analyzer)

// WithChainBuilder sets a custom chain builder for the analyzer.
// Panics if builder is nil (programmer error).
func WithChainBuilder(builder ChainBuilder) AnalyzerOption {
	return func(a *Analyzer) {
		if builder == nil {
			panic("certree: WithChainBuilder called with nil builder")
		}
		a.chainBuilder = builder
	}
}

// WithParser sets the parser for the analyzer; required -- NewAnalyzer returns an error without it.
// Panics if parser is nil (programmer error).
func WithParser(parser Parser) AnalyzerOption {
	return func(a *Analyzer) {
		if parser == nil {
			panic("certree: WithParser called with nil parser")
		}
		a.parser = parser
	}
}

// WithSNI sets the Server Name Indication hostname for TLS connections, overriding the source hostname.
// Useful for servers behind CDNs, load balancers, or when connecting by IP address.
// An empty string causes SNI to be derived from the source hostname.
func WithSNI(sni string) AnalyzerOption {
	return func(a *Analyzer) {
		a.sni = sni
	}
}

// WithAnalyzerLogger sets the logger for analyzer diagnostics and, when sub-components are not
// explicitly provided, propagates it as their default logger.
// Panics if logger is nil (programmer error).
func WithAnalyzerLogger(logger *slog.Logger) AnalyzerOption {
	return func(a *Analyzer) {
		if logger == nil {
			panic("certree: WithAnalyzerLogger called with nil logger")
		}
		a.logger = logger
	}
}

// WithTrustStore sets a custom trust store for the analyzer.
// Panics if trustStore is nil (programmer error).
func WithTrustStore(trustStore TrustStore) AnalyzerOption {
	return func(a *Analyzer) {
		if trustStore == nil {
			panic("certree: WithTrustStore called with nil trust store")
		}
		a.trustStore = trustStore
	}
}

// WithValidator sets a custom validator for the analyzer.
// Panics if validator is nil (programmer error).
func WithValidator(validator Validator) AnalyzerOption {
	return func(a *Analyzer) {
		if validator == nil {
			panic("certree: WithValidator called with nil validator")
		}
		a.validator = validator
	}
}

// WithValidationOptions overrides the validation checks performed during analysis.
func WithValidationOptions(opts ValidationOptions) AnalyzerOption {
	return func(a *Analyzer) {
		a.validationOpts = &opts
	}
}

// WithRemoteOptions sets the TLS connection options used by AnalyzeHost.
// VerifyHostname defaults to false because certree validates hostnames independently.
func WithRemoteOptions(opts RemoteOptions) AnalyzerOption {
	return func(a *Analyzer) {
		a.remoteOpts = &opts
	}
}

// NewAnalyzer creates an Analyzer with the given options; a Parser must be supplied via WithParser.
func NewAnalyzer(opts ...AnalyzerOption) (*Analyzer, error) {
	a := &Analyzer{
		logger: NewLogger(),
	}

	// Apply options first so user-provided components take precedence.
	for _, opt := range opts {
		opt(a)
	}

	if a.parser == nil {
		return nil, NewStructuredError(
			"parser is required; use WithParser to provide one",
			ErrParserRequired,
			nil,
		)
	}

	// Order matters: trust store first (validator depends on it).
	if a.trustStore == nil {
		a.trustStore = NewTrustStore(WithTrustStoreLogger(a.logger))
	}

	if a.chainBuilder == nil {
		a.chainBuilder = NewChainBuilder(
			WithMaxDepth(DefaultMaxDepth),
			WithAIAFetch(false),
			WithCircularDetection(true),
			WithChainLogger(a.logger),
		)
	}

	if a.validator == nil {
		revocationChecker := NewRevocationChecker(WithRevocationLogger(a.logger))
		a.validator = NewValidator(
			WithValidatorTrustStore(a.trustStore),
			WithRevocationChecker(revocationChecker),
			WithValidatorLogger(a.logger),
		)
	}

	// Load system trust store eagerly during initialization.
	// With the caching in defaultTrustStore, this is safe to call even if the
	// trust store was already loaded via a custom option.
	// Note: Failure to load system roots is not fatal -- analysis proceeds with
	// an empty trust store. This is intentional for environments without system
	// roots (containers, minimal images, CI). Use a custom trust bundle
	// (WithTrustStore + LoadCustomRoots) when system roots are unavailable.
	if err := a.trustStore.LoadSystemRoots(); err != nil {
		a.logger.Warn("failed to load system trust store, analysis will proceed without system roots", "error", err)
	}

	return a, nil
}

// AnalyzeFile performs complete certificate analysis on a local PEM, DER, PKCS#7, or PKCS#12 file.
func (a *Analyzer) AnalyzeFile(ctx context.Context, path string) (*Analysis, error) {
	select {
	case <-ctx.Done():
		return nil, NewStructuredError(fmt.Sprintf("analysis of %s canceled", path), ErrContextCanceled, ctx.Err())
	default:
	}

	a.logger.Info("starting certificate analysis", "source", path)
	a.logger.Debug("parsing certificates from file", "path", path)

	certs, err := a.parser.ParseFile(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, NewStructuredError(fmt.Sprintf("no certificates found in %s", path), ErrNoCertificatesFound, nil)
	}

	return a.analyzeChains(ctx, certs, path)
}

// AnalyzeHost performs complete certificate analysis on a remote TLS host in "host:port" format.
func (a *Analyzer) AnalyzeHost(ctx context.Context, hostPort string) (*Analysis, error) {
	select {
	case <-ctx.Done():
		return nil, NewStructuredError(fmt.Sprintf("analysis of %s canceled", hostPort), ErrContextCanceled, ctx.Err())
	default:
	}

	a.logger.Info("starting certificate analysis", "source", hostPort)
	a.logger.Debug("parsing certificates from remote host", "host", hostPort)

	sni := a.sni
	if sni == "" {
		if h, _, err := net.SplitHostPort(hostPort); err == nil {
			sni = h
		} else {
			sni = hostPort
		}
	}

	var opts RemoteOptions
	if a.remoteOpts != nil {
		opts = *a.remoteOpts
		// Only override SNI when explicitly set via WithSNI. Otherwise
		// prefer the value from RemoteOptions, falling back to hostname.
		if a.sni != "" {
			opts.SNI = a.sni
		} else if opts.SNI == "" {
			opts.SNI = sni
		}
	} else {
		opts = RemoteOptions{
			SNI:            sni,
			VerifyHostname: false,
		}
	}

	certs, err := a.parser.ParseRemote(ctx, hostPort, opts)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, NewStructuredError(fmt.Sprintf("no certificates received from %s", hostPort), ErrNoCertificatesFound, nil)
	}

	return a.analyzeChains(ctx, certs, hostPort)
}

// AnalyzeBytes performs complete certificate analysis on raw bytes; source is used only for metadata labels (e.g., "stdin").
// Context cancellation is checked before parsing but not during, so large inputs near the 10 MB limit complete before cancellation is detected.
func (a *Analyzer) AnalyzeBytes(ctx context.Context, data []byte, source string) (*Analysis, error) {
	select {
	case <-ctx.Done():
		return nil, NewStructuredError(fmt.Sprintf("analysis of %s canceled", source), ErrContextCanceled, ctx.Err())
	default:
	}

	a.logger.Info("starting certificate analysis from bytes", "source", source)

	certs, err := a.parser.ParseBytes(data)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, NewStructuredError(fmt.Sprintf("no certificates found in %s", source), ErrNoCertificatesFound, nil)
	}

	return a.analyzeChains(ctx, certs, source)
}

// AnalyzeURL performs complete certificate analysis on certificates fetched from an HTTP or HTTPS URL.
func (a *Analyzer) AnalyzeURL(ctx context.Context, rawURL string) (*Analysis, error) {
	select {
	case <-ctx.Done():
		return nil, NewStructuredError(fmt.Sprintf("analysis of %s canceled", rawURL), ErrContextCanceled, ctx.Err())
	default:
	}

	a.logger.Info("starting certificate analysis", "source", rawURL)

	certs, err := a.parser.ParseURL(ctx, rawURL)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, NewStructuredError(fmt.Sprintf("no certificates found at %s", rawURL), ErrNoCertificatesFound, nil)
	}

	return a.analyzeChains(ctx, certs, rawURL)
}

// Analyze auto-detects whether source is a file path, remote host, or HTTP(S)
// URL and delegates to [Analyzer.AnalyzeFile], [Analyzer.AnalyzeHost], or
// [Analyzer.AnalyzeURL] accordingly. Use [Analyzer.AnalyzeBytes] for
// in-memory data. Source classification uses [DetectSource]; normalization
// (e.g., appending ":443") uses [NormalizeSource].
func (a *Analyzer) Analyze(ctx context.Context, source string) (*Analysis, error) {
	kind := DetectSource(source)
	normalized := normalizeByKind(source, kind)
	switch kind {
	case SourceStdin:
		return nil, NewStructuredError(
			"stdin source \"-\" is not supported by Analyze; use AnalyzeBytes to process piped input",
			ErrInvalidInput, nil,
		)
	case SourceURL:
		return a.AnalyzeURL(ctx, normalized)
	case SourceHost:
		return a.AnalyzeHost(ctx, normalized)
	default:
		return a.AnalyzeFile(ctx, normalized)
	}
}

// analyzeChains builds chains, validates them, and returns the Analysis.
func (a *Analyzer) analyzeChains(ctx context.Context, certs []*Certificate, source string) (*Analysis, error) {
	a.logger.Info("parsed certificates", "count", len(certs))

	paths, err := a.chainBuilder.BuildChains(ctx, certs, a.trustStore)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewStructuredError(
				"building chains canceled", ErrContextCanceled, ctx.Err(),
			)
		}
		return nil, NewStructuredError(
			"failed to build certificate chains", ErrChainBuildFailed, err,
		)
	}

	vopts := a.resolveValidationOptions(source)
	if err := a.validator.Validate(ctx, paths, vopts); err != nil {
		if ctx.Err() != nil {
			return nil, NewStructuredError(
				"validating chains canceled", ErrContextCanceled, ctx.Err(),
			)
		}
		return nil, NewStructuredError(
			"certificate chain validation failed", ErrValidationFailed, err,
		)
	}

	analysis := NewAnalysis(certs, paths, source)

	a.logger.Info("analysis complete", "certs", len(certs), "paths", len(paths), "trusted", analysis.Metadata.TrustedPaths)

	return analysis, nil
}

// resolveValidationOptions returns the validation options to use. If custom
// options were provided via WithValidationOptions, those are used as a base.
// Otherwise sensible defaults are returned. After resolving the base options,
// hostname auto-derivation is applied when enabled and no explicit
// hostname is set.
func (a *Analyzer) resolveValidationOptions(source string) ValidationOptions {
	var opts ValidationOptions
	if a.validationOpts != nil {
		opts = *a.validationOpts
	} else {
		opts = ValidationOptions{
			VerifyExpiry:       true,
			ExpiryWarningDays:  DefaultExpiryWarningDays,
			VerifyHostname:     true,
			VerifyRevocation:   false,
			RevocationFailOpen: true,
			VerifySignatures:   true,
		}
	}

	if opts.VerifyHostname && opts.Hostname == "" {
		derived := deriveHostname(source, a.sni, a.validationOpts)
		if derived != "" {
			opts.Hostname = derived
		} else {
			opts.VerifyHostname = false
		}
	}

	return opts
}

// deriveHostname determines the effective hostname to verify against based on
// the source string, SNI value, and existing validation options. It implements
// the precedence rules: explicit Hostname > SNI > source domain.
// Returns empty string if no hostname can be derived.
func deriveHostname(source, sni string, opts *ValidationOptions) string {
	if opts != nil && opts.Hostname != "" {
		return ""
	}
	if sni != "" {
		return sni
	}
	// URL sources are file fetches over HTTP, not TLS endpoints -- skip
	// hostname derivation so verification is disabled by default.
	if isURL(source) {
		return ""
	}
	if classifySource(source) != SourceHost {
		return ""
	}
	host, _, err := net.SplitHostPort(source)
	if err != nil || host == "" || isIPAddress(host) {
		return ""
	}
	return host
}

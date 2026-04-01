// Package certree provides X.509 certificate chain analysis.
//
// It parses certificates from files (PEM, DER, PKCS#7, PKCS#12), remote TLS
// connections, URLs, and raw bytes. It builds all possible trust paths -- including
// cross-signed chains via AIA discovery -- validates signatures and expiry,
// and integrates with platform-specific trust stores (macOS Keychain, Linux
// cert directories, Windows Certificate Store).
//
// The primary entry point is the [Analyzer], which orchestrates parsing,
// chain building, validation, and trust store loading:
//
//	p := certree.NewParser()
//	analyzer, err := certree.NewAnalyzer(certree.WithParser(p))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	ctx := context.Background()
//	analysis, err := analyzer.Analyze(ctx, "example.com") // auto-appends :443
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// The analysis result contains all discovered certificates, trust paths,
// and validation errors/warnings. Use [json.MarshalIndent] for machine-readable
// output, or iterate TrustPaths directly.
//
// Core interfaces ([Parser], [ChainBuilder], [Validator], [Simulator],
// [TrustStore], [AIAFetcher], [RevocationChecker]) can be used independently
// or composed through the Analyzer. The [Simulator] supports certificate
// exclusion and injection for CA migration planning.
//
// Hard errors from exported user-facing boundaries ([Parser], [Analyzer],
// [AIAFetcher], [Simulator], [RevocationChecker], [TrustStore],
// [BatchAnalyzer], and standalone functions like [ValidateSource],
// [ParsePEMCertificates] and [ParseDERCertificate]) are returned as [*StructuredError]
// values carrying a user-facing message, a sentinel category, and the
// underlying cause. Use [errors.As] to extract
// user messages and [errors.Is] to match sentinel categories such as
// [ErrConnectionFailed] or [ErrFileReadFailed]. See errors.go for the
// complete sentinel catalog.
//
// For batch processing, use [BatchAnalyzer] which processes multiple sources
// in parallel via a worker pool.
package certree

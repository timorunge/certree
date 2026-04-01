# Using certree as a Go Library

`pkg/certree` is the library behind the certree CLI. Everything the CLI does
-- parsing, chain building, validation, simulation -- is available as a Go API.

## Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Working with Certificates](#working-with-certificates)
- [Trust Paths](#trust-paths)
- [Configuring the Analyzer](#configuring-the-analyzer)
- [Validation Options](#validation-options)
- [Simulation](#simulation)
- [Batch Processing](#batch-processing)
- [Error Handling](#error-handling)
- [Complete Example](#complete-example)

## Installation

```bash
go get github.com/timorunge/certree@latest
```

Import the package:

```go
import "github.com/timorunge/certree/pkg/certree"
```

## Basic Usage

The `Analyzer` is the main entry point. It orchestrates parsing, chain
building, and validation in a single call:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/timorunge/certree/pkg/certree"
)

func main() {
	// Create a parser (required by the analyzer).
	p := certree.NewParser()

	// Create the analyzer with the parser.
	analyzer, err := certree.NewAnalyzer(
		certree.WithParser(p),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Analyze a certificate file.
	analysis, err := analyzer.Analyze(context.Background(), "cert.pem")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Certificates: %d\n", len(analysis.Certificates))
	fmt.Printf("Trust paths:  %d (%d trusted)\n",
		analysis.Metadata.TotalPaths,
		analysis.Metadata.TrustedPaths)
}
```

The source can be a file path (`cert.pem`, `bundle.der`), a remote host in
`host:port` format (`example.com:443`), or an HTTP(S) URL
(`https://pki.example.com/ca.pem`). `Analyze()` auto-appends `:443` to bare
hostnames, so `analyzer.Analyze(ctx, "example.com")` works. `AnalyzeHost()`
does not -- it requires an explicit `host:port`.

### Analyzing a URL

When the source is an HTTP(S) URL, use `AnalyzeURL` to fetch and parse
certificates from a remote endpoint:

```go
analysis, err := analyzer.AnalyzeURL(context.Background(), "https://pki.example.com/ca.pem")
if err != nil {
	log.Fatal(err)
}
```

`AnalyzeURL` fetches the URL, parses the response as PEM or DER, and runs the
same pipeline as `Analyze`. HTTP URLs are automatically upgraded to HTTPS.
SSRF protection blocks private IP addresses by default; use
`WithRemoteOptions` to permit private networks when needed. `Analyze()` also
accepts URLs directly -- it detects the `http://` or `https://` scheme and
dispatches to `AnalyzeURL` internally.

### Analyzing Raw Bytes

When you already have certificate data in memory (from an HTTP response,
stdin, or another source), use `AnalyzeBytes` to skip source detection:

```go
data, err := os.ReadFile("cert.pem")
if err != nil {
	log.Fatal(err)
}

analysis, err := analyzer.AnalyzeBytes(context.Background(), data, "cert.pem")
if err != nil {
	log.Fatal(err)
}
```

`AnalyzeBytes` runs the same pipeline as `Analyze` (parse, chain build,
validate) but accepts raw bytes directly. The source parameter is used only
as a label in metadata. This is useful when integrating with code that fetches
certificates through its own transport.

> **Note:** The parser auto-detects PEM and DER formats by default. To also
> detect PKCS#7 and PKCS#12 formats, pass `WithAutoDetectFormat(true)` to
> `NewParser`. PKCS#12 bundles are tried with an empty password.
> Password-protected PKCS#12 files are not supported -- extract certificates
> to PEM first using `openssl pkcs12 -in bundle.p12 -nokeys -out certs.pem`.

## Working with Certificates

Certificates are created through `NewCertificate`, which wraps a standard
library `*x509.Certificate` and computes metadata upfront. In practice you
rarely call this directly -- the parser does it for you -- but it is useful
when integrating with other code that already has parsed certificates.

```go
cert := certree.NewCertificate(x509Cert, certree.CertificateSource{
	Type:     certree.SourceTypeFile,
	Location: "/path/to/cert.pem",
})
```

All fields are accessed through getter methods:

```go
raw := cert.Raw()                  // *x509.Certificate
der := cert.DER()                  // DER-encoded bytes
source := cert.Source()            // Where the cert came from
meta := cert.Metadata()            // Computed metadata
cn := cert.CommonName()            // Subject Common Name
fp := cert.FingerprintSHA256()     // SHA-256 fingerprint (uppercase hex, no colons)
serial := cert.SerialNumber()      // Serial number (uppercase hex, no colons)
pemStr := cert.PEM()               // PEM-encoded string (lazy)
```

Use `WithCertificateTime(t)` to override the current time used for computing
metadata fields like `IsExpired`, `IsNotYetValid`, and `DaysUntilExpiry`.
This is useful for deterministic testing or temporal what-if analysis.

The metadata struct gives you expiry status, self-signed detection, and trust
store locations without recomputing anything:

```go
meta := cert.Metadata()

if meta.IsExpired {
	fmt.Println("Certificate has expired")
}
if meta.IsNotYetValid {
	fmt.Println("Certificate is not yet valid")
}
if meta.IsSelfSigned {
	fmt.Printf("Self-signed certificate, %d days until expiry\n", meta.DaysUntilExpiry)
}
if len(meta.TrustedLocations) > 0 {
	fmt.Printf("Trust store: %v\n", meta.TrustedLocations)
}
```

## Trust Paths

After analysis, `analysis.TrustPaths` contains every possible chain from
end-entity to root. Each `TrustPath` tells you whether the chain is trusted,
its status, and whether it has validation errors:

```go
for i, path := range analysis.TrustPaths {
	fmt.Printf("Path %d: %d certificates, status=%s\n",
		i+1, len(path.Certificates), path.Status)

	if path.Status.IsTrusted() && len(path.Errors) == 0 {
		fmt.Println("  Valid path (trusted, no errors)")
	}

	// The end-entity certificate is first in the chain.
	if len(path.Certificates) > 0 {
		leaf := path.Certificates[0]
		fmt.Printf("  Leaf: %s\n", leaf.CommonName())
	}

	// The root is available via Root() method.
	if root := path.Root(); root != nil {
		fmt.Printf("  Root: %s\n", root.CommonName())
	}

	for _, e := range path.Errors {
		fmt.Printf("  Error: %s\n", e.Message)
	}
	for _, w := range path.Warnings {
		fmt.Printf("  Warning: %s\n", w.Message)
	}
}
```

Helper methods on `Analysis` make common queries easy:

```go
if analysis.HasErrors() {
	fmt.Println("Validation errors found")
}

// Root-to-leaf order (default is leaf-to-root).
reversed := analysis.Reversed()

// Compact reference-based JSON: certificates defined once in a
// fingerprint-keyed map, trust paths reference by fingerprint.
jsonBytes, _ := reversed.MarshalJSON()
```

### Trust Path Helpers

`TrustPath` provides helper methods for inspecting simulation state and
computing path metadata.

**Simulation state** -- after a simulation, each `TrustPath` carries a
`SimulationMetadata` map (keyed by certificate fingerprint) of
`CertSimulationState` values. Each entry has three flags:

- `IsExcluded` -- true when the certificate was directly targeted for removal.
- `IsGhosted` -- true when the certificate became unreachable because a
  certificate below it in the chain was excluded.
- `IsInjected` -- true when the certificate was added to the simulation pool
  via `InjectCertificates` for rotation simulation.

Convenience methods on `TrustPath` look up these flags by certificate:

```go
for _, path := range simulated.TrustPaths {
	for _, cert := range path.Certificates {
		if path.IsExcluded(cert) {
			fmt.Printf("  [excluded]  %s\n", cert.CommonName())
		} else if path.IsGhosted(cert) {
			fmt.Printf("  [ghosted]   %s\n", cert.CommonName())
		} else if path.IsInjected(cert) {
			fmt.Printf("  [injected]  %s\n", cert.CommonName())
		}
	}
}
```

## Configuring the Analyzer

The analyzer uses functional options. Sensible defaults are provided for
everything except the parser, which is required:

```go
analyzer, err := certree.NewAnalyzer(
	certree.WithParser(parser),
	certree.WithValidationOptions(certree.ValidationOptions{
		VerifySignatures:  true,
		VerifyExpiry:      true,
		ExpiryWarningDays: 60,
		VerifyRevocation:  false,
	}),
)
```

### Custom Chain Builder

Control chain depth and AIA fetching:

```go
builder := certree.NewChainBuilder(
	certree.WithMaxDepth(15),
	certree.WithAIAFetch(true),
	certree.WithAIAForce(true),
	certree.WithCircularDetection(true),
)

analyzer, err := certree.NewAnalyzer(
	certree.WithParser(parser),
	certree.WithChainBuilder(builder),
)
```

### Custom AIA Fetcher

Customize the URL-keyed certificate cache and other fetcher options:

```go
fetcher := certree.NewAIAFetcher(
	certree.WithAIACache(true),      // default is true
	certree.WithAIALogger(certree.NewLogger()),
)

builder := certree.NewChainBuilder(
	certree.WithAIAFetch(true),
	certree.WithAIAFetcher(fetcher),
)
```

Total AIA fetches per analysis are bounded by the chain builder's `MaxDepth`
setting (default 10): each recursion level performs at most one AIA fetch.

`WithAIACache(bool)` enables or disables the URL-keyed certificate cache.
When enabled (the default), successfully fetched certificates are cached by
their AIA URL, so batch operations that share the same intermediate chains
incur only one network request per unique URL. Disable caching when you need
to detect certificate changes at the same URL.

`WithAIAAllowPrivateNetworks(true)` permits AIA fetches to RFC 1918 private
IP addresses. This is required for internal PKI environments where AIA URLs
point to private infrastructure. Disabled by default as an SSRF safeguard.

### Custom Trust Store

Point to a specific trust store instead of the system default:

```go
ts := certree.NewTrustStore(
	certree.WithCustomRootsPrecedence(true),
	certree.WithSystemRootsPath("/etc/ssl/certs"),
	certree.WithTrustStoreLogger(certree.NewLogger()),
)

analyzer, err := certree.NewAnalyzer(
	certree.WithParser(parser),
	certree.WithTrustStore(ts),
)
```

`WithCustomRootsPrecedence(true)` controls certificate precedence when a
certificate appears in both the system trust store and a custom trust bundle
loaded via `LoadCustomRoots`. When true, the custom bundle takes precedence
-- locations reported by `TrustedLocations` list the custom store first, and
matching favors the custom copy. The default is false (system roots take
precedence). This is useful for testing or for environments where a custom CA
must override a system-distributed certificate.

The `TrustStore` interface also exposes `FindIssuers(cert)` which returns
trusted certificates that could be the issuer of a given certificate. The
chain builder uses this to complete chains when the server does not send the
root. Custom `TrustStore` implementations must provide this method.

### SNI for Remote Hosts

When connecting to servers behind CDNs or by IP address:

```go
analyzer, err := certree.NewAnalyzer(
	certree.WithParser(parser),
	certree.WithSNI("example.com"),
)

analysis, err := analyzer.Analyze(ctx, "10.0.0.1:443")
```

For mutual TLS (mTLS) connections, set `RemoteOptions.ClientCert` (a
`*tls.Certificate`) to present a client certificate during the TLS
handshake. The CLI exposes this via `--client-cert` and `--client-key`.

## Validation Options

The `ValidationOptions` struct controls what gets checked. Pass it to the
analyzer:

```go
analyzer, err := certree.NewAnalyzer(
	certree.WithParser(parser),
	certree.WithValidationOptions(opts),
)
```

Or use the validator directly for more control:

```go
validator := certree.NewValidator(
	certree.WithValidatorTrustStore(trustStore),
	certree.WithRevocationChecker(revocationChecker),
	certree.WithValidatorLogger(certree.NewLogger()),
)
err := validator.Validate(ctx, paths, opts)
// Errors and warnings are appended to each TrustPath, not returned as errors.
// A returned error means validation could not proceed (e.g., context cancelled).
```

See `ValidationOptions` in `pkg/certree/validator.go` for the full set of
fields (expiry, hostname, revocation, signatures, EKU, name constraints,
max validity days, validation time override).

OCSP and CRL responses are cached by default (keyed by responder URL + serial
for OCSP, by URL for CRLs). Entries expire at the response's NextUpdate. Use
`WithRevocationCache(false)` to disable caching for testing.

`WithRevocationAllowPrivateNetworks(true)` permits OCSP and CRL fetches to
RFC 1918 private IP addresses. Required for internal PKI where revocation
endpoints are on private networks. Disabled by default as an SSRF safeguard.

## Simulation

The simulator lets you exclude certificates at any level of the chain --
leaf, intermediate, or root -- and see how trust paths change. Useful for
planning CA migrations, testing revocation scenarios, or understanding chain
dependencies. All exclusion methods support exact values, wildcard patterns
(via Go's `path.Match` syntax: `*` matches any sequence, `?` matches a single
character, `[abc]` matches a character class), and pipe-separated alternatives
(`"Old CA|Legacy*"` matches either value):

```go
simulator := certree.NewSimulator()

// Exclude by Common Name, fingerprint, or serial number.
// Exact matches and wildcard patterns are both supported.
// Colons in hex values are stripped automatically.
simulator.ExcludeByCommonName("Intermediate CA")
simulator.ExcludeByCommonName("Legacy*")
simulator.ExcludeByFingerprint("A1:B2:C3:D4:*")
simulator.ExcludeBySerial("04:00:00:*")

// Run the simulation against an existing analysis.
simulated, err := simulator.Simulate(ctx, originalAnalysis)
if err != nil {
	log.Fatal(err)
}

fmt.Printf("Before: %d trusted paths\n", originalAnalysis.Metadata.TrustedPaths)
fmt.Printf("After:  %d trusted paths\n", simulated.Metadata.TrustedPaths)
```

Exclusion methods support chaining:

```go
simulated, err := certree.NewSimulator().
	ExcludeByCommonName("Compromised*").
	ExcludeByFingerprint("A1:B2:C3:D4:*").
	Simulate(ctx, analysis)
```

### Simulator Options

`NewSimulator()` accepts functional options that control simulation behavior:

- `WithSimulatorValidator(validator)` -- when provided, the simulator
  re-validates rebuilt trust paths after exclusion. Without this, the
  simulator only restructures paths without re-checking validity.
- `WithSimulatorLogger(logger)` -- attaches a logger for debug output during
  simulation.
- `WithSimulatorValidationOptions(opts)` -- sets validation options used
  during re-validation (requires `WithSimulatorValidator`).
- `WithSimulatorChainBuilder(chainBuilder)` -- provides a custom chain builder
  used when rebuilding paths during certificate injection via
  `InjectCertificates`.
- `WithSimulatorTrustStore(trustStore)` -- provides a trust store used when
  rebuilding paths during certificate injection via `InjectCertificates`.

Temporal what-if analysis combines `WithSimulatorValidator` and
`WithSimulatorValidationOptions` to re-validate paths at a shifted time:

```go
// Temporal what-if: re-validate at a future date.
futureDate := time.Date(2040, 9, 1, 0, 0, 0, 0, time.UTC)
sim := certree.NewSimulator(
	certree.WithSimulatorValidator(validator),
	certree.WithSimulatorValidationOptions(certree.ValidationOptions{
		VerifySignatures:  true,
		VerifyExpiry:      true,
		ExpiryWarningDays: 30,
		ValidationTime:    futureDate,
	}),
)
simulated, err := sim.Simulate(ctx, analysis)
```

The initial analysis runs against the current time. The time shift is applied
during simulation re-validation. Use this pattern for any temporal what-if
scenario.

## Batch Processing

Process multiple sources in parallel with `BatchAnalyzer`:

```go
batchAnalyzer, err := certree.NewBatchAnalyzer(analyzer, 4) // 4 workers
if err != nil {
	log.Fatal(err)
}

analyses, err := batchAnalyzer.AnalyzeMultiple(ctx, []string{
	"cert1.pem",
	"cert2.pem",
	"example.com:443",
})
if err != nil {
	log.Fatal(err) // Aggregated errors from all failed sources
}

for _, analysis := range analyses {
	fmt.Printf("[+ ] %s: %d certs, %d trusted paths\n",
		analysis.Metadata.Source,
		len(analysis.Certificates),
		analysis.Metadata.TrustedPaths)
}
```

Register a `ProgressFunc` to receive a callback after each source completes.
The callback receives the running completed count, total count, and source
identifier. It may be called concurrently from multiple workers. Pass `nil`
to disable progress reporting.

```go
batch.SetProgress(func(completed, total int, source string) {
	fmt.Printf("Analyzed %d/%d: %s\n", completed, total, source)
})
```

`SetProgress` is safe to call at any time, including while `AnalyzeMultiple`
is running. The new callback takes effect for subsequent progress reports.

## Error Handling

The library returns two kinds of errors:

1. **Structured errors** -- returned from `Analyzer` methods (`Analyze`,
   `AnalyzeFile`, `AnalyzeHost`, `AnalyzeURL`, `AnalyzeBytes`) and directly
   from `Parser` and `AIAFetcher` methods. These mean the operation could not
   complete (connection failed, file unreadable, no certificates found).
   Structured errors from user-facing call sites are
   `*certree.StructuredError` values carrying a short user message, a
   sentinel category, and the raw cause.

2. **Validation results** -- recorded on each `TrustPath` as
   `ValidationError` / `ValidationWarning`. These mean analysis succeeded but
   some paths have issues (expired certificate, untrusted root, signature
   mismatch). You always get an analysis result even when paths have issues.

### Structured errors

When an operation fails, extract the structured error for clean user-facing
output:

```go
analysis, err := analyzer.Analyze(ctx, "cert.pem")
if err != nil {
	var se *certree.StructuredError
	if errors.As(err, &se) {
		// Short, actionable message (no Go internals):
		// "could not read file cert.pem"
		fmt.Fprintf(os.Stderr, "Error: %s\n", se.UserMessage())

		// Underlying cause with full diagnostic detail:
		// "open cert.pem: no such file or directory"
		if se.Detail() != nil {
			fmt.Fprintf(os.Stderr, "Detail: %s\n", se.Detail())
		}

		// Sentinel category for programmatic matching:
		// "certree: file read failed"
		fmt.Fprintf(os.Stderr, "Category: %s\n", se.Category())
	} else {
		// Non-structured error (context cancellation, config error, etc.)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	os.Exit(1)
}
```

Use `errors.Is` for sentinel matching without extracting the full error:

```go
_, err := analyzer.Analyze(ctx, "example.com:443")
if errors.Is(err, certree.ErrConnectionFailed) {
	fmt.Println("Could not connect to host")
} else if errors.Is(err, certree.ErrNoCertificatesFound) {
	fmt.Println("Server returned no certificates")
} else if err != nil {
	fmt.Printf("Unexpected error: %v\n", err)
}
```

Structured errors pass through the Analyzer unchanged. The error returned by
`Analyze`, `AnalyzeFile`, `AnalyzeHost`, or `AnalyzeBytes` is the same
`*StructuredError` created by the Parser or AIAFetcher. For the complete list
of sentinel error categories, see `pkg/certree/errors.go`.

### Validation errors on trust paths

Validation errors are not returned from `Analyze` -- they are recorded on
each `TrustPath`. This means you always get an analysis result even when some
paths have issues. A special case: if the system trust store cannot be loaded
(common in containers, minimal images, or CI environments), `Analyze` logs a
warning but continues with an empty trust store. All paths will show as
untrusted in this case. To avoid this, provide a custom trust store or bundle:

```go
trustStore := certree.NewTrustStore()
if err := trustStore.LoadCustomRoots("/path/to/bundle.pem"); err != nil {
    log.Fatalf("Failed to load trust bundle: %v", err)
}
analyzer, err := certree.NewAnalyzer(
    certree.WithParser(p),
    certree.WithTrustStore(trustStore),
)
```

Inspect soft failures on paths after a successful analysis:

```go
analysis, err := analyzer.Analyze(ctx, source)
if err != nil {
	// Hard failure: could not parse, could not connect, etc.
	log.Fatal(err)
}

// Soft failures live on the paths.
for _, path := range analysis.TrustPaths {
	for _, e := range path.Errors {
		switch e.Type {
		case certree.ErrorExpired:
			fmt.Printf("Expired: %s\n", e.Certificate.CommonName())
		case certree.ErrorSignatureInvalid:
			fmt.Printf("Bad signature: %s\n", e.Certificate.CommonName())
		case certree.ErrorUntrustedRoot:
			fmt.Printf("Untrusted root: %s\n", e.Certificate.CommonName())
		case certree.ErrorInvalidEKU:
			fmt.Printf("EKU violation: %s\n", e.Certificate.CommonName())
		case certree.ErrorNameConstraintViolation:
			fmt.Printf("Name constraint violation: %s\n", e.Message)
		case certree.ErrorInvalidKeyUsage:
			fmt.Printf("Key Usage violation: %s\n", e.Certificate.CommonName())
		case certree.ErrorInvalidSerialNumber:
			fmt.Printf("Invalid serial number: %s\n", e.Certificate.CommonName())
		}
	}
}
```

For the complete list of `ErrorType` and `WarningType` constants, see
`pkg/certree/validator.go` or the package godoc.

## Complete Example

A working program that analyzes a certificate source and prints a summary:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/timorunge/certree/pkg/certree"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <file-or-host>\n", os.Args[0])
		os.Exit(1)
	}
	source := os.Args[1]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p := certree.NewParser()
	analyzer, err := certree.NewAnalyzer(
		certree.WithParser(p),
		certree.WithValidationOptions(certree.ValidationOptions{
			VerifySignatures:  true,
			VerifyExpiry:      true,
			ExpiryWarningDays: 30,
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	analysis, err := analyzer.Analyze(ctx, source)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Source: %s\n", analysis.Metadata.Source)
	fmt.Printf("Certificates: %d\n", analysis.Metadata.TotalCerts)
	fmt.Printf("Trust paths: %d (%d trusted)\n",
		analysis.Metadata.TotalPaths, analysis.Metadata.TrustedPaths)
	fmt.Println()

	for _, cert := range analysis.Certificates {
		meta := cert.Metadata()
		status := "[+ ]"
		if meta.IsExpired {
			status = "[x ]"
		} else if meta.DaysUntilExpiry < 30 {
			status = "[! ]"
		}
		fmt.Printf("%s %s (expires in %d days)\n",
			status, cert.CommonName(), meta.DaysUntilExpiry)
	}

	for i, path := range analysis.TrustPaths {
		fmt.Printf("\nPath %d: %d certs, trusted=%v\n", i+1, len(path.Certificates), path.Status.IsTrusted())
		for _, cert := range path.Certificates {
			fmt.Printf("  -> %s\n", cert.CommonName())
		}
	}
}
```

See also: [Certificate Trust Paths](./certificate-trust-paths.md),
[CLI Reference](./cli.md), [Design Philosophy](./design-philosophy.md),
[Configuration Reference](./configuration.md).

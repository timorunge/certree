// Benchmarks for hot-path functions in the certree library.
//
// Each benchmark targets a function where a performance regression would
// materially affect end-to-end latency or memory pressure. Functions that
// are trivial getters, one-shot setup, or network-bound are intentionally
// excluded.
//
// Run with: go test -bench=. -benchmem -run=^$ ./pkg/certree/

package certree

import (
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// BenchmarkNewCertificate measures the per-certificate wrapping cost:
// SHA-256 fingerprint, SPKI SHA-256 hash, serial hex encoding, expiry
// calculation, and self-signed detection. This runs once per parsed
// certificate, so regressions here multiply by every cert in every chain.
func BenchmarkNewCertificate(b *testing.B) {
	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "bench.example.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	src := CertificateSource{Type: SourceTypeFile, Location: "bench.pem"}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = NewCertificate(raw, src)
	}
}

// BenchmarkFingerprint measures cached fingerprint retrieval. After
// NewCertificate computes the SHA-256 hex string, Fingerprint() should
// be a zero-allocation field access. This benchmark guards against
// accidental recomputation or copy overhead being introduced.
func BenchmarkFingerprint(b *testing.B) {
	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "bench.example.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	cert := NewCertificate(raw, CertificateSource{Type: SourceTypeFile})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = cert.FingerprintSHA256()
	}
}

// BenchmarkCertificatePEM measures lazy PEM encoding via sync.Once. The
// first call allocates ~1-2 KB for pem.EncodeToMemory; subsequent calls
// return the cached string. This benchmark exercises both paths: a fresh
// certificate (cold) and a pre-warmed certificate (hot). PEM() is called
// during rendering and by WithTrustedLocations, so regressions propagate
// to every displayed certificate.
func BenchmarkCertificatePEM(b *testing.B) {
	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "bench.example.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	src := CertificateSource{Type: SourceTypeFile, Location: "bench.pem"}

	b.Run("cold", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			cert := NewCertificate(raw, src)
			_ = cert.PEM()
		}
	})

	b.Run("hot", func(b *testing.B) {
		cert := NewCertificate(raw, src)
		_ = cert.PEM() // warm the cache
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = cert.PEM()
		}
	})
}

// BenchmarkMarshalJSON measures custom JSON serialization of a single
// certificate. The custom MarshalJSON uses a named helper struct to
// control field layout and avoid reflection overhead. This is the
// innermost serialization call when producing JSON output -- every
// certificate in every trust path calls this method.
func BenchmarkMarshalJSON(b *testing.B) {
	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "bench.example.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	cert := NewCertificate(raw, CertificateSource{Type: SourceTypeFile, Location: "bench.pem"})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := cert.MarshalJSON(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHexEncodeUpper measures the single-allocation hex encoder used
// by NewCertificate (3 calls: SHA-256, SPKI SHA-256, serial), FindIssuers, and
// skiHex. This function's existence is motivated by avoiding the 3-4
// allocations of fmt.Sprintf("%X", ...), so a benchmark guards that claim.
func BenchmarkHexEncodeUpper(b *testing.B) {
	// Use a SHA-256-length input (32 bytes) as the representative case.
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = HexEncodeUpper(input)
	}
}

// BenchmarkColonHex measures colon insertion into hex strings, used in
// fingerprint display formatting and short fingerprint prefixes.
func BenchmarkColonHex(b *testing.B) {
	hex := "A887602F1B4C2E93D5A1F70E8C6B9D24E3F5A8C71D0B2E94F6A3C8D5E7B1A2"

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = ColonHex(hex)
	}
}

// BenchmarkStripColons measures colon removal from user input, used to
// normalize colon-separated hex (e.g. "A8:87:60:2F") before pattern matching.
func BenchmarkStripColons(b *testing.B) {
	b.Run("with_colons", func(b *testing.B) {
		input := "A8:87:60:2F:1B:4C:2E:93:D5:A1:F7:0E:8C:6B:9D:24"
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = stripColons(input)
		}
	})

	b.Run("no_colons", func(b *testing.B) {
		input := "A887602F1B4C2E93D5A1F70E8C6B9D24"
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = stripColons(input)
		}
	})
}

// BenchmarkParsePEM measures the PEM decode loop: pem.Decode per block,
// x509.ParseCertificate per DER payload, and NewCertificate wrapping.
// All sub-benchmarks use ParsePEMCertificates with zero limit (unlimited)
// to ensure the same code path is compared across scaling points.
func BenchmarkParsePEM(b *testing.B) {
	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "bench.example.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw.Raw})
	src := CertificateSource{Type: SourceTypeFile, Location: "bench.pem"}

	b.Run("1cert", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := ParsePEMCertificates(block, src, 0); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("10certs", func(b *testing.B) {
		pemData := make([]byte, 0, len(block)*10)
		for range 10 {
			pemData = append(pemData, block...)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := ParsePEMCertificates(pemData, src, 0); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("100certs", func(b *testing.B) {
		pemData := make([]byte, 0, len(block)*100)
		for range 100 {
			pemData = append(pemData, block...)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := ParsePEMCertificates(pemData, src, 0); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkParseDERCertificate measures DER certificate parsing: a single
// x509.ParseCertificate call plus NewCertificate wrapping. This isolates
// the per-certificate cost without PEM decode overhead, useful for
// measuring AIA-fetched certificate processing.
func BenchmarkParseDERCertificate(b *testing.B) {
	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "bench.example.com"},
	})
	if err != nil {
		b.Fatal(err)
	}
	derData := raw.Raw
	src := CertificateSource{Type: SourceTypeFile, Location: "bench.der"}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := ParseDERCertificate(derData, src); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBuildChains measures recursive chain building including index
// construction (subject and AKI maps), end-entity detection, DFS path
// enumeration, and path deduplication. Sub-benchmarks test 3-cert and
// 5-cert depths to detect scaling behavior in the recursive builder.
func BenchmarkBuildChains(b *testing.B) {
	b.Run("3certs", func(b *testing.B) {
		x509Certs, _, err := testutil.GenerateSimpleChain()
		if err != nil {
			b.Fatal(err)
		}
		src := CertificateSource{Type: SourceTypeFile}
		certs := make([]*Certificate, len(x509Certs))
		for i, raw := range x509Certs {
			certs[i] = NewCertificate(raw, src)
		}
		ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
		ts.(*defaultTrustStore).systemRoots[certs[2].FingerprintSHA256()] = certs[2]
		cb := NewChainBuilder()
		ctx := b.Context()

		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := cb.BuildChains(ctx, certs, ts); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("5certs", func(b *testing.B) {
		x509Certs, _, err := testutil.GenerateChainWithDepth(5)
		if err != nil {
			b.Fatal(err)
		}
		src := CertificateSource{Type: SourceTypeFile}
		certs := make([]*Certificate, len(x509Certs))
		for i, raw := range x509Certs {
			certs[i] = NewCertificate(raw, src)
		}
		ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
		ts.(*defaultTrustStore).systemRoots[certs[4].FingerprintSHA256()] = certs[4]
		cb := NewChainBuilder()
		ctx := b.Context()

		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := cb.BuildChains(ctx, certs, ts); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkLoadSystemRoots_Cached measures the cached (no-op) path of
// LoadSystemRoots. After the first call loads and indexes system roots,
// subsequent calls return immediately via a double-checked locking pattern:
// a read lock checks the boolean guard (fast path), promoting to a write
// lock only on the first call. This benchmark measures the read-lock fast
// path that every chain build and validation pays.
func BenchmarkLoadSystemRoots_Cached(b *testing.B) {
	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
	if err := ts.LoadSystemRoots(); err != nil {
		b.Skip("system trust store not available:", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := ts.LoadSystemRoots(); err != nil {
			b.Fatalf("LoadSystemRoots: %v", err)
		}
	}
}

// BenchmarkIsTrusted measures trust determination for a certificate:
// fingerprint map lookup, then SPKI SHA-256 hash computation with map
// lookup as fallback. Called per-certificate during chain building and
// validation, making it one of the highest-frequency trust store
// operations. The SPKI hash path is exercised separately to isolate
// the SHA-256 cost from the fast fingerprint-hit path.
func BenchmarkIsTrusted(b *testing.B) {
	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatal(err)
	}
	src := CertificateSource{Type: SourceTypeFile}
	root := NewCertificate(x509Certs[2], src)
	leaf := NewCertificate(x509Certs[0], src)

	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
	ts.(*defaultTrustStore).systemRoots[root.FingerprintSHA256()] = root

	b.Run("trusted_fingerprint_hit", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = ts.IsTrusted(root)
		}
	})

	b.Run("untrusted_full_check", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = ts.IsTrusted(leaf)
		}
	})
}

// BenchmarkFindIssuers measures issuer lookup via AKI-to-SKI index and the
// subject DN fallback path. The aki_hit sub-benchmark exercises the fast
// SKI map lookup. The subject_fallback sub-benchmark exercises the slower
// path that uses raw ASN.1 subject DN comparison with deduplication, which
// is taken when the certificate lacks an AKI or the SKI lookup misses.
func BenchmarkFindIssuers(b *testing.B) {
	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatal(err)
	}
	src := CertificateSource{Type: SourceTypeFile}
	certs := make([]*Certificate, len(x509Certs))
	for i, raw := range x509Certs {
		certs[i] = NewCertificate(raw, src)
	}

	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
	dts := ts.(*defaultTrustStore)

	// Populate the trust store indexes with the root and intermediate.
	root := certs[2]
	intermediate := certs[1]
	dts.systemRoots[root.FingerprintSHA256()] = root
	dts.systemRoots[intermediate.FingerprintSHA256()] = intermediate
	skiRoot := HexEncodeUpper(root.Raw().SubjectKeyId)
	if skiRoot != "" {
		dts.systemBySKI[skiRoot] = append(dts.systemBySKI[skiRoot], root)
	}
	skiInt := HexEncodeUpper(intermediate.Raw().SubjectKeyId)
	if skiInt != "" {
		dts.systemBySKI[skiInt] = append(dts.systemBySKI[skiInt], intermediate)
	}
	rootSubj := string(root.Raw().RawSubject)
	dts.systemBySubject[rootSubj] = append(dts.systemBySubject[rootSubj], root)
	intSubj := string(intermediate.Raw().RawSubject)
	dts.systemBySubject[intSubj] = append(dts.systemBySubject[intSubj], intermediate)

	leaf := certs[0]

	b.Run("aki_hit", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = ts.FindIssuers(leaf)
		}
	})

	b.Run("subject_fallback", func(b *testing.B) {
		// Create a certificate with no AKI so FindIssuers falls through
		// the SKI lookup and uses the subject DN comparison path.
		noAKICert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{
				CommonName:   "No AKI Leaf",
				Organization: root.Raw().Subject.Organization,
			},
			IsCA: false,
		})
		if err != nil {
			b.Fatal(err)
		}
		// Clear AKI to force the fallback path. The generated self-signed
		// cert has AKI == SKI; we need a cert whose issuer matches by
		// subject DN but has no AKI. Use the root's subject as issuer.
		noAKIWrapped := NewCertificate(noAKICert, src)
		// Populate subject index for the root's subject.
		rootIssuerDN := string(noAKIWrapped.Raw().RawIssuer)
		if _, ok := dts.systemBySubject[rootIssuerDN]; !ok {
			// Self-signed cert's issuer == its own subject, so it will
			// match itself. Add it to the subject index for benchmark purposes.
			dts.systemBySubject[rootIssuerDN] = append(dts.systemBySubject[rootIssuerDN], noAKIWrapped)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = ts.FindIssuers(noAKIWrapped)
		}
	})
}

// BenchmarkValidate measures per-path validation: signature verification,
// issuer constraint checks, expiry evaluation, and warning/error
// accumulation. Validation runs once per trust path after chain building,
// and signature verification (crypto operations) dominates the cost.
func BenchmarkValidate(b *testing.B) {
	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatal(err)
	}
	src := CertificateSource{Type: SourceTypeFile}
	certs := make([]*Certificate, len(x509Certs))
	for i, raw := range x509Certs {
		certs[i] = NewCertificate(raw, src)
	}
	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
	paths := []*TrustPath{{
		Certificates: certs,
		Status:       PathTrusted,
	}}
	v := NewValidator(
		WithValidatorTrustStore(ts),
		WithRevocationChecker(NewRevocationChecker()),
		WithValidatorLogger(NewLogger()),
	)
	opts := ValidationOptions{
		VerifySignatures: true,
		VerifyExpiry:     true,
	}
	ctx := b.Context()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		// Reset errors/warnings before each iteration.
		paths[0].Errors = nil
		paths[0].Warnings = nil
		_ = v.Validate(ctx, paths, opts)
	}
}

// BenchmarkSimulate measures exclusion simulation: pattern matching against
// all certificates, path filtering, certificate deduplication, and new
// Analysis creation. The simulator and exclusion matcher are constructed
// outside the loop to isolate the Simulate hot path from one-time setup.
func BenchmarkSimulate(b *testing.B) {
	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatal(err)
	}
	src := CertificateSource{Type: SourceTypeFile}
	certs := make([]*Certificate, len(x509Certs))
	for i, raw := range x509Certs {
		certs[i] = NewCertificate(raw, src)
	}
	certs[1] = certs[1].WithTrustedLocations([]string{"system"})
	analysis := NewAnalysis(certs, []*TrustPath{{Certificates: certs, Status: PathTrusted}}, "bench.pem")
	ctx := b.Context()

	sim := NewSimulator()
	sim.ExcludeByCommonName(certs[2].CommonName())

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = sim.Simulate(ctx, analysis)
	}
}

// BenchmarkNewAnalysis measures analysis creation: trust path counting,
// metadata computation (trusted/untrusted/incomplete counts, validation
// mode), and struct initialization. Called once per source after chain
// building and validation.
func BenchmarkNewAnalysis(b *testing.B) {
	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatal(err)
	}
	src := CertificateSource{Type: SourceTypeFile}
	certs := make([]*Certificate, len(x509Certs))
	for i, raw := range x509Certs {
		certs[i] = NewCertificate(raw, src)
	}
	paths := []*TrustPath{
		{Certificates: certs, Status: PathTrusted},
		{Certificates: certs[:2], Status: PathIncomplete},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = NewAnalysis(certs, paths, "bench.pem")
	}
}

// BenchmarkAnalysisJSON measures compact JSON serialization of a full
// analysis. This exercises Certificate.MarshalJSON for every cert in
// every path, plus the analysis-level metadata marshaling.
// Compact JSON is the default for programmatic consumers piping output.
func BenchmarkAnalysisJSON(b *testing.B) {
	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatal(err)
	}
	src := CertificateSource{Type: SourceTypeFile}
	certs := make([]*Certificate, len(x509Certs))
	for i, raw := range x509Certs {
		certs[i] = NewCertificate(raw, src)
	}
	analysis := NewAnalysis(certs, []*TrustPath{{Certificates: certs, Status: PathTrusted}}, "bench.pem")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := json.Marshal(analysis); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAnalysisJSON_Pretty measures pretty-printed JSON serialization.
// Indented JSON uses json.MarshalIndent which allocates more than the
// compact path. This is the format used by --format=json in the CLI,
// so regressions affect interactive use.
func BenchmarkAnalysisJSON_Pretty(b *testing.B) {
	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatal(err)
	}
	src := CertificateSource{Type: SourceTypeFile}
	certs := make([]*Certificate, len(x509Certs))
	for i, raw := range x509Certs {
		certs[i] = NewCertificate(raw, src)
	}
	analysis := NewAnalysis(certs, []*TrustPath{{Certificates: certs, Status: PathTrusted}}, "bench.pem")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := json.MarshalIndent(analysis, "", "  "); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAnalyzeFile measures the full single-source analysis pipeline:
// file read, format auto-detection, PEM parsing, chain building, and
// validation. This is an integration-level benchmark that catches
// regressions in the interaction between components -- useful because
// the CLI's BenchmarkRun includes flag parsing and config overhead that
// can mask library-level changes.
func BenchmarkAnalyzeFile(b *testing.B) {
	// Generate a 3-cert chain and write it to a temp PEM file.
	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatal(err)
	}
	pemData := make([]byte, 0, len(x509Certs)*2048)
	for _, cert := range x509Certs {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	path := filepath.Join(b.TempDir(), "bench-chain.pem")
	err = os.WriteFile(path, pemData, 0600)
	if err != nil {
		b.Fatalf("writing PEM file: %v", err)
	}

	// Construct the analyzer with defaults (no network, no revocation).
	logger := NewLogger()
	p := NewParser(WithParserLogger(logger))
	ts := NewTrustStore(WithTrustStoreLogger(logger))
	cb := NewChainBuilder()
	v := NewValidator(
		WithValidatorTrustStore(ts),
		WithRevocationChecker(NewRevocationChecker()),
		WithValidatorLogger(logger),
	)
	analyzer, err := NewAnalyzer(
		WithParser(p),
		WithTrustStore(ts),
		WithChainBuilder(cb),
		WithValidator(v),
	)
	if err != nil {
		b.Fatalf("creating analyzer: %v", err)
	}
	ctx := b.Context()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		analysis, err := analyzer.AnalyzeFile(ctx, path)
		if err != nil {
			b.Fatalf("AnalyzeFile: %v", err)
		}
		if analysis == nil {
			b.Fatal("AnalyzeFile returned nil analysis")
		}
	}
}

// BenchmarkBatchAnalyze measures batch processing of 5 local PEM files
// using the worker pool. This isolates batch overhead (goroutine fan-out,
// channel coordination, result aggregation, order-preserving sort) from
// network latency. Regressions here affect --batch mode with large host
// lists.
func BenchmarkBatchAnalyze(b *testing.B) {
	dir := b.TempDir()
	sources := make([]string, 5)
	for i := range 5 {
		certs, _, err := testutil.GenerateSimpleChain()
		if err != nil {
			b.Fatalf("generating chain: %v", err)
		}
		pemData := make([]byte, 0, len(certs)*2048)
		for _, cert := range certs {
			pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})...)
		}
		path := filepath.Join(dir, fmt.Sprintf("cert-%d.pem", i))
		if err := os.WriteFile(path, pemData, 0600); err != nil {
			b.Fatalf("writing PEM: %v", err)
		}
		sources[i] = path
	}

	logger := NewLogger()
	p := NewParser(WithParserLogger(logger))
	ts := NewTrustStore(WithTrustStoreLogger(logger))
	cb := NewChainBuilder()
	rc := NewRevocationChecker()
	v := NewValidator(
		WithValidatorTrustStore(ts),
		WithRevocationChecker(rc),
		WithValidatorLogger(logger),
	)
	analyzer, err := NewAnalyzer(
		WithParser(p),
		WithTrustStore(ts),
		WithChainBuilder(cb),
		WithValidator(v),
	)
	if err != nil {
		b.Fatalf("creating analyzer: %v", err)
	}
	ba, err := NewBatchAnalyzer(analyzer, 4)
	if err != nil {
		b.Fatalf("creating batch analyzer: %v", err)
	}
	ctx := b.Context()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		analyses, err := ba.AnalyzeMultiple(ctx, sources)
		if err != nil {
			b.Fatalf("AnalyzeMultiple: %v", err)
		}
		if len(analyses) != 5 {
			b.Fatalf("expected 5 analyses, got %d", len(analyses))
		}
	}
}

// BenchmarkPatternMatch measures the compiled PatternMatcher's per-value
// matching cost in isolation. The matcher is created once per sub-benchmark,
// so the loop body measures only the map lookup / path.Match evaluation.
// Sub-benchmarks cover exact hits, wildcard hits, misses, and scaling
// across pattern counts.
func BenchmarkPatternMatch(b *testing.B) {
	b.Run("exact_hit", func(b *testing.B) {
		m := NewPatternMatcher([]string{"example.com"})
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = m.Match("example.com")
		}
	})

	b.Run("wildcard_hit", func(b *testing.B) {
		m := NewPatternMatcher([]string{"*.example.com"})
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = m.Match("www.example.com")
		}
	})

	b.Run("miss_2patterns", func(b *testing.B) {
		m := NewPatternMatcher([]string{"other.com", "*.other.com"})
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = m.Match("www.example.com")
		}
	})

	b.Run("miss_10patterns", func(b *testing.B) {
		m := NewPatternMatcher([]string{
			"a.com", "*.b.com", "c.org", "*.d.net", "e.io",
			"f.com", "*.g.com", "h.org", "*.i.net", "j.io",
		})
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = m.Match("www.example.com")
		}
	})
}

// Benchmarks for render package hot paths.
//
// Each benchmark targets a function where a performance regression would
// materially affect end-to-end rendering latency or memory pressure.
// Trivial helpers (theme lookup, terminal detection) are intentionally
// excluded -- they run once per render and are dominated by I/O.
//
// Run with: go test -bench=. -benchmem -run=^$ ./internal/render/

package render

import (
	"io"
	"testing"

	"github.com/timorunge/certree/pkg/certree"
	"github.com/timorunge/certree/pkg/certree/testutil"
)

// buildBenchChain generates a 3-cert chain wrapped as certree.Certificates.
// Reused across benchmarks that need a minimal realistic analysis.
func buildBenchChain(b *testing.B) []*certree.Certificate {
	b.Helper()
	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	rawChain, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatal(err)
	}
	chain := make([]*certree.Certificate, len(rawChain))
	for i, raw := range rawChain {
		chain[i] = certree.NewCertificate(raw, src)
	}
	return chain
}

// buildBenchAnalysis creates a minimal trusted analysis from a chain.
func buildBenchAnalysis(b *testing.B, chain []*certree.Certificate) *certree.Analysis {
	b.Helper()
	return &certree.Analysis{
		Certificates: chain,
		TrustPaths:   []*certree.TrustPath{{Certificates: chain, Status: certree.PathTrusted}},
		Metadata:     certree.AnalysisMetadata{Source: "bench.pem"},
	}
}

// buildBenchSimulatedAnalysis creates an analysis simulating root exclusion.
// The root is marked excluded and the intermediate ghosted via
// SimulationMetadata. Warnings match what the real simulator produces:
// WarningExcludedBySimulation on the root (excluded cert) and on the
// end-entity and intermediate (broken chain below). This exercises
// collectSimulationCerts' excluded, ghosted, and broken detection paths.
func buildBenchSimulatedAnalysis(b *testing.B, chain []*certree.Certificate) *certree.Analysis {
	b.Helper()
	// Path with the excluded root: root is excluded, intermediate is ghosted.
	excludedFP := chain[2].FingerprintSHA256()
	ghostedFP := chain[1].FingerprintSHA256()
	simMeta := map[string]certree.CertSimulationState{
		excludedFP: {IsExcluded: true},
		ghostedFP:  {IsGhosted: true},
	}
	return &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{{
			Certificates:       chain,
			Status:             certree.PathIncomplete,
			SimulationMetadata: simMeta,
			Warnings: []certree.ValidationWarning{
				{Certificate: chain[2], Type: certree.WarningExcludedBySimulation, Message: "certificate excluded by simulation"},
				{Certificate: chain[0], Type: certree.WarningExcludedBySimulation, Message: "trust chain broken: upstream certificate excluded by simulation"},
				{Certificate: chain[1], Type: certree.WarningExcludedBySimulation, Message: "trust chain broken: upstream certificate excluded by simulation"},
			},
		}},
		Metadata: certree.AnalysisMetadata{Source: "bench.pem", IsSimulated: true},
	}
}

// benchRenderEnv returns a pre-built renderEnv that avoids detectTerminal()
// syscalls. Used by micro-benchmarks that isolate rendering from terminal detection.
func benchRenderEnv() *renderEnv {
	return &renderEnv{
		opts:  Options{ThemeName: "classic", ColorMode: "never"},
		theme: classicTheme,
		width: 120,
	}
}

// BenchmarkRender measures end-to-end tree rendering for a 3-cert chain in
// default (merged) mode with no detail fields enabled. This includes
// resolveRenderEnv (terminal detection, theme resolution) because that is
// part of every real Trees() call. This is the most common render path --
// every certree invocation without --fields ends up here.
func BenchmarkRender(b *testing.B) {
	chain := buildBenchChain(b)
	analysis := buildBenchAnalysis(b, chain)
	opts := Options{ThemeName: "classic", ColorMode: "never"}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = Trees([]*certree.Analysis{analysis}, opts, io.Discard)
	}
}

// BenchmarkRenderDetailed measures tree rendering with all detail fields
// enabled via ShowAll (fingerprint, serial, validity, extensions, source,
// subject, issuer, SAN, trust store, algorithm, AIA, CRL,
// diagnostics). Uses a full 3-cert chain (end-entity, intermediate, root)
// so that column alignment, issuer/subject display, and per-cert detail
// logic are exercised for multiple certificates. Regressions here affect
// --fields=all.
func BenchmarkRenderDetailed(b *testing.B) {
	chain := buildBenchChain(b)
	analysis := buildBenchAnalysis(b, chain)
	opts := Options{
		ShowAll:   true,
		ThemeName: "classic", ColorMode: "never",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = Trees([]*certree.Analysis{analysis}, opts, io.Discard)
	}
}

// BenchmarkRenderExpanded measures expanded view rendering where each
// TrustPath gets its own "Trust Path N" node. This exercises
// buildFromAnalysis / buildPathNode / buildCertNode, which are distinct
// code paths from the default merged view.
func BenchmarkRenderExpanded(b *testing.B) {
	chain := buildBenchChain(b)
	analysis := buildBenchAnalysis(b, chain)
	opts := Options{ThemeName: "classic", ColorMode: "never", ExpandedView: true}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = Trees([]*certree.Analysis{analysis}, opts, io.Discard)
	}
}

// BenchmarkComparisons measures side-by-side comparison rendering with
// impact summary enabled. This exercises renderSideBySide (per-line
// truncation + padding via visibleLen/padRight), tree rendering for both
// before and after analyses, the impact summary computation including
// collectSimulationCerts (double-nested path*cert iteration), and
// header/separator formatting.
func BenchmarkComparisons(b *testing.B) {
	chain := buildBenchChain(b)
	before := buildBenchAnalysis(b, chain)
	after := buildBenchSimulatedAnalysis(b, chain)
	pairs := []AnalysisPair{{Before: before, After: after}}
	opts := Options{ThemeName: "classic", ColorMode: "never", Impact: true}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = Comparisons(pairs, opts, io.Discard)
	}
}

// BenchmarkDiffs measures end-to-end unified diff rendering: tree rendering
// for both before/after analyses, LCS-based line diff (O(m*n) DP table),
// and per-line colorization. The LCS algorithm is the most compute-intensive
// function in the render package, and regressions here directly affect
// --diff output.
func BenchmarkDiffs(b *testing.B) {
	chain := buildBenchChain(b)
	before := buildBenchAnalysis(b, chain)
	after := buildBenchSimulatedAnalysis(b, chain)
	pairs := []AnalysisPair{{Before: before, After: after}}
	sources := []string{"bench.pem"}
	opts := Options{ThemeName: "classic", ColorMode: "never"}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = Diffs(pairs, sources, opts, io.Discard)
	}
}

// BenchmarkComputeLineDiff measures the LCS-based line diff algorithm in
// isolation with a medium-sized tree diff (8 lines with ~50% changes).
// The O(m*n) DP table allocation dominates cost; this benchmark catches
// regressions in the flat-allocation optimization and backtrack logic.
func BenchmarkComputeLineDiff(b *testing.B) {
	before := "  [+ ] example.com\n" +
		"    [+ ] Intermediate CA\n" +
		"      [+ ] Root CA\n" +
		"    [+ ] Cross-signed CA\n" +
		"      [+ ] Other Root\n" +
		"  [+ ] api.example.com\n" +
		"    [+ ] Intermediate CA\n" +
		"      [+ ] Root CA\n"
	after := "  [! ] example.com\n" +
		"    [! ] Intermediate CA\n" +
		"      [+ ] Root CA\n" +
		"    [x ] Cross-signed CA (excluded)\n" +
		"      [- ] Other Root (broken)\n" +
		"  [+ ] api.example.com\n" +
		"    [+ ] Intermediate CA\n" +
		"      [+ ] Root CA\n"

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = computeLineDiff(before, after)
	}
}

// BenchmarkImpactSummary measures the exported ImpactSummary function with
// realistic simulation metadata: excluded root, ghosted intermediate, and
// broken end-entity/intermediate (via WarningExcludedBySimulation). This
// exercises collectSimulationCerts (double-nested path*cert iteration with
// set deduplication for excluded, ghosted, and broken certs), path signature
// computation (fingerprint concatenation), and broken/remaining path counting.
func BenchmarkImpactSummary(b *testing.B) {
	chain := buildBenchChain(b)
	before := buildBenchAnalysis(b, chain)
	after := buildBenchSimulatedAnalysis(b, chain)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = ImpactSummary(before, after, "  ", "  ", 30)
	}
}

// BenchmarkStripANSICodes measures ANSI escape code stripping from a
// colorized status line. Uses a byte scanner with a CSI/OSC/DCS/bare-ESC
// state machine. Called during diff ghosting, displayName sanitization,
// and truncate fallback for maxLen < 3. This benchmarks the slow path
// (input contains escape codes); the fast path (no escapes, zero alloc)
// is trivial and not benchmarked separately.
func BenchmarkStripANSICodes(b *testing.B) {
	input := "\x1b[32m[+ ]\x1b[0m example.com \x1b[33m(expires in 25 days)\x1b[0m"

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = stripANSICodes(input)
	}
}

// BenchmarkVisibleLen measures ANSI-aware visible character counting via
// skipEscape without allocating a stripped copy. This is the highest-
// frequency string utility in the render package: called by every
// padRight() and truncate() invocation, which means 2x per line in
// side-by-side comparisons.
func BenchmarkVisibleLen(b *testing.B) {
	b.Run("plain", func(b *testing.B) {
		input := "  example.com certificate with a moderately long name"
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = visibleLen(input)
		}
	})

	b.Run("ansi_csi", func(b *testing.B) {
		input := "\x1b[32m[+ ]\x1b[0m example.com \x1b[33m(expires in 25 days)\x1b[0m"
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = visibleLen(input)
		}
	})

	b.Run("ansi_heavy", func(b *testing.B) {
		// Simulate a detailed-field line with many color codes.
		input := "\x1b[32m[+ ]\x1b[0m \x1b[1mSubject:\x1b[0m \x1b[36mCN=\x1b[0mexample.com, " +
			"\x1b[36mO=\x1b[0mAcme Corp, \x1b[36mL=\x1b[0mSan Francisco, " +
			"\x1b[36mST=\x1b[0mCalifornia, \x1b[36mC=\x1b[0mUS"
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = visibleLen(input)
		}
	})
}

// BenchmarkPadRight measures ANSI-aware right-padding: a visibleLen call
// plus strings.Repeat for the deficit. Called 2x per line in
// renderSideBySide (once per column), so per-call cost directly affects
// comparison rendering time.
func BenchmarkPadRight(b *testing.B) {
	b.Run("no_padding_needed", func(b *testing.B) {
		input := "\x1b[32m[+ ]\x1b[0m example.com"
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = padRight(input, 10)
		}
	})

	b.Run("padding_needed", func(b *testing.B) {
		input := "\x1b[32m[+ ]\x1b[0m example.com"
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = padRight(input, 60)
		}
	})
}

// BenchmarkComputeLCS_Runes measures character-level LCS on a typical certree
// line pair where status icon and annotation differ. This is the core of the
// intra-line diff highlighting feature.
func BenchmarkComputeLCS_Runes(b *testing.B) {
	a := []rune("`- [+ ] Trust Path 1")
	bLine := []rune("`- [x ] Trust Path 1 (GTS Root R4 excluded by simulation)")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = computeLCS(a, bLine)
	}
}

// BenchmarkTruncate measures ANSI-aware string truncation with ellipsis.
// Uses findTruncatePos (byte-level rune-boundary scanner via skipEscape)
// to locate the cut point without allocating a stripped copy. Called
// per-line in renderSideBySide when content exceeds column width.
func BenchmarkTruncate(b *testing.B) {
	input := "\x1b[32m[+ ]\x1b[0m example.com certificate with a very long name that needs truncation"

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = truncate(input, 40)
	}
}

// BenchmarkWrapValue measures value wrapping for fingerprint-length strings.
// Sub-benchmarks cover plain text and ANSI-colored input to exercise
// the adjustCutForANSI backward-scan path.
func BenchmarkWrapValue(b *testing.B) {
	b.Run("plain", func(b *testing.B) {
		fp := "7A:70:78:8F:E1:F5:A9:0E:81:F7:AC:BD:C1:64:22:CB:6E:5D:76:4B:E8:D0:F4:DA:97:21:BA:96:74:AA:8B:A9"
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = wrapValue(fp, 30)
		}
	})

	b.Run("ansi", func(b *testing.B) {
		fp := "\x1b[33m7A:70:78:8F\x1b[0m:\x1b[32mE1:F5:A9:0E\x1b[0m:81:F7:AC:BD:C1:64:22:CB:6E:5D:76:4B"
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = wrapValue(fp, 30)
		}
	})
}

// BenchmarkVisualize measures the tree visualizer directly, bypassing
// resolveRenderEnv to isolate pure rendering cost from terminal detection.
// Useful for detecting regressions in tree building and node rendering
// independent of OS-level terminal introspection.
func BenchmarkVisualize(b *testing.B) {
	chain := buildBenchChain(b)
	analysis := buildBenchAnalysis(b, chain)

	b.Run("merged", func(b *testing.B) {
		vis := newTreeVisualizer(benchRenderEnv())
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_, _ = vis.visualize(analysis)
		}
	})

	b.Run("detailed", func(b *testing.B) {
		detailedOpts := Options{
			ShowAll: true, ShowFingerprint: true, ShowSerial: true,
			ShowValidity: true, ShowExtensions: true, ShowSource: true,
			ShowSubject: true, ShowIssuer: true, ShowSAN: true,
			ShowTrustStore: true, ShowAlgorithm: true,
			ShowAIA: true, ShowCRL: true, ShowDiagnostics: true,
		}
		detailedEnv := &renderEnv{
			opts:  detailedOpts,
			theme: classicTheme,
			width: 120,
		}
		vis := newTreeVisualizer(detailedEnv)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_, _ = vis.visualize(analysis)
		}
	})
}

// Benchmarks for the certree CLI pipeline.
//
// Each benchmark targets a function where a performance regression would
// materially affect CLI latency or memory pressure. Orchestration functions
// (renderComparison, renderDiff, renderSimulation) are intentionally
// excluded -- their rendering cost is benchmarked in internal/render, and
// the thin CLI wiring adds negligible overhead. Instead, this file focuses
// on the component functions that do real per-invocation work: flag parsing,
// config construction, analyzer building, render dispatch, JSON
// serialization, CN filtering, and field parsing.
//
// Run with: go test -bench=. -benchmem -run=^$ ./internal/cli/

package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/timorunge/certree/internal/config"
	"github.com/timorunge/certree/internal/render"
	"github.com/timorunge/certree/pkg/certree"
	"github.com/timorunge/certree/pkg/certree/testutil"
)

// writeBenchPEM generates a 3-cert chain and writes it as PEM to a temp file.
// Used by BenchmarkRun for a realistic local source.
func writeBenchPEM(b *testing.B) string {
	b.Helper()

	certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatalf("generating test chain: %v", err)
	}

	path := filepath.Join(b.TempDir(), "bench-chain.pem")
	if err := os.WriteFile(path, testutil.EncodePEMChain(certs), 0600); err != nil {
		b.Fatalf("writing PEM file: %v", err)
	}

	return path
}

// buildBenchAnalysis creates a pre-built Analysis for rendering benchmarks.
// Uses a 3-cert chain with realistic metadata so that rendering exercises
// the full label-building and tree-construction code paths.
func buildBenchAnalysis(b *testing.B) *certree.Analysis {
	b.Helper()

	certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		b.Fatalf("generating test chain: %v", err)
	}

	src := certree.CertificateSource{Type: certree.SourceTypeFile, Location: "bench.pem"}
	wrapped := make([]*certree.Certificate, len(certs))
	for i, raw := range certs {
		wrapped[i] = certree.NewCertificate(raw, src)
	}

	return &certree.Analysis{
		Certificates: wrapped,
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: wrapped,
				Status:       certree.PathTrusted,
			},
		},
		Metadata: certree.AnalysisMetadata{
			Source:       "bench.pem",
			Timestamp:    time.Now(),
			TotalCerts:   len(wrapped),
			TotalPaths:   1,
			TrustedPaths: 1,
		},
	}
}

// BenchmarkRegisterFlags measures flag registration (~40 flags plus hidden
// negation counterparts) and a minimal parse. Flag registration runs once
// per CLI invocation and allocates pflag metadata for every flag. This
// benchmark catches regressions from adding flags or changing registration
// patterns.
func BenchmarkRegisterFlags(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		fs := registerFlags()
		_ = fs.Parse([]string{"--color=never", "cert.pem"})
	}
}

// BenchmarkDefaultConfig measures config struct construction with all
// default values. This allocates nested structs, initializes default
// strings, and populates zero-value fields. Called once per invocation
// before flag overrides are applied.
func BenchmarkDefaultConfig(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = config.DefaultConfig()
	}
}

// BenchmarkBuildAnalyzer measures the full component construction pipeline:
// Parser, TrustStore, ChainBuilder, RevocationChecker, Validator, and
// Analyzer -- each with functional options. This includes loading and
// indexing the system trust store on every iteration (the dominant cost,
// ~20ms on macOS), which reflects real per-invocation startup behavior.
func BenchmarkBuildAnalyzer(b *testing.B) {
	cfg := config.DefaultConfig()
	logger := certree.NewLogger()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := buildAnalyzer(cfg, logger)
		if err != nil {
			b.Fatalf("buildAnalyzer: %v", err)
		}
	}
}

// BenchmarkRun measures the full CLI pipeline end-to-end with a local PEM
// file: flag parsing, config layering, analyzer construction (including
// system trust store loading), file analysis, and tree rendering. This is
// the integration-level benchmark where system trust store I/O dominates.
// It catches regressions in any component, though changes smaller than
// the trust store loading noise floor (~10ms) may not be visible here.
func BenchmarkRun(b *testing.B) {
	pemPath := writeBenchPEM(b)
	args := []string{"--color=never", pemPath}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		code := Run(io.Discard, io.Discard, args, "test-version")
		if code != exitSuccess && code != exitValidationError {
			b.Fatalf("Run() returned unexpected exit code %d", code)
		}
	}
}

// BenchmarkRenderOutput measures renderAnalyses in tree format, isolating
// rendering from analysis overhead. This exercises buildRenderOptions,
// applyParsedFields (with default empty fields), and the full render.Trees
// path through the CLI layer. It is the most common render path for
// interactive use without --format=json.
func BenchmarkRenderOutput(b *testing.B) {
	analysis := buildBenchAnalysis(b)
	analyses := []*certree.Analysis{analysis}
	cfg := config.DefaultConfig()
	cfg.Output.Color = "never"

	b.ReportAllocs()
	b.ResetTimer()

	er := &errReporter{w: io.Discard, icons: render.LogIcons{Error: "[x ]"}}

	for b.Loop() {
		code := renderAnalyses(analyses, nonConfigFlags{}, cfg, io.Discard, er)
		if code != exitSuccess && code != exitValidationError {
			b.Fatalf("renderAnalyses() returned unexpected exit code %d", code)
		}
	}
}

// BenchmarkRenderJSON measures the JSON output path: json.MarshalIndent on
// a full analysis slice followed by a write. This is the entire JSON render
// pipeline that --format=json exercises. json.MarshalIndent is allocation-
// heavy (it builds the full indented string in memory), so regressions here
// affect machine-consumable output in CI pipelines.
func BenchmarkRenderJSON(b *testing.B) {
	b.Run("single", func(b *testing.B) {
		analysis := buildBenchAnalysis(b)
		analyses := []*certree.Analysis{analysis}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := renderJSON(analyses, io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("batch_5", func(b *testing.B) {
		batch := make([]*certree.Analysis, 5)
		for i := range batch {
			batch[i] = buildBenchAnalysis(b)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := renderJSON(batch, io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkParseFields measures --fields value parsing: string splitting,
// map-based validation, and deduplication. Called on every render via
// buildRenderOptions -> applyParsedFields. The map allocation
// and per-token trimming/lookup represent real per-render overhead,
// especially with multiple fields specified.
func BenchmarkParseFields(b *testing.B) {
	b.Run("empty", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_, _ = parseFields("")
		}
	})

	b.Run("single", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_, _ = parseFields("serial")
		}
	})

	b.Run("multiple", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_, _ = parseFields("fingerprint, serial, validity, dns, source")
		}
	})

	b.Run("all", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_, _ = parseFields("all")
		}
	})
}

// BenchmarkFilterAnalyses measures display filtering: per-certificate field
// extraction + pattern matching, plus trust path filtering via
// slices.ContainsFunc. Each call constructs a PatternMatcher (via
// buildFilters) and then matches, reflecting the real filterAnalyses path.
// The wildcard_cn sub-benchmark uses a pattern that matches the test chain's
// leaf certificate ("test.example.com") to exercise the match-hit path.
func BenchmarkFilterAnalyses(b *testing.B) {
	analysis := buildBenchAnalysis(b)
	analyses := []*certree.Analysis{analysis}

	b.Run("no_filters", func(b *testing.B) {
		flags := nonConfigFlags{}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = filterAnalyses(analyses, flags)
		}
	})

	b.Run("exact_cn", func(b *testing.B) {
		flags := nonConfigFlags{filterCN: []string{analysis.Certificates[0].CommonName()}}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = filterAnalyses(analyses, flags)
		}
	})

	b.Run("wildcard_cn", func(b *testing.B) {
		// Matches the leaf cert "test.example.com" from GenerateSimpleChain.
		flags := nonConfigFlags{filterCN: []string{"*.example.com"}}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = filterAnalyses(analyses, flags)
		}
	})

	b.Run("pipe_or", func(b *testing.B) {
		flags := nonConfigFlags{filterCN: []string{"*.example.com|Root*"}}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = filterAnalyses(analyses, flags)
		}
	})

	b.Run("no_match", func(b *testing.B) {
		flags := nonConfigFlags{filterCN: []string{"nonexistent.example.com"}}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = filterAnalyses(analyses, flags)
		}
	})

	b.Run("multiple_patterns", func(b *testing.B) {
		flags := nonConfigFlags{filterCN: []string{"a.example.com", "b.example.com", "*.test.com", "nonexistent.org"}}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			_ = filterAnalyses(analyses, flags)
		}
	})
}

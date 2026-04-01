package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/internal/config"
	"github.com/timorunge/certree/internal/render"
	"github.com/timorunge/certree/pkg/certree"
	"github.com/timorunge/certree/pkg/certree/testutil"
)

var (
	renderDepthChainsOnce sync.Once
	renderDepthChains     map[int][]*certree.Certificate
	renderDepthChainsErr  error
)

// newTestAnalysis creates a minimal Analysis for testing output functions.
func newTestAnalysis() *certree.Analysis {
	return certree.NewAnalysis(
		[]*certree.Certificate{},
		[]*certree.TrustPath{},
		"test.pem",
	)
}

// testER creates an errReporter suitable for tests that only need error
// icon output (no StructuredError formatting). The reporter uses classic
// theme icons and verbosity 0.
func testER(w *bytes.Buffer) *errReporter {
	return &errReporter{
		w:     w,
		icons: render.LogIcons{Error: "[x ]", Continuation: "[. ]"},
		level: logLevelOff,
	}
}

// getRenderDepthChains returns a map from chain depth (1-5) to a slice of
// Certificate wrappers. The underlying x509 certificates are generated once
// and cached; callers that need writable slices must copy them.
func getRenderDepthChains(t *testing.T) map[int][]*certree.Certificate {
	t.Helper()
	renderDepthChainsOnce.Do(func() {
		renderDepthChains = make(map[int][]*certree.Certificate)
		src := certree.CertificateSource{Type: certree.SourceTypeFile, Location: "test"}
		for depth := 1; depth <= 5; depth++ {
			x509Certs, _, err := testutil.GenerateChainWithDepth(depth)
			if err != nil {
				renderDepthChainsErr = fmt.Errorf("generating chain with depth %d: %w", depth, err)
				return
			}
			certs := make([]*certree.Certificate, len(x509Certs))
			for i, raw := range x509Certs {
				certs[i] = certree.NewCertificate(raw, src)
			}
			renderDepthChains[depth] = certs
		}
	})
	if renderDepthChainsErr != nil {
		t.Fatal(renderDepthChainsErr)
	}
	return renderDepthChains
}

func TestBuildRenderOptions_Whitespace(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Render.Fields = " serial , san "
	pf, err := parseFields(cfg.Render.Fields)
	require.NoError(t, err)
	opts := buildRenderOptions(cfg, nonConfigFlags{parsedFields: pf})

	assert.True(t, opts.ShowSerial, "ShowSerial should be enabled")
	assert.True(t, opts.ShowSAN, "ShowSAN should be enabled")
	assert.False(t, opts.ShowFingerprint, "ShowFingerprint should be false")
}

func TestBuildRenderOptions_CopiesNonFieldConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Render.Theme = "terse"
	cfg.Output.Color = "always"
	cfg.Render.Reverse = true
	cfg.Render.Fields = "serial"
	pf, err := parseFields(cfg.Render.Fields)
	require.NoError(t, err)
	opts := buildRenderOptions(cfg, nonConfigFlags{parsedFields: pf})

	assert.Equal(t, "terse", opts.ThemeName, "ThemeName")
	assert.Equal(t, "always", opts.ColorMode, "ColorMode")
	assert.True(t, opts.ReverseOrder, "ReverseOrder")
}

func TestRenderJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input any
	}{
		{"single analysis", newTestAnalysis()},
		{"before/after map", map[string]*certree.Analysis{"before": newTestAnalysis(), "after": newTestAnalysis()}},
		{"array", []*certree.Analysis{newTestAnalysis(), newTestAnalysis()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := renderJSON(tt.input, &buf)
			require.NoError(t, err)
			assert.True(t, json.Valid(buf.Bytes()), "output must be valid JSON")
		})
	}
}

func TestReverseAnalysisCopy(t *testing.T) {
	t.Parallel()

	depthChains := getRenderDepthChains(t)

	for depth := 1; depth <= 5; depth++ {
		t.Run(fmt.Sprintf("depth=%d", depth), func(t *testing.T) {
			t.Parallel()

			chain := depthChains[depth]
			fps := make([]string, len(chain))
			for i, c := range chain {
				fps[i] = c.FingerprintSHA256()
			}
			n := len(chain)

			analysis := certree.NewAnalysis(chain,
				[]*certree.TrustPath{
					{Certificates: chain, Status: certree.PathTrusted},
				},
				"test.pem",
			)

			reversed := analysis.Reversed()

			// Original must be unchanged.
			for i, cert := range analysis.TrustPaths[0].Certificates {
				assert.Equal(t, fps[i], cert.FingerprintSHA256(),
					"original cert[%d] fingerprint must be unchanged", i)
			}

			// Reversed copy must have certificates in reverse order.
			require.Len(t, reversed.TrustPaths, 1)
			require.Len(t, reversed.TrustPaths[0].Certificates, n)
			for i, cert := range reversed.TrustPaths[0].Certificates {
				assert.Equal(t, fps[n-1-i], cert.FingerprintSHA256(),
					"reversed cert[%d] should be original cert[%d]", i, n-1-i)
			}
		})
	}
}

func TestAnalysisPairs(t *testing.T) {
	t.Parallel()

	a1 := newTestAnalysis()
	a2 := newTestAnalysis()
	b1 := newTestAnalysis()
	b2 := newTestAnalysis()

	t.Run("equal lengths", func(t *testing.T) {
		t.Parallel()
		pairs := analysisPairs([]*certree.Analysis{a1, a2}, []*certree.Analysis{b1, b2})
		require.Len(t, pairs, 2)
		assert.Equal(t, a1, pairs[0].Before)
		assert.Equal(t, b1, pairs[0].After)
		assert.Equal(t, a2, pairs[1].Before)
		assert.Equal(t, b2, pairs[1].After)
	})

	t.Run("empty slices", func(t *testing.T) {
		t.Parallel()
		pairs := analysisPairs(nil, nil)
		assert.Empty(t, pairs)
	})

	t.Run("simulated shorter", func(t *testing.T) {
		t.Parallel()
		pairs := analysisPairs([]*certree.Analysis{a1, a2}, []*certree.Analysis{b1})
		assert.Len(t, pairs, 1)
	})
}

func TestAnalysesExitCode(t *testing.T) {
	t.Parallel()

	t.Run("no analyses", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, exitSuccess, analysesExitCode(nil))
	})

	t.Run("no errors", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, exitSuccess, analysesExitCode([]*certree.Analysis{newTestAnalysis()}))
	})

	t.Run("with errors", func(t *testing.T) {
		t.Parallel()
		analysis := certree.NewAnalysis(
			[]*certree.Certificate{},
			[]*certree.TrustPath{
				{
					Certificates: []*certree.Certificate{},
					Status:       certree.PathUntrusted,
					Errors: []certree.ValidationError{
						{Type: certree.ErrorExpired, Message: "certificate expired"},
					},
				},
			},
			"test.pem",
		)
		assert.Equal(t, exitValidationError, analysesExitCode([]*certree.Analysis{analysis}))
	})
}

func TestRenderAnalyses_JSONArray(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		analyses []*certree.Analysis
		wantLen  int
	}{
		{
			name:     "single analysis produces one-element array",
			analyses: []*certree.Analysis{newTestAnalysis()},
			wantLen:  1,
		},
		{
			name:     "batch produces multi-element array",
			analyses: []*certree.Analysis{newTestAnalysis(), newTestAnalysis()},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Output.Format = "json"

			var stdout, stderr bytes.Buffer
			er := testER(&stderr)
			code := renderAnalyses(tt.analyses, nonConfigFlags{}, cfg, &stdout, er)

			assert.Equal(t, exitSuccess, code)
			assert.True(t, json.Valid(stdout.Bytes()), "output must be valid JSON")

			var result []any
			err := json.Unmarshal(stdout.Bytes(), &result)
			require.NoError(t, err)
			assert.Len(t, result, tt.wantLen)
		})
	}
}

func TestRenderAnalyses_TreeFormat(t *testing.T) {
	t.Parallel()

	// Use an analysis with a trust path so the tree header includes the source.
	analysis := certree.NewAnalysis(
		[]*certree.Certificate{},
		[]*certree.TrustPath{
			{
				Certificates: []*certree.Certificate{},
				Status:       certree.PathTrusted,
			},
		},
		"test.pem",
	)

	cfg := config.DefaultConfig()
	var stdout, stderr bytes.Buffer
	er := testER(&stderr)

	code := renderAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{}, cfg, &stdout, er)

	assert.Equal(t, exitSuccess, code)
	output := stdout.String()
	assert.Contains(t, output, "test.pem", "tree output should contain source identifier")
}

// TestRenderAnalyses_BatchJSONReverse verifies that --reverse is applied to
// each analysis element when multiple analyses produce a JSON array. This is a
// regression test for A1 where batch JSON silently ignored --reverse.
func TestRenderAnalyses_BatchJSONReverse(t *testing.T) {
	t.Parallel()

	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	rawChain, _, err := testutil.GenerateChainWithDepth(3)
	require.NoError(t, err)

	chain := make([]*certree.Certificate, len(rawChain))
	for i, raw := range rawChain {
		chain[i] = certree.NewCertificate(raw, src)
	}

	analysis := certree.NewAnalysis(chain,
		[]*certree.TrustPath{
			{Certificates: chain, Status: certree.PathTrusted},
		},
		"test.pem",
	)

	cfg := config.DefaultConfig()
	cfg.Output.Format = "json"
	cfg.Render.Reverse = true

	var stdout, stderr bytes.Buffer
	er := testER(&stderr)
	code := renderAnalyses(
		[]*certree.Analysis{analysis, analysis},
		nonConfigFlags{}, cfg, &stdout, er,
	)
	assert.Equal(t, exitSuccess, code)

	var parsed []struct {
		TrustPaths []struct {
			Certificates []string `json:"certificates"`
		} `json:"trust_paths"`
	}
	err = json.Unmarshal(stdout.Bytes(), &parsed)
	require.NoError(t, err)
	require.Len(t, parsed, 2)
	require.Len(t, parsed[0].TrustPaths, 1)

	fingerprints := parsed[0].TrustPaths[0].Certificates
	n := len(chain)
	require.Len(t, fingerprints, n)

	// With reverse, first JSON cert should be the last chain cert.
	assert.Equal(t, certree.ColonHex(chain[n-1].FingerprintSHA256()), fingerprints[0],
		"batch JSON reverse: first cert should be root")
}

func TestJSONReverseOrder(t *testing.T) {
	t.Parallel()

	// Use the shared depth-chain cache. Raw x509 certs are immutable and safe
	// to share; Certificate wrappers contain lazy-init fields, so each subtest
	// creates its own wrappers via Raw() to avoid data races.
	depthChains := getRenderDepthChains(t)

	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	for depth := 1; depth <= 5; depth++ {
		for _, reverse := range []bool{false, true} {
			name := fmt.Sprintf("depth=%d/reverse=%t", depth, reverse)
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				// Create fresh Certificate wrappers for this subtest.
				cached := depthChains[depth]
				chain := make([]*certree.Certificate, len(cached))
				for i, c := range cached {
					chain[i] = certree.NewCertificate(c.Raw(), src)
				}
				n := len(chain)

				analysis := certree.NewAnalysis(chain,
					[]*certree.TrustPath{
						{Certificates: chain, Status: certree.PathTrusted},
					},
					"test.pem",
				)

				cfg := config.DefaultConfig()
				cfg.Render.Reverse = reverse
				cfg.Output.Format = "json"

				var buf, stderr bytes.Buffer
				er := testER(&stderr)
				code := renderAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{}, cfg, &buf, er)
				assert.Equal(t, exitSuccess, code)

				var parsed []struct {
					TrustPaths []struct {
						Certificates []string `json:"certificates"`
					} `json:"trust_paths"`
				}
				err := json.Unmarshal(buf.Bytes(), &parsed)
				require.NoError(t, err)
				require.Len(t, parsed, 1)
				require.Len(t, parsed[0].TrustPaths, 1)

				fingerprints := parsed[0].TrustPaths[0].Certificates
				require.Len(t, fingerprints, n)

				for i, fp := range fingerprints {
					var expectedIdx int
					if reverse {
						expectedIdx = n - 1 - i
					} else {
						expectedIdx = i
					}
					assert.Equal(t, certree.ColonHex(chain[expectedIdx].FingerprintSHA256()), fp,
						"cert[%d] fingerprint mismatch (reverse=%t)", i, reverse)
				}
			})
		}
	}
}

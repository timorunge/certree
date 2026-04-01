package render

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree"
)

func TestTrees_EmptySlice(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := Trees(nil, Options{}, &buf)
	if err == nil {
		t.Fatal("expected error for nil analyses, got nil")
	}
	if !errors.Is(err, errNoAnalysis) {
		t.Fatalf("expected errNoAnalysis, got: %v", err)
	}
}

func TestTrees_NilAnalysis(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := Trees([]*certree.Analysis{nil}, Options{}, &buf)
	if err == nil {
		t.Fatal("expected error for nil analysis, got nil")
	}
	if !errors.Is(err, errNoAnalysis) {
		t.Fatalf("expected errNoAnalysis, got: %v", err)
	}
}

func TestTrees_ValidAnalysisDefaultOptions(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{
			{Certificates: cached.chain3, Status: certree.PathTrusted},
		},
	}

	var buf bytes.Buffer
	err := Trees([]*certree.Analysis{analysis}, Options{}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Fatal("expected non-empty output, got empty string")
	}

	for _, cert := range cached.chain3 {
		cn := cert.CommonName()
		if cn == "" {
			continue
		}
		if !strings.Contains(output, cn) {
			t.Errorf("expected output to contain CN %q, got:\n%s", cn, output)
		}
	}
}

func TestTrees_WritesToCustomWriter(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	analysis := &certree.Analysis{
		Certificates: []*certree.Certificate{cached.singleCert},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{cached.singleCert}, Status: certree.PathTrusted},
		},
	}

	var buf bytes.Buffer
	err := Trees([]*certree.Analysis{analysis}, Options{}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("expected output written to buffer, got 0 bytes")
	}

	if !strings.Contains(buf.String(), "Single Cert") {
		t.Errorf("expected buffer to contain 'Single Cert', got:\n%s", buf.String())
	}
}

func TestTrees_MultipleAnalyses(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	a1 := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{
			{Certificates: cached.chain3, Status: certree.PathTrusted},
		},
		Metadata: certree.AnalysisMetadata{Source: "source-a"},
	}
	a2 := &certree.Analysis{
		Certificates: []*certree.Certificate{cached.singleCert},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{cached.singleCert}, Status: certree.PathTrusted},
		},
		Metadata: certree.AnalysisMetadata{Source: "source-b"},
	}

	var buf bytes.Buffer
	err := Trees([]*certree.Analysis{a1, a2}, Options{}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	assert.Contains(t, output, "source-a", "output should contain first source")
	assert.Contains(t, output, "source-b", "output should contain second source")
	assert.Contains(t, output, "Single Cert", "output should contain second analysis cert")
}

func TestComparisons_TwoValidAnalyses(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{
			{Certificates: cached.chain3, Status: certree.PathTrusted},
		},
	}

	pairs := []AnalysisPair{{Before: analysis, After: analysis}}

	var buf bytes.Buffer
	err := Comparisons(pairs, Options{}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
	if strings.Contains(buf.String(), "Impact:") {
		t.Errorf("expected no 'Impact:' by default, got:\n%s", buf.String())
	}

	buf.Reset()
	err = Comparisons(pairs, Options{Impact: true}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Impact:") {
		t.Errorf("expected 'Impact:' with Impact=true, got:\n%s", buf.String())
	}
}

func TestDiffs_HappyPath(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	before := &certree.Analysis{
		Certificates: []*certree.Certificate{cached.singleCert},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{cached.singleCert}, Status: certree.PathTrusted},
		},
		Metadata: certree.AnalysisMetadata{Source: "before-source"},
	}
	after := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{
			{Certificates: cached.chain3, Status: certree.PathTrusted},
		},
		Metadata: certree.AnalysisMetadata{Source: "after-source"},
	}

	pairs := []AnalysisPair{{Before: before, After: after}}
	sources := []string{"test-source"}

	var buf bytes.Buffer
	err := Diffs(pairs, sources, Options{ColorMode: "never"}, &buf)
	require.NoError(t, err)
	assert.NotEmpty(t, buf.String(), "Diffs should produce non-empty output")
}

func TestDiffs_EmptyPairs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := Diffs(nil, nil, Options{}, &buf)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errNoAnalysis), "expected errNoAnalysis, got: %v", err)
}

func TestDiffs_NilAnalysisInPair(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: []*certree.Certificate{cached.singleCert},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{cached.singleCert}, Status: certree.PathTrusted},
		},
	}

	tests := []struct {
		name   string
		before *certree.Analysis
		after  *certree.Analysis
	}{
		{name: "nil before", before: nil, after: analysis},
		{name: "nil after", before: analysis, after: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := Diffs([]AnalysisPair{{Before: tt.before, After: tt.after}}, nil, Options{}, &buf)
			require.Error(t, err)
			assert.True(t, errors.Is(err, errNoAnalysis), "expected errNoAnalysis, got: %v", err)
		})
	}
}

func TestResolveRenderEnv_ShowAllExpandsFlags(t *testing.T) {
	t.Parallel()

	env, err := resolveRenderEnv(Options{ShowAll: true, ColorMode: "never"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assert.True(t, env.opts.ShowTrustStore, "ShowAll should enable ShowTrustStore")
	assert.True(t, env.opts.ShowFingerprint, "ShowAll should enable ShowFingerprint")
	assert.True(t, env.opts.ShowSerial, "ShowAll should enable ShowSerial")
	assert.True(t, env.opts.ShowValidity, "ShowAll should enable ShowValidity")
	assert.True(t, env.opts.ShowExtensions, "ShowAll should enable ShowExtensions")
	assert.True(t, env.opts.ShowSource, "ShowAll should enable ShowSource")
	assert.True(t, env.opts.ShowSubject, "ShowAll should enable ShowSubject")
	assert.True(t, env.opts.ShowIssuer, "ShowAll should enable ShowIssuer")
	assert.True(t, env.opts.ShowSAN, "ShowAll should enable ShowSAN")
	assert.True(t, env.opts.ShowAlgorithm, "ShowAll should enable ShowAlgorithm")
	assert.True(t, env.opts.ShowAIA, "ShowAll should enable ShowAIA")
	assert.True(t, env.opts.ShowCRL, "ShowAll should enable ShowCRL")
	assert.True(t, env.opts.ShowDiagnostics, "ShowAll should enable ShowDiagnostics")
}

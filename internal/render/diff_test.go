package render

import (
	"fmt"
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/timorunge/certree/pkg/certree"
)

// containsANSI reports whether s contains any ANSI escape sequences.
func containsANSI(s string) bool {
	return strings.Contains(s, "\x1b[")
}

func TestVisualizeDiff_HeadersPresent(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	dv := newDiffVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
	output, err := dv.visualizeDiff(analysis, analysis, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "--- Before") {
		t.Errorf("first line should start with '--- Before', got: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "+++ After") {
		t.Errorf("second line should start with '+++ After', got: %q", lines[1])
	}
}

func TestVisualizeDiff_HeadersWithSource(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	dv := newDiffVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
	output, err := dv.visualizeDiff(analysis, analysis, "example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "--- Before (example.com:443)") {
		t.Errorf("expected '--- Before (example.com:443)' in output")
	}
	if !strings.Contains(output, "+++ After (example.com:443)") {
		t.Errorf("expected '+++ After (example.com:443)' in output")
	}
}

func TestVisualizeDiff_ClassicDiffColors(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	trustedChain := buildTrustedChain(t)
	beforeAnalysis := &certree.Analysis{
		Certificates: trustedChain,
		TrustPaths:   []*certree.TrustPath{{Certificates: trustedChain, Status: certree.PathTrusted}},
	}
	afterAnalysis := &certree.Analysis{
		Certificates: []*certree.Certificate{trustedChain[0]},
		TrustPaths:   []*certree.TrustPath{{Certificates: []*certree.Certificate{trustedChain[0]}, Status: certree.PathUntrusted}},
	}
	dv := newDiffVisualizer(&renderEnv{opts: Options{}, theme: classicTheme.WithColor()})
	output, err := dv.visualizeDiff(beforeAnalysis, afterAnalysis, "test.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(output, "\n")

	// Headers (--- / +++) should be bold (1m).
	if !strings.Contains(lines[0], "\x1b[1m") {
		t.Errorf("before header should be bold (1m), got: %q", lines[0])
	}
	if !strings.Contains(lines[1], "\x1b[1m") {
		t.Errorf("after header should be bold (1m), got: %q", lines[1])
	}

	// Removal lines should contain red (31m).
	hasRed := false
	for _, line := range lines {
		stripped := stripANSICodes(line)
		if strings.HasPrefix(stripped, "-") {
			if strings.Contains(line, "\x1b[31m") {
				hasRed = true
				break
			}
		}
	}
	if !hasRed {
		t.Error("removal lines should contain red ANSI code (31m)")
	}

	// Addition lines should contain green (32m).
	hasGreen := false
	for _, line := range lines {
		stripped := stripANSICodes(line)
		if strings.HasPrefix(stripped, "+") {
			if strings.Contains(line, "\x1b[32m") {
				hasGreen = true
				break
			}
		}
	}
	if !hasGreen {
		t.Error("addition lines should contain green ANSI code (32m)")
	}
}

func TestVisualizeDiff_NoANSIInNoColorMode(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	dv := newDiffVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
	output, err := dv.visualizeDiff(analysis, analysis, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containsANSI(output) {
		t.Errorf("expected no ANSI escape codes in no-color mode")
	}
}

func TestVisualizeDiff_IdenticalInputContextOnly(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	dv := newDiffVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
	output, err := dv.visualizeDiff(analysis, analysis, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for line := range strings.SplitSeq(strings.TrimRight(output, "\n"), "\n") {
		if strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ ") {
			continue
		}
		if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "+") {
			t.Errorf("identical input should produce only context lines, found: %q", line)
		}
	}
}

func TestVisualizeDiffs_HeaderCount(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	sources := []string{"src1.com:443", "src2.com:443", "src3.com:443"}
	pairs := make([]AnalysisPair, len(sources))
	for i := range sources {
		pairs[i] = AnalysisPair{Before: analysis, After: analysis}
	}
	dv := newDiffVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
	output, err := dv.visualizeDiffs(pairs, sources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.Count(output, "--- Before"); got != len(sources) {
		t.Errorf("expected %d '--- Before' headers, got %d", len(sources), got)
	}
	for _, src := range sources {
		if !strings.Contains(output, "--- Before ("+src+")") {
			t.Errorf("expected '--- Before (%s)' in output", src)
		}
	}
}

func TestComputeLineDiff_EmptyInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		before string
		after  string
		want   int
	}{
		{"both empty", "", "", 0},
		{"before empty", "", "line1\nline2", 2},
		{"after empty", "line1\nline2", "", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := computeLineDiff(tt.before, tt.after)
			if len(result) != tt.want {
				t.Errorf("expected %d lines, got %d: %v", tt.want, len(result), result)
			}
		})
	}
}

func TestComputeLineDiff_Identical(t *testing.T) {
	t.Parallel()
	result := computeLineDiff("line1\nline2\nline3", "line1\nline2\nline3")
	if len(result) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(result))
	}
	for _, line := range result {
		if !strings.HasPrefix(line, " ") {
			t.Errorf("identical input should produce context lines, got: %q", line)
		}
	}
}

func TestComputeLineDiff_CompletelyDifferent(t *testing.T) {
	t.Parallel()
	result := computeLineDiff("alpha\nbeta", "gamma\ndelta")
	removals, additions := 0, 0
	for _, line := range result {
		switch {
		case strings.HasPrefix(line, "-"):
			removals++
		case strings.HasPrefix(line, "+"):
			additions++
		}
	}
	if removals != 2 || additions != 2 {
		t.Errorf("expected 2 removals and 2 additions, got %d/%d", removals, additions)
	}
}

func TestComputeLineDiff_LargeInputFallback(t *testing.T) {
	t.Parallel()

	// Generate inputs exceeding diffMaxLines to trigger the fallback path.
	var before, after strings.Builder
	for i := range diffMaxLines + 10 {
		fmt.Fprintf(&before, "before-line-%d\n", i)
		fmt.Fprintf(&after, "after-line-%d\n", i)
	}

	result := computeLineDiff(before.String(), after.String())

	// Fallback produces only removal and addition lines -- no context (space-prefixed) lines.
	for _, line := range result {
		if strings.HasPrefix(line, " ") {
			t.Fatalf("fallback should not produce context lines, got: %q", line)
		}
		if !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "+") {
			t.Fatalf("unexpected prefix in fallback output: %q", line)
		}
	}

	removals, additions := 0, 0
	for _, line := range result {
		switch {
		case strings.HasPrefix(line, "-"):
			removals++
		case strings.HasPrefix(line, "+"):
			additions++
		}
	}

	wantCount := diffMaxLines + 10
	if removals != wantCount {
		t.Errorf("expected %d removals, got %d", wantCount, removals)
	}
	if additions != wantCount {
		t.Errorf("expected %d additions, got %d", wantCount, additions)
	}
}

func TestComputeLineDiff_Mixed(t *testing.T) {
	t.Parallel()
	result := computeLineDiff("A\nB\nC\nD", "A\nX\nC\nD")
	expected := []string{" A", "-B", "+X", " C", " D"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d lines, got %d: %v", len(expected), len(result), result)
	}
	for i, want := range expected {
		if result[i] != want {
			t.Errorf("line %d: got %q, want %q", i, result[i], want)
		}
	}
}

func TestVisualizeDiff_ImpactAppended(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	dv := newDiffVisualizer(&renderEnv{opts: Options{Impact: true}, theme: classicTheme})
	output, err := dv.visualizeDiff(analysis, analysis, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Impact:") {
		t.Errorf("expected 'Impact:' in output when Impact is true")
	}
}

func TestBuildIntraSegments(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		mine        string
		other       string
		wantChanged bool
		wantSegs    int
	}{
		{"identical", "abc", "abc", false, 1},
		{"completely different", "abc", "xyz", true, 1},
		{"partial overlap", "[+ ] Trust Path 1", "[x ] Trust Path 1 (excluded)", true, 2},
		{"empty mine", "", "abc", false, 1},
		{"empty other", "abc", "", true, 1},
		{"both empty", "", "", false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			segs := buildIntraSegments([]rune(tt.mine), []rune(tt.other))
			if len(segs) == 0 {
				t.Fatal("expected at least one segment")
			}
			hasChanged := false
			for _, seg := range segs {
				if seg.changed {
					hasChanged = true
					break
				}
			}
			if tt.wantChanged && !hasChanged {
				t.Errorf("expected changed segments, got none")
			}
			if !tt.wantChanged && hasChanged {
				t.Errorf("expected no changed segments, got changed")
			}
			if tt.wantSegs > 0 && len(segs) < tt.wantSegs {
				t.Errorf("expected at least %d segments, got %d", tt.wantSegs, len(segs))
			}
		})
	}
}

func TestBuildIntraSegments_Oversized(t *testing.T) {
	t.Parallel()
	long := make([]rune, intraDiffMaxLineLen+1)
	for i := range long {
		long[i] = 'a'
	}
	segs := buildIntraSegments(long, []rune("b"))
	if len(segs) != 1 || segs[0].changed {
		t.Errorf("oversized input should return single unchanged segment")
	}
}

func TestRenderIntraLine_PairedHighlighting(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	baseFunc := color.New(color.FgGreen).SprintFunc()
	emphFunc := color.New(color.FgHiGreen, color.Bold).SprintFunc()

	result := renderIntraLine("+", "[x ] Trust Path 1 (excluded)", "[+ ] Trust Path 1", baseFunc, emphFunc)

	// Must contain bold+hi-green ANSI code for the changed segments.
	if !strings.Contains(result, "\x1b[92;1m") {
		t.Errorf("expected bold+hi-green ANSI code (92;1m) for changed segments, got: %q", result)
	}
	// Must also contain plain green for unchanged segments.
	if !strings.Contains(result, "\x1b[32m") {
		t.Errorf("expected plain green ANSI code (32m) for unchanged segments, got: %q", result)
	}
}

func TestRenderIntraLine_NoColorMode(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = true
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	baseFunc := color.New(color.FgGreen).SprintFunc()
	emphFunc := color.New(color.FgGreen, color.Bold).SprintFunc()

	result := renderIntraLine("+", "[x ] Trust Path 1 (excluded)", "[+ ] Trust Path 1", baseFunc, emphFunc)
	if containsANSI(result) {
		t.Errorf("expected no ANSI codes in no-color mode, got: %q", result)
	}
}

func TestVisualizeDiff_IntraLineHighlighting(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	trustedChain := buildTrustedChain(t)
	beforeAnalysis := &certree.Analysis{
		Certificates: trustedChain,
		TrustPaths:   []*certree.TrustPath{{Certificates: trustedChain, Status: certree.PathTrusted}},
	}
	afterAnalysis := &certree.Analysis{
		Certificates: []*certree.Certificate{trustedChain[0]},
		TrustPaths:   []*certree.TrustPath{{Certificates: []*certree.Certificate{trustedChain[0]}, Status: certree.PathUntrusted}},
	}
	dv := newDiffVisualizer(&renderEnv{opts: Options{}, theme: classicTheme.WithColor()})
	output, err := dv.visualizeDiff(beforeAnalysis, afterAnalysis, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Bold codes (;1m) should appear for intra-line emphasis on changed segments.
	if !strings.Contains(output, ";1m") {
		t.Errorf("expected bold ANSI codes for intra-line highlighting in diff output")
	}
}

func TestWriteIntraDiffLines_UnpairedWholeColor(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	dv := newDiffVisualizer(&renderEnv{opts: Options{}, theme: classicTheme.WithColor()})

	// Two removals, one addition: first pair gets intra-line, second removal is unpaired.
	diffLines := []string{"-line A", "-line B only removed", "+line A changed"}
	var b strings.Builder
	dv.writeIntraDiffLines(&b, diffLines)
	output := b.String()

	// The unpaired line "-line B only removed" should be fully red (31m) without bold.
	if !strings.Contains(output, "\x1b[31m-line B only removed") {
		t.Errorf("expected unpaired removal to be whole-line red, got: %q", output)
	}
}

func TestComputeLCS_Runes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a    string
		b    string
		want string
	}{
		{"identical", "abc", "abc", "abc"},
		{"completely different", "abc", "xyz", ""},
		{"partial", "abcdef", "abxdyf", "abdf"},
		{"empty a", "", "abc", ""},
		{"empty b", "abc", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := string(computeLCS([]rune(tt.a), []rune(tt.b)))
			if got != tt.want {
				t.Errorf("computeLCS(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

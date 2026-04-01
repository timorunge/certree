// Unified diff visualization for before/after simulation tree outputs.

package render

import (
	"fmt"
	"slices"
	"strings"

	"github.com/timorunge/certree/pkg/certree"
)

const (
	// Character limit above which intra-line diff is skipped to bound O(n^2) LCS cost.
	intraDiffMaxLineLen = 512

	// Line-count limit above which line-level LCS falls back to a simple
	// before/after display to bound O(m*n) cost.
	diffMaxLines = 1000
)

// diffVisualizer produces unified diff output from two rendered tree outputs.
type diffVisualizer struct {
	treeVis       *treeVisualizer
	headerFunc    colorFunc
	redFunc       colorFunc
	greenFunc     colorFunc
	redEmphFunc   colorFunc
	greenEmphFunc colorFunc
}

// newDiffVisualizer creates a new diff visualizer; the internal tree visualizer always uses the plain theme.
func newDiffVisualizer(env *renderEnv) *diffVisualizer {
	// Resolve the base (uncolored) theme for tree rendering. Built-in themes
	// are registered with defaultColors (identity functions), so looking up
	// by name yields the plain variant regardless of whether WithColor was
	// applied to the caller's copy.
	plainTheme, err := lookupTheme(env.theme.name)
	if err != nil {
		// Defensive fallback: reset colors on the provided theme.
		plainTheme = env.theme
		plainTheme.colors = defaultColors
	}

	// Disable ShowPathIndex for internal tree rendering: the before/after
	// trees may have different path counts, producing different alignment
	// padding that causes spurious diff hunks on otherwise-identical lines.
	plainOpts := env.opts
	plainOpts.ShowPathIndex = false
	plainEnv := &renderEnv{opts: plainOpts, theme: plainTheme, width: env.width}

	return &diffVisualizer{
		treeVis:       newTreeVisualizer(plainEnv),
		headerFunc:    env.theme.colors.diffHeader,
		redFunc:       env.theme.colors.diffRemove,
		greenFunc:     env.theme.colors.diffAdd,
		redEmphFunc:   env.theme.colors.diffEmphDel,
		greenEmphFunc: env.theme.colors.diffEmphAdd,
	}
}

// visualizeDiff renders before/after analyses as a unified diff, including source in the header when non-empty.
func (dv *diffVisualizer) visualizeDiff(before, after *certree.Analysis, source string) (string, error) {
	if before == nil || after == nil {
		return "", errNoAnalysis
	}

	beforeText, err := dv.treeVis.visualize(before)
	if err != nil {
		return "", fmt.Errorf("rendering before analysis: %w", err)
	}

	afterText, err := dv.treeVis.visualize(after)
	if err != nil {
		return "", fmt.Errorf("rendering after analysis: %w", err)
	}

	diffLines := computeLineDiff(beforeText, afterText)

	var b strings.Builder

	beforeHeader := "--- Before"
	afterHeader := "+++ After"
	if source != "" {
		safeSource := SanitizeCertString(source)
		beforeHeader = "--- Before (" + safeSource + ")"
		afterHeader = "+++ After (" + safeSource + ")"
	}

	b.WriteString(dv.headerFunc(beforeHeader))
	b.WriteByte('\n')
	b.WriteString(dv.headerFunc(afterHeader))
	b.WriteByte('\n')

	dv.writeIntraDiffLines(&b, diffLines)

	if dv.treeVis.opts.Impact {
		b.WriteByte('\n')
		b.WriteString(ImpactSummary(before, after, dv.treeVis.theme.treeChars.sectionIndent, dv.treeVis.theme.treeChars.labelSep, dv.treeVis.opts.ExpiryWarningDays))
	}

	return b.String(), nil
}

// visualizeDiffs renders multiple before/after pairs as separate diffs with a blank line between them.
func (dv *diffVisualizer) visualizeDiffs(pairs []AnalysisPair, sources []string) (string, error) {
	var b strings.Builder

	for i, pair := range pairs {
		source := ""
		if i < len(sources) {
			source = sources[i]
		}

		output, err := dv.visualizeDiff(pair.Before, pair.After, source)
		if err != nil {
			return "", err
		}

		b.WriteString(output)

		if i < len(pairs)-1 {
			b.WriteByte('\n')
		}
	}

	return b.String(), nil
}

// computeLineDiff computes a unified diff between two multi-line strings using LCS.
func computeLineDiff(before, after string) []string {
	beforeLines := splitLines(before)
	afterLines := splitLines(after)

	// Fall back to simple remove-all/add-all when inputs are too large for O(m*n) LCS.
	// The single-char prefix ("-"/"+"/space) is always the first byte and is
	// stripped positionally by writeIntraDiffLines, so content that starts
	// with "+" or "-" (e.g., minimal theme's "+" icon) is not ambiguous.
	if len(beforeLines) > diffMaxLines || len(afterLines) > diffMaxLines {
		result := make([]string, 0, len(beforeLines)+len(afterLines))
		for _, l := range beforeLines {
			result = append(result, "-"+l)
		}
		for _, l := range afterLines {
			result = append(result, "+"+l)
		}
		return result
	}

	// Use index-based LCS to avoid incorrect matches when duplicate lines
	// exist. The LCS backtrack selects specific positions; reconstructing
	// with string equality would match the wrong occurrence of a repeated
	// line and produce a corrupted diff.
	beforeIdxs, afterIdxs := computeLCSIndices(beforeLines, afterLines)

	result := make([]string, 0, len(beforeLines)+len(afterLines))

	bi, ai := 0, 0
	for k := range beforeIdxs {
		for bi < beforeIdxs[k] {
			result = append(result, "-"+beforeLines[bi])
			bi++
		}
		for ai < afterIdxs[k] {
			result = append(result, "+"+afterLines[ai])
			ai++
		}
		result = append(result, " "+beforeLines[bi])
		bi++
		ai++
	}

	for bi < len(beforeLines) {
		result = append(result, "-"+beforeLines[bi])
		bi++
	}
	for ai < len(afterLines) {
		result = append(result, "+"+afterLines[ai])
		ai++
	}

	return result
}

// computeLCSIndices returns the indices of the LCS elements in a and b.
// Unlike computeLCS, this preserves positional information needed for
// correct diff reconstruction when duplicate elements exist.
func computeLCSIndices[T comparable](a, b []T) (aIdxs, bIdxs []int) {
	m, n := len(a), len(b)
	if m == 0 || n == 0 {
		return nil, nil
	}

	cols := n + 1
	table := make([]int, (m+1)*cols)
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				table[i*cols+j] = table[(i-1)*cols+(j-1)] + 1
			} else {
				table[i*cols+j] = max(table[(i-1)*cols+j], table[i*cols+(j-1)])
			}
		}
	}

	lcsLen := table[m*cols+n]
	aIdxs = make([]int, 0, lcsLen)
	bIdxs = make([]int, 0, lcsLen)
	i, j := m, n
	for i > 0 && j > 0 {
		switch {
		case a[i-1] == b[j-1]:
			aIdxs = append(aIdxs, i-1)
			bIdxs = append(bIdxs, j-1)
			i--
			j--
		case table[(i-1)*cols+j] >= table[i*cols+(j-1)]:
			i--
		default:
			j--
		}
	}

	slices.Reverse(aIdxs)
	slices.Reverse(bIdxs)

	return aIdxs, bIdxs
}

// computeLCS returns the longest common subsequence of two comparable slices in O(m*n) time and space.
func computeLCS[T comparable](a, b []T) []T {
	m, n := len(a), len(b)
	if m == 0 || n == 0 {
		return nil
	}

	cols := n + 1
	table := make([]int, (m+1)*cols)
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				table[i*cols+j] = table[(i-1)*cols+(j-1)] + 1
			} else {
				table[i*cols+j] = max(table[(i-1)*cols+j], table[i*cols+(j-1)])
			}
		}
	}

	lcs := make([]T, 0, table[m*cols+n])
	i, j := m, n
	for i > 0 && j > 0 {
		switch {
		case a[i-1] == b[j-1]:
			lcs = append(lcs, a[i-1])
			i--
			j--
		case table[(i-1)*cols+j] >= table[i*cols+(j-1)]:
			i--
		default:
			j--
		}
	}

	slices.Reverse(lcs)

	return lcs
}

// writeIntraDiffLines pairs consecutive -/+ hunks and applies intra-line
// highlighting to paired lines. Unpaired lines get whole-line color.
func (dv *diffVisualizer) writeIntraDiffLines(b *strings.Builder, diffLines []string) {
	i := 0
	for i < len(diffLines) {
		if !strings.HasPrefix(diffLines[i], "-") && !strings.HasPrefix(diffLines[i], "+") {
			b.WriteString(diffLines[i])
			b.WriteByte('\n')
			i++
			continue
		}

		var removals, additions []string
		for i < len(diffLines) && strings.HasPrefix(diffLines[i], "-") {
			removals = append(removals, diffLines[i][1:])
			i++
		}
		for i < len(diffLines) && strings.HasPrefix(diffLines[i], "+") {
			additions = append(additions, diffLines[i][1:])
			i++
		}

		paired := min(len(removals), len(additions))
		for j := range paired {
			b.WriteString(renderIntraLine("-", removals[j], additions[j], dv.redFunc, dv.redEmphFunc))
			b.WriteByte('\n')
			b.WriteString(renderIntraLine("+", additions[j], removals[j], dv.greenFunc, dv.greenEmphFunc))
			b.WriteByte('\n')
		}
		for j := paired; j < len(removals); j++ {
			b.WriteString(dv.redFunc("-" + removals[j]))
			b.WriteByte('\n')
		}
		for j := paired; j < len(additions); j++ {
			b.WriteString(dv.greenFunc("+" + additions[j]))
			b.WriteByte('\n')
		}
	}
}

// segment represents a contiguous run of characters with a change marker.
type segment struct {
	text    string
	changed bool
}

// renderIntraLine applies intra-line highlighting to a single changed line.
// baseFunc colors unchanged segments; emphFunc colors changed segments.
func renderIntraLine(prefix, content, other string, baseFunc, emphFunc colorFunc) string {
	segs := buildIntraSegments([]rune(content), []rune(other))
	if len(segs) == 1 && !segs[0].changed {
		return baseFunc(prefix + content)
	}

	var b strings.Builder
	b.WriteString(baseFunc(prefix))
	for _, seg := range segs {
		if seg.changed {
			b.WriteString(emphFunc(seg.text))
		} else {
			b.WriteString(baseFunc(seg.text))
		}
	}
	return b.String()
}

// buildIntraSegments classifies each rune in mine as changed or unchanged
// relative to other, using character-level LCS.
func buildIntraSegments(mine, other []rune) []segment {
	if len(mine) == 0 {
		return []segment{{text: "", changed: false}}
	}
	if len(mine) > intraDiffMaxLineLen || len(other) > intraDiffMaxLineLen {
		return []segment{{text: string(mine), changed: false}}
	}

	lcs := computeLCS(mine, other)

	segs := make([]segment, 0, 8)
	li := 0
	var buf strings.Builder
	currentChanged := false

	flush := func() {
		if buf.Len() > 0 {
			segs = append(segs, segment{text: buf.String(), changed: currentChanged})
			buf.Reset()
		}
	}

	for _, r := range mine {
		inLCS := li < len(lcs) && r == lcs[li]
		if inLCS {
			li++
		}
		changed := !inLCS
		if buf.Len() > 0 && changed != currentChanged {
			flush()
		}
		currentChanged = changed
		buf.WriteRune(r)
	}
	flush()

	if len(segs) == 0 {
		return []segment{{text: "", changed: false}}
	}
	return segs
}

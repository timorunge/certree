// Side-by-side before/after comparison visualization for exclusion simulations.

package render

import (
	"fmt"
	"strings"

	"github.com/timorunge/certree/pkg/certree"
)

// comparisonVisualizer implements side-by-side comparison visualization.
type comparisonVisualizer struct {
	width   int
	treeVis *treeVisualizer
}

// newComparisonVisualizer creates a new comparison visualizer from the
// resolved render environment.
func newComparisonVisualizer(env *renderEnv) *comparisonVisualizer {
	return &comparisonVisualizer{
		width:   env.width,
		treeVis: newTreeVisualizer(env),
	}
}

// renderedPair holds pre-rendered tree text for a before/after comparison pair.
type renderedPair struct {
	before, after string
}

// visualizeComparisons renders multiple before/after pairs under a single "Before | After" header.
func (cv *comparisonVisualizer) visualizeComparisons(pairs []AnalysisPair) (string, error) {
	rendered := make([]renderedPair, len(pairs))
	leftContent, rightContent := 0, 0
	for i, pair := range pairs {
		rp, err := cv.renderPair(pair.Before, pair.After)
		if err != nil {
			return "", err
		}
		rendered[i] = rp
		leftContent = max(leftContent, maxLineWidth(rp.before))
		rightContent = max(rightContent, maxLineWidth(rp.after))
	}

	leftWidth, rightWidth := columnWidths(cv.width, leftContent, rightContent)

	var builder strings.Builder
	builder.WriteString(formatHeader("Before", "After", leftWidth, rightWidth))
	builder.WriteString(formatSeparator(leftWidth, rightWidth))
	for i, rp := range rendered {
		builder.WriteString(renderSideBySide(rp.before, rp.after, leftWidth, rightWidth))
		if cv.treeVis.opts.Impact {
			builder.WriteString("\n")
			builder.WriteString(ImpactSummary(pairs[i].Before, pairs[i].After, cv.treeVis.theme.treeChars.sectionIndent, cv.treeVis.theme.treeChars.labelSep, cv.treeVis.opts.ExpiryWarningDays))
		}
		if i < len(rendered)-1 {
			builder.WriteString(formatSeparator(leftWidth, rightWidth))
		}
	}
	return builder.String(), nil
}

// columnWidths computes asymmetric column widths for side-by-side comparison.
// When both sides fit at natural width, both columns match their content.
// When space is tight, the left column keeps its natural width and the right
// gets the rest. When even the left exceeds half the terminal, both columns
// fall back to an equal split.
func columnWidths(termWidth, leftContent, rightContent int) (left, right int) {
	half := max((termWidth-3)/2, 1)

	// If left content exceeds half, equal split.
	if leftContent > half {
		return half, half
	}

	// Both sides fit at equal width -- expand left to match right
	// for a balanced appearance.
	w := max(leftContent, rightContent)
	if w+3+w <= termWidth {
		return w, w
	}

	// Natural widths fit but equal doesn't -- use natural widths.
	if leftContent+3+rightContent <= termWidth {
		return max(leftContent, 1), max(rightContent, 1)
	}

	// Tight: left keeps natural width, right gets the rest.
	leftWidth := max(leftContent, 1)
	rightWidth := max(termWidth-leftWidth-3, 1)
	return leftWidth, rightWidth
}

// renderPair renders a before/after pair to tree text.
func (cv *comparisonVisualizer) renderPair(before, after *certree.Analysis) (renderedPair, error) {
	if before == nil || after == nil {
		return renderedPair{}, errNoAnalysis
	}
	beforeText, err := cv.treeVis.visualize(before)
	if err != nil {
		return renderedPair{}, fmt.Errorf("rendering before analysis: %w", err)
	}
	afterText, err := cv.treeVis.visualize(after)
	if err != nil {
		return renderedPair{}, fmt.Errorf("rendering after analysis: %w", err)
	}
	return renderedPair{before: beforeText, after: afterText}, nil
}

// formatHeader creates the header row for side-by-side comparison.
func formatHeader(left, right string, leftWidth, rightWidth int) string {
	var b strings.Builder
	b.WriteString(padRight(left, leftWidth))
	b.WriteString(" | ")
	b.WriteString(padRight(right, rightWidth))
	b.WriteByte('\n')
	return b.String()
}

// renderSideBySide renders two strings side by side, truncating lines to fit
// within the given column widths.
func renderSideBySide(left, right string, leftWidth, rightWidth int) string {
	leftLines := splitLines(left)
	rightLines := splitLines(right)
	maxLines := max(len(rightLines), len(leftLines))
	var builder strings.Builder
	for i := range maxLines {
		leftLine := ""
		if i < len(leftLines) {
			leftLine = leftLines[i]
		}
		rightLine := ""
		if i < len(rightLines) {
			rightLine = rightLines[i]
		}
		leftLine = padRight(truncate(leftLine, leftWidth), leftWidth)
		rightLine = truncate(rightLine, rightWidth)
		builder.WriteString(leftLine)
		builder.WriteString(" | ")
		builder.WriteString(rightLine)
		builder.WriteByte('\n')
	}
	return builder.String()
}

// formatSeparator returns a separator string for side-by-side comparison.
func formatSeparator(leftWidth, rightWidth int) string {
	return strings.Repeat("-", leftWidth) + "-+-" + strings.Repeat("-", rightWidth) + "\n"
}

// maxLineWidth returns the maximum visible width of a string, considering
// multi-byte characters.
func maxLineWidth(s string) int {
	width := 0
	for line := range strings.SplitSeq(s, "\n") {
		if w := visibleLen(line); w > width {
			width = w
		}
	}
	return width
}

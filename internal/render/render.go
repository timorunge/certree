// Public API: types, options, and render entry points.

package render

import (
	"errors"
	"fmt"
	"io"

	"github.com/fatih/color"

	"github.com/timorunge/certree/pkg/certree"
)

var (
	errNoAnalysis   = errors.New("no analysis to visualize")
	errInvalidTheme = errors.New("invalid theme")
)

// Options configures visualization behavior.
type Options struct {
	// ThemeName selects the output theme ("classic", "terse", "minimal"); defaults to "classic".
	ThemeName string

	// ColorMode controls ANSI color output: "auto", "always", or "never".
	ColorMode string

	// ExpiryWarningDays is the threshold for expiry-soon warnings.
	// Zero and negative values fall back to certree.DefaultExpiryWarningDays (30).
	ExpiryWarningDays int

	// ReverseOrder displays certificates in root-to-leaf order.
	ReverseOrder bool
	// WrapLines enables line wrapping for long field values.
	WrapLines bool
	// ShowAll enables all detail fields at once.
	ShowAll         bool
	ShowSubject     bool
	ShowSAN         bool
	ShowIssuer      bool
	ShowValidity    bool
	ShowTrustStore  bool
	ShowSerial      bool
	ShowFingerprint bool
	ShowAlgorithm   bool
	ShowExtensions  bool
	ShowAIA         bool
	ShowCRL         bool
	ShowSource      bool
	ShowDiagnostics bool
	// Impact enables simulation impact display (runtime-only, not a detail flag).
	Impact bool
	// ShowAnnotations enables parenthesized status annotations on certificate
	// and path nodes (e.g. "(expired)", "(self-signed, trusted)").
	ShowAnnotations bool
	// ShowPathIndex displays a right-aligned path index (#1, #2, ...) on
	// path terminal certificates to identify which trust path each branch represents.
	ShowPathIndex bool
	// ExpandedView disables the default merged tree view and renders each
	// TrustPath under its own "Trust Path N" node.
	ExpandedView bool
}

// hasDetailFlags reports whether any --show-* detail flag is set.
// Used to decide between the fast single-line path and the multi-line
// detailed rendering mode.
func (o Options) hasDetailFlags() bool {
	return o.ShowAll || o.ShowFingerprint || o.ShowSerial || o.ShowValidity ||
		o.ShowExtensions || o.ShowSource || o.ShowSubject ||
		o.ShowIssuer || o.ShowSAN || o.ShowTrustStore ||
		o.ShowAlgorithm || o.ShowAIA || o.ShowCRL || o.ShowDiagnostics
}

// AnalysisPair holds a before/after analysis pair for batch operations.
type AnalysisPair struct {
	// Before is the baseline analysis for comparison.
	Before *certree.Analysis
	// After is the updated analysis to compare against Before.
	After *certree.Analysis
}

// renderEnv holds resolved options, theme, and terminal width for a single render call.
type renderEnv struct {
	opts  Options
	theme renderTheme
	width int
}

// resolveRenderEnv detects the terminal, resolves theme and color mode, expands ShowAll, and returns the environment.
func resolveRenderEnv(opts Options) (*renderEnv, error) {
	t := detectTerminal()

	theme, err := resolveTheme(opts)
	if err != nil {
		return nil, err
	}

	colorOn := resolveColorEnabled(t, opts.ColorMode)
	if colorOn {
		OverrideColorLibrary(opts.ColorMode)
		theme = theme.WithColor()
	}

	if opts.ShowAll {
		opts.ShowFingerprint = true
		opts.ShowSerial = true
		opts.ShowValidity = true
		opts.ShowExtensions = true
		opts.ShowSource = true
		opts.ShowSubject = true
		opts.ShowIssuer = true
		opts.ShowSAN = true
		opts.ShowTrustStore = true
		opts.ShowAlgorithm = true
		opts.ShowAIA = true
		opts.ShowCRL = true
		opts.ShowDiagnostics = true
	}

	return &renderEnv{
		opts:  opts,
		theme: theme,
		width: t.width,
	}, nil
}

// writeOutput writes the given output string to the writer with a label prefix.
func writeOutput(output, label string, w io.Writer) error {
	if _, err := io.WriteString(w, output); err != nil {
		return fmt.Errorf("writing %s output: %w", label, err)
	}
	return nil
}

// Trees renders analysis results to the given writer using the provided options.
// It auto-detects terminal capabilities, resolves the theme, and writes tree output.
func Trees(analyses []*certree.Analysis, opts Options, w io.Writer) error {
	if len(analyses) == 0 {
		return errNoAnalysis
	}

	env, err := resolveRenderEnv(opts)
	if err != nil {
		return fmt.Errorf("resolving render environment for trees: %w", err)
	}

	vis := newTreeVisualizer(env)
	output, err := vis.visualizeAll(analyses)
	if err != nil {
		return fmt.Errorf("rendering output: %w", err)
	}

	return writeOutput(output, "tree", w)
}

// Comparisons renders multiple before/after pairs under a single
// "Before | After" header with dashed separators between sources.
func Comparisons(pairs []AnalysisPair, opts Options, w io.Writer) error {
	if len(pairs) == 0 {
		return errNoAnalysis
	}
	for _, p := range pairs {
		if p.Before == nil || p.After == nil {
			return errNoAnalysis
		}
	}

	env, err := resolveRenderEnv(opts)
	if err != nil {
		return fmt.Errorf("resolving render environment for comparisons: %w", err)
	}

	cv := newComparisonVisualizer(env)

	output, err := cv.visualizeComparisons(pairs)
	if err != nil {
		return fmt.Errorf("rendering comparisons: %w", err)
	}

	return writeOutput(output, "comparisons", w)
}

// Diffs renders unified diffs for multiple before/after pairs.
// Each pair produces a separate diff section with the corresponding source
// identifier in the header.
func Diffs(pairs []AnalysisPair, sources []string, opts Options, w io.Writer) error {
	if len(pairs) == 0 {
		return errNoAnalysis
	}
	for _, p := range pairs {
		if p.Before == nil || p.After == nil {
			return errNoAnalysis
		}
	}

	env, err := resolveRenderEnv(opts)
	if err != nil {
		return fmt.Errorf("resolving render environment for diffs: %w", err)
	}

	dv := newDiffVisualizer(env)

	output, err := dv.visualizeDiffs(pairs, sources)
	if err != nil {
		return fmt.Errorf("rendering diffs: %w", err)
	}

	return writeOutput(output, "diffs", w)
}

// resolveTheme returns the theme for opts, defaulting to classicTheme.
func resolveTheme(opts Options) (renderTheme, error) {
	if opts.ThemeName == "" {
		return classicTheme, nil
	}

	theme, err := lookupTheme(opts.ThemeName)
	if err != nil {
		return renderTheme{}, fmt.Errorf("%w: %s", errInvalidTheme, err)
	}

	return theme, nil
}

// OverrideColorLibrary forces the fatih/color library to emit ANSI codes
// when --color=always is set. The library auto-detects non-TTY stdout and
// sets its global NoColor flag, which suppresses output from SprintFunc
// closures at call time. This override is only applied in the "always" mode.
// Must be called before any color.SprintFunc closures are invoked.
func OverrideColorLibrary(colorMode string) {
	if colorMode == "always" {
		color.NoColor = false
	}
}

// resolveColorEnabled determines whether ANSI color output should be enabled based on colorMode and terminal.
func resolveColorEnabled(t *terminal, colorMode string) bool {
	switch colorMode {
	case "always":
		return true
	case "never":
		return false
	default:
		return t.colorEnabled
	}
}

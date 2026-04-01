// renderTheme definitions, tree characters, and built-in theme registry.

package render

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/fatih/color"
)

// renderTheme defines visual appearance for certificate visualization.
type renderTheme struct {
	name          string
	treeChars     treeCharacters
	statusIcons   statusIcons
	spinnerFrames []string
	// colors holds color functions; identity (no-op) functions when color is disabled.
	colors colorFuncs
}

// treeCharacters defines ASCII characters for tree structure.
type treeCharacters struct {
	branch        string // non-last children, e.g. "+-"
	lastChild     string // last child, e.g. "`-"
	vertical      string // continuation, e.g. "|  "
	blank         string // vertical-width spacing without a connector
	sectionIndent string // indentation for section content lines
	labelSep      string // spacing between "label:" and value in detail fields
}

// statusIcons defines status indicators.
type statusIcons struct {
	valid        string
	warning      string
	err          string
	info         string
	debug        string
	continuation string // subordinate icon for error detail/context lines
}

// colorFunc wraps text with ANSI color codes, or returns it unchanged when
// color is disabled. Signature matches fatih/color.SprintFunc return type.
type colorFunc func(a ...any) string

// colorFuncs holds color functions for each status category.
type colorFuncs struct {
	valid    colorFunc
	warning  colorFunc
	err      colorFunc
	info     colorFunc
	debug    colorFunc
	injected colorFunc // magenta, for injected certificate annotations
	source   colorFunc // blue, for source identifiers in batch headers
	dim      colorFunc // faint, for ghosted certificate lines

	// Diff colors: green for additions, red for removals, bold for headers.
	// Emph variants use high-intensity + bold for intra-line changed segments.
	diffHeader  colorFunc // bold, for --- / +++ headers
	diffAdd     colorFunc // green for added lines
	diffRemove  colorFunc // red for removed lines
	diffEmphAdd colorFunc // hi-green + bold for intra-line additions
	diffEmphDel colorFunc // hi-red + bold for intra-line removals
}

// identityColorFunc returns text unchanged, used when color is disabled.
func identityColorFunc(a ...any) string {
	if len(a) == 1 {
		if s, ok := a[0].(string); ok {
			return s
		}
	}
	return fmt.Sprint(a...)
}

// defaultColors is the no-op color function set used by all themes when color is disabled.
var defaultColors = colorFuncs{
	valid:       identityColorFunc,
	warning:     identityColorFunc,
	err:         identityColorFunc,
	info:        identityColorFunc,
	debug:       identityColorFunc,
	injected:    identityColorFunc,
	source:      identityColorFunc,
	dim:         identityColorFunc,
	diffHeader:  identityColorFunc,
	diffAdd:     identityColorFunc,
	diffRemove:  identityColorFunc,
	diffEmphAdd: identityColorFunc,
	diffEmphDel: identityColorFunc,
}

// WithColor returns a new renderTheme with ANSI color functions and pre-colorized icons.
// The original theme is not modified. Color functions use github.com/fatih/color
// which respects NO_COLOR and TTY detection.
func (t renderTheme) WithColor() renderTheme {
	t.colors = colorFuncs{
		valid:       color.New(color.FgGreen).SprintFunc(),
		warning:     color.New(color.FgYellow).SprintFunc(),
		err:         color.New(color.FgRed).SprintFunc(),
		info:        color.New(color.FgBlue).SprintFunc(),
		debug:       color.New(color.FgMagenta).SprintFunc(),
		injected:    color.New(color.FgMagenta).SprintFunc(),
		source:      color.New(color.FgBlue).SprintFunc(),
		dim:         color.New(color.Faint).SprintFunc(),
		diffHeader:  color.New(color.Bold).SprintFunc(),
		diffAdd:     color.New(color.FgGreen).SprintFunc(),
		diffRemove:  color.New(color.FgRed).SprintFunc(),
		diffEmphAdd: color.New(color.FgHiGreen, color.Bold).SprintFunc(),
		diffEmphDel: color.New(color.FgHiRed, color.Bold).SprintFunc(),
	}
	t.statusIcons = statusIcons{
		valid:        colorizeIcon(t.statusIcons.valid, t.colors.valid),
		warning:      colorizeIcon(t.statusIcons.warning, t.colors.warning),
		err:          colorizeIcon(t.statusIcons.err, t.colors.err),
		info:         colorizeIcon(t.statusIcons.info, t.colors.info),
		debug:        colorizeIcon(t.statusIcons.debug, t.colors.debug),
		continuation: colorizeIcon(t.statusIcons.continuation, t.colors.debug),
	}
	return t
}

// DefaultThemeName is the name of the default built-in theme.
const DefaultThemeName = "classic"

// classicTheme is the standard theme with full tree characters and bracketed status icons.
var classicTheme = renderTheme{
	name: "classic",
	treeChars: treeCharacters{
		branch:        "+- ",
		lastChild:     "`- ",
		vertical:      "|  ",
		blank:         "   ",
		sectionIndent: "  ",
		labelSep:      "  ",
	},
	statusIcons: statusIcons{
		valid:        "[+ ]",
		warning:      "[! ]",
		err:          "[x ]",
		info:         "[i ]",
		debug:        "[. ]",
		continuation: "[. ]",
	},
	spinnerFrames: []string{"[- ]", "[\\ ]", "[| ]", "[/ ]"},
	colors:        defaultColors,
}

// terseTheme is a space-efficient theme with shorter tree characters and terse icons.
var terseTheme = renderTheme{
	name: "terse",
	treeChars: treeCharacters{
		branch:        "+-",
		lastChild:     "`-",
		vertical:      "| ",
		blank:         "  ",
		sectionIndent: " ",
		labelSep:      " ",
	},
	statusIcons: statusIcons{
		valid:        "[+]",
		warning:      "[!]",
		err:          "[x]",
		info:         "[i]",
		debug:        "[.]",
		continuation: "[.]",
	},
	spinnerFrames: []string{"[-]", "[\\]", "[|]", "[/]"},
	colors:        defaultColors,
}

// minimalTheme is a minimal theme with no tree decorations and single-character icons.
var minimalTheme = renderTheme{
	name: "minimal",
	treeChars: treeCharacters{
		branch:        "",
		lastChild:     "",
		vertical:      "  ",
		blank:         "  ",
		sectionIndent: " ",
		labelSep:      " ",
	},
	statusIcons: statusIcons{
		valid:        "+",
		warning:      "!",
		err:          "x",
		info:         "i",
		debug:        ".",
		continuation: ".",
	},
	spinnerFrames: []string{".", " "},
	colors:        defaultColors,
}

// builtinThemes maps theme names to their definitions.
var builtinThemes = map[string]renderTheme{
	"classic": classicTheme,
	"terse":   terseTheme,
	"minimal": minimalTheme,
}

// lookupTheme returns a built-in theme by name, or an error listing available themes.
func lookupTheme(name string) (renderTheme, error) {
	if theme, ok := builtinThemes[name]; ok {
		return theme, nil
	}

	available := slices.Sorted(maps.Keys(builtinThemes))

	return renderTheme{}, fmt.Errorf("unknown theme %q: available themes are %s", name, strings.Join(available, ", "))
}

// ThemeNames returns the sorted list of built-in theme names.
func ThemeNames() []string {
	return slices.Sorted(maps.Keys(builtinThemes))
}

// themeOrClassic returns the named theme, falling back to classicTheme for empty or unknown names.
func themeOrClassic(name string) renderTheme {
	if name == "" {
		return classicTheme
	}
	theme, err := lookupTheme(name)
	if err != nil {
		return classicTheme
	}
	return theme
}

// LogIcons contains pre-formatted icon strings for each log level,
// ready for use as log message prefixes. Icons are pre-colorized when
// color is enabled.
type LogIcons struct {
	Debug        string
	Info         string
	Warning      string
	Error        string
	Continuation string
}

// LookupLogIcons returns log-level icons for the named theme. If the
// theme name is empty or unknown, the classic theme icons are returned.
// When useColor is true, the icons are pre-colorized using the theme's
// color scheme.
func LookupLogIcons(themeName string, useColor bool) LogIcons {
	theme := themeOrClassic(themeName)
	if useColor {
		theme = theme.WithColor()
	}
	return LogIcons{
		Debug:        theme.statusIcons.debug,
		Info:         theme.statusIcons.info,
		Warning:      theme.statusIcons.warning,
		Error:        theme.statusIcons.err,
		Continuation: theme.statusIcons.continuation,
	}
}

// SectionIndent returns the section content indentation string for the named theme.
// If the theme name is empty or unknown, the classic theme indent is returned.
func SectionIndent(themeName string) string {
	return themeOrClassic(themeName).treeChars.sectionIndent
}

// LabelSep returns the label separator string for the named theme.
// If the theme name is empty or unknown, the classic theme separator is returned.
func LabelSep(themeName string) string {
	return themeOrClassic(themeName).treeChars.labelSep
}

// SpinnerFrames returns the spinner animation frames for the named theme.
// If the theme name is empty or unknown, the classic theme frames are returned.
// When useColor is true, the icon content inside brackets is colorized using
// the info (blue) color, matching the colorization style of status icons.
func SpinnerFrames(themeName string, useColor bool) []string {
	theme := themeOrClassic(themeName)
	frames := slices.Clone(theme.spinnerFrames)
	if useColor {
		infoColor := color.New(color.FgBlue).SprintFunc()
		for i, f := range frames {
			frames[i] = colorizeIcon(f, infoColor)
		}
	}
	return frames
}

// colorizeIcon applies a color function to a status icon, coloring only the inner content for bracketed icons.
func colorizeIcon(icon string, colorFn colorFunc) string {
	if strings.HasPrefix(icon, "[") && strings.HasSuffix(icon, "]") {
		content := icon[1 : len(icon)-1]
		return "[" + colorFn(content) + "]"
	}
	return colorFn(icon)
}

package render

import (
	"strings"
	"sync"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noColorMu serializes access to the fatih/color global NoColor flag across
// concurrent parent tests. Subtests that mutate NoColor must hold this lock
// for the duration of the mutation and its cleanup, because parallel parent
// tests run concurrently and their non-parallel subtests can overlap.
var noColorMu sync.Mutex

func TestTheme_IdentityColorFunc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []any
		want string
	}{
		{
			name: "empty string",
			args: []any{""},
			want: "",
		},
		{
			name: "simple string",
			args: []any{"hello"},
			want: "hello",
		},
		{
			name: "string with special characters",
			args: []any{"[+ ] cert (expired)"},
			want: "[+ ] cert (expired)",
		},
		{
			name: "multiple arguments",
			args: []any{"hello", " ", "world"},
			want: "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := identityColorFunc(tt.args...)
			if got != tt.want {
				t.Errorf("identityColorFunc(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestWithColor_ClassicTheme(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	theme := classicTheme.WithColor()

	tests := []struct {
		name      string
		icon      string
		ansiCode  string
		colorName string
	}{
		{
			name:      "valid icon is green",
			icon:      theme.statusIcons.valid,
			ansiCode:  "\x1b[32m",
			colorName: "green",
		},
		{
			name:      "error icon is red",
			icon:      theme.statusIcons.err,
			ansiCode:  "\x1b[31m",
			colorName: "red",
		},
		{
			name:      "warning icon is yellow",
			icon:      theme.statusIcons.warning,
			ansiCode:  "\x1b[33m",
			colorName: "yellow",
		},
		{
			name:      "info icon is blue",
			icon:      theme.statusIcons.info,
			ansiCode:  "\x1b[34m",
			colorName: "blue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Must contain the expected ANSI color code.
			if !strings.Contains(tt.icon, tt.ansiCode) {
				t.Errorf("ColoredIcons should contain %s ANSI code %q, got %q",
					tt.colorName, tt.ansiCode, tt.icon)
			}

			// Stripping ANSI should yield the plain icon.
			stripped := stripANSICodes(tt.icon)
			var plainIcon string
			switch tt.colorName {
			case "green":
				plainIcon = classicTheme.statusIcons.valid
			case "red":
				plainIcon = classicTheme.statusIcons.err
			case "yellow":
				plainIcon = classicTheme.statusIcons.warning
			case "blue":
				plainIcon = classicTheme.statusIcons.info
			}
			if stripped != plainIcon {
				t.Errorf("stripANSICodes(%q) = %q, want %q", tt.icon, stripped, plainIcon)
			}
		})
	}
}

func TestWithColor_MinimalTheme(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	theme := minimalTheme.WithColor()

	tests := []struct {
		name      string
		icon      string
		plainIcon string
	}{
		{"valid icon", theme.statusIcons.valid, minimalTheme.statusIcons.valid},
		{"warning icon", theme.statusIcons.warning, minimalTheme.statusIcons.warning},
		{"error icon", theme.statusIcons.err, minimalTheme.statusIcons.err},
		{"info icon", theme.statusIcons.info, minimalTheme.statusIcons.info},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Non-bracketed icons should start with ANSI escape.
			if !strings.HasPrefix(tt.icon, "\x1b[") {
				t.Errorf("minimalTheme colored icon %q should start with ANSI escape", tt.icon)
			}

			// Stripping ANSI should yield the plain icon.
			stripped := stripANSICodes(tt.icon)
			if stripped != tt.plainIcon {
				t.Errorf("stripANSICodes(%q) = %q, want %q", tt.icon, stripped, tt.plainIcon)
			}
		})
	}
}

func TestWithColor_DoesNotModifyOriginal(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	// Capture original values before calling WithColor.
	origValidIcon := classicTheme.statusIcons.valid
	origErrorIcon := classicTheme.statusIcons.err

	_ = classicTheme.WithColor()

	// Original theme's ColoredIcons should still be plain (no ANSI).
	if classicTheme.statusIcons.valid != origValidIcon {
		t.Errorf("WithColor modified original Valid icon: got %q, want %q",
			classicTheme.statusIcons.valid, origValidIcon)
	}
	if classicTheme.statusIcons.err != origErrorIcon {
		t.Errorf("WithColor modified original Error icon: got %q, want %q",
			classicTheme.statusIcons.err, origErrorIcon)
	}

	// Original theme's Colors should still be identity functions.
	testStr := "test-string"
	if classicTheme.colors.valid(testStr) != testStr {
		t.Errorf("WithColor modified original Valid color func: got %q, want %q",
			classicTheme.colors.valid(testStr), testStr)
	}
	if classicTheme.colors.err(testStr) != testStr {
		t.Errorf("WithColor modified original Error color func: got %q, want %q",
			classicTheme.colors.err(testStr), testStr)
	}
}

func TestColorizeIcon_Bracketed(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	green := color.New(color.FgGreen).SprintFunc()

	tests := []struct {
		name string
		icon string
		want string
	}{
		{
			name: "OK icon",
			icon: "[+ ]",
			want: "[" + green("+ ") + "]",
		},
		{
			name: "error icon",
			icon: "[x ]",
			want: "[" + green("x ") + "]",
		},
		{
			name: "warning icon",
			icon: "[! ]",
			want: "[" + green("! ") + "]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := colorizeIcon(tt.icon, green)
			if got != tt.want {
				t.Errorf("colorizeIcon(%q, green) = %q, want %q", tt.icon, got, tt.want)
			}
			// Verify bracket structure: starts with "[", ends with "]".
			if !strings.HasPrefix(got, "[") {
				t.Errorf("colorizeIcon(%q) should start with '[', got %q", tt.icon, got)
			}
			if !strings.HasSuffix(got, "]") {
				t.Errorf("colorizeIcon(%q) should end with ']', got %q", tt.icon, got)
			}
		})
	}
}

func TestColorizeIcon_NonBracketed(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	green := color.New(color.FgGreen).SprintFunc()

	tests := []struct {
		name string
		icon string
		want string
	}{
		{
			name: "plus icon",
			icon: "+",
			want: green("+"),
		},
		{
			name: "x icon",
			icon: "x",
			want: green("x"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := colorizeIcon(tt.icon, green)
			if got != tt.want {
				t.Errorf("colorizeIcon(%q, green) = %q, want %q", tt.icon, got, tt.want)
			}
			// Non-bracketed icons should start with ANSI escape.
			if !strings.HasPrefix(got, "\x1b[") {
				t.Errorf("colorizeIcon(%q) should start with ANSI escape, got %q", tt.icon, got)
			}
		})
	}
}

func TestTheme_Lookup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "classic theme", input: "classic"},
		{name: "terse theme", input: "terse"},
		{name: "minimal theme", input: "minimal"},
		{name: "default is unknown", input: "default", wantErr: true},
		{name: "unknown theme", input: "nonexistent", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			theme, err := lookupTheme(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "classic")
				assert.Contains(t, err.Error(), "terse")
				assert.Contains(t, err.Error(), "minimal")
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, theme.name, "theme Name should not be empty")
			assert.NotEmpty(t, theme.statusIcons.valid, "theme statusIcons.valid should not be empty")
		})
	}
}

func TestLookupLogIcons(t *testing.T) {
	t.Parallel()

	t.Run("valid and fallback themes return correct icons", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name  string
			theme renderTheme
		}{
			{"", classicTheme},
			{"classic", classicTheme},
			{"terse", terseTheme},
			{"minimal", minimalTheme},
			{"nonexistent-theme", classicTheme},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				icons := LookupLogIcons(tt.name, false)
				assert.Equal(t, tt.theme.statusIcons.debug, icons.Debug)
				assert.Equal(t, tt.theme.statusIcons.info, icons.Info)
				assert.Equal(t, tt.theme.statusIcons.warning, icons.Warning)
				assert.Equal(t, tt.theme.statusIcons.err, icons.Error)
				assert.Equal(t, tt.theme.statusIcons.continuation, icons.Continuation)
			})
		}
	})

	t.Run("without color returns plain icons", func(t *testing.T) {
		t.Parallel()
		icons := LookupLogIcons("classic", false)
		// Plain icons should not contain ANSI escape sequences.
		assert.False(t, strings.Contains(icons.Debug, "\x1b["), "debug icon should not contain ANSI codes")
		assert.False(t, strings.Contains(icons.Info, "\x1b["), "info icon should not contain ANSI codes")
		assert.False(t, strings.Contains(icons.Warning, "\x1b["), "warning icon should not contain ANSI codes")
		assert.False(t, strings.Contains(icons.Error, "\x1b["), "error icon should not contain ANSI codes")
		assert.False(t, strings.Contains(icons.Continuation, "\x1b["), "continuation icon should not contain ANSI codes")
	})

	t.Run("with color returns colorized icons", func(t *testing.T) {
		// Not parallel: mutates global color.NoColor. Hold noColorMu for the
		// entire subtest so concurrent parent tests cannot race on this global.
		noColorMu.Lock()
		origNoColor := color.NoColor
		color.NoColor = false
		t.Cleanup(func() {
			color.NoColor = origNoColor
			noColorMu.Unlock()
		})

		icons := LookupLogIcons("classic", true)
		// Colorized icons should contain ANSI escape sequences.
		assert.True(t, strings.Contains(icons.Debug, "\x1b["), "debug icon should contain ANSI codes")
		assert.True(t, strings.Contains(icons.Info, "\x1b["), "info icon should contain ANSI codes")
		assert.True(t, strings.Contains(icons.Warning, "\x1b["), "warning icon should contain ANSI codes")
		assert.True(t, strings.Contains(icons.Error, "\x1b["), "error icon should contain ANSI codes")
		assert.True(t, strings.Contains(icons.Continuation, "\x1b["), "continuation icon should contain ANSI codes")

		// Stripping ANSI should yield the plain classic icons.
		assert.Equal(t, classicTheme.statusIcons.debug, stripANSICodes(icons.Debug))
		assert.Equal(t, classicTheme.statusIcons.info, stripANSICodes(icons.Info))
		assert.Equal(t, classicTheme.statusIcons.warning, stripANSICodes(icons.Warning))
		assert.Equal(t, classicTheme.statusIcons.err, stripANSICodes(icons.Error))
		assert.Equal(t, classicTheme.statusIcons.continuation, stripANSICodes(icons.Continuation))
	})
}

func TestSpinnerFrames(t *testing.T) {
	t.Parallel()

	t.Run("known themes have frames", func(t *testing.T) {
		t.Parallel()
		for _, name := range ThemeNames() {
			frames := SpinnerFrames(name, false)
			assert.NotEmpty(t, frames, "theme %q should have spinner frames", name)
			for i, f := range frames {
				assert.NotEmpty(t, f, "theme %q frame[%d] should not be empty", name, i)
			}
		}
	})

	t.Run("empty name returns classic frames", func(t *testing.T) {
		t.Parallel()
		frames := SpinnerFrames("", false)
		assert.Equal(t, classicTheme.spinnerFrames, frames)
	})

	t.Run("unknown name returns classic frames", func(t *testing.T) {
		t.Parallel()
		frames := SpinnerFrames("nonexistent", false)
		assert.Equal(t, classicTheme.spinnerFrames, frames)
	})

	t.Run("returns a copy not a reference", func(t *testing.T) {
		t.Parallel()
		frames := SpinnerFrames("classic", false)
		original := make([]string, len(frames))
		copy(original, frames)
		frames[0] = "MUTATED"
		assert.Equal(t, original, SpinnerFrames("classic", false),
			"mutating returned slice should not affect theme")
	})

	t.Run("colorized frames differ from plain", func(t *testing.T) {
		// Not parallel: mutates global color.NoColor. Hold noColorMu for the
		// entire subtest so concurrent parent tests cannot race on this global.
		noColorMu.Lock()
		origNoColor := color.NoColor
		color.NoColor = false
		t.Cleanup(func() {
			color.NoColor = origNoColor
			noColorMu.Unlock()
		})

		plain := SpinnerFrames("classic", false)
		colored := SpinnerFrames("classic", true)
		assert.Equal(t, len(plain), len(colored),
			"colorized and plain should have same number of frames")
		for i := range plain {
			assert.NotEqual(t, plain[i], colored[i],
				"colorized frame[%d] should differ from plain", i)
			assert.Contains(t, colored[i], "[",
				"colorized frame[%d] should still have bracket", i)
		}
	})
}

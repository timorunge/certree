package render

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminal_Detect(t *testing.T) {
	t.Parallel()

	term := detectTerminal()

	require.NotNil(t, term, "detectTerminal should return non-nil terminal")
	assert.GreaterOrEqual(t, term.width, minTerminalWidth, "width should be >= minimum")
	assert.LessOrEqual(t, term.width, maxTerminalWidth, "width should be <= maximum")
}

func TestTerminal_ColorSupport(t *testing.T) {
	tests := []struct {
		name    string
		noColor string // empty string means unset.
		term    string
		isTTY   bool
		want    bool
	}{
		{
			name:    "NO_COLOR set disables color",
			noColor: "1",
			term:    "xterm-256color",
			isTTY:   true,
			want:    false,
		},
		{
			name:    "TERM=dumb disables color",
			noColor: "",
			term:    "dumb",
			isTTY:   true,
			want:    false,
		},
		{
			name:    "empty TERM disables color",
			noColor: "",
			term:    "",
			isTTY:   true,
			want:    false,
		},
		{
			name:    "non-TTY disables color",
			noColor: "",
			term:    "xterm-256color",
			isTTY:   false,
			want:    false,
		},
		{
			name:    "TTY with valid TERM enables color",
			noColor: "",
			term:    "xterm-256color",
			isTTY:   true,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origNoColor, noColorSet := os.LookupEnv("NO_COLOR")
			origTerm, termSet := os.LookupEnv("TERM")
			t.Cleanup(func() {
				if noColorSet {
					_ = os.Setenv("NO_COLOR", origNoColor)
				} else {
					_ = os.Unsetenv("NO_COLOR")
				}
				if termSet {
					_ = os.Setenv("TERM", origTerm)
				} else {
					_ = os.Unsetenv("TERM")
				}
			})

			if tt.noColor != "" {
				_ = os.Setenv("NO_COLOR", tt.noColor)
			} else {
				_ = os.Unsetenv("NO_COLOR")
			}
			_ = os.Setenv("TERM", tt.term)

			got := detectColorSupport(tt.isTTY)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWidthFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string // empty means unset
		want int
	}{
		{"unset returns default", "", defaultTerminalWidth},
		{"valid value", "120", 120},
		{"negative value returns default", "-1", defaultTerminalWidth},
		{"zero returns default", "0", defaultTerminalWidth},
		{"non-numeric returns default", "abc", defaultTerminalWidth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig, set := os.LookupEnv("COLUMNS")
			t.Cleanup(func() {
				if set {
					_ = os.Setenv("COLUMNS", orig)
				} else {
					_ = os.Unsetenv("COLUMNS")
				}
			})

			if tt.env != "" {
				_ = os.Setenv("COLUMNS", tt.env)
			} else {
				_ = os.Unsetenv("COLUMNS")
			}

			assert.Equal(t, tt.want, widthFromEnv())
		})
	}
}

func TestTerminal_RegularFileIsNotTTY(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "regular"))
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	assert.False(t, isTerminal(f), "regular file should not be a terminal")
}

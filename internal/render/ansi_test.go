package render

import (
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestPadRight(t *testing.T) {
	// Force color output so fatih/color emits ANSI codes regardless of TTY.
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	greenFn := color.New(color.FgGreen).SprintFunc()

	tests := []struct {
		name      string
		input     string
		width     int
		wantLen   int // expected visible length after padding
		wantExact string
	}{
		{
			name:      "plain string shorter than width gets padded",
			input:     "hello",
			width:     10,
			wantLen:   10,
			wantExact: "hello     ",
		},
		{
			name:      "plain string equal to width stays unchanged",
			input:     "hello",
			width:     5,
			wantLen:   5,
			wantExact: "hello",
		},
		{
			name:      "plain string longer than width stays unchanged",
			input:     "hello world",
			width:     5,
			wantLen:   11,
			wantExact: "hello world",
		},
		{
			name:    "empty string gets padded to width",
			input:   "",
			width:   5,
			wantLen: 5,
		},
		{
			name:  "zero width returns input unchanged",
			input: "hello",
			width: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := padRight(tt.input, tt.width)

			if tt.wantExact != "" && got != tt.wantExact {
				t.Errorf("padRight(%q, %d) = %q, want %q", tt.input, tt.width, got, tt.wantExact)
			}

			if tt.wantLen > 0 {
				visibleLen := len(stripANSICodes(got))
				if visibleLen != tt.wantLen {
					t.Errorf("padRight(%q, %d) visible length = %d, want %d", tt.input, tt.width, visibleLen, tt.wantLen)
				}
			}
		})
	}

	// ANSI-aware test: padding based on visible length, not raw length.
	t.Run("string with ANSI codes pads based on visible length", func(t *testing.T) {
		t.Parallel()

		colored := greenFn("OK")
		input := "[" + colored + "]"
		width := 10

		got := padRight(input, width)
		visibleLen := len(stripANSICodes(got))

		if visibleLen != width {
			t.Errorf("padRight(colored, %d) visible length = %d, want %d", width, visibleLen, width)
		}

		// The original colored content must be preserved.
		if !strings.Contains(got, colored) {
			t.Errorf("padRight should preserve ANSI codes in original string")
		}
	})
}

func TestTruncate(t *testing.T) {
	// Force color output so fatih/color emits ANSI codes regardless of TTY.
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	greenFn := color.New(color.FgGreen).SprintFunc()

	tests := []struct {
		name      string
		input     string
		maxLen    int
		wantExact string
	}{
		{
			name:      "plain string shorter than maxLen stays unchanged",
			input:     "hello",
			maxLen:    10,
			wantExact: "hello",
		},
		{
			name:      "plain string equal to maxLen stays unchanged",
			input:     "hello",
			maxLen:    5,
			wantExact: "hello",
		},
		{
			name:      "plain string longer than maxLen gets truncated with ellipsis",
			input:     "hello world",
			maxLen:    8,
			wantExact: "hello...",
		},
		{
			name:      "very short maxLen truncates without ellipsis",
			input:     "hello",
			maxLen:    2,
			wantExact: "he",
		},
		{
			name:      "maxLen of 1 truncates to single char",
			input:     "hello",
			maxLen:    1,
			wantExact: "h",
		},
		{
			name:      "maxLen of 0 returns empty",
			input:     "hello",
			maxLen:    0,
			wantExact: "",
		},
		{
			name:      "maxLen of 3 truncates with ellipsis",
			input:     "hello",
			maxLen:    3,
			wantExact: "...",
		},
		{
			name:      "empty string stays unchanged",
			input:     "",
			maxLen:    5,
			wantExact: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := truncate(tt.input, tt.maxLen)
			if got != tt.wantExact {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.wantExact)
			}
		})
	}

	// ANSI-aware test: truncation based on visible length.
	t.Run("string with ANSI codes truncates based on visible length", func(t *testing.T) {
		t.Parallel()

		// Build a string with ANSI codes whose visible text is "OK cert-name here".
		colored := greenFn("OK") + " cert-name here"
		maxLen := 10

		got := truncate(colored, maxLen)
		visibleLen := len(stripANSICodes(got))

		if visibleLen > maxLen {
			t.Errorf("truncate(colored, %d) visible length = %d, want <= %d", maxLen, visibleLen, maxLen)
		}

		stripped := stripANSICodes(got)
		if !strings.HasSuffix(stripped, "...") {
			t.Errorf("truncate(colored, %d) visible = %q, want suffix '...'", maxLen, stripped)
		}
	})

	// Verify that truncating a colored string appends a color reset to prevent bleeding.
	t.Run("truncated colored string ends with color reset", func(t *testing.T) {
		t.Parallel()

		colored := greenFn("hello world long text")
		got := truncate(colored, 8)

		// The ANSI reset sequence \x1b[0m must be appended after the ellipsis.
		if !strings.HasSuffix(got, "\x1b[0m") {
			t.Errorf("truncate of colored string should end with color reset, got %q", got)
		}
	})

	// Verify that truncating a plain string does NOT append a color reset.
	t.Run("truncated plain string has no color reset", func(t *testing.T) {
		t.Parallel()

		got := truncate("hello world", 8)

		if strings.Contains(got, "\x1b[") {
			t.Errorf("truncate of plain string should not contain ANSI codes, got %q", got)
		}
		if got != "hello..." {
			t.Errorf("truncate(\"hello world\", 8) = %q, want %q", got, "hello...")
		}
	})
}

func TestWrapValue(t *testing.T) {
	t.Parallel()

	// Real SHA-256 fingerprint in colon-hex (95 visible chars).
	fingerprint := "7A:70:78:8F:E1:F5:A9:0E:81:F7:AC:BD:C1:64:22:CB:6E:5D:76:4B:E8:D0:F4:DA:97:21:BA:96:74:AA:8B:A9"

	tests := []struct {
		name       string
		value      string
		availWidth int
		wantCount  int // expected number of segments
	}{
		{"no wrap when fits", "short value", 40, 1},
		{"no wrap when zero width", fingerprint, 0, 1},
		{"no wrap when negative width", fingerprint, -1, 1},
		{"fingerprint wraps at colon boundary", fingerprint, 30, 4},
		{"fingerprint wraps at wider boundary", fingerprint, 60, 2},
		{"space-delimited wraps at space", "Digital Signature, Key Encipherment, Server Authentication", 30, 3},
		{"empty string returns single segment", "", 30, 1},
		{"very narrow width still progresses", fingerprint, 5, -1}, // -1 = just check it doesn't hang
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			segments := wrapValue(tt.value, tt.availWidth)

			if tt.wantCount == -1 {
				if len(segments) == 0 {
					t.Fatal("wrapValue returned empty slice")
				}
				return
			}

			if len(segments) != tt.wantCount {
				t.Errorf("wrapValue(%q, %d) returned %d segments, want %d", tt.value, tt.availWidth, len(segments), tt.wantCount)
			}

			if tt.availWidth > 0 {
				for i, seg := range segments {
					vl := visibleLen(seg)
					if vl > tt.availWidth {
						t.Errorf("segment %d visible length %d > availWidth %d: %q", i, vl, tt.availWidth, seg)
					}
				}
			}

			joined := strings.Join(segments, "")
			if joined != tt.value {
				t.Errorf("segments do not reconstruct original value:\n  got:  %q\n  want: %q", joined, tt.value)
			}
		})
	}
}

func TestStripANSICodes(t *testing.T) {
	// Force color output so fatih/color emits ANSI codes regardless of TTY.
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	greenFn := color.New(color.FgGreen).SprintFunc()
	redFn := color.New(color.FgRed).SprintFunc()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "string with no ANSI codes returns unchanged",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "string with single ANSI code has it removed",
			input: greenFn("OK"),
			want:  "OK",
		},
		{
			name:  "string with multiple ANSI codes has all removed",
			input: greenFn("OK") + " " + redFn("ERROR"),
			want:  "OK ERROR",
		},
		{
			name:  "empty string returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "string with only ANSI codes returns empty",
			input: "\x1b[32m\x1b[0m",
			want:  "",
		},
		{
			name:  "mixed content preserves non-ANSI text",
			input: "[" + greenFn("+ ") + "] cert-name (" + redFn("expired") + ")",
			want:  "[+ ] cert-name (expired)",
		},
		{
			name:  "OSC sequence stripped (BEL terminated)",
			input: "evil\x1b]0;pwned\x07cert",
			want:  "evilcert",
		},
		{
			name:  "OSC sequence stripped (ST terminated)",
			input: "evil\x1b]0;pwned\x1b\\cert",
			want:  "evilcert",
		},
		{
			name:  "DCS sequence stripped",
			input: "evil\x1bPpayload\x1b\\cert",
			want:  "evilcert",
		},
		{
			name:  "two-character escape stripped",
			input: "evil\x1bMcert",
			want:  "evilcert",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := stripANSICodes(tt.input)
			if got != tt.want {
				t.Errorf("stripANSICodes(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

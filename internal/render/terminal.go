// Terminal detection: width, color support, and TTY status.

package render

import (
	"os"
	"strconv"

	"golang.org/x/term"
)

const (
	minTerminalWidth     = 40
	maxTerminalWidth     = 500
	defaultTerminalWidth = 80
)

// terminal holds detected terminal capabilities.
type terminal struct {
	// Width is the terminal width in columns, clamped to [40, 500].
	width        int
	colorEnabled bool
}

// detectTerminal probes stdout for width and color support.
func detectTerminal() *terminal {
	return &terminal{
		colorEnabled: detectColorSupport(isTerminal(os.Stdout)),
		width:        detectTerminalWidth(),
	}
}

// detectTerminalWidth returns the detected stdout terminal width in columns,
// clamped to [40, 500]. An explicit COLUMNS environment variable takes
// precedence (standard Unix convention), then ioctl, then default 80.
func detectTerminalWidth() int {
	width := widthFromEnv()
	if width == defaultTerminalWidth && os.Getenv("COLUMNS") == "" {
		// COLUMNS not set explicitly -- try ioctl.
		// #nosec G115 -- File descriptor conversion is safe for terminal operations.
		if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			width = w
		}
	}

	if width < minTerminalWidth {
		return minTerminalWidth
	}
	if width > maxTerminalWidth {
		return maxTerminalWidth
	}
	return width
}

// widthFromEnv reads the COLUMNS environment variable, returning
// [defaultTerminalWidth] when unset or unparseable.
func widthFromEnv() int {
	s := os.Getenv("COLUMNS")
	if s == "" {
		return defaultTerminalWidth
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return defaultTerminalWidth
	}
	return n
}

// detectColorSupport checks whether the terminal supports ANSI color output.
// Note: returns false when TERM is empty (some CI/Docker environments). Use
// --color=always to override.
func detectColorSupport(isTTY bool) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	termEnv := os.Getenv("TERM")
	if termEnv == "dumb" || termEnv == "" {
		return false
	}

	return isTTY
}

// isTerminal checks whether the given file descriptor corresponds to a terminal.
func isTerminal(f *os.File) bool {
	// #nosec G115 -- File descriptor conversion is safe for terminal operations.
	return term.IsTerminal(int(f.Fd()))
}

// TerminalWidth returns the detected stdout terminal width in columns.
func TerminalWidth() int {
	return detectTerminalWidth()
}

// StderrColorEnabled reports whether stderr supports ANSI color output,
// using the same auto-detection logic as --color=auto (NO_COLOR, TERM,
// TTY check).
func StderrColorEnabled() bool {
	return detectColorSupport(isTerminal(os.Stderr))
}

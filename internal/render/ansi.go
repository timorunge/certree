// ANSI-aware string utilities for padding, truncation, and escape code handling.

package render

import (
	"strings"
	"unicode/utf8"
)

// padRight pads a string to the specified width with spaces, handling ANSI codes.
func padRight(s string, width int) string {
	vl := visibleLen(s)
	if vl >= width {
		return s
	}
	return s + strings.Repeat(" ", width-vl)
}

// truncate truncates a string to the specified maximum visible length,
// handling ANSI codes. When maxLen >= 3, an ellipsis ("...") is appended
// and any open ANSI color state is reset. When maxLen < 3, ANSI codes
// are stripped and the result is plain text with no ellipsis.
func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if visibleLen(s) <= maxLen {
		return s
	}

	if maxLen < 3 {
		runes := []rune(stripANSICodes(s))
		if len(runes) > maxLen {
			runes = runes[:maxLen]
		}
		return string(runes)
	}

	truncatePos, hasANSI := findTruncatePos(s, maxLen-3)
	truncated := s[:truncatePos] + "..."

	// Only append a color reset if the truncated portion contains ANSI codes
	// that may leave an open color state.
	if hasANSI {
		truncated += "\x1b[0m"
	}

	return truncated
}

// findTruncatePos finds the byte position in s corresponding to visChars
// visible characters, skipping all ANSI escape sequences (CSI, OSC, DCS, etc.)
// via [skipEscape]. Returns the byte offset and whether any ANSI codes were seen.
func findTruncatePos(s string, visChars int) (int, bool) {
	visibleCount := 0
	truncatePos := 0
	hasANSI := false

	for i := 0; i < len(s) && visibleCount < visChars; {
		if s[i] == '\x1b' {
			hasANSI = true
			i = skipEscape(s, i)
			continue
		}

		_, size := utf8.DecodeRuneInString(s[i:])
		visibleCount++
		i += size
		truncatePos = i
	}

	return truncatePos, hasANSI
}

// stripANSICodes removes ANSI escape sequences from a string, covering CSI
// (\x1b[...X), OSC (\x1b]...ST), DCS (\x1bP...ST), and bare \x1b.
// The String Terminator (ST) is \x1b\\ or \x07 (BEL).
// Returns s unchanged (no allocation) when no escape character is present.
func stripANSICodes(s string) string {
	if !strings.Contains(s, "\x1b") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\x1b' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			continue
		}
		switch s[i+1] {
		case '[':
			i += 2
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7E) {
				i++
			}
		case ']', 'P', 'X', '^', '_':
			i += 2
			for i < len(s) {
				if s[i] == '\x07' {
					break
				}
				if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\' {
					i++
					break
				}
				i++
			}
		default:
			i++
		}
	}
	return b.String()
}

// wrapValue splits value into segments each at most availWidth visible chars wide.
func wrapValue(value string, availWidth int) []string {
	if availWidth <= 0 || visibleLen(value) <= availWidth {
		return []string{value}
	}

	var segments []string
	remaining := value

	for visibleLen(remaining) > availWidth {
		cutPos, _ := findTruncatePos(remaining, availWidth)
		if cutPos == 0 {
			// Cannot advance (e.g., leading ANSI escape wider than
			// availWidth); emit remaining as-is to avoid infinite loop.
			break
		}

		bestBreak := -1
		for i := cutPos - 1; i >= 0; i-- {
			if remaining[i] == ':' {
				bestBreak = i + 1 // keep the colon on the current line
				break
			}
		}
		if bestBreak <= 0 {
			for i := cutPos - 1; i >= 0; i-- {
				if remaining[i] == ' ' {
					bestBreak = i + 1
					break
				}
			}
		}

		if bestBreak > 0 {
			cutPos = bestBreak
		}

		// Ensure the cut does not split an ANSI escape sequence. If cutPos
		// lands inside an ESC[...m sequence, back up to before the ESC byte.
		cutPos = adjustCutForANSI(remaining, cutPos)
		if cutPos == 0 {
			break
		}

		segments = append(segments, remaining[:cutPos])
		remaining = remaining[cutPos:]
	}

	if remaining != "" {
		segments = append(segments, remaining)
	}

	return segments
}

// adjustCutForANSI moves cutPos backward if it falls inside an ANSI CSI
// escape sequence (\x1b[...X), returning the position just before the ESC
// byte. The backward scan stops at ESC or newline boundaries.
func adjustCutForANSI(s string, cutPos int) int {
	// Scan backward from cutPos to find any unclosed ESC sequence.
	for i := cutPos - 1; i >= 0; i-- {
		if s[i] == '\x1b' {
			// Found an ESC. Check if the sequence extends past cutPos
			// (meaning cutPos is inside it).
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) && s[j] >= '0' && s[j] <= '?' {
					j++
				}
				if j < len(s) && s[j] >= '@' && s[j] <= '~' {
					j++ // past the final byte
				}
				if j > cutPos {
					return i // cut before the ESC
				}
			}
			break // ESC sequence ends before cutPos, no adjustment needed
		}
		if s[i] == '\n' {
			break // newline boundary, stop scanning
		}
	}
	return cutPos
}

// SanitizeCertString strips ANSI escape sequences and replaces control
// characters (newlines, tabs, carriage returns, null bytes, and other C0/C1
// controls) with a Unicode replacement character. This prevents malicious
// certificate fields from injecting fake output lines or terminal commands.
func SanitizeCertString(s string) string {
	s = stripANSICodes(s)
	hasControl := false
	for _, r := range s {
		if r < 0x20 || (r >= 0x7F && r <= 0x9F) {
			hasControl = true
			break
		}
	}
	if !hasControl {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || (r >= 0x7F && r <= 0x9F) {
			b.WriteRune('\uFFFD')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// splitLines splits a string into lines, trimming a trailing newline to avoid a spurious empty final element.
func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// dedup returns a new slice with duplicate strings removed, preserving order.
func dedup(ss []string) []string {
	if len(ss) <= 1 {
		return ss
	}
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// visibleLen returns the visible rune count in a string, ignoring ANSI escape
// sequences. Handles CSI (\x1b[...X), OSC (\x1b]...ST), DCS (\x1bP...ST),
// and bare \x1b, matching the coverage of [stripANSICodes].
func visibleLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == '\x1b' {
			i = skipEscape(s, i)
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		n++
		i += size
	}
	return n
}

// skipEscape advances past the ANSI escape sequence starting at s[i] (which
// must be \x1b). Returns the index of the first byte after the sequence.
// Handles CSI (\x1b[), OSC/DCS/SOS/PM/APC (\x1b] \x1bP \x1bX \x1b^ \x1b_)
// terminated by BEL or ST, and bare \x1b.
func skipEscape(s string, i int) int {
	if i+1 >= len(s) {
		return i + 1
	}
	switch s[i+1] {
	case '[': // CSI sequence: \x1b[ params final-byte
		i += 2
		for i < len(s) && (s[i] < 0x40 || s[i] > 0x7E) {
			i++
		}
		if i < len(s) {
			i++ // skip final byte
		}
		return i
	case ']', 'P', 'X', '^', '_': // OSC, DCS, SOS, PM, APC
		i += 2
		for i < len(s) {
			if s[i] == '\x07' {
				return i + 1
			}
			if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
			i++
		}
		return i
	default: // bare \x1b followed by unknown byte
		return i + 2
	}
}

// Progress indicator for batch analysis with spinner animation.

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"

	"github.com/timorunge/certree/pkg/certree"
)

// progressWriter renders a single-line progress indicator to stderr,
// overwriting in-place via carriage return. It is safe for concurrent use
// from multiple goroutines. When stderr is not a TTY, all operations are
// no-ops so that piped output remains clean.
type progressWriter struct {
	w      io.Writer
	frames []string
	active bool
	frame  int
	last   string
	mu     sync.Mutex
}

// newProgressWriter creates a progress writer that animates spinner frames
// on w. If w is not backed by a terminal file descriptor, the writer is
// inactive and all calls are no-ops.
func newProgressWriter(w io.Writer, frames []string) *progressWriter {
	active := false
	if f, ok := w.(*os.File); ok {
		// #nosec G115 -- File descriptor conversion is safe for terminal operations.
		active = term.IsTerminal(int(f.Fd()))
	}
	if len(frames) == 0 {
		active = false
	}
	return &progressWriter{
		w:      w,
		frames: frames,
		active: active,
	}
}

// Update writes a progress line showing the current spinner frame, counter,
// and source name. The line overwrites the previous output via \r.
func (pw *progressWriter) Update(completed, total int, source string) {
	if !pw.active {
		return
	}

	pw.mu.Lock()
	defer pw.mu.Unlock()

	icon := pw.frames[pw.frame%len(pw.frames)]
	pw.frame++

	line := fmt.Sprintf("\r%s Analyzing (%d/%d) %s", icon, completed, total, source)

	// Pad with spaces to overwrite any leftover characters from a longer
	// previous line, then return the cursor to the end of the new content.
	// Note: len() counts bytes, not visual width. ANSI sequences may cause
	// slightly off padding, but this is cosmetic and only affects the
	// transient progress line.
	if len(line) < len(pw.last) {
		line += strings.Repeat(" ", len(pw.last)-len(line))
	}
	pw.last = line

	_, _ = fmt.Fprint(pw.w, line)
}

// Done clears the progress line so subsequent output starts on a clean line.
func (pw *progressWriter) Done() {
	if !pw.active {
		return
	}

	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.last != "" {
		blank := "\r" + strings.Repeat(" ", len(pw.last)) + "\r"
		_, _ = fmt.Fprint(pw.w, blank)
		pw.last = ""
	}
}

// progressFunc returns a certree.ProgressFunc that delegates to the
// progressWriter. This bridges the pkg/certree callback to the CLI layer.
func (pw *progressWriter) progressFunc() certree.ProgressFunc {
	return pw.Update
}

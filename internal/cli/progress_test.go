package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProgressWriter_Update(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	pw := &progressWriter{
		w:      &buf,
		frames: []string{"[- ]", "[\\ ]", "[| ]", "[/ ]"},
		active: true,
	}

	pw.Update(1, 5, "example.com:443")
	output := buf.String()

	assert.True(t, strings.HasPrefix(output, "\r"), "output should start with \\r")
	assert.Contains(t, output, "Analyzing")
	assert.Contains(t, output, "(1/5)")
	assert.Contains(t, output, "example.com:443")
}

func TestProgressWriter_FrameCycling(t *testing.T) {
	t.Parallel()

	frames := []string{"A", "B", "C"}
	var buf bytes.Buffer
	pw := &progressWriter{
		w:      &buf,
		frames: frames,
		active: true,
	}

	for i, expected := range frames {
		buf.Reset()
		pw.Update(i+1, 3, "host")
		output := buf.String()
		assert.Contains(t, output, expected+" Analyzing",
			"frame %d should use %q", i, expected)
	}

	// Fourth call wraps to first frame.
	buf.Reset()
	pw.Update(1, 3, "host")
	assert.Contains(t, buf.String(), frames[0]+" Analyzing")
}

func TestProgressWriter_Done(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	pw := &progressWriter{
		w:      &buf,
		frames: []string{"-"},
		active: true,
	}

	pw.Update(1, 1, "host")
	buf.Reset()

	pw.Done()
	output := buf.String()

	assert.True(t, strings.HasPrefix(output, "\r"), "Done should start with \\r")
	assert.True(t, strings.HasSuffix(output, "\r"), "Done should end with \\r")
	// Between the two \r, there should be only spaces (clearing the line).
	trimmed := strings.TrimRight(strings.TrimLeft(output, "\r"), "\r")
	assert.True(t, strings.TrimSpace(trimmed) == "",
		"Done content should be only spaces, got %q", trimmed)
}

func TestProgressWriter_Inactive(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	pw := &progressWriter{
		w:      &buf,
		frames: []string{"-"},
		active: false,
	}

	pw.Update(1, 5, "host")
	assert.Empty(t, buf.String(), "inactive writer should not produce output")

	pw.Done()
	assert.Empty(t, buf.String(), "inactive Done should not produce output")
}

func TestProgressWriter_EmptyFrames(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	pw := newProgressWriter(&buf, nil)
	assert.False(t, pw.active, "nil frames should create inactive writer")

	pw = newProgressWriter(&buf, []string{})
	assert.False(t, pw.active, "empty frames should create inactive writer")
}

func TestProgressWriter_LongToShort(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	pw := &progressWriter{
		w:      &buf,
		frames: []string{"-"},
		active: true,
	}

	pw.Update(1, 2, "very-long-hostname.example.com:443")
	longLen := buf.Len()

	buf.Reset()
	pw.Update(2, 2, "a.io")
	shortOutput := buf.String()

	// The short output should be at least as long as the long output to
	// overwrite all leftover characters.
	assert.GreaterOrEqual(t, len(shortOutput), longLen,
		"short source line should be padded to overwrite long line")
}

func TestProgressWriter_ConcurrentSafety(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	pw := &progressWriter{
		w:      &buf,
		frames: []string{"[- ]", "[\\ ]", "[| ]", "[/ ]"},
		active: true,
	}

	done := make(chan struct{})
	for i := range 10 {
		go func(n int) {
			pw.Update(n+1, 10, "host")
			done <- struct{}{}
		}(i)
	}
	for range 10 {
		<-done
	}
	pw.Done()

	// No panic means success. The output may be interleaved but the mutex
	// prevents data races.
}

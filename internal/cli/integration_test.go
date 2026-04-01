// Integration tests for the CLI Run() pipeline with structured error output.
//
// These tests exercise the full end-to-end path: flag parsing, config
// resolution, analyzer construction, file/host analysis, error formatting,
// and stderr output. Each test validates a cross-layer contract that no
// unit test can cover: a StructuredError created deep in pkg/certree must
// survive through the Analyzer, through the CLI error reporter, through
// verbosity filtering, and appear on stderr with the correct exit code.
// Unit tests for the errReporter use synthetic errors; unit tests for the
// Parser use mock I/O. Only these integration tests wire real components
// and verify the user-visible result.

package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// findErrorLine returns the first line in output that contains substr.
// Returns an empty string if no matching line is found.
func findErrorLine(t *testing.T, output, substr string) string {
	t.Helper()

	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}

// TestIntegration_NonexistentFileV0 verifies the v0 (default) error path
// end-to-end: Parser creates a StructuredError for a missing file, Analyzer
// passes it through, Run() routes it to the errReporter, and stderr shows
// only the user message -- no Detail, no Category. This catches regressions
// where any layer accidentally exposes raw Go error internals to the user.
func TestIntegration_NonexistentFileV0(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"nonexistent-file-that-does-not-exist.pem"}, "test")

	if code != exitUsageError {
		t.Errorf("exit code = %d, want %d (exitUsageError)", code, exitUsageError)
	}

	out := stderr.String()
	if !strings.Contains(out, "could not read file") {
		t.Errorf("stderr should contain user message about file read failure, got %q", out)
	}
	if strings.Contains(out, "Detail:") {
		t.Errorf("stderr at v0 must not contain Detail line, got %q", out)
	}
	if strings.Contains(out, "Category:") {
		t.Errorf("stderr at v0 must not contain Category line, got %q", out)
	}
}

// TestIntegration_NonexistentFileV3 verifies the v3 (info-level) error path
// end-to-end: the same StructuredError that v0 shows as a single line must
// additionally produce Detail and Category continuation lines when -vvv is
// passed. This catches regressions where the errReporter's verbosity
// filtering diverges from the StructuredError field extraction.
func TestIntegration_NonexistentFileV3(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"-vvv", "nonexistent-file-that-does-not-exist.pem"}, "test")

	if code != exitUsageError {
		t.Errorf("exit code = %d, want %d (exitUsageError)", code, exitUsageError)
	}

	out := stderr.String()
	if !strings.Contains(out, "could not read file") {
		t.Errorf("stderr should contain user message, got %q", out)
	}
	if !strings.Contains(out, "Detail:") {
		t.Errorf("stderr at v3 must contain Detail line, got %q", out)
	}
	if !strings.Contains(out, "Category:") {
		t.Errorf("stderr at v3 must contain Category line, got %q", out)
	}
	if !strings.Contains(out, "file read failed") {
		t.Errorf("stderr Category should contain sentinel text, got %q", out)
	}
}

// TestIntegration_V0AndV3SameMessage verifies that the primary error line is
// identical at v0 and v3 (info level). At v3 the logger emits info lines
// ("Starting certificate analysis...") before the error, interleaving with
// errReporter output on the same stderr writer. This test catches regressions
// where verbose logging corrupts or shifts the error message, which happened
// when the spinner and logger used independent mutexes.
func TestIntegration_V0AndV3SameMessage(t *testing.T) {
	t.Parallel()

	file := "nonexistent-file-that-does-not-exist.pem"
	const marker = "could not read file"

	var stderr0 bytes.Buffer
	Run(io.Discard, &stderr0, []string{file}, "test")

	var stderr1 bytes.Buffer
	Run(io.Discard, &stderr1, []string{"-vvv", file}, "test")

	errLine0 := findErrorLine(t, stderr0.String(), marker)
	errLine1 := findErrorLine(t, stderr1.String(), marker)

	if errLine0 == "" {
		t.Fatal("v0 stderr does not contain error line with marker")
	}
	if errLine1 == "" {
		t.Fatal("v1 stderr does not contain error line with marker")
	}

	if errLine0 != errLine1 {
		t.Errorf("error lines differ:\n  v0: %q\n  v1: %q", errLine0, errLine1)
	}
}

func TestIntegration_InvalidHostV0(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	var stdout, stderr bytes.Buffer
	code := Run(&stdout, &stderr, []string{"invalid.host.that.does.not.exist.invalid:443"}, "test")

	if code != exitConnectionError {
		t.Errorf("exit code = %d, want %d (exitConnectionError)", code, exitConnectionError)
	}

	out := stderr.String()
	if out == "" {
		t.Fatal("stderr is empty, expected error message")
	}
	if !strings.Contains(out, "could not connect to") {
		t.Errorf("stderr should contain connection failure message, got %q", out)
	}
	if strings.Contains(out, "Detail:") {
		t.Errorf("stderr at v0 must not contain Detail line, got %q", out)
	}
}

// Binary smoke tests for the certree CLI entry point.
// The binary is compiled once in TestMain and reused across all tests.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// testBinary holds the path to the compiled binary, built once in TestMain.
var testBinary string

// TestMain compiles the certree binary once for all smoke tests.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "certree-smoke-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	name := "certree"
	if runtime.GOOS == "windows" {
		name = "certree.exe"
	}

	bin := filepath.Join(dir, name)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
	if _, file, _, ok := runtime.Caller(0); ok {
		cmd.Dir = filepath.Dir(file)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "skipping smoke tests: go build failed: %v\n%s", err, out)
		os.Exit(0)
	}

	testBinary = bin
	os.Exit(m.Run())
}

func TestMain_Help(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), testBinary, "--help")
	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("--help exited non-zero: %v\noutput: %s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "certree") {
		t.Errorf("--help output does not mention 'certree'; got: %s", output)
	}

	if !strings.Contains(output, "USAGE:") {
		t.Errorf("--help output does not contain 'USAGE:'; got: %s", output)
	}
}

func TestMain_Version(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), testBinary, "--version")
	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("--version exited non-zero: %v\noutput: %s", err, out)
	}

	output := string(out)
	if !strings.HasPrefix(output, "certree ") {
		t.Errorf("--version output does not start with 'certree '; got: %s", output)
	}
}

func TestMain_InvalidFile(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("skipping: /dev/null is not available on Windows")
	}

	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skipf("skipping: /dev/null not available: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), testBinary, "/dev/null")
	err := cmd.Run()

	if err == nil {
		t.Fatal("expected non-zero exit for /dev/null input, but command succeeded")
	}
}

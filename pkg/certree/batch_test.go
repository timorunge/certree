package certree

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// generateSelfSignedPEMs creates n temp PEM files with self-signed certs.
func generateSelfSignedPEMs(t *testing.T, n int) []string {
	t.Helper()

	dir := t.TempDir()
	paths := make([]string, n)
	for i := range n {
		cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{})
		if err != nil {
			t.Fatalf("generating cert: %v", err)
		}
		pemData := testutil.EncodePEM(cert)

		p := filepath.Join(dir, fmt.Sprintf("batch-%d.pem", i))
		if err := os.WriteFile(p, pemData, 0600); err != nil {
			t.Fatalf("writing temp file: %v", err)
		}
		paths[i] = p
	}
	return paths
}

func TestBatchAnalyzer_ProgressFunc(t *testing.T) {
	t.Parallel()

	certs := generateSelfSignedPEMs(t, 3)

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(WithAutoDetectFormat(true))),
	)
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}

	ba, err := NewBatchAnalyzer(analyzer, 2)
	if err != nil {
		t.Fatalf("NewBatchAnalyzer: %v", err)
	}

	var callCount atomic.Int64
	var maxCompleted atomic.Int64
	total := len(certs)

	ba.SetProgress(func(completed, tot int, source string) {
		callCount.Add(1)
		for {
			cur := maxCompleted.Load()
			if int64(completed) <= cur || maxCompleted.CompareAndSwap(cur, int64(completed)) {
				break
			}
		}
		if tot != total {
			t.Errorf("total = %d, want %d", tot, total)
		}
		if source == "" {
			t.Error("source should not be empty")
		}
	})

	analyses, err := ba.AnalyzeMultiple(t.Context(), certs)
	if err != nil {
		t.Fatalf("AnalyzeMultiple: %v", err)
	}

	if int(callCount.Load()) != total {
		t.Errorf("ProgressFunc called %d times, want %d", callCount.Load(), total)
	}
	if int(maxCompleted.Load()) != total {
		t.Errorf("max completed = %d, want %d", maxCompleted.Load(), total)
	}
	if len(analyses) != total {
		t.Errorf("got %d analyses, want %d", len(analyses), total)
	}
}

func TestBatchAnalyzer_NilProgress(t *testing.T) {
	t.Parallel()

	certs := generateSelfSignedPEMs(t, 2)

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(WithAutoDetectFormat(true))),
	)
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}

	ba, err := NewBatchAnalyzer(analyzer, 2)
	if err != nil {
		t.Fatalf("NewBatchAnalyzer: %v", err)
	}

	analyses, err := ba.AnalyzeMultiple(t.Context(), certs)
	if err != nil {
		t.Fatalf("AnalyzeMultiple: %v", err)
	}
	if len(analyses) != len(certs) {
		t.Errorf("got %d analyses, want %d", len(analyses), len(certs))
	}
}

func TestBatchAnalyzer_StructuredErrorsPreserved(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))),
	)
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}

	ba, err := NewBatchAnalyzer(analyzer, 2)
	if err != nil {
		t.Fatalf("NewBatchAnalyzer: %v", err)
	}

	// Get a port that is guaranteed to not be listening.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	// Use sources that will fail: nonexistent file and unreachable host.
	sources := []string{
		"/nonexistent/path/cert.pem",
		addr,
	}

	_, batchErr := ba.AnalyzeMultiple(t.Context(), sources)
	if batchErr == nil {
		t.Fatal("expected batch error, got nil")
	}

	// The batch error should implement Unwrap() []error (from errors.Join).
	type unwrapMulti interface{ Unwrap() []error }
	multi, ok := batchErr.(unwrapMulti)
	if !ok {
		t.Fatalf("batch error does not implement Unwrap() []error: %T", batchErr)
	}

	innerErrs := multi.Unwrap()
	if len(innerErrs) != 2 {
		t.Fatalf("expected 2 inner errors, got %d", len(innerErrs))
	}

	// Track which sentinels we find to verify both error types are present.
	foundFile := false
	foundConnection := false

	for _, inner := range innerErrs {
		// Each inner error is fmt.Errorf("%s: %w", source, analyzerErr) which
		// wraps the analyzer error (which itself wraps the StructuredError).
		var se *StructuredError
		if !errors.As(inner, &se) {
			t.Errorf("errors.As(inner, *StructuredError) = false; inner = %v", inner)
			continue
		}

		// Verify no Go internals in the user message.
		msg := se.UserMessage()
		for _, internal := range goErrorInternals {
			if strings.Contains(msg, internal) {
				t.Errorf("UserMessage() contains Go internal %q: %s", internal, msg)
			}
		}

		// Check sentinel categories.
		if errors.Is(inner, ErrFileReadFailed) {
			foundFile = true
			if se.Category() != ErrFileReadFailed {
				t.Errorf("file error Category() = %v, want ErrFileReadFailed", se.Category())
			}
		}
		if errors.Is(inner, ErrConnectionFailed) {
			foundConnection = true
			if se.Category() != ErrConnectionFailed {
				t.Errorf("connection error Category() = %v, want ErrConnectionFailed", se.Category())
			}
		}
	}

	if !foundFile {
		t.Error("expected ErrFileReadFailed sentinel in batch errors")
	}
	if !foundConnection {
		t.Error("expected ErrConnectionFailed sentinel in batch errors")
	}
}

func TestNewBatchAnalyzer_InvalidConcurrency(t *testing.T) {
	t.Parallel()

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(WithAutoDetectFormat(true))),
	)
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}

	// When maxWorkers <= 0, the constructor uses defaultBatchWorkers (4)
	// and clamps to [1, 8].
	ba, err := NewBatchAnalyzer(analyzer, 0)
	if err != nil {
		t.Fatalf("NewBatchAnalyzer() error = %v", err)
	}
	if ba.maxWorkers < 1 {
		t.Errorf("maxWorkers = %d, want >= 1", ba.maxWorkers)
	}
	if ba.maxWorkers > maxBatchWorkers {
		t.Errorf("maxWorkers = %d, want <= %d", ba.maxWorkers, maxBatchWorkers)
	}
}

func TestNewBatchAnalyzer_NilAnalyzer(t *testing.T) {
	t.Parallel()

	_, err := NewBatchAnalyzer(nil, 4)
	if err == nil {
		t.Fatal("NewBatchAnalyzer(nil, 4) expected error, got nil")
	}
	if !errors.Is(err, ErrNilArgument) {
		t.Errorf("errors.Is(err, ErrNilArgument) = false; err = %v", err)
	}
}

func TestBatchErrorAccumulation(t *testing.T) {
	t.Parallel()

	validPaths := generateSelfSignedPEMs(t, 2)
	invalidPaths := []string{
		"/nonexistent/path/a.pem",
		"/nonexistent/path/b.pem",
	}

	allPaths := make([]string, 0, len(validPaths)+len(invalidPaths))
	allPaths = append(allPaths, validPaths...)
	allPaths = append(allPaths, invalidPaths...)

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(WithAutoDetectFormat(true))),
	)
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}

	ba, err := NewBatchAnalyzer(analyzer, 2)
	if err != nil {
		t.Fatalf("NewBatchAnalyzer: %v", err)
	}

	_, err = ba.AnalyzeMultiple(t.Context(), allPaths)
	if err == nil {
		t.Fatal("expected error from AnalyzeMultiple with invalid paths")
	}

	errMsg := err.Error()
	mentionsInvalid := false
	for _, p := range invalidPaths {
		if strings.Contains(errMsg, p) {
			mentionsInvalid = true
			break
		}
	}
	if !mentionsInvalid {
		t.Errorf("error does not mention any invalid path: %s", errMsg)
	}
}

func TestSecurityBatchAnalyzerLimits(t *testing.T) {
	t.Parallel()

	newTestAnalyzer := func(t *testing.T) *Analyzer {
		t.Helper()
		a, err := NewAnalyzer(WithParser(NewParser()))
		require.NoError(t, err)
		return a
	}

	t.Run("maxWorkers 100 clamps to 8", func(t *testing.T) {
		t.Parallel()
		// Unbounded parallelism is gated at maxBatchWorkers (8) to protect
		// downstream servers from being overwhelmed by certree clients.
		ba, err := NewBatchAnalyzer(newTestAnalyzer(t), 100)
		require.NoError(t, err)
		assert.Equal(t, maxBatchWorkers, ba.maxWorkers,
			"maxWorkers 100 must clamp to maxBatchWorkers (%d)", maxBatchWorkers)
	})

	t.Run("AnalyzeMultiple with empty sources returns error", func(t *testing.T) {
		t.Parallel()
		ba, err := NewBatchAnalyzer(newTestAnalyzer(t), 2)
		require.NoError(t, err)
		_, analyzeErr := ba.AnalyzeMultiple(t.Context(), []string{})
		require.Error(t, analyzeErr)
		assert.True(t, errors.Is(analyzeErr, ErrEmptyInput),
			"empty sources must return ErrEmptyInput, got: %v", analyzeErr)
	})

	t.Run("AnalyzeMultiple with nil sources returns error", func(t *testing.T) {
		t.Parallel()
		ba, err := NewBatchAnalyzer(newTestAnalyzer(t), 2)
		require.NoError(t, err)
		_, analyzeErr := ba.AnalyzeMultiple(t.Context(), nil)
		require.Error(t, analyzeErr)
		assert.True(t, errors.Is(analyzeErr, ErrEmptyInput),
			"nil sources must return ErrEmptyInput, got: %v", analyzeErr)
	})

	t.Run("AnalyzeMultiple with already-canceled context returns error", func(t *testing.T) {
		t.Parallel()
		// A pre-canceled context exercises the ctx.Done() select path in the
		// batch worker pool without needing a nil context (which would panic).
		ba, err := NewBatchAnalyzer(newTestAnalyzer(t), 1)
		require.NoError(t, err)
		canceledCtx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err = ba.AnalyzeMultiple(canceledCtx, []string{"not-a-real-source.pem"})
		require.Error(t, err, "canceled context must yield an error from AnalyzeMultiple")
	})
}

func TestSecurityBatchAnalyzer_ConcurrentAnalyzeMultiple(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	const sourceCount = 8
	sources := make([]string, sourceCount)
	for i := range sourceCount {
		rawCert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{})
		require.NoError(t, err, "generating self-signed cert")
		p := filepath.Join(dir, fmt.Sprintf("cert-%d.pem", i))
		require.NoError(t, os.WriteFile(p, testutil.EncodePEM(rawCert), 0600))
		sources[i] = p
	}

	parser := NewParser(WithAutoDetectFormat(true))
	analyzer, err := NewAnalyzer(WithParser(parser))
	require.NoError(t, err, "NewAnalyzer")

	// Use maxBatchWorkers (8) so that all workers race against each other.
	ba, err := NewBatchAnalyzer(analyzer, maxBatchWorkers)
	require.NoError(t, err, "NewBatchAnalyzer")

	analyses, err := ba.AnalyzeMultiple(t.Context(), sources)
	require.NoError(t, err)
	assert.Len(t, analyses, sourceCount, "all sources should produce results")
}

func TestSecurityBatchAnalyzer_ConcurrentProgressCallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	const sourceCount = 6
	sources := make([]string, sourceCount)
	for i := range sourceCount {
		rawCert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{})
		require.NoError(t, err)
		p := filepath.Join(dir, fmt.Sprintf("cert-progress-%d.pem", i))
		require.NoError(t, os.WriteFile(p, testutil.EncodePEM(rawCert), 0600))
		sources[i] = p
	}

	parser := NewParser(WithAutoDetectFormat(true))
	analyzer, err := NewAnalyzer(WithParser(parser))
	require.NoError(t, err)

	ba, err := NewBatchAnalyzer(analyzer, 4)
	require.NoError(t, err)

	ba.SetProgress(func(_, _ int, _ string) {})

	// Race: replace the progress callback while workers are running.
	// The progressMu RW-lock must prevent a torn read or write.
	var replaceDone sync.WaitGroup
	replaceDone.Go(func() {
		ba.SetProgress(func(_, _ int, _ string) {})
	})

	_, err = ba.AnalyzeMultiple(t.Context(), sources)
	replaceDone.Wait()
	_ = err // goal is absence of data races, not a specific result
}

func TestSecurityBatchAnalyzer_DuplicateSources(t *testing.T) {
	t.Parallel()

	rawCert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{})
	require.NoError(t, err)

	pemPath := filepath.Join(t.TempDir(), "dup.pem")
	require.NoError(t, os.WriteFile(pemPath, testutil.EncodePEM(rawCert), 0600))

	// Each slot gets its own sourceIndex, so results are sorted by position
	// and not deduplicated.
	sources := []string{pemPath, pemPath, pemPath, pemPath}

	parser := NewParser(WithAutoDetectFormat(true))
	analyzer, err := NewAnalyzer(WithParser(parser))
	require.NoError(t, err)

	ba, err := NewBatchAnalyzer(analyzer, 4)
	require.NoError(t, err)

	analyses, err := ba.AnalyzeMultiple(t.Context(), sources)
	require.NoError(t, err)
	assert.Len(t, analyses, len(sources), "duplicate sources must each produce a result")
}

func TestSecurityContextCancellation_BatchCleanShutdown(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	const sourceCount = 20
	sources := make([]string, sourceCount)
	for i := range sourceCount {
		rawCert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{})
		require.NoError(t, err)
		p := filepath.Join(dir, fmt.Sprintf("cancel-%d.pem", i))
		require.NoError(t, os.WriteFile(p, testutil.EncodePEM(rawCert), 0600))
		sources[i] = p
	}

	parser := NewParser(WithAutoDetectFormat(true))
	analyzer, err := NewAnalyzer(WithParser(parser))
	require.NoError(t, err)

	ba, err := NewBatchAnalyzer(analyzer, maxBatchWorkers)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	// Cancel immediately so most workers see ctx.Done on the fast path.
	cancel()

	_, batchErr := ba.AnalyzeMultiple(ctx, sources)

	require.Error(t, batchErr, "expected error after context cancellation")
	assert.True(t,
		errors.Is(batchErr, context.Canceled) ||
			errors.Is(batchErr, ErrContextCanceled),
		"error chain must contain context cancellation: %v", batchErr,
	)
}

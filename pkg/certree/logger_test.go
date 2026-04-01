package certree

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestNewLogger_Discards(t *testing.T) {
	t.Parallel()

	logger := NewLogger()
	if logger == nil {
		t.Fatal("NewLogger() returned nil")
	}

	// Should not panic when called at all levels.
	logger.Debug("debug", "key", "val")
	logger.Info("info")
	logger.Warn("warn", "n", 42)
	logger.Error("error", "err", "oops")

	// Verify a real logger produces output, contrasting with the discard logger.
	var buf bytes.Buffer
	realLogger := slog.New(slog.NewTextHandler(&buf, nil))
	realLogger.Info("probe")
	if buf.Len() == 0 {
		t.Error("real logger should produce output for Info")
	}
}

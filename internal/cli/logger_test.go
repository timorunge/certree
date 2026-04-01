package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/internal/render"
)

func TestResolveLogLevel_CLIVerboseOverridesConfig(t *testing.T) {
	t.Parallel()
	assert.Equal(t, logLevelError, resolveLogLevel(1, true, "debug"))
	assert.Equal(t, logLevelWarn, resolveLogLevel(2, true, ""))
	assert.Equal(t, logLevelInfo, resolveLogLevel(3, true, ""))
	assert.Equal(t, logLevelDebug, resolveLogLevel(4, true, ""))
	assert.Equal(t, logLevelOff, resolveLogLevel(0, true, "info"))
}

func TestResolveLogLevel_ConfigFallback(t *testing.T) {
	t.Parallel()
	assert.Equal(t, logLevelInfo, resolveLogLevel(0, false, "info"))
	assert.Equal(t, logLevelDebug, resolveLogLevel(0, false, "debug"))
	assert.Equal(t, logLevelOff, resolveLogLevel(0, false, ""))
}

func TestResolveLogLevel_InvalidConfigFallsBackToOff(t *testing.T) {
	t.Parallel()
	assert.Equal(t, logLevelOff, resolveLogLevel(0, false, "verbose"))
	assert.Equal(t, logLevelOff, resolveLogLevel(0, false, "trace"))
}

func TestCLILogger_OutputFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := newCLILogger(&buf, logLevelDebug, render.LookupLogIcons("classic", false))

	logger.Info("connecting", "host", "example.com", "port", 443)
	line := buf.String()

	assert.Contains(t, line, "[i ]", "info line should contain classic info icon")
	assert.Contains(t, line, "connecting", "info line should contain message")
	assert.Contains(t, line, "host=example.com", "info line should contain key=value")
	assert.Contains(t, line, "port=443", "info line should contain numeric value")
	assert.True(t, strings.HasSuffix(line, "\n"), "log line should end with newline")
}

func TestCLILogger_AllLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call func(*slog.Logger)
		icon string
	}{
		{"debug", func(l *slog.Logger) { l.Debug("msg") }, "[. ]"},
		{"info", func(l *slog.Logger) { l.Info("msg") }, "[i ]"},
		{"warn", func(l *slog.Logger) { l.Warn("msg") }, "[! ]"},
		{"error", func(l *slog.Logger) { l.Error("msg") }, "[x ]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := newCLILogger(&buf, logLevelDebug, render.LookupLogIcons("classic", false))
			tt.call(logger)

			line := buf.String()
			assert.Contains(t, line, tt.icon,
				"%s line should contain icon %q", tt.name, tt.icon)
			assert.Contains(t, line, "msg",
				"%s line should contain message", tt.name)
		})
	}
}

func TestCLILogger_InfoLevelSuppressesDebug(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := newCLILogger(&buf, logLevelInfo, render.LookupLogIcons("classic", false))

	logger.Debug("should be suppressed")
	assert.Empty(t, buf.String(), "debug should be suppressed at info level")

	logger.Info("visible")
	assert.Contains(t, buf.String(), "visible", "info should pass through")

	buf.Reset()
	logger.Warn("warning")
	assert.Contains(t, buf.String(), "warning", "warn should pass through")

	buf.Reset()
	logger.Error("failure")
	assert.Contains(t, buf.String(), "failure", "error should pass through")
}

func TestCLILogger_ThemeVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		theme    string
		infoIcon string
	}{
		{"classic", "[i ]"},
		{"terse", "[i]"},
		{"minimal", "i"},
	}

	for _, tt := range tests {
		t.Run(tt.theme, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := newCLILogger(&buf, logLevelInfo, render.LookupLogIcons(tt.theme, false))
			logger.Info("test")

			assert.Contains(t, buf.String(), tt.infoIcon,
				"theme %q should use icon %q", tt.theme, tt.infoIcon)
		})
	}
}

func TestCLILogger_UnknownThemeFallback(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := newCLILogger(&buf, logLevelInfo, render.LookupLogIcons("nonexistent", false))
	logger.Info("test")

	assert.Contains(t, buf.String(), "[i ]", "unknown theme should fall back to classic")
}

func TestCLILogger_WithAttrs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := newCLILogger(&buf, logLevelDebug, render.LookupLogIcons("classic", false))
	derived := logger.With("service", "certree")
	derived.Info("started")

	line := buf.String()
	assert.Contains(t, line, "service=certree", "pre-attached attr should appear")
	assert.Contains(t, line, "started", "message should appear")
}

func TestCLILogger_WithGroup(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := newCLILogger(&buf, logLevelDebug, render.LookupLogIcons("classic", false))
	derived := logger.WithGroup("tls").With("host", "example.com")
	derived.Info("connected")

	line := buf.String()
	assert.Contains(t, line, "tls.host=example.com", "group should prefix attr key")
	assert.Contains(t, line, "connected", "message should appear")
}

func TestLogLevel_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		level logLevel
		want  string
	}{
		{"off level", logLevelOff, "off"},
		{"error level", logLevelError, "error"},
		{"warn level", logLevelWarn, "warn"},
		{"info level", logLevelInfo, "info"},
		{"debug level", logLevelDebug, "debug"},
		{"unknown shows numeric value", logLevel(99), "logLevel(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.level.String())
		})
	}
}

func TestLogLevel_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    logLevel
		wantErr bool
	}{
		{"off", logLevelOff, false},
		{"error", logLevelError, false},
		{"warn", logLevelWarn, false},
		{"info", logLevelInfo, false},
		{"debug", logLevelDebug, false},
		{"Warn", logLevelWarn, false},
		{"", 0, true},
		{"trace", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			got, err := parseLogLevel(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestCLILogger_IntegrationWithRun(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	// Use a nonexistent file to trigger a parse error -- the logger
	// should still be wired and produce themed output on stderr.
	// -vvv enables info-level logging.
	exitCode := Run(&stdout, &stderr, []string{"-vvv", "nonexistent.pem"}, "test")

	require.NotEqual(t, exitSuccess, exitCode, "nonexistent file should fail")
	// With -vvv, the logger is active at info level. Any log output should
	// use themed icons rather than the library's [INFO] prefix.
	output := stderr.String()
	if strings.Contains(output, "[INFO]") {
		t.Errorf("stderr should use themed icons, not library [INFO] prefix: %s", output)
	}
	// Positive check: stderr must contain at least one themed icon from the
	// error reporter (nonexistent file triggers an error written via errReporter).
	assert.True(t, strings.Contains(output, "[x ]") || strings.Contains(output, "[! ]"),
		"stderr should contain themed icon output, got: %s", output)
}

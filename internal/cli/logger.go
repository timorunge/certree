// Themed CLI logger: slog.Handler backed by status icons and colors.

package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/timorunge/certree/internal/render"
	"github.com/timorunge/certree/pkg/certree"
)

// logLevel represents the minimum severity level for log output.
// Messages at or above the configured level are emitted; others are discarded.
type logLevel int

const (
	logLevelOff logLevel = iota
	logLevelError
	logLevelWarn
	logLevelInfo
	logLevelDebug
)

// String returns the human-readable name of the log level.
func (l logLevel) String() string {
	switch l {
	case logLevelOff:
		return "off"
	case logLevelError:
		return "error"
	case logLevelWarn:
		return "warn"
	case logLevelInfo:
		return "info"
	case logLevelDebug:
		return "debug"
	default:
		return fmt.Sprintf("logLevel(%d)", l)
	}
}

// parseLogLevel parses a log level string into a logLevel value.
func parseLogLevel(s string) (logLevel, error) {
	switch strings.ToLower(s) {
	case "off":
		return logLevelOff, nil
	case "error":
		return logLevelError, nil
	case "warn":
		return logLevelWarn, nil
	case "info":
		return logLevelInfo, nil
	case "debug":
		return logLevelDebug, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (accepted values are \"off\", \"error\", \"warn\", \"info\", and \"debug\"): %w", s, certree.ErrInvalidInput)
	}
}

// cliHandler implements slog.Handler using themed status icons and ANSI
// colors. It writes structured key-value log messages to an io.Writer,
// prefixed with the appropriate theme icon for each level.
type cliHandler struct {
	// mu is a pointer so copies produced by WithAttrs and WithGroup
	// share the same lock, serializing writes across the handler tree.
	mu       *sync.Mutex
	w        io.Writer
	icons    render.LogIcons
	level    logLevel
	preAttrs []preformatted
	group    string
}

// newCLILogger creates a *slog.Logger backed by a themed cliHandler.
// The logger respects the given log level: each level enables messages at
// that severity and above. Icons should be pre-resolved via
// render.LookupLogIcons.
func newCLILogger(w io.Writer, level logLevel, icons render.LogIcons) *slog.Logger {
	return slog.New(&cliHandler{
		mu:    &sync.Mutex{},
		w:     w,
		icons: icons,
		level: level,
	})
}

var _ slog.Handler = (*cliHandler)(nil)

// Enabled reports whether the handler is enabled for the given level.
func (h *cliHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.level >= slogToLogLevel(level)
}

// Handle formats a log record as an icon-prefixed line to the configured writer.
func (h *cliHandler) Handle(_ context.Context, r slog.Record) error {
	icon := h.iconForLevel(r.Level)
	var b strings.Builder
	b.WriteString(render.SanitizeCertString(r.Message))

	// Pre-attached attrs already have their group prefix baked in.
	for _, pf := range h.preAttrs {
		appendAttr(&b, pf.key, pf.value)
	}

	r.Attrs(func(a slog.Attr) bool {
		v := a.Value.Resolve()
		if v.Kind() == slog.KindGroup {
			h.writeGroupAttrs(&b, h.prefixKey(a.Key), v.Group())
		} else {
			appendAttr(&b, h.prefixKey(a.Key), v)
		}
		return true
	})

	line := fmt.Sprintf("%s %s\n", icon, b.String())
	h.mu.Lock()
	_, _ = io.WriteString(h.w, line)
	h.mu.Unlock()
	return nil
}

// WithAttrs returns a handler copy with pre-attached attrs; keys are group-prefixed
// at call time so later WithGroup calls do not retroactively modify them.
func (h *cliHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	h2 := *h
	h2.preAttrs = make([]preformatted, 0, len(h.preAttrs)+len(attrs))
	h2.preAttrs = append(h2.preAttrs, h.preAttrs...)
	for _, a := range attrs {
		h2.preAttrs = append(h2.preAttrs, preformatted{
			key:   h.prefixKey(a.Key),
			value: a.Value.Resolve(),
		})
	}
	return &h2
}

// WithGroup returns a handler that prefixes all subsequent keys with name.
func (h *cliHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := *h
	if h2.group != "" {
		h2.group += "." + name
	} else {
		h2.group = name
	}
	return &h2
}

// prefixKey returns the key with the group prefix, if any.
func (h *cliHandler) prefixKey(key string) string {
	if h.group != "" {
		return h.group + "." + key
	}
	return key
}

// writeGroupAttrs recursively flattens group attributes into dot-separated keys.
func (h *cliHandler) writeGroupAttrs(b *strings.Builder, prefix string, attrs []slog.Attr) {
	for _, a := range attrs {
		v := a.Value.Resolve()
		key := a.Key
		if prefix != "" {
			key = prefix + "." + key
		}
		if v.Kind() == slog.KindGroup {
			h.writeGroupAttrs(b, key, v.Group())
		} else {
			appendAttr(b, key, v)
		}
	}
}

// iconForLevel returns the themed icon string for a given slog.Level.
func (h *cliHandler) iconForLevel(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return h.icons.Error
	case level >= slog.LevelWarn:
		return h.icons.Warning
	case level >= slog.LevelInfo:
		return h.icons.Info
	default:
		return h.icons.Debug
	}
}

// preformatted holds an attribute key with its group prefix already applied
// at the time WithAttrs was called, so that later WithGroup calls do not
// retroactively prefix earlier attributes (slog spec compliance).
type preformatted struct {
	key   string
	value slog.Value
}

// slogToLogLevel maps a slog.Level to the corresponding logLevel.
// Levels between named values are rounded up to the next certree level.
func slogToLogLevel(level slog.Level) logLevel {
	switch {
	case level >= slog.LevelError:
		return logLevelError
	case level >= slog.LevelWarn:
		return logLevelWarn
	case level >= slog.LevelInfo:
		return logLevelInfo
	default:
		return logLevelDebug
	}
}

// appendAttr appends a sanitized key-value pair to the given strings.Builder.
// String values are sanitized to prevent terminal injection from certificate
// fields; values containing spaces or tabs are quoted for unambiguous parsing.
func appendAttr(b *strings.Builder, key string, v slog.Value) {
	s := v.String()
	if v.Kind() == slog.KindString {
		s = render.SanitizeCertString(s)
		if strings.ContainsAny(s, " \t") {
			_, _ = fmt.Fprintf(b, " %s=%q", key, s)
			return
		}
	}
	_, _ = fmt.Fprintf(b, " %s=%s", key, s)
}

// resolveLogLevel computes the effective log level from CLI flags and config
// file. CLI -v/-vv/-vvv/-vvvv takes precedence when explicitly set; otherwise
// the config output.log_level value is used.
func resolveLogLevel(cliVerbose int, cliChanged bool, configLogLevel string) logLevel {
	if cliChanged {
		switch cliVerbose {
		case 1:
			return logLevelError
		case 2:
			return logLevelWarn
		case 3:
			return logLevelInfo
		case 4:
			return logLevelDebug
		default:
			return logLevelOff
		}
	}
	level, err := parseLogLevel(configLogLevel)
	if err != nil {
		// Unreachable in normal operation: config.Validate() rejects invalid
		// log_level values before resolveLogLevel is called. Defensive fallback.
		return logLevelOff
	}
	return level
}

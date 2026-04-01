// Default discard logger for certree components.

package certree

import (
	"io"
	"log/slog"
)

// NewLogger returns a *slog.Logger that discards all output.
// Use a component's With*Logger option to replace it with a real logger.
func NewLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

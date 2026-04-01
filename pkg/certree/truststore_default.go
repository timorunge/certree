//go:build !darwin && !linux && !windows

// Fallback trust store for unsupported platforms.

package certree

import (
	"fmt"
	"log/slog"
)

// loadSystemRoots is a fallback for unsupported platforms.
func loadSystemRoots(_ string, _ *slog.Logger) ([]*Certificate, error) {
	return nil, fmt.Errorf("system root loading not supported on this platform: %w", ErrPlatformNotSupported)
}

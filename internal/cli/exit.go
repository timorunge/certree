// Exit codes for the certree CLI.

package cli

import "github.com/timorunge/certree/pkg/certree"

// exitCode represents a CLI process exit code.
type exitCode int

// Follows POSIX conventions:
//   - 0: success
//   - 1: primary failure (certificate validation issues)
//   - 2: usage error (matches bash, grep, curl convention for misuse)
//   - 3+: infrastructure errors (config, network, parsing)
const (
	exitSuccess exitCode = iota
	exitValidationError
	exitUsageError
	exitConfigError
	exitConnectionError
	exitParseError
	exitRenderError
)

// worstExitCode returns the numerically higher (more severe) of two exit
// codes. exitSuccess (0) is absorbed by any non-zero code, ensuring that
// partial batch failures or validation errors are never masked.
func worstExitCode(a, b exitCode) exitCode {
	if a > b {
		return a
	}
	return b
}

// analysesExitCode returns exitValidationError if any analysis has errors, or
// if a simulated analysis has no trust paths (simulation excluded everything).
func analysesExitCode(analyses []*certree.Analysis) exitCode {
	for _, a := range analyses {
		if a.HasErrors() {
			return exitValidationError
		}
		if a.Metadata.IsSimulated && len(a.TrustPaths) == 0 {
			return exitValidationError
		}
	}
	return exitSuccess
}

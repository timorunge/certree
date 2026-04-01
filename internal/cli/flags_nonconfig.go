// Non-config flag types, parsing, and simulation validation.

package cli

import (
	"fmt"
	"time"

	"github.com/spf13/pflag"

	"github.com/timorunge/certree/internal/config"
)

const (
	// maxVerboseLevel is the upper bound for the -v/--verbose count flag.
	// Verbosity levels: 0 = off, 1 = error, 2 = warn, 3 = info, 4 = debug.
	maxVerboseLevel = 4

	// maxInjectFiles is the upper bound for --inject flag repetitions.
	maxInjectFiles = 10
)

// nonConfigFlags holds the raw values of CLI flags that are not backed by
// the Config struct. These flags are read directly by run() rather than
// going through applyFlagOverrides. The struct centralizes the scattered
// fs.GetString/fs.GetBool calls into a single parse site.
type nonConfigFlags struct {
	hostsFile          string
	filterCN           []string
	filterFingerprint  []string
	filterSerial       []string
	excludeCN          []string
	excludeFingerprint []string
	excludeSerial      []string
	injectFiles        []string

	compare           bool
	diff              bool
	validationTimeRaw string
	validationTime    *time.Time
	impact            bool

	quiet          bool
	verboseCount   int
	verboseChanged bool

	// parsedFields holds the validated --fields values, parsed once during
	// flag validation and reused by buildRenderOptions to avoid redundant
	// re-parsing on every render call.
	parsedFields []string
}

// hasExclusions reports whether any exclusion flag is set.
func (f nonConfigFlags) hasExclusions() bool {
	return len(f.excludeCN) > 0 || len(f.excludeFingerprint) > 0 || len(f.excludeSerial) > 0
}

// hasInjections reports whether any injection flag is set.
func (f nonConfigFlags) hasInjections() bool {
	return len(f.injectFiles) > 0
}

// parseNonConfigFlags reads all non-config-backed flag values from fs and
// returns them as a single struct. The verbose count is capped at maxVerboseLevel (4).
func parseNonConfigFlags(fs *pflag.FlagSet) nonConfigFlags {
	// Get* errors are unreachable: each flag is registered above with the
	// matching type, so type-assertion failures cannot occur.
	hostsFile, _ := fs.GetString("batch")
	excludeCN, _ := fs.GetStringArray("exclude-cn")
	excludeFingerprint, _ := fs.GetStringArray("exclude-fingerprint")
	excludeSerial, _ := fs.GetStringArray("exclude-serial")
	injectFiles, _ := fs.GetStringArray("inject")
	compare, _ := fs.GetBool("compare")
	diff, _ := fs.GetBool("diff")
	validationTimeRaw, _ := fs.GetString("validation-time")
	impact, _ := fs.GetBool("impact")
	quiet, _ := fs.GetBool("quiet")
	filterCN, _ := fs.GetStringArray("filter-cn")
	filterFingerprint, _ := fs.GetStringArray("filter-fingerprint")
	filterSerial, _ := fs.GetStringArray("filter-serial")
	verboseCount, _ := fs.GetCount("verbose")
	if verboseCount > maxVerboseLevel {
		verboseCount = maxVerboseLevel
	}

	return nonConfigFlags{
		hostsFile:          hostsFile,
		excludeCN:          excludeCN,
		excludeFingerprint: excludeFingerprint,
		excludeSerial:      excludeSerial,
		injectFiles:        injectFiles,
		compare:            compare,
		diff:               diff,
		validationTimeRaw:  validationTimeRaw,
		impact:             impact,
		quiet:              quiet,
		filterCN:           filterCN,
		filterFingerprint:  filterFingerprint,
		filterSerial:       filterSerial,
		verboseCount:       verboseCount,
		verboseChanged:     fs.Changed("verbose"),
	}
}

// parseValidationTime parses the --validation-time value if set. On success
// the parsed time is stored in flags.validationTime. Returns an error for
// malformed RFC 3339 values.
func parseValidationTime(flags *nonConfigFlags) error {
	if flags.validationTimeRaw == "" {
		return nil
	}
	vt, err := time.Parse(time.RFC3339, flags.validationTimeRaw)
	if err != nil {
		return fmt.Errorf("invalid --validation-time %q: must be RFC 3339 format (e.g. 2020-01-01T00:00:00Z)",
			flags.validationTimeRaw)
	}
	flags.validationTime = &vt
	return nil
}

// validateSimulationFlags checks that simulation-related flag combinations are
// valid. Returns an error describing the first invalid combination found.
func validateSimulationFlags(flags *nonConfigFlags, format string) error {
	if err := parseValidationTime(flags); err != nil {
		return err
	}

	if len(flags.injectFiles) > maxInjectFiles {
		return fmt.Errorf("--inject accepts at most %d files, got %d", maxInjectFiles, len(flags.injectFiles))
	}

	hasExclusions := flags.hasExclusions()
	hasSimTrigger := hasExclusions || flags.hasInjections() || flags.validationTime != nil
	if flags.compare && !hasSimTrigger {
		return fmt.Errorf("--compare requires at least one simulation flag (--exclude-*, --inject, or --validation-time)")
	}
	if flags.impact && !hasSimTrigger {
		return fmt.Errorf("--impact requires at least one simulation flag (--exclude-*, --inject, or --validation-time)")
	}
	if flags.diff && !hasSimTrigger {
		return fmt.Errorf("--diff requires at least one simulation flag (--exclude-*, --inject, or --validation-time)")
	}
	if flags.diff && flags.compare {
		return fmt.Errorf("--diff and --compare are mutually exclusive")
	}
	if flags.diff && format == config.FormatJSON {
		return fmt.Errorf("--diff is not supported with JSON format")
	}
	if flags.impact && format == config.FormatJSON {
		return fmt.Errorf("--impact is not supported with JSON format")
	}
	return nil
}

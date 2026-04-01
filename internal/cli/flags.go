// Flag registration, config overrides, validation, and error handling.

package cli

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/timorunge/certree/internal/config"
	"github.com/timorunge/certree/internal/render"
)

const (
	// noBoolFlagPrefix is the prefix added to boolean flag names to create their
	// negated counterparts (e.g., --no-verify-expiry for --verify-expiry).
	noBoolFlagPrefix = "no-"

	// needsArgPrefix is the pflag error prefix for missing flag arguments.
	needsArgPrefix = "flag needs an argument: "
)

// pflagErrPattern matches pflag's integer/bool/float parse error format:
// invalid argument "VALUE" for "--FLAG" flag: strconv.Parse*: ...
// The flag name group accounts for pflag including the shorthand prefix
// (e.g., "-v, --verbose") by matching everything between the quotes.
var pflagErrPattern = regexp.MustCompile(
	`^invalid argument "([^"]*)" for "([^"]*)" flag: strconv\.(ParseInt|ParseBool|ParseFloat):`,
)

// registerFlags creates a pflag.FlagSet with all CLI flags and their
// defaults. Defaults for config-backed flags are taken from
// config.DefaultConfig to keep a single source of truth.
func registerFlags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("certree", pflag.ContinueOnError)
	defaults := config.DefaultConfig()

	fs.String("connect-timeout", defaults.Connection.ConnectTimeout, "TLS connection timeout for remote hosts")
	fs.String("fetch-timeout", defaults.Connection.FetchTimeout, "HTTP timeout for URL certificate fetches")
	fs.String("sni", defaults.Connection.SNI, "Override SNI hostname sent in TLS handshake")
	fs.String("client-cert", defaults.Connection.ClientCert, "Client certificate PEM file for mutual TLS")
	fs.String("client-key", defaults.Connection.ClientKey, "Client private key PEM file for mutual TLS")
	fs.Bool("aia-fetch", defaults.Connection.AIAFetch, "Fetch missing intermediates via AIA")
	fs.Bool("aia-force", defaults.Connection.AIAForce, "Always fetch via AIA, even when local issuers exist (implies --aia-fetch)")
	fs.String("aia-timeout", defaults.Connection.AIATimeout, "Per-request HTTP timeout for AIA fetches")
	fs.Bool("allow-private-networks", defaults.Connection.AllowPrivateNetworks, "Allow AIA/OCSP/CRL fetches to private IPs (RFC 1918)")

	fs.Bool("verify-signatures", defaults.Validation.VerifySignatures, "Verify certificate signatures in the chain (RFC 5280, section 6.1)")
	fs.Bool("verify-expiry", defaults.Validation.VerifyExpiry, "Verify certificate expiry dates (RFC 5280, section 4.1.2.5)")
	fs.Int("expiry-warning-days", defaults.Validation.ExpiryWarningDays, "Warn if a certificate expires within N days from now (renewal monitoring)")
	fs.Int("max-validity-days", defaults.Validation.MaxValidityDays, "Warn if total issued lifetime (NotAfter-NotBefore) exceeds N days (0 = disabled, 398 = CA/B Forum TLS limit)")
	fs.Bool("verify-hostname", defaults.Validation.VerifyHostname, "Verify hostname against certificate SANs and CN (RFC 6125)")
	fs.String("hostname", defaults.Validation.Hostname, "Override hostname for verification (implies --verify-hostname)")
	fs.Bool("verify-revocation", defaults.Validation.VerifyRevocation, "Check revocation status via OCSP (RFC 6960) and CRL (RFC 5280, section 5)")
	fs.Bool("revocation-fail-open", defaults.Validation.RevocationFailOpen, "Treat OCSP/CRL network failures as warnings, not errors")
	fs.Bool("verify-eku", defaults.Validation.VerifyEKU, "Verify EKU chaining: cert EKU must be subset of issuer EKU (RFC 5280, section 4.2.1.12)")
	fs.Bool("verify-name-constraints", defaults.Validation.VerifyNameConstraints, "Verify name constraints imposed by CA certificates (RFC 5280, section 4.2.1.10)")
	fs.Int("max-certificates", defaults.Validation.MaxCertificates, "Maximum certificates to process per source")
	fs.Int("max-depth", defaults.Validation.MaxDepth, "Maximum chain depth to build")
	fs.Bool("skip-invalid", defaults.Validation.SkipInvalid, "Skip unparseable certificates instead of failing")

	fs.StringP("fields", "f", defaults.Render.Fields, "Certificate fields to display: "+strings.Join(sortedFieldNames(), ", "))
	fs.StringArray("filter-cn", nil, "Filter by Common Name pattern, supports wildcards (repeatable)")
	fs.StringArray("filter-fingerprint", nil, "Filter by SHA-256 fingerprint pattern, supports wildcards (repeatable)")
	fs.StringArray("filter-serial", nil, "Filter by serial number pattern, supports wildcards (repeatable)")
	fs.Bool("reverse", defaults.Render.Reverse, "Render certificates in root-to-leaf order")
	fs.Bool("annotations", defaults.Render.Annotations, "Show status annotations on certificates and paths (e.g. expired, self-signed)")
	fs.Bool("path-index", defaults.Render.PathIndex, "Show path index numbers (#1, #2, ...) on path terminal certificates")
	fs.String("theme", defaults.Render.Theme, "Render theme: classic, terse, minimal")

	fs.String("color", defaults.Output.Color, "Color mode: auto, always, never")
	fs.String("format", defaults.Output.Format, "Output format: tree, json")
	fs.Bool("expand", defaults.Render.Expand, "Show each trust path separately instead of merged tree view")
	fs.Bool("wrap", defaults.Render.Wrap, "Wrap long detail lines to fit terminal width (tree mode only)")
	fs.BoolP("quiet", "q", false, "Suppress stdout and stderr, exit code only")
	fs.CountP("verbose", "v", "Log verbosity: -v (error), -vv (warn), -vvv (info), -vvvv (debug)")

	fs.Bool("prefer-custom-roots", defaults.TrustStore.PreferCustomRoots, "Prefer custom trust bundle over system roots when both match")
	fs.String("system-roots", defaults.TrustStore.SystemRoots, "Path to system root certificates directory or file")
	fs.String("trust-bundle", defaults.TrustStore.TrustBundle, "Path to custom CA bundle PEM file")

	fs.StringP("batch", "b", "", "Batch process sources from file (one per line)")

	fs.StringP("config", "c", "", "Configuration file path")

	fs.Bool("compare", false, "Show side-by-side before/after comparison")
	fs.Bool("diff", false, "Show unified diff of before/after changes")
	fs.StringArray("exclude-cn", nil, "Exclude certificates by Common Name, supports wildcards (repeatable)")
	fs.StringArray("exclude-fingerprint", nil, "Exclude certificates by SHA-256 fingerprint, supports wildcards (repeatable)")
	fs.StringArray("exclude-serial", nil, "Exclude certificates by serial number, supports wildcards (repeatable)")
	fs.StringArray("inject", nil, "Add certificates from file (PEM/DER) into the chain analysis and rebuild all trust paths (repeatable)")
	fs.String("validation-time", "", "Override current time for validation (RFC 3339, e.g. 2025-06-01T00:00:00Z)")
	fs.Bool("impact", false, "Show impact summary after simulation")

	fs.BoolP("help", "h", false, "Show help message")
	fs.Bool("version", false, "Show version information")

	registerNoBoolFlags(fs)

	return fs
}

// applyFlagOverrides applies explicitly-set CLI flags onto the Config.
// Only flags that were set on the command line are applied; unset flags
// leave the config value unchanged (preserving config file or defaults).
//
//nolint:gocyclo,cyclop // flat switch over ~20 flag names, no nesting or decision logic
func applyFlagOverrides(cfg *config.Config, fs *pflag.FlagSet) {
	// GetBool/GetInt errors are unreachable inside Visit: the flag exists by
	// definition and was registered with the correct type.
	fs.Visit(func(f *pflag.Flag) {
		v := f.Value.String()
		switch f.Name {
		case "aia-fetch":
			cfg.Connection.AIAFetch, _ = fs.GetBool(f.Name)
		case "aia-force":
			cfg.Connection.AIAForce, _ = fs.GetBool(f.Name)
		case "aia-timeout":
			cfg.Connection.AIATimeout = v
		case "sni":
			cfg.Connection.SNI = v
		case "connect-timeout":
			cfg.Connection.ConnectTimeout = v
		case "fetch-timeout":
			cfg.Connection.FetchTimeout = v
		case "client-cert":
			cfg.Connection.ClientCert = v
		case "client-key":
			cfg.Connection.ClientKey = v
		case "allow-private-networks":
			cfg.Connection.AllowPrivateNetworks, _ = fs.GetBool(f.Name)

		case "verify-expiry":
			cfg.Validation.VerifyExpiry, _ = fs.GetBool(f.Name)
		case "verify-revocation":
			cfg.Validation.VerifyRevocation, _ = fs.GetBool(f.Name)
		case "expiry-warning-days":
			cfg.Validation.ExpiryWarningDays, _ = fs.GetInt(f.Name)
		case "hostname":
			cfg.Validation.Hostname = v
		case "max-certificates":
			cfg.Validation.MaxCertificates, _ = fs.GetInt(f.Name)
		case "max-depth":
			cfg.Validation.MaxDepth, _ = fs.GetInt(f.Name)
		case "revocation-fail-open":
			cfg.Validation.RevocationFailOpen, _ = fs.GetBool(f.Name)
		case "skip-invalid":
			cfg.Validation.SkipInvalid, _ = fs.GetBool(f.Name)
		case "verify-hostname":
			cfg.Validation.VerifyHostname, _ = fs.GetBool(f.Name)
		case "verify-signatures":
			cfg.Validation.VerifySignatures, _ = fs.GetBool(f.Name)
		case "verify-eku":
			cfg.Validation.VerifyEKU, _ = fs.GetBool(f.Name)
		case "verify-name-constraints":
			cfg.Validation.VerifyNameConstraints, _ = fs.GetBool(f.Name)
		case "max-validity-days":
			cfg.Validation.MaxValidityDays, _ = fs.GetInt(f.Name)

		case "fields":
			cfg.Render.Fields = v
		case "reverse":
			cfg.Render.Reverse, _ = fs.GetBool(f.Name)
		case "annotations":
			cfg.Render.Annotations, _ = fs.GetBool(f.Name)
		case "path-index":
			cfg.Render.PathIndex, _ = fs.GetBool(f.Name)
		case "expand":
			cfg.Render.Expand, _ = fs.GetBool(f.Name)
		case "wrap":
			cfg.Render.Wrap, _ = fs.GetBool(f.Name)
		case "theme":
			cfg.Render.Theme = v

		case "color":
			cfg.Output.Color = v
		case "format":
			cfg.Output.Format = v

		case "prefer-custom-roots":
			cfg.TrustStore.PreferCustomRoots, _ = fs.GetBool(f.Name)
		case "system-roots":
			cfg.TrustStore.SystemRoots = v
		case "trust-bundle":
			cfg.TrustStore.TrustBundle = v

		}
	})
}

// applyFlagImplications enforces semantic dependencies between flags. These
// apply regardless of whether the value came from the CLI or a config file:
//   - aia_force = true implies aia_fetch = true (force is meaningless without fetch)
//   - hostname = "<non-empty>" implies verify_hostname = true, unless the user
//     explicitly set --no-verify-hostname (allowing hostname for SNI only)
//
// When fs is non-nil, explicitly-set flags are respected: an explicit
// --no-aia-fetch with --aia-force returns a conflict error, and an explicit
// --no-verify-hostname suppresses the hostname implication. When fs is nil
// (config-file-only pass), implications apply unconditionally.
func applyFlagImplications(cfg *config.Config, fs *pflag.FlagSet) error {
	if cfg.Connection.AIAForce {
		if fs != nil && fs.Changed("aia-fetch") && !cfg.Connection.AIAFetch {
			return fmt.Errorf("--aia-force and --no-aia-fetch conflict: --aia-force requires AIA fetching")
		}
		cfg.Connection.AIAFetch = true
	}
	if cfg.Validation.Hostname != "" {
		if fs != nil && fs.Changed("verify-hostname") && !cfg.Validation.VerifyHostname {
			// User explicitly disabled hostname verification but set a
			// hostname (e.g. for SNI matching only). Respect the explicit
			// --no-verify-hostname.
		} else {
			cfg.Validation.VerifyHostname = true
		}
	}
	return nil
}

// registerNoBoolFlags iterates over all boolean flags in fs whose default is
// "true" and registers a hidden --no-<name> counterpart for each. Only
// defaults-to-true flags benefit from negation (e.g., --no-verify-expiry);
// defaults-to-false flags (like --quiet, --help) are already in the "off"
// state and their --no-* counterparts would be no-ops.
func registerNoBoolFlags(fs *pflag.FlagSet) {
	// Collect bool flag names first to avoid mutating fs while iterating.
	var boolNames []string
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Value.Type() == "bool" && f.DefValue == "true" {
			boolNames = append(boolNames, f.Name)
		}
	})

	for _, name := range boolNames {
		noName := noBoolFlagPrefix + name
		fs.Bool(noName, false, "")
		_ = fs.MarkHidden(noName)
	}
}

// resolveNoBoolFlags checks whether any --no-<name> flag was explicitly set
// and, if so, sets the corresponding positive flag to "false". This makes
// --no-verify-expiry equivalent to --verify-expiry=false. If both the positive
// and negated flag are set, the negated flag wins (last-writer-wins is not
// possible with pflag, so we pick the explicit negation as the stronger
// signal).
//
// Note: when both --flag and --no-flag are set, --no-flag unconditionally
// wins regardless of order. pflag does not expose argument ordering, so
// true last-writer-wins semantics are not achievable.
func resolveNoBoolFlags(fs *pflag.FlagSet) {
	fs.Visit(func(f *pflag.Flag) {
		positiveName, ok := strings.CutPrefix(f.Name, noBoolFlagPrefix)
		if !ok {
			return
		}
		positive := fs.Lookup(positiveName)
		if positive == nil || positive.Value.Type() != "bool" {
			return
		}
		// The negated flag's value determines the positive flag's value:
		// --no-aia-fetch (true) -> aia-fetch=false
		// --no-aia-fetch=false  -> aia-fetch=true (double negation)
		negatedValue := f.Value.String()
		if negatedValue == "true" {
			_ = fs.Set(positiveName, "false")
		} else {
			_ = fs.Set(positiveName, "true")
		}
	})
}

// validateThemeName returns nil if name is empty or a known builtin theme.
// It returns an error listing available themes otherwise.
func validateThemeName(name string) error {
	if name == "" {
		return nil
	}
	known := render.ThemeNames()
	if slices.Contains(known, name) {
		return nil
	}
	return fmt.Errorf("unknown theme %q: available themes are %s", name, strings.Join(known, ", "))
}

// validateColorMode returns nil if mode is empty or one of the defined
// color mode constants. It returns an error describing valid values otherwise.
func validateColorMode(mode string) error {
	switch mode {
	case "", config.ColorAuto, config.ColorAlways, config.ColorNever:
		return nil
	default:
		return fmt.Errorf("unknown color mode %q: valid values are %s, %s, %s", mode, config.ColorAuto, config.ColorAlways, config.ColorNever)
	}
}

// validateFormat returns nil if format is empty or one of "tree" or "json".
// It returns an error describing valid values otherwise.
func validateFormat(format string) error {
	switch format {
	case "", config.FormatTree, config.FormatJSON:
		return nil
	default:
		return fmt.Errorf("unknown format %q: valid values are tree, json", format)
	}
}

// validateFlagValues checks render flag values against known themes and
// field names. These checks are separate from config.Validate because they
// depend on domain knowledge that lives in the cli and render packages,
// and config must not import either. Format and color validation is handled
// by config.Validate, which runs first.
// On success, the parsed field names are returned for reuse by
// buildRenderOptions, eliminating redundant re-parsing.
func validateFlagValues(cfg *config.Config) ([]string, error) {
	parsedFields, err := parseFields(cfg.Render.Fields)
	if err != nil {
		return nil, fmt.Errorf("invalid --fields value: %w", err)
	}
	if err := validateThemeName(cfg.Render.Theme); err != nil {
		return nil, fmt.Errorf("invalid --theme value: %w", err)
	}
	return parsedFields, nil
}

// resolveConfigPaths resolves filesystem paths in cfg to absolute paths.
// Called after flag overrides so both config-file and CLI-provided paths
// are normalized before the library's IsAbs checks reject them.
func resolveConfigPaths(cfg *config.Config) error {
	if cfg.TrustStore.TrustBundle != "" {
		abs, err := filepath.Abs(cfg.TrustStore.TrustBundle)
		if err != nil {
			return fmt.Errorf("resolving trust bundle path: %w", err)
		}
		cfg.TrustStore.TrustBundle = abs
	}
	if cfg.TrustStore.SystemRoots != "" {
		abs, err := filepath.Abs(cfg.TrustStore.SystemRoots)
		if err != nil {
			return fmt.Errorf("resolving system roots path: %w", err)
		}
		cfg.TrustStore.SystemRoots = abs
	}
	return nil
}

// humanizeFlagError rewrites pflag parse errors that leak Go internals
// (e.g. strconv.ParseInt) into user-friendly messages. For "flag needs an
// argument" errors, it appends contextual help listing valid values when
// available. Errors that do not match a known pattern are returned unchanged.
func humanizeFlagError(err error) error {
	if err == nil {
		return nil
	}

	msg := err.Error()

	if suffix, ok := strings.CutPrefix(msg, needsArgPrefix); ok {
		return humanizeNeedsArg(suffix)
	}

	m := pflagErrPattern.FindStringSubmatch(msg)
	if m == nil {
		return err
	}

	value, rawFlag, parser := m[1], m[2], m[3]

	// pflag includes the shorthand prefix (e.g., "-v, --verbose").
	flag := rawFlag
	if idx := strings.LastIndex(rawFlag, "--"); idx >= 0 {
		flag = rawFlag[idx+2:]
	}

	if hint := flagValueHint(flag); hint != "" {
		return fmt.Errorf("--%s does not accept %q; %s", flag, value, hint)
	}

	var kind string
	switch parser {
	case "ParseInt":
		kind = "an integer value"
	case "ParseBool":
		kind = "a boolean value (true/false)"
	case "ParseFloat":
		kind = "a numeric value"
	default:
		return err
	}

	return fmt.Errorf("--%s requires %s, got %q", flag, kind, value)
}

// humanizeNeedsArg rewrites a "flag needs an argument" suffix into a
// user-friendly message with contextual help for flags that have a known
// set of valid values.
func humanizeNeedsArg(suffix string) error {
	// Long form: "--name", shorthand form: "'x' in -x".
	name := strings.TrimPrefix(suffix, "--")
	if name == suffix {
		// Shorthand form -- extract the long name from the FlagSet via
		// the shorthand-to-flag registration table. Only shorthands for
		// flags with value hints matter; fall through for unknown ones.
		name = shorthandLongName(suffix)
	}

	if hint := flagValueHint(name); hint != "" {
		return fmt.Errorf("--%s requires a value (%s)", name, hint)
	}
	if name != "" {
		return fmt.Errorf("--%s requires a value", name)
	}
	return fmt.Errorf("%s%s", needsArgPrefix, suffix)
}

// flagValueHint returns a contextual help string for flags with a known set
// of valid values. Returns empty for flags without predefined choices.
func flagValueHint(name string) string {
	switch name {
	case "fields":
		return "valid values: " + strings.Join(sortedFieldNames(), ", ")
	case "theme":
		return "valid values: " + strings.Join(render.ThemeNames(), ", ")
	case "color":
		return "valid values: auto, always, never"
	case "format":
		return "valid values: tree, json"
	case "verbose":
		return "use -v (error), -vv (warn), -vvv (info), or -vvvv (debug); omit for silent"
	default:
		return ""
	}
}

// shorthandLongName extracts the long flag name from a pflag shorthand
// error suffix like "'f' in -f". Returns empty if the format is
// unrecognized or the shorthand has no value hint.
func shorthandLongName(suffix string) string {
	// Format: "'x' in -x" -- the character at index 1 is the shorthand.
	if len(suffix) < 3 || suffix[0] != '\'' || suffix[2] != '\'' {
		return ""
	}
	switch suffix[1] {
	case 'b':
		return "batch"
	case 'c':
		return "config"
	case 'f':
		return "fields"
	default:
		return ""
	}
}

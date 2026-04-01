package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/internal/config"
)

// expectedFlagSpec describes the expected metadata for a registered flag.
type expectedFlagSpec struct {
	name      string
	valueType string // pflag type string: "string", "bool", "int"
	defValue  string
	shorthand string
}

func TestGetFlagsInGroup_ReturnsExpectedFlags(t *testing.T) {
	t.Parallel()

	fs := registerFlags()

	for _, group := range flagGroups {
		var gotNames []string
		for _, name := range group.flags {
			if f := fs.Lookup(name); f != nil {
				gotNames = append(gotNames, f.Name)
			}
		}
		assert.Equal(t, group.flags, gotNames, "group %q flags", group.name)
	}

	// Non-existent flag returns nothing.
	f := fs.Lookup("nonexistent")
	assert.Nil(t, f, "unknown flag should not exist")
}

func TestFlagRegistrationPreservesSpec(t *testing.T) {
	t.Parallel()

	defaults := config.DefaultConfig()

	expected := []expectedFlagSpec{
		// Connection.
		{"aia-fetch", "bool", "false", ""},
		{"aia-force", "bool", "false", ""},
		{"aia-timeout", "string", defaults.Connection.AIATimeout, ""},
		{"connect-timeout", "string", defaults.Connection.ConnectTimeout, ""},
		{"fetch-timeout", "string", defaults.Connection.FetchTimeout, ""},
		{"sni", "string", defaults.Connection.SNI, ""},
		{"client-cert", "string", defaults.Connection.ClientCert, ""},
		{"client-key", "string", defaults.Connection.ClientKey, ""},
		{"allow-private-networks", "bool", strconv.FormatBool(defaults.Connection.AllowPrivateNetworks), ""},

		// Validation.
		{"max-depth", "int", strconv.Itoa(defaults.Validation.MaxDepth), ""},
		{"skip-invalid", "bool", "false", ""},
		{"verify-revocation", "bool", "false", ""},
		{"revocation-fail-open", "bool", strconv.FormatBool(defaults.Validation.RevocationFailOpen), ""},
		{"verify-signatures", "bool", strconv.FormatBool(defaults.Validation.VerifySignatures), ""},
		{"verify-eku", "bool", "false", ""},
		{"verify-name-constraints", "bool", "false", ""},
		{"verify-expiry", "bool", strconv.FormatBool(defaults.Validation.VerifyExpiry), ""},
		{"verify-hostname", "bool", "true", ""},
		{"hostname", "string", defaults.Validation.Hostname, ""},
		{"expiry-warning-days", "int", strconv.Itoa(defaults.Validation.ExpiryWarningDays), ""},
		{"max-validity-days", "int", strconv.Itoa(defaults.Validation.MaxValidityDays), ""},
		{"max-certificates", "int", strconv.Itoa(defaults.Validation.MaxCertificates), ""},

		// Render.
		{"theme", "string", defaults.Render.Theme, ""},
		{"fields", "string", defaults.Render.Fields, "f"},
		{"reverse", "bool", "false", ""},
		{"annotations", "bool", "false", ""},
		{"path-index", "bool", "false", ""},
		{"verbose", "count", "0", "v"},
		{"filter-cn", "stringArray", "[]", ""},
		{"filter-fingerprint", "stringArray", "[]", ""},
		{"filter-serial", "stringArray", "[]", ""},
		// Output.
		{"format", "string", defaults.Output.Format, ""},
		{"color", "string", defaults.Output.Color, ""},
		{"quiet", "bool", "false", "q"},
		{"expand", "bool", "false", ""},
		{"wrap", "bool", "false", ""},

		// Trust store.
		{"prefer-custom-roots", "bool", "false", ""},
		{"system-roots", "string", defaults.TrustStore.SystemRoots, ""},
		{"trust-bundle", "string", defaults.TrustStore.TrustBundle, ""},

		// Simulation.
		{"validation-time", "string", "", ""},
		{"exclude-cn", "stringArray", "[]", ""},
		{"exclude-fingerprint", "stringArray", "[]", ""},
		{"exclude-serial", "stringArray", "[]", ""},
		{"inject", "stringArray", "[]", ""},
		{"compare", "bool", "false", ""},
		{"diff", "bool", "false", ""},
		{"impact", "bool", "false", ""},

		// Source.
		{"batch", "string", "", "b"},

		// Configuration.
		{"config", "string", "", "c"},

		// Info.
		{"version", "bool", "false", ""},
		{"help", "bool", "false", "h"},
	}

	fs := registerFlags()

	// Verify every expected flag exists with correct metadata.
	expectedNames := make(map[string]bool, len(expected))
	for _, spec := range expected {
		expectedNames[spec.name] = true

		f := fs.Lookup(spec.name)
		if !assert.NotNilf(t, f, "flag --%s must be registered", spec.name) {
			continue
		}
		assert.Equal(t, spec.valueType, f.Value.Type(),
			"flag --%s type", spec.name)
		assert.Equal(t, spec.defValue, f.DefValue,
			"flag --%s default", spec.name)
		assert.Equal(t, spec.shorthand, f.Shorthand,
			"flag --%s shorthand", spec.name)
	}

	// Verify no unexpected flags exist. Hidden --no-<name> counterparts of
	// boolean flags are expected and excluded from this check.
	fs.VisitAll(func(f *pflag.Flag) {
		if strings.HasPrefix(f.Name, "no-") && expectedNames[strings.TrimPrefix(f.Name, "no-")] {
			return
		}
		assert.True(t, expectedNames[f.Name],
			"unexpected flag --%s registered", f.Name)
	})
}

func TestHumanizeFlagError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		wantMsg string
		wantNil bool
	}{
		{
			name:    "nil error returns nil",
			err:     nil,
			wantNil: true,
		},
		{
			name:    "integer parse error for expiry-warning-days",
			err:     fmt.Errorf(`invalid argument "a" for "--expiry-warning-days" flag: strconv.ParseInt: parsing "a": invalid syntax`),
			wantMsg: `--expiry-warning-days requires an integer value, got "a"`,
		},
		{
			name:    "boolean parse error",
			err:     fmt.Errorf(`invalid argument "maybe" for "--verify-revocation" flag: strconv.ParseBool: parsing "maybe": invalid syntax`),
			wantMsg: `--verify-revocation requires a boolean value (true/false), got "maybe"`,
		},
		{
			name:    "float parse error",
			err:     fmt.Errorf(`invalid argument "abc" for "--threshold" flag: strconv.ParseFloat: parsing "abc": invalid syntax`),
			wantMsg: `--threshold requires a numeric value, got "abc"`,
		},
		{
			name:    "non-matching error passes through",
			err:     fmt.Errorf("something else"),
			wantMsg: "something else",
		},
		{
			name:    "unknown flag error passes through",
			err:     fmt.Errorf("unknown flag: --nonexistent"),
			wantMsg: "unknown flag: --nonexistent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := humanizeFlagError(tt.err)
			if tt.wantNil {
				assert.Nil(t, got, "expected nil error")
				return
			}
			require.NotNil(t, got, "expected non-nil error")
			assert.Equal(t, tt.wantMsg, got.Error())
		})
	}
}

func TestValidateThemeName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{name: "empty is valid", input: "", wantErr: false},
		{name: "classic is valid", input: "classic", wantErr: false},
		{name: "terse is valid", input: "terse", wantErr: false},
		{name: "minimal is valid", input: "minimal", wantErr: false},
		{name: "default is invalid", input: "default", wantErr: true, errMsg: "unknown theme"},
		{name: "unknown is invalid", input: "fancy", wantErr: true, errMsg: "unknown theme"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateThemeName(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateColorMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "empty is valid", input: "", wantErr: false},
		{name: "auto is valid", input: "auto", wantErr: false},
		{name: "always is valid", input: "always", wantErr: false},
		{name: "never is valid", input: "never", wantErr: false},
		{name: "yes is invalid", input: "yes", wantErr: true},
		{name: "true is invalid", input: "true", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateColorMode(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unknown color mode")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "empty is valid", input: "", wantErr: false},
		{name: "tree is valid", input: "tree", wantErr: false},
		{name: "json is valid", input: "json", wantErr: false},
		{name: "yaml is invalid", input: "yaml", wantErr: true},
		{name: "xml is invalid", input: "xml", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateFormat(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unknown format")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigLayeringPrecedence(t *testing.T) {
	t.Parallel()

	defaults := config.DefaultConfig()

	tests := []struct {
		name     string
		tomlBody string   // TOML content (empty = no file)
		args     []string // CLI args to parse
		check    func(*config.Config) bool
	}{
		// String (connect-timeout): default layer.
		{
			name:  "string/default",
			args:  []string{},
			check: func(c *config.Config) bool { return c.Connection.ConnectTimeout == defaults.Connection.ConnectTimeout },
		},
		// String (connect-timeout): config layer overrides default.
		{
			name:     "string/config",
			tomlBody: "[connection]\nconnect_timeout = \"99s\"\n",
			args:     []string{},
			check:    func(c *config.Config) bool { return c.Connection.ConnectTimeout == "99s" },
		},
		// String (connect-timeout): flag overrides config.
		{
			name:     "string/flag",
			tomlBody: "[connection]\nconnect_timeout = \"99s\"\n",
			args:     []string{"--connect-timeout", "5s"},
			check:    func(c *config.Config) bool { return c.Connection.ConnectTimeout == "5s" },
		},
		// Int (max-depth): default layer.
		{
			name:  "int/default",
			args:  []string{},
			check: func(c *config.Config) bool { return c.Validation.MaxDepth == defaults.Validation.MaxDepth },
		},
		// Int (max-depth): config layer overrides default.
		{
			name:     "int/config",
			tomlBody: "[validation]\nmax_depth = 42\n",
			args:     []string{},
			check:    func(c *config.Config) bool { return c.Validation.MaxDepth == 42 },
		},
		// Int (max-depth): flag overrides config.
		{
			name:     "int/flag",
			tomlBody: "[validation]\nmax_depth = 42\n",
			args:     []string{"--max-depth", "7"},
			check:    func(c *config.Config) bool { return c.Validation.MaxDepth == 7 },
		},
		// Bool (verify-signatures): default layer.
		{
			name: "bool/default",
			args: []string{},
			check: func(c *config.Config) bool {
				return c.Validation.VerifySignatures == defaults.Validation.VerifySignatures
			},
		},
		// Bool (verify-signatures): config layer overrides default.
		{
			name:     "bool/config",
			tomlBody: "[validation]\nverify_signatures = false\n",
			args:     []string{},
			check:    func(c *config.Config) bool { return !c.Validation.VerifySignatures },
		},
		// Bool (verify-signatures): flag overrides config.
		{
			name:     "bool/flag",
			tomlBody: "[validation]\nverify_signatures = false\n",
			args:     []string{"--verify-signatures=true"},
			check:    func(c *config.Config) bool { return c.Validation.VerifySignatures },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cfg *config.Config
			if tt.tomlBody != "" {
				dir := t.TempDir()
				cfgPath := filepath.Join(dir, "config.toml")
				require.NoError(t, os.WriteFile(cfgPath, []byte(tt.tomlBody), 0o600))
				var err error
				cfg, err = config.LoadConfig(cfgPath)
				require.NoError(t, err)
			} else {
				cfg = config.DefaultConfig()
			}

			fs := registerFlags()
			require.NoError(t, fs.Parse(tt.args))
			applyFlagOverrides(cfg, fs)

			assert.True(t, tt.check(cfg), "layering check failed for %s", tt.name)
		})
	}
}

func TestRegisterNoBoolFlags_CreatesHiddenCounterparts(t *testing.T) {
	t.Parallel()

	fs := registerFlags()

	// Collect all defaults-to-true bool flag names. Only these get --no-*
	// counterparts (defaults-to-false flags are already in the "off" state).
	var trueNames []string
	var falseNames []string
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Value.Type() == "bool" && !strings.HasPrefix(f.Name, "no-") {
			if f.DefValue == "true" {
				trueNames = append(trueNames, f.Name)
			} else {
				falseNames = append(falseNames, f.Name)
			}
		}
	})

	require.NotEmpty(t, trueNames, "expected at least one defaults-to-true boolean flag")

	for _, name := range trueNames {
		noName := "no-" + name
		f := fs.Lookup(noName)
		if !assert.NotNilf(t, f, "expected hidden --%s flag for --%s", noName, name) {
			continue
		}
		assert.Equal(t, "bool", f.Value.Type(), "--%s type", noName)
		assert.Equal(t, "false", f.DefValue, "--%s default", noName)
		assert.True(t, f.Hidden, "--%s should be hidden", noName)
	}

	// Defaults-to-false flags should NOT have --no-* counterparts.
	for _, name := range falseNames {
		noName := "no-" + name
		assert.Nilf(t, fs.Lookup(noName), "--%s should not exist for defaults-to-false --%s", noName, name)
	}
}

func TestResolveNoBoolFlags_SetsPositiveToFalse(t *testing.T) {
	t.Parallel()

	fs := registerFlags()
	err := fs.Parse([]string{"--no-verify-expiry"})
	require.NoError(t, err)

	resolveNoBoolFlags(fs)

	val, err := fs.GetBool("verify-expiry")
	require.NoError(t, err)
	assert.False(t, val, "--verify-expiry should be false after --no-verify-expiry")
	assert.True(t, fs.Changed("verify-expiry"), "--verify-expiry should be marked as changed")
}

func TestResolveNoBoolFlags_OverridesConfigFile(t *testing.T) {
	t.Parallel()

	// Write a config that enables verify-expiry.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("[validation]\nverify_expiry = true\n"), 0o600))

	cfg, err := config.LoadConfig(cfgPath)
	require.NoError(t, err)
	require.True(t, cfg.Validation.VerifyExpiry, "config must enable verify-expiry")

	// Parse with --no-verify-expiry.
	fs := registerFlags()
	err = fs.Parse([]string{"--no-verify-expiry"})
	require.NoError(t, err)
	resolveNoBoolFlags(fs)
	applyFlagOverrides(cfg, fs)

	assert.False(t, cfg.Validation.VerifyExpiry, "--no-verify-expiry should override config true")
}

func TestValidateSimulationFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		flags     nonConfigFlags
		format    string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid with exclusion and compare",
			flags:   nonConfigFlags{excludeCN: []string{"Old CA"}, compare: true},
			format:  config.FormatTree,
			wantErr: false,
		},
		{
			name:    "valid no simulation flags",
			flags:   nonConfigFlags{},
			format:  config.FormatTree,
			wantErr: false,
		},
		{
			name:      "compare without exclusion or validation-time",
			flags:     nonConfigFlags{compare: true},
			format:    config.FormatTree,
			wantErr:   true,
			errSubstr: "--compare requires at least one simulation flag",
		},
		{
			name:      "impact without exclusion or validation-time",
			flags:     nonConfigFlags{impact: true},
			format:    config.FormatTree,
			wantErr:   true,
			errSubstr: "--impact requires at least one simulation flag",
		},
		{
			name:      "diff without exclusion or validation-time",
			flags:     nonConfigFlags{diff: true},
			format:    config.FormatTree,
			wantErr:   true,
			errSubstr: "--diff requires at least one simulation flag",
		},
		{
			name:      "diff and compare mutually exclusive",
			flags:     nonConfigFlags{excludeCN: []string{"CA"}, diff: true, compare: true},
			format:    config.FormatTree,
			wantErr:   true,
			errSubstr: "--diff and --compare are mutually exclusive",
		},
		{
			name:      "diff not supported with JSON format",
			flags:     nonConfigFlags{excludeCN: []string{"CA"}, diff: true},
			format:    config.FormatJSON,
			wantErr:   true,
			errSubstr: "--diff is not supported with JSON format",
		},
		{
			name:      "impact not supported with JSON format",
			flags:     nonConfigFlags{excludeCN: []string{"CA"}, impact: true},
			format:    config.FormatJSON,
			wantErr:   true,
			errSubstr: "--impact is not supported with JSON format",
		},
		{
			name:    "compare supported with JSON format",
			flags:   nonConfigFlags{excludeCN: []string{"CA"}, compare: true},
			format:  config.FormatJSON,
			wantErr: false,
		},
		{
			name:      "invalid validation-time format",
			flags:     nonConfigFlags{validationTimeRaw: "not-a-date"},
			format:    config.FormatTree,
			wantErr:   true,
			errSubstr: "invalid --validation-time",
		},
		{
			name:      "compare with only validation-time is valid",
			flags:     nonConfigFlags{validationTimeRaw: "2025-01-15T12:00:00Z", compare: true},
			format:    config.FormatTree,
			wantErr:   false,
			errSubstr: "",
		},
		{
			name:      "impact with only validation-time is valid",
			flags:     nonConfigFlags{validationTimeRaw: "2025-01-15T12:00:00Z", impact: true},
			format:    config.FormatTree,
			wantErr:   false,
			errSubstr: "",
		},
		{
			name:      "diff with only validation-time is valid",
			flags:     nonConfigFlags{validationTimeRaw: "2025-01-15T12:00:00Z", diff: true},
			format:    config.FormatTree,
			wantErr:   false,
			errSubstr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateSimulationFlags(&tt.flags, tt.format)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestHumanizeNeedsArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		suffix    string
		wantParts []string
	}{
		{
			name:      "long form fields flag",
			suffix:    "--fields",
			wantParts: []string{"requires a value", "valid values"},
		},
		{
			name:      "long form theme flag",
			suffix:    "--theme",
			wantParts: []string{"requires a value", "valid values"},
		},
		{
			name:      "long form color flag",
			suffix:    "--color",
			wantParts: []string{"requires a value", "valid values"},
		},
		{
			name:      "long form format flag",
			suffix:    "--format",
			wantParts: []string{"requires a value", "valid values"},
		},
		{
			name:      "short form f flag",
			suffix:    "'f' in -f",
			wantParts: []string{"--fields", "requires a value"},
		},
		{
			name:      "long form unknown flag",
			suffix:    "--batch",
			wantParts: []string{"--batch", "requires a value"},
		},
		{
			name:      "short form unknown shorthand",
			suffix:    "'x' in -x",
			wantParts: []string{needsArgPrefix},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := humanizeNeedsArg(tt.suffix)
			require.Error(t, err)
			msg := err.Error()
			for _, part := range tt.wantParts {
				assert.Contains(t, msg, part, "error message should contain %q", part)
			}
		})
	}
}

func TestFlagValueHint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		flagName  string
		wantEmpty bool
		wantPart  string
	}{
		{name: "fields has valid values", flagName: "fields", wantPart: "valid values"},
		{name: "theme has valid values", flagName: "theme", wantPart: "valid values"},
		{name: "color has valid values", flagName: "color", wantPart: "valid values"},
		{name: "format has valid values", flagName: "format", wantPart: "valid values"},
		{name: "unknown is empty", flagName: "unknown", wantEmpty: true},
		{name: "batch is empty", flagName: "batch", wantEmpty: true},
		{name: "connect-timeout is empty", flagName: "connect-timeout", wantEmpty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := flagValueHint(tt.flagName)
			if tt.wantEmpty {
				assert.Empty(t, got, "flagValueHint(%q) should be empty", tt.flagName)
				return
			}
			assert.Contains(t, got, tt.wantPart, "flagValueHint(%q) should contain %q", tt.flagName, tt.wantPart)
		})
	}
}

func TestShorthandLongName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		suffix string
		want   string
	}{
		{name: "f maps to fields", suffix: "'f' in -f", want: "fields"},
		{name: "x has no mapping", suffix: "'x' in -x", want: ""},
		{name: "invalid format", suffix: "invalid", want: ""},
		{name: "empty string", suffix: "", want: ""},
		{name: "too short", suffix: "'f", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := shorthandLongName(tt.suffix)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestShorthandLongName_MatchesRegisteredFlags verifies that every shorthand
// mapping in shorthandLongName corresponds to an actual registered flag with
// a shorthand. This catches drift when flags are added or renamed.
func TestShorthandLongName_MatchesRegisteredFlags(t *testing.T) {
	t.Parallel()

	fs := registerFlags()

	// Build the set of shorthand-to-long-name from the registered FlagSet.
	registered := make(map[byte]string)
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Shorthand != "" {
			registered[f.Shorthand[0]] = f.Name
		}
	})

	// Every shorthand in shorthandLongName must match the FlagSet.
	shorthands := []byte{'b', 'c', 'f'}
	for _, sh := range shorthands {
		suffix := fmt.Sprintf("'%c' in -%c", sh, sh)
		got := shorthandLongName(suffix)
		if got == "" {
			t.Errorf("shorthandLongName has no mapping for %q but registerFlags registers it as %q", string(sh), registered[sh])
			continue
		}
		regName, ok := registered[sh]
		if !ok {
			t.Errorf("shorthandLongName maps %q to %q but registerFlags has no flag with that shorthand", string(sh), got)
			continue
		}
		assert.Equal(t, regName, got, "shorthandLongName(%q) should match registered flag name", string(sh))
	}
}

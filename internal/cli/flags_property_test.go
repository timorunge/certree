package cli

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"github.com/timorunge/certree/internal/config"
)

// configBackedFlag describes a config-backed flag and how to read/write its
// corresponding config field.
type configBackedFlag struct {
	name     string // flag name
	flagType string // "string", "bool", "int"
	// getField returns the current value of the config field as a string.
	getField func(cfg *config.Config) string
	// testValue is a non-default value to set via the flag.
	testValue string
}

// configBackedFlags returns the complete list of config-backed flags with
// their config field accessors and a non-default test value for each.
func configBackedFlags() []configBackedFlag {
	return []configBackedFlag{
		// Connection.
		{name: "connect-timeout", flagType: "string", testValue: "99s",
			getField: func(c *config.Config) string { return c.Connection.ConnectTimeout }},
		{name: "fetch-timeout", flagType: "string", testValue: "88s",
			getField: func(c *config.Config) string { return c.Connection.FetchTimeout }},
		{name: "sni", flagType: "string", testValue: "test.host",
			getField: func(c *config.Config) string { return c.Connection.SNI }},
		{name: "client-cert", flagType: "string", testValue: "/prop/client.pem",
			getField: func(c *config.Config) string { return c.Connection.ClientCert }},
		{name: "client-key", flagType: "string", testValue: "/prop/client.key",
			getField: func(c *config.Config) string { return c.Connection.ClientKey }},
		{name: "aia-fetch", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Connection.AIAFetch) }},
		{name: "aia-force", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Connection.AIAForce) }},
		{name: "aia-timeout", flagType: "string", testValue: "15s",
			getField: func(c *config.Config) string { return c.Connection.AIATimeout }},
		{name: "allow-private-networks", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Connection.AllowPrivateNetworks) }},

		// Validation.
		{name: "max-depth", flagType: "int", testValue: "42",
			getField: func(c *config.Config) string { return strconv.Itoa(c.Validation.MaxDepth) }},
		{name: "skip-invalid", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Validation.SkipInvalid) }},
		{name: "verify-revocation", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Validation.VerifyRevocation) }},
		{name: "revocation-fail-open", flagType: "bool", testValue: "false",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Validation.RevocationFailOpen) }},
		{name: "verify-signatures", flagType: "bool", testValue: "false",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Validation.VerifySignatures) }},
		{name: "verify-expiry", flagType: "bool", testValue: "false",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Validation.VerifyExpiry) }},
		{name: "verify-hostname", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Validation.VerifyHostname) }},
		{name: "verify-eku", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Validation.VerifyEKU) }},
		{name: "verify-name-constraints", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Validation.VerifyNameConstraints) }},
		{name: "hostname", flagType: "string", testValue: "prop.example.com",
			getField: func(c *config.Config) string { return c.Validation.Hostname }},
		{name: "expiry-warning-days", flagType: "int", testValue: "77",
			getField: func(c *config.Config) string { return strconv.Itoa(c.Validation.ExpiryWarningDays) }},
		{name: "max-certificates", flagType: "int", testValue: "7777",
			getField: func(c *config.Config) string { return strconv.Itoa(c.Validation.MaxCertificates) }},
		{name: "max-validity-days", flagType: "int", testValue: "365",
			getField: func(c *config.Config) string { return strconv.Itoa(c.Validation.MaxValidityDays) }},

		// Render.
		{name: "theme", flagType: "string", testValue: "minimal",
			getField: func(c *config.Config) string { return c.Render.Theme }},
		{name: "fields", flagType: "string", testValue: "fingerprint,serial",
			getField: func(c *config.Config) string { return c.Render.Fields }},
		{name: "reverse", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Render.Reverse) }},
		{name: "annotations", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Render.Annotations) }},
		{name: "expand", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Render.Expand) }},
		{name: "wrap", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.Render.Wrap) }},

		// Output. testValue for format must differ from nonDefaultConfig's "json".
		{name: "format", flagType: "string", testValue: "tree",
			getField: func(c *config.Config) string { return c.Output.Format }},
		{name: "color", flagType: "string", testValue: "never",
			getField: func(c *config.Config) string { return c.Output.Color }},

		// Trust store.
		{name: "prefer-custom-roots", flagType: "bool", testValue: "true",
			getField: func(c *config.Config) string { return strconv.FormatBool(c.TrustStore.PreferCustomRoots) }},
		{name: "trust-bundle", flagType: "string", testValue: "/prop/bundle",
			getField: func(c *config.Config) string { return c.TrustStore.TrustBundle }},
		{name: "system-roots", flagType: "string", testValue: "/prop/roots",
			getField: func(c *config.Config) string { return c.TrustStore.SystemRoots }},
	}
}

// nonDefaultConfig returns a Config where every field has a non-default,
// non-zero value so that unset flags can be detected (they must not zero
// out existing values).
func nonDefaultConfig() *config.Config {
	return &config.Config{
		Connection: config.ConnectionConfig{
			ConnectTimeout:       "30s",
			FetchTimeout:         "20s",
			SNI:                  "original.host",
			ClientCert:           "/original/client.pem",
			ClientKey:            "/original/client.key",
			AIAFetch:             true,
			AIAForce:             true,
			AIATimeout:           "7s",
			AllowPrivateNetworks: false,
		},
		Validation: config.ValidationConfig{
			MaxDepth:              5,
			SkipInvalid:           true,
			VerifyRevocation:      true,
			RevocationFailOpen:    true,
			VerifySignatures:      true,
			VerifyExpiry:          true,
			VerifyHostname:        true,
			VerifyEKU:             false,
			VerifyNameConstraints: false,
			Hostname:              "original.com",
			ExpiryWarningDays:     45,
			MaxCertificates:       500,
			MaxValidityDays:       730,
		},
		Render: config.RenderConfig{
			Theme:       "terse",
			Fields:      "all",
			Reverse:     true,
			Annotations: false,
			Expand:      false,
			Wrap:        false,
		},
		Output: config.OutputConfig{
			Format: "json",
			Color:  "always",
		},
		TrustStore: config.TrustStoreConfig{
			TrustBundle:       "/original/bundle",
			SystemRoots:       "/original/roots",
			PreferCustomRoots: true,
		},
	}
}

// buildFlagArgs constructs CLI arguments that set the given subset of
// config-backed flags to their testValue.
func buildFlagArgs(subset []configBackedFlag) []string {
	args := make([]string, 0, len(subset)*2)
	for _, f := range subset {
		switch f.flagType {
		case "bool":
			args = append(args, fmt.Sprintf("--%s=%s", f.name, f.testValue))
		default:
			args = append(args, "--"+f.name, f.testValue)
		}
	}
	return args
}

func TestProperty_FlagOverridesApplyOnlyExplicitlySetFlags(t *testing.T) {
	t.Parallel()

	allFlags := configBackedFlags()

	parameters := gopter.DefaultTestParameters()
	if testing.Short() {
		parameters.MinSuccessfulTests = 10
	} else {
		parameters.MinSuccessfulTests = 100
	}

	properties := gopter.NewProperties(parameters)

	// Generate a random bitmask selecting a subset of config-backed flags.
	// With 31 flags, an int64 bitmask covers the full power set.
	subsetGen := gen.Int64Range(0, (1<<len(allFlags))-1)

	properties.Property("only explicitly-set flags modify config", prop.ForAll(
		func(mask int64) bool {
			// Build the subset from the bitmask.
			var subset []configBackedFlag
			setNames := make(map[string]bool)
			for i, f := range allFlags {
				if mask&(1<<i) != 0 {
					subset = append(subset, f)
					setNames[f.name] = true
				}
			}

			// Start from a non-default config so unset flags are detectable.
			cfg := nonDefaultConfig()
			original := nonDefaultConfig()

			fs := registerFlags()
			args := buildFlagArgs(subset)
			if err := fs.Parse(args); err != nil {
				return false
			}
			applyFlagOverrides(cfg, fs)

			// Check every config-backed flag.
			for _, f := range allFlags {
				got := f.getField(cfg)
				orig := f.getField(original)

				if setNames[f.name] {
					// Explicitly set: must equal the test value.
					if got != f.testValue {
						return false
					}
				} else {
					// Not set: must equal the original value.
					if got != orig {
						return false
					}
				}
			}
			return true
		},
		subsetGen,
	))

	properties.TestingRun(t)
}

package config

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

func nonEmptyAlphaGen() gopter.Gen {
	return gen.AlphaString().SuchThat(func(s string) bool {
		return s != ""
	})
}

func nonZeroIntGen() gopter.Gen {
	return gen.IntRange(1, 100000)
}

func connectionConfigGen() gopter.Gen {
	return gopter.CombineGens(
		nonEmptyAlphaGen(), // ConnectTimeout.
		nonEmptyAlphaGen(), // FetchTimeout.
		nonEmptyAlphaGen(), // SNI.
		gen.Bool(),         // AIAFetch.
		gen.Bool(),         // AIAForce.
		nonEmptyAlphaGen(), // AIATimeout.
		nonEmptyAlphaGen(), // ClientCert.
		nonEmptyAlphaGen(), // ClientKey.
		gen.Bool(),         // AllowPrivateNetworks.
	).Map(func(v []any) ConnectionConfig {
		return ConnectionConfig{
			ConnectTimeout:       v[0].(string),
			FetchTimeout:         v[1].(string),
			SNI:                  v[2].(string),
			AIAFetch:             v[3].(bool),
			AIAForce:             v[4].(bool),
			AIATimeout:           v[5].(string),
			ClientCert:           v[6].(string),
			ClientKey:            v[7].(string),
			AllowPrivateNetworks: v[8].(bool),
		}
	})
}

func validationConfigGen() gopter.Gen {
	return gopter.CombineGens(
		nonZeroIntGen(),    // MaxDepth.
		gen.Bool(),         // SkipInvalid.
		gen.Bool(),         // VerifyRevocation.
		gen.Bool(),         // RevocationFailOpen.
		gen.Bool(),         // VerifySignatures.
		gen.Bool(),         // VerifyExpiry.
		gen.Bool(),         // VerifyHostname.
		gen.Bool(),         // VerifyEKU.
		gen.Bool(),         // VerifyNameConstraints.
		nonEmptyAlphaGen(), // Hostname.
		nonZeroIntGen(),    // ExpiryWarningDays.
		nonZeroIntGen(),    // MaxCertificates.
		nonZeroIntGen(),    // MaxValidityDays.
	).Map(func(v []any) ValidationConfig {
		return ValidationConfig{
			MaxDepth:              v[0].(int),
			SkipInvalid:           v[1].(bool),
			VerifyRevocation:      v[2].(bool),
			RevocationFailOpen:    v[3].(bool),
			VerifySignatures:      v[4].(bool),
			VerifyExpiry:          v[5].(bool),
			VerifyHostname:        v[6].(bool),
			VerifyEKU:             v[7].(bool),
			VerifyNameConstraints: v[8].(bool),
			Hostname:              v[9].(string),
			ExpiryWarningDays:     v[10].(int),
			MaxCertificates:       v[11].(int),
			MaxValidityDays:       v[12].(int),
		}
	})
}

func renderConfigGen() gopter.Gen {
	return gopter.CombineGens(
		nonEmptyAlphaGen(), // Theme.
		nonEmptyAlphaGen(), // Fields.
		gen.Bool(),         // Reverse.
		gen.Bool(),         // Annotations.
		gen.Bool(),         // Expand.
		gen.Bool(),         // Wrap.
	).Map(func(v []any) RenderConfig {
		return RenderConfig{
			Theme:       v[0].(string),
			Fields:      v[1].(string),
			Reverse:     v[2].(bool),
			Annotations: v[3].(bool),
			Expand:      v[4].(bool),
			Wrap:        v[5].(bool),
		}
	})
}

func outputConfigGen() gopter.Gen {
	return gopter.CombineGens(
		nonEmptyAlphaGen(), // Format.
		nonEmptyAlphaGen(), // Color.
		nonEmptyAlphaGen(), // LogLevel.
	).Map(func(v []any) OutputConfig {
		return OutputConfig{
			Format:   v[0].(string),
			Color:    v[1].(string),
			LogLevel: v[2].(string),
		}
	})
}

func trustStoreConfigGen() gopter.Gen {
	return gopter.CombineGens(
		nonEmptyAlphaGen(), // TrustBundle.
		nonEmptyAlphaGen(), // SystemRoots.
		gen.Bool(),         // PreferCustomRoots.
	).Map(func(v []any) TrustStoreConfig {
		return TrustStoreConfig{
			TrustBundle:       v[0].(string),
			SystemRoots:       v[1].(string),
			PreferCustomRoots: v[2].(bool),
		}
	})
}

func configGen() gopter.Gen {
	return gopter.CombineGens(
		connectionConfigGen(),
		validationConfigGen(),
		renderConfigGen(),
		outputConfigGen(),
		trustStoreConfigGen(),
	).Map(func(v []any) *Config {
		return &Config{
			Connection: v[0].(ConnectionConfig),
			Validation: v[1].(ValidationConfig),
			Render:     v[2].(RenderConfig),
			Output:     v[3].(OutputConfig),
			TrustStore: v[4].(TrustStoreConfig),
		}
	})
}

func TestProperty_ConfigTOMLRoundTrip(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	if testing.Short() {
		parameters.MinSuccessfulTests = 10
	}

	properties := gopter.NewProperties(parameters)

	properties.Property("Config TOML round-trip preserves all fields", prop.ForAll(
		func(original *Config) bool {
			var buf bytes.Buffer
			if err := toml.NewEncoder(&buf).Encode(original); err != nil {
				return false
			}

			var restored Config
			if _, err := toml.Decode(buf.String(), &restored); err != nil {
				return false
			}

			return reflect.DeepEqual(*original, restored)
		},
		configGen(),
	))

	properties.TestingRun(t)
}

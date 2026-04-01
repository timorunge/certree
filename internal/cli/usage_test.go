package cli

import (
	"bytes"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestShowDefaultValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		flagName string
		flagType string // "string", "bool", "int"
		defValue string
		want     bool
	}{
		{name: "string flag with non-empty default", flagName: "connect-timeout", flagType: "string", defValue: "5s", want: true},
		{name: "string flag with empty default", flagName: "sni", flagType: "string", defValue: "", want: false},
		{name: "int flag with zero default", flagName: "max-validity-days", flagType: "int", defValue: "0", want: false},
		{name: "int flag with non-zero default", flagName: "max-depth", flagType: "int", defValue: "10", want: true},
		{name: "bool flag with true default", flagName: "verify-expiry", flagType: "bool", defValue: "true", want: true},
		{name: "verbose is excluded by name", flagName: "verbose", flagType: "int", defValue: "1", want: false},
		{name: "compare is excluded by name", flagName: "compare", flagType: "bool", defValue: "false", want: false},
		{name: "diff is excluded by name", flagName: "diff", flagType: "bool", defValue: "true", want: false},
		{name: "impact is excluded by name", flagName: "impact", flagType: "bool", defValue: "true", want: false},
		{name: "quiet is excluded by name", flagName: "quiet", flagType: "bool", defValue: "false", want: false},
		{name: "help is excluded by name", flagName: "help", flagType: "bool", defValue: "true", want: false},
		{name: "version is excluded by name", flagName: "version", flagType: "bool", defValue: "true", want: false},
		{name: "slice default is excluded", flagName: "filter-cn", flagType: "string", defValue: "[]", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			switch tt.flagType {
			case "string":
				fs.String(tt.flagName, tt.defValue, "test flag")
			case "bool":
				val := tt.defValue == "true"
				fs.Bool(tt.flagName, val, "test flag")
			case "int":
				// Register with a dummy default; override DefValue below.
				fs.Int(tt.flagName, 0, "test flag")
			}

			f := fs.Lookup(tt.flagName)
			// Override DefValue to match the test case exactly.
			f.DefValue = tt.defValue

			assert.Equal(t, tt.want, showDefaultValue(f))
		})
	}
}

func TestWriteGroupedOptions(t *testing.T) {
	t.Parallel()

	fs := registerFlags()
	var buf bytes.Buffer
	writeGroupedOptions(fs, &buf)
	output := buf.String()

	assert.NotEmpty(t, output, "writeGroupedOptions should produce non-empty output")

	// Verify the OPTIONS header is present.
	assert.Contains(t, output, "OPTIONS:", "output must contain OPTIONS header")

	// Verify each group heading appears in the output.
	expectedGroups := []string{
		"Source:", "Configuration:", "Trust Store:",
		"Connection:", "Validation:", "Display:",
		"Output:", "Simulation:", "Info:",
	}
	for _, group := range expectedGroups {
		assert.Contains(t, output, group, "output must contain group heading %q", group)
	}

	// Verify a few representative flags from different groups appear.
	representativeFlags := []string{
		"--batch", "--config", "--trust-bundle",
		"--connect-timeout", "--verify-expiry", "--fields",
		"--format", "--compare", "--help",
	}
	for _, flag := range representativeFlags {
		assert.Contains(t, output, flag, "output must contain flag %q", flag)
	}

	assert.Contains(t, output, "(default:", "output should contain at least one default value annotation")
}

func TestWriteGroupedOptions_HidesNoBoolFlags(t *testing.T) {
	t.Parallel()

	fs := registerFlags()
	var buf bytes.Buffer
	writeGroupedOptions(fs, &buf)
	output := buf.String()

	// Hidden --no-<name> flags should not appear in the output.
	assert.NotContains(t, output, "--no-verify-expiry", "hidden --no-verify-expiry must not appear in usage")
	assert.NotContains(t, output, "--no-verify-signatures", "hidden --no-verify-signatures must not appear in usage")
}

func TestWrapDescription(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		desc      string
		indent    int
		termWidth int
		want      string
	}{
		{
			name:      "short description fits on one line",
			desc:      "Show help message",
			indent:    34,
			termWidth: 80,
			want:      "Show help message",
		},
		{
			name:      "long description wraps at word boundary",
			desc:      "Certificate fields to display: aia, algorithm, all, crl, diagnostics, extensions, fingerprint, issuer, san, serial, source, subject, trust-store, validity",
			indent:    34,
			termWidth: 80,
			want:      "Certificate fields to display: aia, algorithm,\n                                  all, crl, diagnostics, extensions,\n                                  fingerprint, issuer, san, serial, source,\n                                  subject, trust-store, validity",
		},
		{
			name:      "narrow terminal disables wrapping",
			desc:      "Some long description that would wrap",
			indent:    34,
			termWidth: 40,
			want:      "Some long description that would wrap",
		},
		{
			name:      "empty description",
			desc:      "",
			indent:    34,
			termWidth: 80,
			want:      "",
		},
		{
			name:      "single long word never broken",
			desc:      "superlongwordthatcannotbebrokenatall",
			indent:    34,
			termWidth: 50,
			want:      "superlongwordthatcannotbebrokenatall",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := wrapDescription(tt.desc, tt.indent, tt.termWidth)
			assert.Equal(t, tt.want, got)
		})
	}
}

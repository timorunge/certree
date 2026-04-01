package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/internal/render"
)

func TestFieldRegistry_Completeness(t *testing.T) {
	t.Parallel()

	showFields := []string{
		"ShowFingerprint", "ShowSerial", "ShowValidity", "ShowExtensions",
		"ShowSource", "ShowSubject", "ShowIssuer", "ShowSAN", "ShowTrustStore",
		"ShowAlgorithm", "ShowAIA", "ShowCRL", "ShowDiagnostics",
	}

	getBoolField := func(opts render.Options, field string) bool {
		switch field {
		case "ShowFingerprint":
			return opts.ShowFingerprint
		case "ShowSerial":
			return opts.ShowSerial
		case "ShowValidity":
			return opts.ShowValidity
		case "ShowExtensions":
			return opts.ShowExtensions
		case "ShowSource":
			return opts.ShowSource
		case "ShowSubject":
			return opts.ShowSubject
		case "ShowIssuer":
			return opts.ShowIssuer
		case "ShowSAN":
			return opts.ShowSAN
		case "ShowTrustStore":
			return opts.ShowTrustStore
		case "ShowAlgorithm":
			return opts.ShowAlgorithm
		case "ShowAIA":
			return opts.ShowAIA
		case "ShowCRL":
			return opts.ShowCRL
		case "ShowDiagnostics":
			return opts.ShowDiagnostics
		default:
			t.Fatalf("unknown field: %s", field)
			return false
		}
	}

	for _, fe := range fields {
		var opts render.Options
		fe.apply(&opts)

		setCount := 0
		for _, field := range showFields {
			if getBoolField(opts, field) {
				setCount++
			}
		}
		assert.Equal(t, 1, setCount,
			"fieldEntry %q apply should set exactly 1 Show* field, got %d", fe.name, setCount)
		assert.False(t, opts.ShowAll, "fieldEntry %q apply must not set ShowAll", fe.name)
		assert.False(t, opts.Impact, "fieldEntry %q apply must not set Impact", fe.name)
	}

	for _, field := range showFields {
		matchCount := 0
		for _, fe := range fields {
			var opts render.Options
			fe.apply(&opts)
			if getBoolField(opts, field) {
				matchCount++
			}
		}
		assert.Equal(t, 1, matchCount,
			"Show* field %q should have exactly 1 registry entry, got %d", field, matchCount)
	}
}

func TestParseFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		want      []string
		wantErr   bool
		errSubstr string
	}{
		{"valid single field", "fingerprint", []string{"fingerprint"}, false, ""},
		{"valid multiple fields", "fingerprint,serial", []string{"fingerprint", "serial"}, false, ""},
		{"all keyword", "all", []string{"all"}, false, ""},
		{"empty string", "", []string{}, false, ""},
		{"whitespace trimmed", " serial , san ", []string{"serial", "san"}, false, ""},
		{"unknown field", "foobar", nil, true, `unknown field(s) "foobar"`},
		{"duplicates removed", "serial,serial", []string{"serial"}, false, ""},
		{"mixed valid and invalid", "serial,foo,bar", nil, true, `"foo"`},
		{"all with others", "all,serial", []string{"all", "serial"}, false, ""},
		{"all thirteen fields", "fingerprint,serial,validity,extensions,source,subject,issuer,san,trust-store,algorithm,aia,crl,diagnostics",
			[]string{"fingerprint", "serial", "validity", "extensions", "source", "subject", "issuer", "san", "trust-store", "algorithm", "aia", "crl", "diagnostics"}, false, ""},
		{"only commas and spaces", " , , ", []string{}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseFields(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestApplyParsedFields_All(t *testing.T) {
	t.Parallel()

	var opts render.Options
	applyParsedFields(&opts, []string{"all"})

	assert.True(t, opts.ShowAll, "ShowAll must be set by applyParsedFields")
}

func TestApplyParsedFields_Single(t *testing.T) {
	t.Parallel()

	var opts render.Options
	applyParsedFields(&opts, []string{"serial"})

	assert.True(t, opts.ShowSerial, "ShowSerial should be true")
	assert.False(t, opts.ShowAll, "ShowAll should be false")
	assert.False(t, opts.ShowFingerprint, "ShowFingerprint should be false")
}

func TestApplyParsedFields_Empty(t *testing.T) {
	t.Parallel()

	var opts render.Options
	applyParsedFields(&opts, nil)

	assert.False(t, opts.ShowAll, "ShowAll should be false")
	assert.False(t, opts.ShowSerial, "ShowSerial should be false")
}

func TestSortedFieldNames(t *testing.T) {
	t.Parallel()

	result := sortedFieldNames()
	assert.Contains(t, result, "san")
	assert.Contains(t, result, "fingerprint")
	assert.Contains(t, result, "trust-store")
	assert.Contains(t, result, "all")
}

package certree

import (
	"crypto/x509/pkix"
	"encoding/json"
	"testing"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

func generateSimMetadataTestCert(t *testing.T) *Certificate {
	t.Helper()
	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "sim-test.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	return NewCertificate(cert, CertificateSource{Type: SourceTypeFile})
}

func TestTrustPath_SimulationMetadata(t *testing.T) {
	t.Parallel()

	wrapped := generateSimMetadataTestCert(t)
	fp := wrapped.FingerprintSHA256()

	type checkFunc func(*TrustPath, *Certificate) bool

	tests := []struct {
		name    string
		simMeta map[string]CertSimulationState
		check   checkFunc
		want    bool
	}{
		// IsExcluded cases.
		{"IsExcluded/nil metadata", nil, (*TrustPath).IsExcluded, false},
		{"IsExcluded/missing entry", map[string]CertSimulationState{}, (*TrustPath).IsExcluded, false},
		{"IsExcluded/excluded cert", map[string]CertSimulationState{fp: {IsExcluded: true}}, (*TrustPath).IsExcluded, true},
		{"IsExcluded/ghosted only", map[string]CertSimulationState{fp: {IsGhosted: true}}, (*TrustPath).IsExcluded, false},
		// IsGhosted cases.
		{"IsGhosted/nil metadata", nil, (*TrustPath).IsGhosted, false},
		{"IsGhosted/missing entry", map[string]CertSimulationState{}, (*TrustPath).IsGhosted, false},
		{"IsGhosted/ghosted cert", map[string]CertSimulationState{fp: {IsGhosted: true}}, (*TrustPath).IsGhosted, true},
		{"IsGhosted/excluded only", map[string]CertSimulationState{fp: {IsExcluded: true}}, (*TrustPath).IsGhosted, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := &TrustPath{
				Certificates:       []*Certificate{wrapped},
				SimulationMetadata: tt.simMeta,
			}
			if got := tt.check(path, wrapped); got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestPathStatus_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status PathStatus
		str    string
	}{
		{"trusted", PathTrusted, "trusted"},
		{"untrusted", PathUntrusted, "untrusted"},
		{"incomplete", PathIncomplete, "incomplete"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Marshal to JSON.
			data, err := json.Marshal(tt.status)
			if err != nil {
				t.Fatalf("Marshal PathStatus: %v", err)
			}

			// Unmarshal back.
			var got PathStatus
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal PathStatus: %v", err)
			}

			if got != tt.status {
				t.Errorf("round-trip: got %v, want %v", got, tt.status)
			}
		})
	}

	t.Run("unknown value", func(t *testing.T) {
		t.Parallel()

		var ps PathStatus
		err := json.Unmarshal([]byte(`"bogus"`), &ps)
		if err == nil {
			t.Fatal("expected error for unknown PathStatus value, got nil")
		}
	})
}

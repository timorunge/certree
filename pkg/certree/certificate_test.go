package certree

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

func TestSourceType_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sourceType SourceType
		str        string
	}{
		{"file", SourceTypeFile, "file"},
		{"remote", SourceTypeRemote, "remote"},
		{"stdin", SourceTypeStdin, "stdin"},
		{"aia", SourceTypeAIA, "aia"},
		{"url", SourceTypeURL, "url"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Marshal to JSON.
			data, err := json.Marshal(tt.sourceType)
			if err != nil {
				t.Fatalf("Marshal SourceType: %v", err)
			}

			// Unmarshal back.
			var got SourceType
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal SourceType: %v", err)
			}

			if got != tt.sourceType {
				t.Errorf("round-trip: got %v, want %v", got, tt.sourceType)
			}
		})
	}

}

func TestNewCertificate(t *testing.T) {
	t.Parallel()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(30 * 24 * time.Hour), // 30 days
	}
	x509Cert, _, err := testutil.GenerateSelfSignedCertUniqueKey(template)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	source := CertificateSource{
		Type:     SourceTypeFile,
		Location: "test.pem",
	}

	cert := NewCertificate(x509Cert, source)

	if len(cert.DER()) == 0 {
		t.Error("DER should not be empty")
	}

	if cert.PEM() == "" {
		t.Error("PEM should not be empty")
	}

	if cert.FingerprintSHA256() == "" {
		t.Error("FingerprintSHA256 should not be empty")
	}

	if cert.SerialNumber() == "" {
		t.Error("SerialNumber should not be empty")
	}

	if cert.CommonName() != "test.example.com" {
		t.Errorf("CommonName() = %q, want %q", cert.CommonName(), "test.example.com")
	}
}

func TestCertificate_IsSelfSigned(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		isSelfSigned bool
	}{
		{
			name:         "self-signed certificate",
			isSelfSigned: true,
		},
		{
			name:         "signed certificate",
			isSelfSigned: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var x509Cert *x509.Certificate
			var err error

			if tt.isSelfSigned {
				// Generate self-signed certificate
				template := testutil.CertificateTemplate{
					Subject: pkix.Name{
						CommonName: "test.example.com",
					},
				}
				x509Cert, _, err = testutil.GenerateSelfSignedCertUniqueKey(template)
			} else {
				// Generate a chain and use the end-entity cert
				var certs []*x509.Certificate
				certs, _, err = testutil.GenerateSimpleChain()
				if err == nil && len(certs) > 0 {
					x509Cert = certs[0] // End-entity cert
				}
			}

			if err != nil {
				t.Fatalf("Failed to generate test certificate: %v", err)
			}

			cert := NewCertificate(x509Cert, CertificateSource{
				Type:     SourceTypeFile,
				Location: "test.pem",
			})

			result := cert.IsSelfSigned()
			if result != tt.isSelfSigned {
				t.Errorf("Expected IsSelfSigned=%v, got %v", tt.isSelfSigned, result)
			}
		})
	}
}

func TestCertificate_MarshalJSON(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	wrapped := NewCertificate(cert, CertificateSource{
		Type:     SourceTypeFile,
		Location: "/path/to/cert.pem",
	})

	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("Failed to marshal certificate: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	expectedFields := []string{"subject", "issuer", "serial_number", "fingerprint_sha256", "not_before", "not_after", "is_ca", "source", "metadata"}
	for _, field := range expectedFields {
		if _, ok := result[field]; !ok {
			t.Errorf("Expected field %q not found in JSON", field)
		}
	}

	source, ok := result["source"].(map[string]any)
	if !ok {
		t.Fatal("Source field is not an object")
	}
	if source["type"] != "file" {
		t.Errorf("Expected source type 'file', got %v", source["type"])
	}
	if source["location"] != "/path/to/cert.pem" {
		t.Errorf("Expected source location '/path/to/cert.pem', got %v", source["location"])
	}
}

func TestJSON_TrustedLocationsAlwaysPresent(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "untrusted.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	wrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})

	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("Failed to marshal certificate: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	metadata, ok := result["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata field is missing or not an object")
	}

	// trusted_locations must be present even when empty.
	locations, ok := metadata["trusted_locations"]
	if !ok {
		t.Fatal("trusted_locations field is missing from JSON output")
	}

	locArray, ok := locations.([]any)
	if !ok {
		t.Fatalf("trusted_locations is not an array, got %T", locations)
	}

	if len(locArray) != 0 {
		t.Errorf("Expected empty trusted_locations array, got %v", locArray)
	}
}

func TestSourceTracking_MultiplePaths(t *testing.T) {
	t.Parallel()

	certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("Failed to generate chain: %v", err)
	}

	endEntity := NewCertificate(certs[0], CertificateSource{
		Type: SourceTypeRemote, Location: "example.com:443",
	})
	// Both intermediates wrap the same raw cert (same fingerprint). BuildChains
	// produces one deduplicated path -- two wrappers of the same DER are not
	// cross-signing and deduplicatePaths correctly collapses them.
	intermediate1 := NewCertificate(certs[1], CertificateSource{
		Type: SourceTypeFile, Location: "/path/to/intermediate1.pem",
	})
	intermediate2 := NewCertificate(certs[1], CertificateSource{
		Type: SourceTypeAIA, Location: "http://ca.example.com/intermediate2.crt",
	})
	root := NewCertificate(certs[2], CertificateSource{
		Type: SourceTypeFile, Location: "/path/to/root.pem",
	})

	certsWrapped := []*Certificate{endEntity, intermediate1, intermediate2, root}

	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
	ts.(*defaultTrustStore).systemRoots[root.FingerprintSHA256()] = root

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), certsWrapped, ts)
	if err != nil {
		t.Fatalf("BuildChains() error = %v", err)
	}

	if len(paths) == 0 {
		t.Fatalf("Expected at least one trust path, got 0")
	}

	for i, path := range paths {
		if path.Certificates[0].Source().Type != SourceTypeRemote {
			t.Errorf("Path %d: end-entity source type = %v, want %v", i, path.Certificates[0].Source().Type, SourceTypeRemote)
		}
	}
}

func TestSourceTracking_AnalysisPreservation(t *testing.T) {
	t.Parallel()

	certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("Failed to generate chain: %v", err)
	}

	sources := []struct {
		sourceType SourceType
		location   string
	}{
		{SourceTypeFile, "/path/to/cert.pem"},
		{SourceTypeAIA, "http://ca.example.com/intermediate.crt"},
		{SourceTypeFile, "/path/to/root.pem"},
	}

	certsWrapped := make([]*Certificate, len(certs))
	for i, cert := range certs {
		certsWrapped[i] = NewCertificate(cert, CertificateSource{
			Type: sources[i].sourceType, Location: sources[i].location,
		})
	}

	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
	root := certsWrapped[len(certsWrapped)-1]
	ts.(*defaultTrustStore).systemRoots[root.FingerprintSHA256()] = root

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), certsWrapped, ts)
	if err != nil {
		t.Fatalf("BuildChains() error = %v", err)
	}

	analysis := NewAnalysis(certsWrapped, paths, "test")

	for i, cert := range analysis.Certificates {
		if cert.Source().Type != sources[i].sourceType {
			t.Errorf("Certificate %d: source type = %v, want %v", i, cert.Source().Type, sources[i].sourceType)
		}
		if cert.Source().Location != sources[i].location {
			t.Errorf("Certificate %d: source location = %s, want %s", i, cert.Source().Location, sources[i].location)
		}
	}
}

func TestCertificate_MarshalJSON_NilRaw(t *testing.T) {
	t.Parallel()

	cert := &Certificate{raw: nil}
	data, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("MarshalJSON with nil raw = %s, want \"null\"", string(data))
	}
}

func TestCertificate_MarshalJSON_WithIPAddresses(t *testing.T) {
	t.Parallel()

	key := testutil.GetCachedKey()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ip-test.example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("::1")},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}

	wrapped := NewCertificate(x509Cert, CertificateSource{Type: SourceTypeFile})
	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	ips, ok := result["ip_addresses"].([]any)
	if !ok {
		t.Fatal("ip_addresses field missing or not an array")
	}
	if len(ips) != 2 {
		t.Errorf("expected 2 IP addresses, got %d", len(ips))
	}
}

func TestCertificate_WithTrustedLocationsImmutability(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "immutable.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	original := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})

	// Original should have empty trusted locations.
	if len(original.Metadata().TrustedLocations) != 0 {
		t.Fatalf("expected empty trusted locations on original, got %v", original.Metadata().TrustedLocations)
	}

	updated := original.WithTrustedLocations([]string{"system", "/etc/ssl/certs/ca.pem"})

	if len(updated.Metadata().TrustedLocations) != 2 {
		t.Fatalf("expected 2 trusted locations on updated, got %d", len(updated.Metadata().TrustedLocations))
	}
	if updated.Metadata().TrustedLocations[0] != "system" {
		t.Errorf("updated location[0] = %q, want %q", updated.Metadata().TrustedLocations[0], "system")
	}
	if updated.Metadata().TrustedLocations[1] != "/etc/ssl/certs/ca.pem" {
		t.Errorf("updated location[1] = %q, want %q", updated.Metadata().TrustedLocations[1], "/etc/ssl/certs/ca.pem")
	}

	if len(original.Metadata().TrustedLocations) != 0 {
		t.Errorf("original trusted locations modified: got %v, want empty", original.Metadata().TrustedLocations)
	}

	if original.FingerprintSHA256() != updated.FingerprintSHA256() {
		t.Errorf("fingerprint mismatch: original %s, updated %s", original.FingerprintSHA256(), updated.FingerprintSHA256())
	}

	if original == updated {
		t.Error("WithTrustedLocations should return a new Certificate, not the same pointer")
	}
}

func TestSourceType_UnmarshalJSON_Unknown(t *testing.T) {
	t.Parallel()

	var st SourceType
	err := json.Unmarshal([]byte(`"bogus"`), &st)
	if err == nil {
		t.Fatal("expected error for unknown SourceType value, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("errors.Is(err, ErrInvalidInput) = false; err = %v", err)
	}
}

func TestWithCertificateTime(t *testing.T) {
	t.Parallel()

	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := NewCertificate(raw, CertificateSource{}, WithCertificateTime(future))
	if !cert.Metadata().IsExpired {
		t.Error("expected cert to be expired with year 2099 reference time")
	}
}

func TestSecurityCertificate_PEMConcurrentAccess(t *testing.T) {
	t.Parallel()

	rawCert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{})
	require.NoError(t, err)

	cert := NewCertificate(rawCert, CertificateSource{Type: SourceTypeBytes})

	const goroutines = 32
	results := make([]string, goroutines)
	var wg sync.WaitGroup

	for i := range goroutines {
		idx := i
		wg.Go(func() {
			results[idx] = cert.PEM()
		})
	}

	wg.Wait()

	// sync.Once failure would produce partially written strings.
	first := results[0]
	assert.NotEmpty(t, first, "PEM should not be empty")
	for i, r := range results {
		assert.Equal(t, first, r, "goroutine %d saw different PEM", i)
	}
}

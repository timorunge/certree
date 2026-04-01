package certree

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// validatorMockTrustStore is a mock trust store that trusts certificates by fingerprint.
type validatorMockTrustStore struct {
	trusted map[string]bool
}

func (m *validatorMockTrustStore) IsTrusted(cert *Certificate) bool {
	return m.trusted[cert.FingerprintSHA256()]
}

func (m *validatorMockTrustStore) TrustedLocations(cert *Certificate) []string {
	if m.IsTrusted(cert) {
		return []string{"test"}
	}
	return nil
}

func (m *validatorMockTrustStore) LoadSystemRoots() error { return nil }

func (m *validatorMockTrustStore) LoadCustomRoots(_ string) error { return nil }

func (m *validatorMockTrustStore) FindIssuers(_ *Certificate) []*Certificate { return nil }

func TestErrorType_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		errorType ErrorType
		str       string
	}{
		{"expired", ErrorExpired, "expired"},
		{"not_yet_valid", ErrorNotYetValid, "not_yet_valid"},
		{"signature_invalid", ErrorSignatureInvalid, "signature_invalid"},
		{"invalid_basic_constraints", ErrorInvalidBasicConstraints, "invalid_basic_constraints"},
		{"missing_key_usage", ErrorMissingKeyUsage, "missing_key_usage"},
		{"revoked", ErrorRevoked, "revoked"},
		{"revocation_check_failed", ErrorRevocationCheckFailed, "revocation_check_failed"},
		{"circular_reference", ErrorCircularReference, "circular_reference"},
		{"depth_exceeded", ErrorDepthExceeded, "depth_exceeded"},
		{"path_length_exceeded", ErrorPathLenExceeded, "path_length_exceeded"},
		{"untrusted_root", ErrorUntrustedRoot, "untrusted_root"},
		{"hostname_mismatch", ErrorHostnameMismatch, "hostname_mismatch"},
		{"invalid_key_usage", ErrorInvalidKeyUsage, "invalid_key_usage"},
		{"invalid_serial_number", ErrorInvalidSerialNumber, "invalid_serial_number"},
		{"invalid_eku", ErrorInvalidEKU, "invalid_eku"},
		{"name_constraint_violation", ErrorNameConstraintViolation, "name_constraint_violation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Marshal to JSON.
			data, err := json.Marshal(tt.errorType)
			if err != nil {
				t.Fatalf("Marshal ErrorType: %v", err)
			}

			// Unmarshal back.
			var got ErrorType
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal ErrorType: %v", err)
			}

			if got != tt.errorType {
				t.Errorf("round-trip: got %v, want %v", got, tt.errorType)
			}
		})
	}

	t.Run("unknown value", func(t *testing.T) {
		t.Parallel()

		var et ErrorType
		err := json.Unmarshal([]byte(`"bogus"`), &et)
		if err == nil {
			t.Fatal("expected error for unknown ErrorType value, got nil")
		}
	})
}

func TestValidationError_Error(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "test.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	wrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})

	tests := []struct {
		name string
		ve   ValidationError
		want string
	}{
		{
			name: "with certificate",
			ve: ValidationError{
				Certificate: wrapped,
				Type:        ErrorExpired,
				Message:     "certificate expired",
			},
			want: "expired: certificate expired (cert: test.example.com)",
		},
		{
			name: "without certificate",
			ve: ValidationError{
				Type:    ErrorExpired,
				Message: "certificate expired",
			},
			want: "expired: certificate expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.ve.Error()
			if got != tt.want {
				t.Errorf("ValidationError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWarningType_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wt   WarningType
		want string
	}{
		{WarningExpiringSoon, "expiring_soon"},
		{WarningRevocationCheckFailed, "revocation_check_failed"},
		{WarningIncompleteChain, "incomplete_chain"},
		{WarningDuplicateCertificate, "duplicate_certificate"},
		{WarningWeakKey, "weak_key"},
		{WarningWeakAlgorithm, "weak_algorithm"},
		{WarningMissingSAN, "missing_san"},
		{WarningCertLifetime, "cert_lifetime_exceeded"},
		{WarningType(99), "WarningType(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.wt.String(); got != tt.want {
				t.Errorf("WarningType(%d).String() = %q, want %q", tt.wt, got, tt.want)
			}
		})
	}
}

func TestWarningType_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		warningType WarningType
		str         string
	}{
		{"expiring_soon", WarningExpiringSoon, "expiring_soon"},
		{"revocation_check_failed", WarningRevocationCheckFailed, "revocation_check_failed"},
		{"incomplete_chain", WarningIncompleteChain, "incomplete_chain"},
		{"duplicate_certificate", WarningDuplicateCertificate, "duplicate_certificate"},
		{"weak_key", WarningWeakKey, "weak_key"},
		{"weak_algorithm", WarningWeakAlgorithm, "weak_algorithm"},
		{"missing_san", WarningMissingSAN, "missing_san"},
		{"cert_lifetime_exceeded", WarningCertLifetime, "cert_lifetime_exceeded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Marshal to JSON.
			data, err := json.Marshal(tt.warningType)
			if err != nil {
				t.Fatalf("Marshal WarningType: %v", err)
			}

			// Unmarshal back.
			var got WarningType
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal WarningType: %v", err)
			}

			if got != tt.warningType {
				t.Errorf("round-trip: got %v, want %v", got, tt.warningType)
			}
		})
	}

	t.Run("unknown value", func(t *testing.T) {
		t.Parallel()

		var wt WarningType
		err := json.Unmarshal([]byte(`"bogus"`), &wt)
		if err == nil {
			t.Fatal("expected error for unknown WarningType value, got nil")
		}
	})
}

// TestCheckEKUChaining verifies that checkEKUChaining correctly detects EKU
// violations per RFC 5280 section 4.2.1.12.
//
// Rule: if an issuer has an EKU extension that does not include
// anyExtendedKeyUsage, every EKU in the cert must appear in the issuer's EKU.
func TestCheckEKUChaining(t *testing.T) {
	t.Parallel()

	makeCA := func(t *testing.T, cn string, ekus []x509.ExtKeyUsage) *Certificate {
		t.Helper()
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject:     pkix.Name{CommonName: cn},
			IsCA:        true,
			KeyUsage:    x509.KeyUsageCertSign,
			ExtKeyUsage: ekus,
		})
		if err != nil {
			t.Fatalf("generating CA %q: %v", cn, err)
		}
		return NewCertificate(raw, CertificateSource{Type: SourceTypeFile})
	}

	makeLeaf := func(t *testing.T, cn string, ekus []x509.ExtKeyUsage) *Certificate {
		t.Helper()
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject:     pkix.Name{CommonName: cn},
			IsCA:        false,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: ekus,
		})
		if err != nil {
			t.Fatalf("generating leaf %q: %v", cn, err)
		}
		return NewCertificate(raw, CertificateSource{Type: SourceTypeFile})
	}

	tests := []struct {
		name       string
		issuerEKUs []x509.ExtKeyUsage
		certEKUs   []x509.ExtKeyUsage
		wantError  bool
	}{
		{
			name:       "no EKU on issuer -- no constraint",
			issuerEKUs: nil,
			certEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantError:  false,
		},
		{
			name:       "anyExtendedKeyUsage on issuer -- permits all",
			issuerEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			certEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageEmailProtection},
			wantError:  false,
		},
		{
			name:       "cert EKU exact match of issuer EKU",
			issuerEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			certEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantError:  false,
		},
		{
			name:       "cert EKU strict subset of issuer EKU",
			issuerEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			certEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantError:  false,
		},
		{
			name:       "cert EKU has value not in issuer EKU -- violation",
			issuerEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			certEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageEmailProtection},
			wantError:  true,
		},
		{
			name:       "cert EKU entirely outside issuer EKU -- violation",
			issuerEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			certEKUs:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantError:  true,
		},
		{
			name:       "no EKU on cert when issuer has EKU -- legacy compat, no error",
			issuerEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			certEKUs:   nil,
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			issuer := makeCA(t, "Issuer CA", tt.issuerEKUs)
			cert := makeLeaf(t, "leaf.example.com", tt.certEKUs)

			path := &TrustPath{Certificates: []*Certificate{cert, issuer}}
			v := NewValidator().(*defaultValidator)
			v.checkEKUChaining(cert, issuer, path)

			if tt.wantError && len(path.Errors) == 0 {
				t.Error("expected ErrorInvalidEKU, got no errors")
			}
			if !tt.wantError && len(path.Errors) > 0 {
				t.Errorf("expected no errors, got: %v", path.Errors)
			}
			for _, e := range path.Errors {
				if e.Type != ErrorInvalidEKU {
					t.Errorf("expected ErrorInvalidEKU, got %v", e.Type)
				}
				if e.Certificate.FingerprintSHA256() != cert.FingerprintSHA256() {
					t.Errorf("error should reference the cert, not the issuer")
				}
			}
		})
	}
}

func TestValidator_EKUChaining_EndToEnd(t *testing.T) {
	t.Parallel()

	// Chain: leaf (serverAuth+emailProtection) -> CA (serverAuth only).
	// emailProtection is not in the CA's EKU -- violation.
	caRaw, caKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Constrained CA"},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SerialNumber: big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("generating CA: %v", err)
	}

	leafRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com"},
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageEmailProtection},
		SerialNumber: big.NewInt(2),
	}, caRaw, caKey)
	if err != nil {
		t.Fatalf("generating leaf: %v", err)
	}

	caCert := NewCertificate(caRaw, CertificateSource{Type: SourceTypeFile})
	leafCert := NewCertificate(leafRaw, CertificateSource{Type: SourceTypeFile})
	path := &TrustPath{Certificates: []*Certificate{leafCert, caCert}, Status: PathTrusted}

	v := NewValidator()
	if err := v.Validate(t.Context(), []*TrustPath{path}, ValidationOptions{VerifyEKU: true}); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	found := false
	for _, e := range path.Errors {
		if e.Type == ErrorInvalidEKU {
			found = true
			if !strings.Contains(e.Message, "emailProtection") {
				t.Errorf("expected message to mention emailProtection, got: %s", e.Message)
			}
			break
		}
	}
	if !found {
		t.Error("expected ErrorInvalidEKU for emailProtection not permitted by CA, found none")
	}
}

func TestCheckNameConstraints_NoViolation(t *testing.T) {
	t.Parallel()

	// CA permits only example.com subtree.
	caRaw, caKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject:             pkix.Name{CommonName: "Name-Constrained CA"},
		IsCA:                true,
		KeyUsage:            x509.KeyUsageCertSign,
		SerialNumber:        big.NewInt(1),
		PermittedDNSDomains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("generating CA: %v", err)
	}

	leafRaw, _, err := testutil.GenerateSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com"},
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SerialNumber: big.NewInt(2),
	}, caRaw, caKey)
	if err != nil {
		t.Fatalf("generating leaf: %v", err)
	}

	caCert := NewCertificate(caRaw, CertificateSource{Type: SourceTypeFile})
	leafCert := NewCertificate(leafRaw, CertificateSource{Type: SourceTypeFile})
	path := &TrustPath{Certificates: []*Certificate{leafCert, caCert}, Status: PathTrusted}

	v := NewValidator()
	if err := v.Validate(t.Context(), []*TrustPath{path}, ValidationOptions{VerifyNameConstraints: true}); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	for _, e := range path.Errors {
		if e.Type == ErrorNameConstraintViolation {
			t.Errorf("unexpected ErrorNameConstraintViolation for permitted SAN: %s", e.Message)
		}
	}
}

func TestCheckNameConstraints_Violation(t *testing.T) {
	t.Parallel()

	// CA permits only example.com subtree; leaf uses evil.org.
	caRaw, caKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject:             pkix.Name{CommonName: "Name-Constrained CA"},
		IsCA:                true,
		KeyUsage:            x509.KeyUsageCertSign,
		SerialNumber:        big.NewInt(1),
		PermittedDNSDomains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("generating CA: %v", err)
	}

	leafRaw, _, err := testutil.GenerateSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "evil.org"},
		DNSNames:     []string{"evil.org"},
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SerialNumber: big.NewInt(2),
	}, caRaw, caKey)
	if err != nil {
		t.Fatalf("generating leaf: %v", err)
	}

	caCert := NewCertificate(caRaw, CertificateSource{Type: SourceTypeFile})
	leafCert := NewCertificate(leafRaw, CertificateSource{Type: SourceTypeFile})

	tests := []struct {
		name    string
		enabled bool
		want    bool
	}{
		{"enabled", true, true},
		{"disabled", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := &TrustPath{Certificates: []*Certificate{leafCert, caCert}, Status: PathTrusted}
			v := NewValidator()
			if err := v.Validate(t.Context(), []*TrustPath{path}, ValidationOptions{VerifyNameConstraints: tt.enabled}); err != nil {
				t.Fatalf("Validate() error: %v", err)
			}
			found := false
			for _, e := range path.Errors {
				if e.Type == ErrorNameConstraintViolation {
					found = true
					break
				}
			}
			if found != tt.want {
				t.Errorf("ErrorNameConstraintViolation found=%v, want %v (VerifyNameConstraints=%v)", found, tt.want, tt.enabled)
			}
		})
	}
}

func TestCheckNameConstraints_ShortPath(t *testing.T) {
	t.Parallel()

	certRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "standalone.example.com"},
		DNSNames: []string{"standalone.example.com"},
		IsCA:     true,
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	cert := NewCertificate(certRaw, CertificateSource{Type: SourceTypeFile})
	path := &TrustPath{Certificates: []*Certificate{cert}, Status: PathTrusted}

	v := NewValidator()
	if err := v.Validate(t.Context(), []*TrustPath{path}, ValidationOptions{VerifyNameConstraints: true}); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	for _, e := range path.Errors {
		if e.Type == ErrorNameConstraintViolation {
			t.Errorf("unexpected ErrorNameConstraintViolation on single-cert path: %s", e.Message)
		}
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	t.Parallel()

	// Generate a simple certificate
	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		IsCA: true,
	}
	cert, _, err := testutil.GenerateSelfSignedCertUniqueKey(template)
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	certWrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})

	path := &TrustPath{
		Certificates: []*Certificate{certWrapped},
		Status:       PathTrusted,
	}

	validator := NewValidator()

	opts := ValidationOptions{
		VerifySignatures: false,
		VerifyExpiry:     false,
	}

	// Create canceled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err = validator.Validate(ctx, []*TrustPath{path}, opts)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

func TestValidator_CrossSignedTrustAnchorWithExpiredRoot(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// Generate the expired root (top of chain, self-signed, expired).
	expiredRootTemplate := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Starfield Technologies (expired)",
			Organization: []string{"Starfield Technologies"},
		},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		NotBefore:    now.Add(-730 * 24 * time.Hour),
		NotAfter:     now.Add(-365 * 24 * time.Hour),
		SerialNumber: big.NewInt(1),
	}
	expiredRoot, expiredRootKey, err := testutil.GenerateSelfSignedCert(expiredRootTemplate)
	if err != nil {
		t.Fatalf("Failed to generate expired root: %v", err)
	}

	// Generate the trusted CA -- signed by the expired root, so NOT self-signed.
	// This is the key difference from TestValidator_ExpiredRootAboveTrustAnchor.
	trustedCATemplate := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Amazon Root CA 1",
			Organization: []string{"Amazon"},
		},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		SerialNumber: big.NewInt(2),
	}
	trustedCA, trustedCAKey, err := testutil.GenerateSignedCert(trustedCATemplate, expiredRoot, expiredRootKey)
	if err != nil {
		t.Fatalf("Failed to generate trusted CA: %v", err)
	}

	// Generate intermediate CA signed by the trusted CA.
	intermediateTemplate := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Amazon RSA 2048 M04",
			Organization: []string{"Amazon"},
		},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		SerialNumber: big.NewInt(3),
	}
	intermediate, intermediateKey, err := testutil.GenerateSignedCert(intermediateTemplate, trustedCA, trustedCAKey)
	if err != nil {
		t.Fatalf("Failed to generate intermediate: %v", err)
	}

	// Generate leaf certificate signed by intermediate.
	leafTemplate := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "aws.eu",
		},
		DNSNames:     []string{"aws.eu"},
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SerialNumber: big.NewInt(4),
	}
	leaf, _, err := testutil.GenerateSignedCert(leafTemplate, intermediate, intermediateKey)
	if err != nil {
		t.Fatalf("Failed to generate leaf: %v", err)
	}

	// Wrap certificates.
	leafCert := NewCertificate(leaf, CertificateSource{Type: SourceTypeFile})
	intermediateCert := NewCertificate(intermediate, CertificateSource{Type: SourceTypeFile})
	trustedCACert := NewCertificate(trustedCA, CertificateSource{Type: SourceTypeFile})
	expiredRootCert := NewCertificate(expiredRoot, CertificateSource{Type: SourceTypeFile})

	// Verify the trusted CA is NOT self-signed (the key property of this test).
	if trustedCACert.IsSelfSigned() {
		t.Fatal("trusted CA should NOT be self-signed for this test")
	}

	// Set up trust store that trusts the non-self-signed CA.
	ts := &validatorMockTrustStore{
		trusted: map[string]bool{
			trustedCACert.FingerprintSHA256(): true,
		},
	}

	// Build the chain: leaf -> intermediate -> trusted_ca -> expired_root.
	path := &TrustPath{
		Certificates: []*Certificate{leafCert, intermediateCert, trustedCACert, expiredRootCert},
		Status:       PathTrusted,
	}

	validator := NewValidator(WithValidatorTrustStore(ts))
	opts := ValidationOptions{
		VerifySignatures:  false,
		VerifyExpiry:      true,
		ExpiryWarningDays: 30,
	}

	err = validator.Validate(t.Context(), []*TrustPath{path}, opts)
	if err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}

	// No errors should reference the expired root above the trust anchor.
	for _, e := range path.Errors {
		if e.Certificate.FingerprintSHA256() == expiredRootCert.FingerprintSHA256() {
			t.Errorf("no validation errors should reference the expired root above cross-signed trust anchor, got: type=%v msg=%q", e.Type, e.Message)
		}
	}

	// No warnings should reference the expired root.
	for _, w := range path.Warnings {
		if w.Certificate != nil && w.Certificate.FingerprintSHA256() == expiredRootCert.FingerprintSHA256() {
			t.Errorf("no validation warnings should reference the expired root above cross-signed trust anchor, got: type=%v msg=%q", w.Type, w.Message)
		}
	}

	_ = expiredRootKey // Used only for generation.
}

func TestCheckIssuerConstraints(t *testing.T) {
	t.Parallel()

	// Generate a leaf certificate used as the "cert" argument in all sub-tests.
	leafRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "leaf.example.com"},
		IsCA:     false,
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		t.Fatalf("generating leaf cert: %v", err)
	}
	leaf := NewCertificate(leafRaw, CertificateSource{Type: SourceTypeFile})

	tests := []struct {
		name       string
		issuerTmpl testutil.CertificateTemplate
		certIndex  int
		wantErrors []ErrorType
	}{
		{
			name: "valid CA issuer",
			issuerTmpl: testutil.CertificateTemplate{
				Subject:  pkix.Name{CommonName: "Valid CA"},
				IsCA:     true,
				KeyUsage: x509.KeyUsageCertSign,
			},
			certIndex:  1,
			wantErrors: nil,
		},
		{
			name: "non-CA issuer",
			issuerTmpl: testutil.CertificateTemplate{
				Subject:  pkix.Name{CommonName: "Non-CA Issuer"},
				IsCA:     false,
				KeyUsage: x509.KeyUsageCertSign,
			},
			certIndex:  1,
			wantErrors: []ErrorType{ErrorInvalidBasicConstraints},
		},
		{
			name: "missing KeyUsageCertSign",
			issuerTmpl: testutil.CertificateTemplate{
				Subject:  pkix.Name{CommonName: "No CertSign CA"},
				IsCA:     true,
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
			certIndex:  1,
			wantErrors: []ErrorType{ErrorMissingKeyUsage},
		},
		{
			name: "KeyUsage zero (legacy omitted)",
			issuerTmpl: testutil.CertificateTemplate{
				Subject:  pkix.Name{CommonName: "Legacy CA"},
				IsCA:     true,
				KeyUsage: 0,
			},
			certIndex:  1,
			wantErrors: nil,
		},
		{
			name: "MaxPathLen exceeded",
			issuerTmpl: testutil.CertificateTemplate{
				Subject:        pkix.Name{CommonName: "Constrained CA"},
				IsCA:           true,
				KeyUsage:       x509.KeyUsageCertSign,
				MaxPathLen:     0,
				MaxPathLenZero: true,
			},
			certIndex:  1, // intermediatesBetween = 1 > MaxPathLen 0
			wantErrors: []ErrorType{ErrorPathLenExceeded},
		},
		{
			name: "MaxPathLen exactly at limit",
			issuerTmpl: testutil.CertificateTemplate{
				Subject:    pkix.Name{CommonName: "CA With PathLen 1"},
				IsCA:       true,
				KeyUsage:   x509.KeyUsageCertSign,
				MaxPathLen: 1,
			},
			certIndex:  1, // intermediatesBetween = 1 == MaxPathLen 1
			wantErrors: nil,
		},
		{
			name: "MaxPathLen exceeded with deep chain",
			issuerTmpl: testutil.CertificateTemplate{
				Subject:    pkix.Name{CommonName: "CA With PathLen 1"},
				IsCA:       true,
				KeyUsage:   x509.KeyUsageCertSign,
				MaxPathLen: 1,
			},
			certIndex:  2, // intermediatesBetween = 2 > MaxPathLen 1
			wantErrors: []ErrorType{ErrorPathLenExceeded},
		},
		{
			name: "MaxPathLen zero allows direct leaf",
			issuerTmpl: testutil.CertificateTemplate{
				Subject:        pkix.Name{CommonName: "CA With PathLen 0"},
				IsCA:           true,
				KeyUsage:       x509.KeyUsageCertSign,
				MaxPathLen:     0,
				MaxPathLenZero: true,
			},
			certIndex:  0, // intermediatesBetween = 0 == MaxPathLen 0
			wantErrors: nil,
		},
		{
			name: "non-CA and missing KeyUsage combined",
			issuerTmpl: testutil.CertificateTemplate{
				Subject:  pkix.Name{CommonName: "Bad Issuer"},
				IsCA:     false,
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
			certIndex:  1,
			wantErrors: []ErrorType{ErrorInvalidBasicConstraints, ErrorMissingKeyUsage},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			issuerRaw, _, err := testutil.GenerateSelfSignedCert(tt.issuerTmpl)
			if err != nil {
				t.Fatalf("generating issuer cert: %v", err)
			}
			issuer := NewCertificate(issuerRaw, CertificateSource{Type: SourceTypeFile})

			path := &TrustPath{
				Certificates: []*Certificate{leaf, issuer},
			}

			v := NewValidator().(*defaultValidator)
			v.checkIssuerConstraints(leaf, issuer, path, tt.certIndex)

			if len(path.Errors) != len(tt.wantErrors) {
				t.Fatalf("expected %d errors, got %d: %v", len(tt.wantErrors), len(path.Errors), path.Errors)
			}

			for i, wantType := range tt.wantErrors {
				if path.Errors[i].Type != wantType {
					t.Errorf("error[%d]: expected type %v, got %v", i, wantType, path.Errors[i].Type)
				}
				if path.Errors[i].Certificate != issuer {
					t.Errorf("error[%d]: expected certificate to reference issuer", i)
				}
			}
		})
	}
}

func TestVerifyExpiry_NotYetValid(t *testing.T) {
	t.Parallel()

	now := time.Now()
	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "future.example.com",
		},
		IsCA:      true,
		NotBefore: now.Add(24 * time.Hour),       // starts 24 hours from now
		NotAfter:  now.Add(365 * 24 * time.Hour), // expires in 1 year
	}
	raw, _, err := testutil.GenerateSelfSignedCertUniqueKey(template)
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	cert := NewCertificate(raw, CertificateSource{Type: SourceTypeFile})
	path := &TrustPath{
		Certificates: []*Certificate{cert},
	}

	v := NewValidator().(*defaultValidator)
	v.checkExpiry(cert, path, 30, time.Time{})

	if len(path.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(path.Errors))
	}
	if path.Errors[0].Type != ErrorNotYetValid {
		t.Errorf("expected ErrorNotYetValid, got %v", path.Errors[0].Type)
	}
}

func TestValidator_SignatureVerificationFailure(t *testing.T) {
	t.Parallel()

	// Generate the real root that will actually sign the leaf.
	realRootTemplate := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Real Root CA"},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		SerialNumber: big.NewInt(1),
	}
	realRoot, realRootKey, err := testutil.GenerateSelfSignedCertUniqueKey(realRootTemplate)
	if err != nil {
		t.Fatalf("Failed to generate real root: %v", err)
	}

	// Generate an unrelated root whose public key does not match the leaf's signature.
	fakeRootTemplate := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Fake Root CA"},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		SerialNumber: big.NewInt(2),
	}
	fakeRoot, _, err := testutil.GenerateSelfSignedCertUniqueKey(fakeRootTemplate)
	if err != nil {
		t.Fatalf("Failed to generate fake root: %v", err)
	}

	// Generate a leaf signed by the REAL root.
	leafTemplate := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SerialNumber: big.NewInt(3),
	}
	leaf, _, err := testutil.GenerateSignedCertUniqueKey(leafTemplate, realRoot, realRootKey)
	if err != nil {
		t.Fatalf("Failed to generate leaf: %v", err)
	}

	leafWrapped := NewCertificate(leaf, CertificateSource{Type: SourceTypeFile})
	fakeRootWrapped := NewCertificate(fakeRoot, CertificateSource{Type: SourceTypeFile})

	// Build a path with the leaf and the FAKE root. The leaf's signature
	// was created by realRoot's key, so verification against fakeRoot must fail.
	path := &TrustPath{
		Certificates: []*Certificate{leafWrapped, fakeRootWrapped},
		Status:       PathUntrusted,
	}

	validator := NewValidator()
	opts := ValidationOptions{
		VerifySignatures: true,
	}

	err = validator.Validate(t.Context(), []*TrustPath{path}, opts)
	if err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}

	foundSigError := false
	for _, e := range path.Errors {
		if e.Type == ErrorSignatureInvalid {
			foundSigError = true
			if e.Certificate.FingerprintSHA256() != leafWrapped.FingerprintSHA256() {
				t.Errorf("Expected signature error on leaf, got on %q", e.Certificate.CommonName())
			}
			break
		}
	}
	if !foundSigError {
		t.Error("Expected ErrorSignatureInvalid when leaf is verified against wrong issuer, but none found")
	}
}

func TestValidator_HostnameVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		certDNS   string
		hostname  string
		wantError bool
	}{
		{"mismatch", "example.com", "other.example.com", true},
		{"match", "match.example.com", "match.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			template := testutil.CertificateTemplate{
				Subject:  pkix.Name{CommonName: tt.certDNS},
				DNSNames: []string{tt.certDNS},
				IsCA:     false,
				KeyUsage: x509.KeyUsageDigitalSignature,
			}
			cert, _, err := testutil.GenerateSelfSignedCert(template)
			if err != nil {
				t.Fatalf("Failed to generate cert: %v", err)
			}

			certWrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})
			path := &TrustPath{
				Certificates: []*Certificate{certWrapped},
				Status:       PathUntrusted,
			}

			validator := NewValidator()
			opts := ValidationOptions{
				VerifyHostname: true,
				Hostname:       tt.hostname,
			}

			err = validator.Validate(t.Context(), []*TrustPath{path}, opts)
			if err != nil {
				t.Fatalf("Validate() returned error: %v", err)
			}

			found := false
			for _, e := range path.Errors {
				if e.Type == ErrorHostnameMismatch {
					found = true
					break
				}
			}
			if found != tt.wantError {
				t.Errorf("ErrorHostnameMismatch found = %v, want %v", found, tt.wantError)
			}
		})
	}
}

func TestValidator_UntrustedRootValidation(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// Generate an expired self-signed root that is NOT in the trust store.
	rootTemplate := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Untrusted Expired Root"},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		NotBefore:    now.Add(-730 * 24 * time.Hour),
		NotAfter:     now.Add(-1 * 24 * time.Hour), // expired yesterday
		SerialNumber: big.NewInt(1),
	}
	rootCert, rootKey, err := testutil.GenerateSelfSignedCertUniqueKey(rootTemplate)
	if err != nil {
		t.Fatalf("Failed to generate expired root: %v", err)
	}

	// Generate a valid leaf signed by the expired root.
	leafTemplate := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SerialNumber: big.NewInt(2),
	}
	leaf, _, err := testutil.GenerateSignedCertUniqueKey(leafTemplate, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to generate leaf: %v", err)
	}

	leafWrapped := NewCertificate(leaf, CertificateSource{Type: SourceTypeFile})
	rootWrapped := NewCertificate(rootCert, CertificateSource{Type: SourceTypeFile})

	path := &TrustPath{
		Certificates: []*Certificate{leafWrapped, rootWrapped},
		Status:       PathUntrusted,
	}

	// Trust store does NOT trust the root.
	ts := &validatorMockTrustStore{trusted: map[string]bool{}}
	validator := NewValidator(WithValidatorTrustStore(ts))
	opts := ValidationOptions{
		VerifyExpiry: true,
	}

	err = validator.Validate(t.Context(), []*TrustPath{path}, opts)
	if err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}

	// Without a trust anchor the validator should check ALL certificates,
	// including the self-signed root. Since the root is expired, it must
	// produce an ErrorExpired.
	foundRootExpiry := false
	for _, e := range path.Errors {
		if e.Type == ErrorExpired && e.Certificate.FingerprintSHA256() == rootWrapped.FingerprintSHA256() {
			foundRootExpiry = true
			break
		}
	}
	if !foundRootExpiry {
		t.Error("Expected ErrorExpired for the untrusted expired root, but none found; " +
			"validator should check all certificates when no trust anchor is present")
	}
}

func TestValidSignaturesPassVerification(t *testing.T) {
	t.Parallel()

	rootTemplate := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "test-root Root CA",
		},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	rootCert, rootKey, err := testutil.GenerateSelfSignedCert(rootTemplate)
	if err != nil {
		t.Fatalf("Failed to generate root certificate: %v", err)
	}

	endEntityTemplate := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "test-root",
		},
		DNSNames: []string{"test-root"},
		IsCA:     false,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	endEntityCert, _, err := testutil.GenerateSignedCert(endEntityTemplate, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to generate end-entity certificate: %v", err)
	}

	rootCertWrapped := NewCertificate(rootCert, CertificateSource{Type: SourceTypeFile})
	endEntityCertWrapped := NewCertificate(endEntityCert, CertificateSource{Type: SourceTypeFile})

	path := &TrustPath{
		Certificates: []*Certificate{endEntityCertWrapped, rootCertWrapped},
		Status:       PathTrusted,
	}

	validator := NewValidator()
	opts := ValidationOptions{
		VerifySignatures: true,
		VerifyExpiry:     false,
	}

	err = validator.Validate(t.Context(), []*TrustPath{path}, opts)
	if err != nil {
		t.Fatalf("Validation returned error: %v", err)
	}

	for _, e := range path.Errors {
		if e.Type == ErrorSignatureInvalid {
			t.Fatalf("Unexpected signature error: %s", e.Message)
		}
	}
}

// mockRevocationChecker is a RevocationChecker that returns a fixed status/error.
type mockRevocationChecker struct {
	status RevocationStatus
	err    error
}

func (m *mockRevocationChecker) CheckRevocation(_ context.Context, _ *Certificate, _ *Certificate) (RevocationStatus, error) {
	return m.status, m.err
}

func (m *mockRevocationChecker) ResetCache() {}

func TestCheckRevocation_NilRevokedAt(t *testing.T) {
	t.Parallel()

	rootTemplate := testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "Root CA"},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	rootCert, rootKey, err := testutil.GenerateSelfSignedCert(rootTemplate)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert() error = %v", err)
	}

	leafTemplate := testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "leaf.example.com"},
		DNSNames: []string{"leaf.example.com"},
		IsCA:     false,
	}
	leafCert, _, err := testutil.GenerateSignedCert(leafTemplate, rootCert, rootKey)
	if err != nil {
		t.Fatalf("GenerateSignedCert() error = %v", err)
	}

	rootWrapped := NewCertificate(rootCert, CertificateSource{Type: SourceTypeFile})
	leafWrapped := NewCertificate(leafCert, CertificateSource{Type: SourceTypeFile})

	path := &TrustPath{
		Certificates: []*Certificate{leafWrapped, rootWrapped},
		Status:       PathTrusted,
	}

	// RevocationStatus with IsRevoked=true but nil RevokedAt -- the panic vector.
	checker := &mockRevocationChecker{
		status: RevocationStatus{
			IsRevoked:  true,
			RevokedAt:  nil, // intentionally nil
			CheckedVia: "mock",
		},
	}

	v := NewValidator(WithRevocationChecker(checker)).(*defaultValidator)

	// Must not panic.
	v.checkRevocation(t.Context(), leafWrapped, rootWrapped, path, false)

	if len(path.Errors) != 1 {
		t.Fatalf("expected 1 error (revoked), got %d", len(path.Errors))
	}
	if path.Errors[0].Type != ErrorRevoked {
		t.Errorf("expected ErrorRevoked, got %v", path.Errors[0].Type)
	}
	if !strings.Contains(path.Errors[0].Message, "unknown") {
		t.Errorf("expected message to contain 'unknown' for nil RevokedAt, got: %s", path.Errors[0].Message)
	}
}

func TestCheckWeakKey(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// makeRaw returns a minimal *x509.Certificate with the given algorithm and public key.
	makeRaw := func(alg x509.SignatureAlgorithm, pub any) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:       big.NewInt(1),
			Subject:            pkix.Name{CommonName: "test"},
			NotBefore:          now.Add(-time.Hour),
			NotAfter:           now.Add(365 * 24 * time.Hour),
			SignatureAlgorithm: alg,
			PublicKey:          pub,
		}
	}

	cachedPub := testutil.GetCachedKey().Public()

	// Build a synthetic 1024-bit RSA public key (not a real key, just enough
	// for the bit-length check in checkWeakKey).
	weakN := new(big.Int).Lsh(big.NewInt(1), 1023) // 1024-bit number
	weakPub := &rsa.PublicKey{N: weakN, E: 65537}

	tests := []struct {
		name        string
		alg         x509.SignatureAlgorithm
		pub         any
		wantWeakAlg bool
		wantWeakKey bool
	}{
		{
			name:        "SHA256WithRSA 2048-bit -- no warning",
			alg:         x509.SHA256WithRSA,
			pub:         cachedPub,
			wantWeakAlg: false,
			wantWeakKey: false,
		},
		{
			name:        "SHA1WithRSA -- WarningWeakAlgorithm",
			alg:         x509.SHA1WithRSA,
			pub:         cachedPub,
			wantWeakAlg: true,
			wantWeakKey: false,
		},
		{
			name:        "MD5WithRSA -- WarningWeakAlgorithm",
			alg:         x509.MD5WithRSA,
			pub:         cachedPub,
			wantWeakAlg: true,
			wantWeakKey: false,
		},
		{
			name:        "RSA 1024-bit -- WarningWeakKey",
			alg:         x509.SHA256WithRSA,
			pub:         weakPub,
			wantWeakAlg: false,
			wantWeakKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw := makeRaw(tt.alg, tt.pub)
			cert := NewCertificate(raw, CertificateSource{Type: SourceTypeFile})
			path := &TrustPath{Certificates: []*Certificate{cert}}

			v := NewValidator().(*defaultValidator)
			v.checkWeakKey(cert, path)

			var gotWeakAlg, gotWeakKey bool
			for _, w := range path.Warnings {
				if w.Type == WarningWeakAlgorithm {
					gotWeakAlg = true
				}
				if w.Type == WarningWeakKey {
					gotWeakKey = true
				}
			}

			if gotWeakAlg != tt.wantWeakAlg {
				t.Errorf("WarningWeakAlgorithm: got %v, want %v", gotWeakAlg, tt.wantWeakAlg)
			}
			if gotWeakKey != tt.wantWeakKey {
				t.Errorf("WarningWeakKey: got %v, want %v", gotWeakKey, tt.wantWeakKey)
			}
		})
	}
}

func TestCheckMissingSAN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		isCA    bool
		dns     []string
		wantWrn bool
	}{
		{
			name:    "end-entity no SANs -- WarningMissingSAN",
			isCA:    false,
			dns:     nil,
			wantWrn: true,
		},
		{
			name:    "end-entity with DNS SAN -- no warning",
			isCA:    false,
			dns:     []string{"leaf.example.com"},
			wantWrn: false,
		},
		{
			name:    "CA with no SANs -- no warning",
			isCA:    true,
			dns:     nil,
			wantWrn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
				Subject:  pkix.Name{CommonName: "test"},
				IsCA:     tt.isCA,
				DNSNames: tt.dns,
			})
			if err != nil {
				t.Fatalf("generating cert: %v", err)
			}
			cert := NewCertificate(raw, CertificateSource{Type: SourceTypeFile})
			path := &TrustPath{Certificates: []*Certificate{cert}}

			v := NewValidator().(*defaultValidator)
			v.checkMissingSAN(cert, path)

			var got bool
			for _, w := range path.Warnings {
				if w.Type == WarningMissingSAN {
					got = true
				}
			}
			if got != tt.wantWrn {
				t.Errorf("WarningMissingSAN: got %v, want %v", got, tt.wantWrn)
			}
		})
	}
}

// TestCheckEndEntityKeyUsage verifies that checkEndEntityKeyUsage correctly
// detects Key Usage violations for TLS server end-entity certs per RFC 5280
// section 4.2.1.3.
func TestCheckEndEntityKeyUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		isCA      bool
		keyUsage  x509.KeyUsage
		ekus      []x509.ExtKeyUsage
		wantError bool
	}{
		{
			name:      "serverAuth + DigitalSignature -- no error",
			isCA:      false,
			keyUsage:  x509.KeyUsageDigitalSignature,
			ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantError: false,
		},
		{
			name:      "serverAuth + KeyEncipherment -- no error",
			isCA:      false,
			keyUsage:  x509.KeyUsageKeyEncipherment,
			ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantError: false,
		},
		{
			name:      "serverAuth + CRLSign only -- ErrorInvalidKeyUsage",
			isCA:      false,
			keyUsage:  x509.KeyUsageCRLSign,
			ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantError: true,
		},
		{
			name:      "no KeyUsage extension (zero) -- no error",
			isCA:      false,
			keyUsage:  0,
			ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantError: false,
		},
		{
			name:      "no serverAuth EKU -- no error",
			isCA:      false,
			keyUsage:  x509.KeyUsageCRLSign,
			ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantError: false,
		},
		{
			name:      "CA cert -- no error",
			isCA:      true,
			keyUsage:  x509.KeyUsageCertSign,
			ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
				Subject:     pkix.Name{CommonName: "test"},
				IsCA:        tt.isCA,
				KeyUsage:    tt.keyUsage,
				ExtKeyUsage: tt.ekus,
				DNSNames:    []string{"test.example.com"},
			})
			if err != nil {
				t.Fatalf("generating cert: %v", err)
			}
			cert := NewCertificate(raw, CertificateSource{Type: SourceTypeFile})
			path := &TrustPath{Certificates: []*Certificate{cert}}

			v := NewValidator().(*defaultValidator)
			v.checkEndEntityKeyUsage(cert, path)

			var got bool
			for _, e := range path.Errors {
				if e.Type == ErrorInvalidKeyUsage {
					got = true
				}
			}
			if got != tt.wantError {
				t.Errorf("ErrorInvalidKeyUsage: got %v, want %v", got, tt.wantError)
			}
		})
	}
}

// TestCheckSerialNumber verifies that checkSerialNumber detects serial numbers
// that violate RFC 5280 section 4.1.2.2 (must be a positive integer, <= 20 octets).
func TestCheckSerialNumber(t *testing.T) {
	t.Parallel()

	now := time.Now()

	makeRaw := func(serial *big.Int) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "test"},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			PublicKey:    testutil.GetCachedKey().Public(),
		}
	}

	// Oversized serial: 21 bytes.
	oversized := new(big.Int).Lsh(big.NewInt(1), 168) // 169-bit -> 22 bytes

	tests := []struct {
		name      string
		serial    *big.Int
		wantError bool
	}{
		{
			name:      "positive serial -- no error",
			serial:    big.NewInt(42),
			wantError: false,
		},
		{
			name:      "zero serial -- ErrorInvalidSerialNumber",
			serial:    big.NewInt(0),
			wantError: true,
		},
		{
			name:      "negative serial -- ErrorInvalidSerialNumber",
			serial:    big.NewInt(-1),
			wantError: true,
		},
		{
			name:      "oversized serial (>20 bytes) -- ErrorInvalidSerialNumber",
			serial:    oversized,
			wantError: true,
		},
		{
			// 20 bytes with the MSB set: big.Int.Bytes() returns 20 bytes but DER
			// encodes this as 21 bytes (a leading 0x00 is required to keep the sign
			// bit clear). RFC 5280 section 4.1.2.2 counts the DER-encoded length.
			name:      "20-byte serial with MSB set (21 DER bytes) -- ErrorInvalidSerialNumber",
			serial:    new(big.Int).Lsh(big.NewInt(1), 159), // exactly 160 bits, MSB=1
			wantError: true,
		},
		{
			// 2^159-1 = 0x7FFF...FFFF: 20 bytes where the first byte is 0x7F
			// (MSB clear). DER encodes as exactly 20 bytes. Valid.
			name:      "20-byte serial with MSB clear (20 DER bytes) -- no error",
			serial:    new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1)),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert := NewCertificate(makeRaw(tt.serial), CertificateSource{Type: SourceTypeFile})
			path := &TrustPath{Certificates: []*Certificate{cert}}

			v := NewValidator().(*defaultValidator)
			v.checkSerialNumber(cert, path)

			var got bool
			for _, e := range path.Errors {
				if e.Type == ErrorInvalidSerialNumber {
					got = true
				}
			}
			if got != tt.wantError {
				t.Errorf("ErrorInvalidSerialNumber: got %v, want %v", got, tt.wantError)
			}
		})
	}
}

func TestCheckCertLifetime(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// 400-day end-entity cert.
	longLeaf, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:   pkix.Name{CommonName: "leaf"},
		IsCA:      false,
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(399 * 24 * time.Hour), // 400 days total
	})
	if err != nil {
		t.Fatalf("generating long-lived leaf: %v", err)
	}

	// 365-day end-entity cert.
	shortLeaf, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:   pkix.Name{CommonName: "leaf-short"},
		IsCA:      false,
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(364 * 24 * time.Hour), // 365 days total
	})
	if err != nil {
		t.Fatalf("generating short-lived leaf: %v", err)
	}

	// 400-day CA cert.
	longCA, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:   pkix.Name{CommonName: "ca"},
		IsCA:      true,
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(399 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("generating long-lived CA: %v", err)
	}

	tests := []struct {
		name     string
		cert     *x509.Certificate
		maxDays  int
		wantWarn bool
	}{
		{
			name:     "400-day leaf, limit 398 -- WarningCertLifetime",
			cert:     longLeaf,
			maxDays:  398,
			wantWarn: true,
		},
		{
			name:     "365-day leaf, limit 398 -- no warning",
			cert:     shortLeaf,
			maxDays:  398,
			wantWarn: false,
		},
		{
			name:     "400-day CA, limit 398 -- CA exempt, no warning",
			cert:     longCA,
			maxDays:  398,
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert := NewCertificate(tt.cert, CertificateSource{Type: SourceTypeFile})
			path := &TrustPath{Certificates: []*Certificate{cert}}

			v := NewValidator().(*defaultValidator)
			v.checkCertLifetime(cert, path, tt.maxDays)

			var got bool
			for _, w := range path.Warnings {
				if w.Type == WarningCertLifetime {
					got = true
				}
			}
			if got != tt.wantWarn {
				t.Errorf("WarningCertLifetime: got %v, want %v", got, tt.wantWarn)
			}
		})
	}
}

func TestCheckCertLifetime_EndToEnd(t *testing.T) {
	t.Parallel()

	now := time.Now()

	caRaw, caKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Test CA"},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		SerialNumber: big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("generating CA: %v", err)
	}

	leafRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com"},
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SerialNumber: big.NewInt(2),
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(399 * 24 * time.Hour), // 400 days
	}, caRaw, caKey)
	if err != nil {
		t.Fatalf("generating leaf: %v", err)
	}

	caCert := NewCertificate(caRaw, CertificateSource{Type: SourceTypeFile})
	leafCert := NewCertificate(leafRaw, CertificateSource{Type: SourceTypeFile})
	path := &TrustPath{Certificates: []*Certificate{leafCert, caCert}, Status: PathTrusted}

	v := NewValidator()
	if err := v.Validate(t.Context(), []*TrustPath{path}, ValidationOptions{MaxValidityDays: 398}); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	found := false
	for _, w := range path.Warnings {
		if w.Type == WarningCertLifetime {
			found = true
			if !strings.Contains(w.Message, "400") {
				t.Errorf("expected message to mention 400 days, got: %s", w.Message)
			}
			break
		}
	}
	if !found {
		t.Error("expected WarningCertLifetime for 400-day leaf with limit 398, found none")
	}
}

func TestCheckExpiry_ThreeRegions(t *testing.T) {
	t.Parallel()

	// Generate a cert with known expiry: expires 30 days from a reference point.
	refTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	template := testutil.CertificateTemplate{
		Subject:   pkix.Name{CommonName: "expiry-regions.example.com"},
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign,
		NotBefore: refTime.Add(-365 * 24 * time.Hour),
		NotAfter:  refTime.Add(30 * 24 * time.Hour),
	}
	raw, _, err := testutil.GenerateSelfSignedCert(template)
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	cert := NewCertificate(raw, CertificateSource{Type: SourceTypeFile})
	v := NewValidator().(*defaultValidator)

	tests := []struct {
		name        string
		daysOffset  int
		wantError   ErrorType
		wantWarning WarningType
		wantMsg     string
		wantClean   bool
	}{
		{
			name:       "expired (past NotAfter)",
			daysOffset: 31,
			wantError:  ErrorExpired,
		},
		{
			name:        "expiring soon (within 30-day window)",
			daysOffset:  10,
			wantWarning: WarningExpiringSoon,
			wantMsg:     "20 days",
		},
		{
			name:       "healthy (well before expiry window)",
			daysOffset: -60,
			wantClean:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			validationTime := refTime.Add(time.Duration(tt.daysOffset) * 24 * time.Hour)
			path := &TrustPath{Certificates: []*Certificate{cert}}

			v.checkExpiry(cert, path, 30, validationTime)

			if tt.wantError != 0 {
				if len(path.Errors) == 0 {
					t.Fatalf("expected error %d, got none", tt.wantError)
				}
				if path.Errors[0].Type != tt.wantError {
					t.Errorf("error type = %v, want %v", path.Errors[0].Type, tt.wantError)
				}
			}
			if tt.wantWarning != 0 {
				if len(path.Warnings) == 0 {
					t.Fatalf("expected warning %d, got none", tt.wantWarning)
				}
				if path.Warnings[0].Type != tt.wantWarning {
					t.Errorf("warning type = %v, want %v", path.Warnings[0].Type, tt.wantWarning)
				}
				if tt.wantMsg != "" && !strings.Contains(path.Warnings[0].Message, tt.wantMsg) {
					t.Errorf("warning message = %q, want substring %q", path.Warnings[0].Message, tt.wantMsg)
				}
			}
			if tt.wantClean {
				if len(path.Errors) != 0 || len(path.Warnings) != 0 {
					t.Errorf("expected clean, got %d errors, %d warnings", len(path.Errors), len(path.Warnings))
				}
			}
		})
	}
}

// secValidatorMockTrustStoreWithRoot is a mock trust store that trusts a single root certificate.
type secValidatorMockTrustStoreWithRoot struct {
	root *Certificate
}

func (m *secValidatorMockTrustStoreWithRoot) IsTrusted(cert *Certificate) bool {
	if m.root == nil {
		return false
	}
	return cert.FingerprintSHA256() == m.root.FingerprintSHA256()
}

func (m *secValidatorMockTrustStoreWithRoot) TrustedLocations(cert *Certificate) []string {
	if m.IsTrusted(cert) {
		return []string{"test"}
	}
	return nil
}

func (m *secValidatorMockTrustStoreWithRoot) LoadSystemRoots() error { return nil }

func (m *secValidatorMockTrustStoreWithRoot) LoadCustomRoots(_ string) error { return nil }

func (m *secValidatorMockTrustStoreWithRoot) FindIssuers(cert *Certificate) []*Certificate {
	if m.root == nil || cert == nil {
		return nil
	}
	if string(cert.Raw().RawIssuer) == string(m.root.Raw().RawSubject) {
		return []*Certificate{m.root}
	}
	return nil
}

func TestSecurityExpiredCertificateChains(t *testing.T) {
	t.Parallel()

	now := time.Now()
	past := now.Add(-48 * time.Hour)
	farFuture := now.Add(365 * 24 * time.Hour)

	t.Run("expired root produces ErrorExpired on the root", func(t *testing.T) {
		t.Parallel()

		rawRoot, rootKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:   pkix.Name{CommonName: "Expired Root"},
			IsCA:      true,
			KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			NotBefore: past.Add(-72 * time.Hour),
			NotAfter:  past, // already expired
		})
		require.NoError(t, err)

		rawLeaf, _, err := testutil.GenerateSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:   pkix.Name{CommonName: "leaf.exproot.test"},
			DNSNames:  []string{"leaf.exproot.test"},
			NotBefore: past.Add(-72 * time.Hour),
			NotAfter:  farFuture,
			KeyUsage:  x509.KeyUsageDigitalSignature,
		}, rawRoot, rootKey)
		require.NoError(t, err)

		rootCert := NewCertificate(rawRoot, CertificateSource{Type: SourceTypeBytes})
		ts := &secValidatorMockTrustStoreWithRoot{root: rootCert}
		certs := []*Certificate{NewCertificate(rawLeaf, CertificateSource{Type: SourceTypeBytes}), rootCert}

		cb := NewChainBuilder()
		paths, err := cb.BuildChains(t.Context(), certs, ts)
		require.NoError(t, err)
		require.NotEmpty(t, paths)

		validator := NewValidator(WithValidatorTrustStore(ts))
		err = validator.Validate(t.Context(), paths, ValidationOptions{
			VerifyExpiry: true,
		})
		require.NoError(t, err)

		hasExpiredError := false
		for _, p := range paths {
			for _, ve := range p.Errors {
				if ve.Type == ErrorExpired {
					hasExpiredError = true
				}
			}
		}
		assert.True(t, hasExpiredError, "expired root must produce ErrorExpired")
	})

	t.Run("expired intermediate with valid leaf produces ErrorExpired on intermediate", func(t *testing.T) {
		t.Parallel()

		rawRoot, rootKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:   pkix.Name{CommonName: "Valid Root"},
			IsCA:      true,
			KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			NotBefore: past.Add(-72 * time.Hour),
			NotAfter:  farFuture,
		})
		require.NoError(t, err)

		rawIntermediate, intKey, err := testutil.GenerateSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:   pkix.Name{CommonName: "Expired Intermediate"},
			IsCA:      true,
			KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			NotBefore: past.Add(-72 * time.Hour),
			NotAfter:  past, // expired
		}, rawRoot, rootKey)
		require.NoError(t, err)

		rawLeaf, _, err := testutil.GenerateSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:   pkix.Name{CommonName: "leaf.expint.test"},
			DNSNames:  []string{"leaf.expint.test"},
			NotBefore: past.Add(-1 * time.Hour),
			NotAfter:  farFuture,
			KeyUsage:  x509.KeyUsageDigitalSignature,
		}, rawIntermediate, intKey)
		require.NoError(t, err)

		src := CertificateSource{Type: SourceTypeBytes}
		rootCert := NewCertificate(rawRoot, src)
		ts := &secValidatorMockTrustStoreWithRoot{root: rootCert}
		certs := []*Certificate{
			NewCertificate(rawLeaf, src),
			NewCertificate(rawIntermediate, src),
			rootCert,
		}

		cb := NewChainBuilder()
		paths, err := cb.BuildChains(t.Context(), certs, ts)
		require.NoError(t, err)
		require.NotEmpty(t, paths)

		validator := NewValidator(WithValidatorTrustStore(ts))
		err = validator.Validate(t.Context(), paths, ValidationOptions{
			VerifyExpiry: true,
		})
		require.NoError(t, err)

		hasExpiredOnIntermediate := false
		for _, p := range paths {
			for _, ve := range p.Errors {
				if ve.Type == ErrorExpired && ve.Certificate != nil &&
					ve.Certificate.CommonName() == "Expired Intermediate" {
					hasExpiredOnIntermediate = true
				}
			}
		}
		assert.True(t, hasExpiredOnIntermediate,
			"expired intermediate must carry ErrorExpired attributed to the intermediate cert")
	})
}

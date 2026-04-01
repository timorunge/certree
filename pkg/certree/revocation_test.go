package certree

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// crlTestCA bundles a CA certificate with its signing key for CRL test helpers.
type crlTestCA struct {
	x509Cert *x509.Certificate
	cert     *Certificate
	key      *rsa.PrivateKey
}

// mustCreateCACert generates a CA cert, wraps it, and returns the signing key.
func mustCreateCACert(t *testing.T) crlTestCA {
	t.Helper()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: 1,
	}
	rawCert, key, err := testutil.GenerateSelfSignedCert(template)
	if err != nil {
		t.Fatalf("failed to generate CA cert: %v", err)
	}
	cert := NewCertificate(rawCert, CertificateSource{Type: SourceTypeFile, Location: "test-ca.pem"})
	return crlTestCA{x509Cert: rawCert, cert: cert, key: key}
}

// mustCreateLeafCert generates a leaf certificate signed by the given CA.
func mustCreateLeafCert(t *testing.T, ca crlTestCA, serial int64) *Certificate {
	t.Helper()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "leaf.example.com",
		},
		SerialNumber: big.NewInt(serial),
		DNSNames:     []string{"leaf.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	rawCert, _, err := testutil.GenerateSignedCert(template, ca.x509Cert, ca.key)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}
	return NewCertificate(rawCert, CertificateSource{Type: SourceTypeFile, Location: "leaf.pem"})
}

func newTestRevocationCache() *expiryCache[revocationCacheEntry] {
	return newExpiryCache(func(e revocationCacheEntry) time.Time { return e.expiresAt })
}

func TestRevocationCache_GetSet(t *testing.T) {
	t.Parallel()

	cache := newTestRevocationCache()
	revokedAtTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	status := RevocationStatus{
		IsRevoked:    true,
		RevokedAt:    &revokedAtTime,
		CheckedVia:   "CRL",
		ResponderURL: "http://crl.example.com/root.crl",
	}
	expiresAt := time.Now().Add(1 * time.Hour)

	cache.set("http://crl.example.com/root.crl", revocationCacheEntry{status: status, expiresAt: expiresAt}, expiresAt)

	entry, ok := cache.get("http://crl.example.com/root.crl", time.Time{})
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	got := entry.status
	if got.IsRevoked != status.IsRevoked {
		t.Errorf("IsRevoked: got %v, want %v", got.IsRevoked, status.IsRevoked)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(*status.RevokedAt) {
		t.Errorf("RevokedAt: got %v, want %v", got.RevokedAt, status.RevokedAt)
	}
	if got.CheckedVia != status.CheckedVia {
		t.Errorf("CheckedVia: got %q, want %q", got.CheckedVia, status.CheckedVia)
	}
	if got.ResponderURL != status.ResponderURL {
		t.Errorf("ResponderURL: got %q, want %q", got.ResponderURL, status.ResponderURL)
	}
}

func TestRevocationCache_Expired(t *testing.T) {
	t.Parallel()

	cache := newTestRevocationCache()
	status := RevocationStatus{
		IsRevoked:  false,
		CheckedVia: "OCSP",
	}
	// Expired 1 hour ago.
	expiresAt := time.Now().Add(-1 * time.Hour)

	cache.set("http://ocsp.example.com", revocationCacheEntry{status: status, expiresAt: expiresAt}, expiresAt)

	_, ok := cache.get("http://ocsp.example.com", time.Time{})
	if ok {
		t.Fatal("expected cache miss for expired entry, got hit")
	}
}

func TestRevocationCache_ZeroExpiry(t *testing.T) {
	t.Parallel()

	cache := newTestRevocationCache()
	status := RevocationStatus{
		IsRevoked:  false,
		CheckedVia: "CRL",
	}

	cache.set("http://crl.example.com/test.crl", revocationCacheEntry{status: status, expiresAt: time.Time{}}, time.Time{})

	_, ok := cache.get("http://crl.example.com/test.crl", time.Time{})
	if ok {
		t.Fatal("expected cache miss for zero-expiry entry, got hit")
	}
}

func TestRevocationCache_ValidationTimeOverride(t *testing.T) {
	t.Parallel()

	cache := newTestRevocationCache()
	status := RevocationStatus{
		IsRevoked:    false,
		CheckedVia:   "OCSP",
		ResponderURL: "http://ocsp.example.com",
	}

	// Entry expires at a fixed point in time.
	expiresAt := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	cache.set("ocsp:http://ocsp.example.com:123", revocationCacheEntry{status: status, expiresAt: expiresAt}, expiresAt)

	// Query before expiry: expect hit.
	beforeExpiry := time.Date(2025, 7, 1, 11, 0, 0, 0, time.UTC)
	entry, ok := cache.get("ocsp:http://ocsp.example.com:123", beforeExpiry)
	if !ok {
		t.Fatal("expected cache hit when now is before expiresAt")
	}
	if entry.status.CheckedVia != "OCSP" {
		t.Errorf("CheckedVia: got %q, want %q", entry.status.CheckedVia, "OCSP")
	}

	// Query after expiry: expect miss.
	afterExpiry := time.Date(2025, 7, 1, 13, 0, 0, 0, time.UTC)
	_, ok = cache.get("ocsp:http://ocsp.example.com:123", afterExpiry)
	if ok {
		t.Fatal("expected cache miss when now is after expiresAt")
	}
}

func TestCRLCache_ValidationTimeOverride(t *testing.T) {
	t.Parallel()

	ca := mustCreateCACert(t)

	crlTemplate := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{},
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate:                time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca.x509Cert, ca.key)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	cache := newExpiryCache(func(e crlCacheEntry) time.Time { return e.expiresAt })
	expiresAt := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	cache.set("http://crl.example.com/root.crl", crlCacheEntry{crl: crl, expiresAt: expiresAt}, expiresAt)

	// Query before expiry: expect hit.
	beforeExpiry := time.Date(2025, 7, 1, 11, 0, 0, 0, time.UTC)
	entry, ok := cache.get("http://crl.example.com/root.crl", beforeExpiry)
	if !ok {
		t.Fatal("expected CRL cache hit when now is before expiresAt")
	}
	if entry.crl != crl {
		t.Error("expected cached CRL to match stored CRL")
	}

	// Query after expiry: expect miss.
	afterExpiry := time.Date(2025, 7, 1, 13, 0, 0, 0, time.UTC)
	_, ok = cache.get("http://crl.example.com/root.crl", afterExpiry)
	if ok {
		t.Fatal("expected CRL cache miss when now is after expiresAt")
	}
}

func TestRevocationChecker_ResetCache(t *testing.T) {
	t.Parallel()

	t.Run("clears OCSP and CRL caches", func(t *testing.T) {
		t.Parallel()
		checker := NewRevocationChecker(WithRevocationCache(true))
		rc := checker.(*defaultRevocationChecker)

		// Populate both caches.
		ocspExpiry := time.Now().Add(time.Hour)
		rc.cache.set("ocsp:test:123", revocationCacheEntry{status: RevocationStatus{CheckedVia: "OCSP"}, expiresAt: ocspExpiry}, ocspExpiry)
		crlExpiry := time.Now().Add(time.Hour)
		rc.crlCache.set("http://crl.example.com/root.crl", crlCacheEntry{crl: &x509.RevocationList{}, expiresAt: crlExpiry}, crlExpiry)

		// Verify entries exist.
		if _, ok := rc.cache.get("ocsp:test:123", time.Time{}); !ok {
			t.Fatal("expected OCSP cache entry before reset")
		}
		if _, ok := rc.crlCache.get("http://crl.example.com/root.crl", time.Time{}); !ok {
			t.Fatal("expected CRL cache entry before reset")
		}

		checker.ResetCache()

		// Verify caches are empty.
		if _, ok := rc.cache.get("ocsp:test:123", time.Time{}); ok {
			t.Error("expected OCSP cache miss after reset")
		}
		if _, ok := rc.crlCache.get("http://crl.example.com/root.crl", time.Time{}); ok {
			t.Error("expected CRL cache miss after reset")
		}
	})

	t.Run("no-op when caching disabled", func(t *testing.T) {
		t.Parallel()
		checker := NewRevocationChecker() // cache disabled by default
		// Should not panic.
		checker.ResetCache()
	})
}

func TestCheckCertInCRL_NotRevoked(t *testing.T) {
	t.Parallel()

	ca := mustCreateCACert(t)
	leafCert := mustCreateLeafCert(t, ca, 42)

	// CRL with a different serial number.
	crlTemplate := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(999),
				RevocationTime: time.Now().Add(-1 * time.Hour),
			},
		},
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-1 * time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca.x509Cert, ca.key)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	status := checkCertInCRL(crl, "http://crl.example.com/root.crl", leafCert)

	if status.IsRevoked {
		t.Error("expected certificate to not be revoked")
	}
	if status.CheckedVia != "CRL" {
		t.Errorf("CheckedVia: got %q, want %q", status.CheckedVia, "CRL")
	}
	if status.ResponderURL != "http://crl.example.com/root.crl" {
		t.Errorf("ResponderURL: got %q, want %q", status.ResponderURL, "http://crl.example.com/root.crl")
	}
}

func TestCheckCertInCRL_Revoked(t *testing.T) {
	t.Parallel()

	ca := mustCreateCACert(t)

	// Generate a leaf with a known serial.
	leafTemplate := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "revoked.example.com",
		},
		SerialNumber: big.NewInt(12345),
		DNSNames:     []string{"revoked.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafX509, _, err := testutil.GenerateSignedCert(leafTemplate, ca.x509Cert, ca.key)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}
	leafCert := NewCertificate(leafX509, CertificateSource{Type: SourceTypeFile, Location: "revoked.pem"})

	revokedAt := time.Date(2025, 3, 1, 10, 0, 0, 0, time.UTC)
	crlTemplate := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   leafX509.SerialNumber,
				RevocationTime: revokedAt,
			},
		},
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-1 * time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca.x509Cert, ca.key)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	crlURL := "http://crl.example.com/root.crl"
	status := checkCertInCRL(crl, crlURL, leafCert)

	if !status.IsRevoked {
		t.Error("expected certificate to be revoked")
	}
	if status.RevokedAt == nil || !status.RevokedAt.Equal(revokedAt) {
		t.Errorf("RevokedAt: got %v, want %v", status.RevokedAt, revokedAt)
	}
	if status.CheckedVia != "CRL" {
		t.Errorf("CheckedVia: got %q, want %q", status.CheckedVia, "CRL")
	}
	if status.ResponderURL != crlURL {
		t.Errorf("ResponderURL: got %q, want %q", status.ResponderURL, crlURL)
	}
}

func TestValidateResponseFreshness_Valid(t *testing.T) {
	t.Parallel()

	thisUpdate := time.Now().Add(-1 * time.Hour)
	nextUpdate := time.Now().Add(24 * time.Hour)

	err := validateResponseFreshness(thisUpdate, nextUpdate, time.Time{}, "test response")
	if err != nil {
		t.Errorf("expected no error for valid timestamps, got: %v", err)
	}
}

func TestValidateResponseFreshness_Stale(t *testing.T) {
	t.Parallel()

	thisUpdate := time.Now().Add(-48 * time.Hour)
	nextUpdate := time.Now().Add(-1 * time.Hour)

	err := validateResponseFreshness(thisUpdate, nextUpdate, time.Time{}, "test response")
	if err == nil {
		t.Fatal("expected error for stale response, got nil")
	}
	if !errors.Is(err, ErrResponseStale) {
		t.Errorf("expected error wrapping ErrResponseStale, got: %v", err)
	}
}

func TestValidateResponseFreshness_NotYetValid(t *testing.T) {
	t.Parallel()

	thisUpdate := time.Now().Add(1 * time.Hour)
	nextUpdate := time.Now().Add(25 * time.Hour)

	err := validateResponseFreshness(thisUpdate, nextUpdate, time.Time{}, "test response")
	if err == nil {
		t.Fatal("expected error for not-yet-valid response, got nil")
	}
	if !errors.Is(err, ErrResponseNotYetValid) {
		t.Errorf("expected error wrapping ErrResponseNotYetValid, got: %v", err)
	}
}

func TestValidateResponseFreshness_ZeroTimes(t *testing.T) {
	t.Parallel()

	err := validateResponseFreshness(time.Time{}, time.Time{}, time.Time{}, "test response")
	if err != nil {
		t.Errorf("expected no error for zero timestamps, got: %v", err)
	}
}

func TestValidateResponseFreshness_WithinClockSkew(t *testing.T) {
	t.Parallel()

	// ThisUpdate is 2 minutes in the future, which is within the 5-minute tolerance.
	thisUpdate := time.Now().Add(2 * time.Minute)
	nextUpdate := time.Now().Add(24 * time.Hour)

	err := validateResponseFreshness(thisUpdate, nextUpdate, time.Time{}, "test response")
	if err != nil {
		t.Errorf("expected no error for ThisUpdate within clock skew tolerance, got: %v", err)
	}
}

func TestOCSPQueryExecution(t *testing.T) {
	t.Parallel()

	// Track if OCSP responder was queried.
	queryCalled := false

	// Create mock OCSP responder.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queryCalled = true
		w.WriteHeader(http.StatusOK)
		// Return a minimal OCSP response indicating "good".
		_, _ = w.Write([]byte{0x30, 0x03, 0x0a, 0x01, 0x00})
	}))
	defer server.Close()

	// Generate certificate with OCSP responder URL.
	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "ocsp-test.example.com",
		},
		IsCA:       false,
		KeyUsage:   x509.KeyUsageDigitalSignature,
		OCSPServer: []string{server.URL},
	}

	cert, _, err := testutil.GenerateSelfSignedCert(template)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	certWrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})

	checker := NewRevocationChecker(
		WithHTTPClient(&http.Client{Timeout: 2 * time.Second}),
		WithRevocationAllowPrivateNetworks(true),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	status, err := checker.CheckRevocation(ctx, certWrapped, certWrapped)

	if !queryCalled {
		t.Error("expected OCSP responder to be queried, but it was not")
	}

	// The mock returns a malformed OCSP response and the certificate has no CRL
	// distribution points, so both check methods fail.
	if err == nil {
		t.Fatal("expected error from CheckRevocation with malformed OCSP response, got nil")
	}
	if !errors.Is(err, ErrRevocationCheckFailed) {
		t.Errorf("expected error wrapping ErrRevocationCheckFailed, got: %v", err)
	}
	if status.IsRevoked {
		t.Error("expected IsRevoked to be false for failed revocation check")
	}
}

func TestCRLFallbackBehavior(t *testing.T) {
	t.Parallel()

	// Track if CRL endpoint was queried.
	crlCalled := false

	// Create mock CRL server.
	crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		crlCalled = true
		w.WriteHeader(http.StatusOK)
		// Return empty CRL (no revoked certificates).
		_, _ = w.Write([]byte{0x30, 0x00})
	}))
	defer crlServer.Close()

	// Create failing OCSP server.
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ocspServer.Close()

	// Generate certificate with both OCSP and CRL URLs.
	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "crl-fallback.example.com",
		},
		IsCA:               false,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		OCSPServer:         []string{ocspServer.URL},
		CRLDistributionPts: []string{crlServer.URL},
	}

	cert, _, err := testutil.GenerateSelfSignedCert(template)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	certWrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})

	// Create revocation checker.
	checker := NewRevocationChecker(
		WithHTTPClient(&http.Client{Timeout: 2 * time.Second}),
		WithRevocationAllowPrivateNetworks(true),
	)

	// Check revocation (OCSP should fail, CRL should be tried).
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	status, err := checker.CheckRevocation(ctx, certWrapped, certWrapped)

	if !crlCalled {
		t.Error("expected CRL endpoint to be queried after OCSP failure, but it was not")
	}

	// OCSP returns 500 and the mock CRL response is malformed, so both methods fail.
	if err == nil {
		t.Fatal("expected error from CheckRevocation when both OCSP and CRL fail, got nil")
	}
	if !errors.Is(err, ErrRevocationCheckFailed) {
		t.Errorf("expected error wrapping ErrRevocationCheckFailed, got: %v", err)
	}
	if status.IsRevoked {
		t.Error("expected IsRevoked to be false for failed revocation check")
	}
}

func TestFailOpenClosedRevocationHandling(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		failOpen bool
		wantWarn bool // expect warning entries
		wantErr  bool // expect error entries
	}{
		{"fail open", true, true, false},
		{"fail closed", false, false, true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()

			// Generate root CA.
			rootTemplate := testutil.CertificateTemplate{
				Subject: pkix.Name{
					CommonName: "Fail Open/Closed Root CA",
				},
				IsCA:     true,
				KeyUsage: x509.KeyUsageCertSign,
			}
			rootCert, rootKey, err := testutil.GenerateSelfSignedCert(rootTemplate)
			if err != nil {
				t.Fatalf("failed to generate root CA: %v", err)
			}

			// Generate end-entity certificate with OCSP responder URL.
			endEntityTemplate := testutil.CertificateTemplate{
				Subject: pkix.Name{
					CommonName: "fail-open-closed.example.com",
				},
				IsCA:       false,
				KeyUsage:   x509.KeyUsageDigitalSignature,
				OCSPServer: []string{server.URL},
			}
			endEntityCert, _, err := testutil.GenerateSignedCert(endEntityTemplate, rootCert, rootKey)
			if err != nil {
				t.Fatalf("failed to generate end-entity cert: %v", err)
			}

			rootWrapped := NewCertificate(rootCert, CertificateSource{Type: SourceTypeFile})
			endEntityWrapped := NewCertificate(endEntityCert, CertificateSource{Type: SourceTypeFile})

			path := &TrustPath{
				Certificates: []*Certificate{endEntityWrapped, rootWrapped},
			}

			checker := NewRevocationChecker(
				WithHTTPClient(&http.Client{Timeout: 2 * time.Second}),
				WithRevocationAllowPrivateNetworks(true),
			)
			validator := NewValidator(WithRevocationChecker(checker))

			opts := ValidationOptions{
				VerifyRevocation:   true,
				RevocationFailOpen: tt.failOpen,
			}

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			err = validator.Validate(ctx, []*TrustPath{path}, opts)

			if tt.failOpen && err != nil {
				t.Errorf("expected no error in fail-open mode, got: %v", err)
			}
			if tt.wantWarn && len(path.Warnings) == 0 {
				t.Error("expected warnings when revocation check fails in fail-open mode, got none")
			}
			if tt.wantErr && len(path.Errors) == 0 {
				t.Error("expected errors when revocation check fails in fail-closed mode, got none")
			}
		})
	}
}

func TestOCSPResponseParsing(t *testing.T) {
	t.Parallel()

	revokedAt := time.Date(2026, 1, 15, 8, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		serial      int64
		ocspStatus  int
		revokedAt   time.Time
		wantRevoked bool
	}{
		{
			name:        "Good",
			serial:      200,
			ocspStatus:  ocsp.Good,
			wantRevoked: false,
		},
		{
			name:        "Revoked",
			serial:      201,
			ocspStatus:  ocsp.Revoked,
			revokedAt:   revokedAt,
			wantRevoked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca := mustCreateCACert(t)
			leaf := mustCreateLeafCert(t, ca, tt.serial)

			now := time.Now()
			ocspTemplate := ocsp.Response{
				Status:       tt.ocspStatus,
				SerialNumber: leaf.Raw().SerialNumber,
				ThisUpdate:   now.Add(-1 * time.Minute),
				NextUpdate:   now.Add(24 * time.Hour),
			}
			if tt.wantRevoked {
				ocspTemplate.RevokedAt = tt.revokedAt
				ocspTemplate.RevocationReason = ocsp.Unspecified
			}
			respBytes, err := ocsp.CreateResponse(ca.x509Cert, ca.x509Cert, ocspTemplate, ca.key)
			if err != nil {
				t.Fatalf("failed to create OCSP response: %v", err)
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/ocsp-response")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(respBytes)
			}))
			defer server.Close()

			leafTemplate := testutil.CertificateTemplate{
				Subject:      leaf.Raw().Subject,
				SerialNumber: leaf.Raw().SerialNumber,
				OCSPServer:   []string{server.URL},
			}
			leafX509, _, genErr := testutil.GenerateSignedCert(leafTemplate, ca.x509Cert, ca.key)
			if genErr != nil {
				t.Fatalf("failed to generate leaf with OCSP URL: %v", genErr)
			}
			leafCert := NewCertificate(leafX509, CertificateSource{Type: SourceTypeFile, Location: "leaf.pem"})

			checker := NewRevocationChecker(
				WithHTTPClient(&http.Client{Timeout: 5 * time.Second}),
				WithRevocationAllowPrivateNetworks(true),
			)

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			status, checkErr := checker.CheckRevocation(ctx, leafCert, ca.cert)
			if checkErr != nil {
				t.Fatalf("expected no error, got: %v", checkErr)
			}
			if status.IsRevoked != tt.wantRevoked {
				t.Errorf("IsRevoked: got %v, want %v", status.IsRevoked, tt.wantRevoked)
			}
			if status.CheckedVia != "OCSP" {
				t.Errorf("CheckedVia: got %q, want %q", status.CheckedVia, "OCSP")
			}
			if status.ResponderURL != server.URL {
				t.Errorf("ResponderURL: got %q, want %q", status.ResponderURL, server.URL)
			}
			if tt.wantRevoked && (status.RevokedAt == nil || !status.RevokedAt.Equal(tt.revokedAt)) {
				t.Errorf("RevokedAt: got %v, want %v", status.RevokedAt, tt.revokedAt)
			}
		})
	}
}

// TestOCSPCertIDMismatch verifies that an OCSP response for a different certificate
// (different serial number) is rejected. This guards against a malicious or
// misconfigured OCSP responder returning a valid "Good" response for a different
// certificate than the one requested (RFC 6960 certID validation).
func TestOCSPCertIDMismatch(t *testing.T) {
	t.Parallel()

	ca := mustCreateCACert(t)
	// Create two leaf certificates with different serial numbers.
	requestedLeaf := mustCreateLeafCert(t, ca, 999)
	differentLeaf := mustCreateLeafCert(t, ca, 888)

	// Build an OCSP "Good" response for differentLeaf, not requestedLeaf.
	now := time.Now()
	ocspTemplate := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: differentLeaf.Raw().SerialNumber, // wrong cert
		ThisUpdate:   now.Add(-1 * time.Minute),
		NextUpdate:   now.Add(24 * time.Hour),
	}
	respBytes, err := ocsp.CreateResponse(ca.x509Cert, ca.x509Cert, ocspTemplate, ca.key)
	if err != nil {
		t.Fatalf("failed to create OCSP response for different cert: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
	}))
	defer server.Close()

	// Build a leaf cert that points to the server URL.
	leafTemplate := testutil.CertificateTemplate{
		Subject:      requestedLeaf.Raw().Subject,
		SerialNumber: requestedLeaf.Raw().SerialNumber,
		OCSPServer:   []string{server.URL},
	}
	leafX509, _, genErr := testutil.GenerateSignedCert(leafTemplate, ca.x509Cert, ca.key)
	if genErr != nil {
		t.Fatalf("failed to generate leaf with OCSP URL: %v", genErr)
	}
	leafCert := NewCertificate(leafX509, CertificateSource{Type: SourceTypeFile, Location: "leaf.pem"})

	checker := NewRevocationChecker(
		WithHTTPClient(&http.Client{Timeout: 5 * time.Second}),
		WithRevocationAllowPrivateNetworks(true),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	_, checkErr := checker.CheckRevocation(ctx, leafCert, ca.cert)
	// The OCSP check must fail because the response is for a different certificate.
	// ParseResponseForCert rejects certID mismatches.
	if checkErr == nil {
		t.Error("expected error when OCSP response is for a different certificate, got nil")
	}
}

func TestWithRevocationLogger_NilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil logger, got none")
		}
	}()
	WithRevocationLogger(nil)(&defaultRevocationChecker{})
}

func TestRevocationCache_EvictOldest(t *testing.T) {
	t.Parallel()

	cache := newTestRevocationCache()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Fill the cache to maxCacheEntries.
	for i := range maxCacheEntries {
		url := fmt.Sprintf("ocsp://entry-%d", i)
		// First entry expires earliest, last entry expires latest.
		expiry := now.Add(time.Duration(i+1) * time.Hour)
		cache.set(url, revocationCacheEntry{status: RevocationStatus{CheckedVia: "OCSP"}, expiresAt: expiry}, expiry)
	}

	if len(cache.entries) != maxCacheEntries {
		t.Fatalf("cache size = %d, want %d", len(cache.entries), maxCacheEntries)
	}

	// Adding one more entry should evict the oldest (entry-0, expires at now+1h).
	newExpiry := now.Add(24 * time.Hour)
	cache.set("ocsp://new-entry", revocationCacheEntry{status: RevocationStatus{CheckedVia: "OCSP"}, expiresAt: newExpiry}, newExpiry)

	if len(cache.entries) != maxCacheEntries {
		t.Fatalf("cache size after eviction = %d, want %d", len(cache.entries), maxCacheEntries)
	}

	// The oldest entry should have been evicted.
	if _, ok := cache.get("ocsp://entry-0", now); ok {
		t.Error("oldest entry should have been evicted")
	}

	// The new entry should be present.
	if _, ok := cache.get("ocsp://new-entry", now); !ok {
		t.Error("new entry should be present")
	}
}

func TestCRLCache_EvictOldest(t *testing.T) {
	t.Parallel()

	cache := newExpiryCache(func(e crlCacheEntry) time.Time { return e.expiresAt })
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Fill the cache to maxCacheEntries.
	for i := range maxCacheEntries {
		url := fmt.Sprintf("crl://entry-%d", i)
		expiry := now.Add(time.Duration(i+1) * time.Hour)
		cache.set(url, crlCacheEntry{crl: &x509.RevocationList{}, expiresAt: expiry}, expiry)
	}

	if len(cache.entries) != maxCacheEntries {
		t.Fatalf("cache size = %d, want %d", len(cache.entries), maxCacheEntries)
	}

	// Adding one more should evict the oldest.
	newExpiry := now.Add(24 * time.Hour)
	cache.set("crl://new-entry", crlCacheEntry{crl: &x509.RevocationList{}, expiresAt: newExpiry}, newExpiry)

	if len(cache.entries) != maxCacheEntries {
		t.Fatalf("cache size after eviction = %d, want %d", len(cache.entries), maxCacheEntries)
	}

	if _, ok := cache.get("crl://entry-0", now); ok {
		t.Error("oldest CRL entry should have been evicted")
	}

	if _, ok := cache.get("crl://new-entry", now); !ok {
		t.Error("new CRL entry should be present")
	}
}

func TestWithRevocationValidationTime(t *testing.T) {
	t.Parallel()

	customTime := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	rc := NewRevocationChecker(WithRevocationValidationTime(customTime)).(*defaultRevocationChecker)
	if !rc.validationTime.Equal(customTime) {
		t.Errorf("validationTime = %v, want %v", rc.validationTime, customTime)
	}
}

func TestOCSPCacheKeySeparator(t *testing.T) {
	t.Parallel()

	cache := newTestRevocationCache()
	expiresAt := time.Now().Add(1 * time.Hour)

	// Key A: responder "http://ocsp.example.com:8080", serial "123"
	keyA := "ocsp\x00" + "http://ocsp.example.com:8080" + "\x00" + "123"
	// Key B: responder "http://ocsp.example.com", serial "8080:123"
	// With ":" separator both would be "ocsp:http://ocsp.example.com:8080:123".
	// With "\x00" separator they are distinct.
	keyB := "ocsp\x00" + "http://ocsp.example.com" + "\x00" + "8080:123"

	statusA := RevocationStatus{IsRevoked: false, CheckedVia: "OCSP"}
	cache.set(keyA, revocationCacheEntry{status: statusA, expiresAt: expiresAt}, expiresAt)

	_, ok := cache.get(keyB, time.Time{})
	if ok {
		t.Error("cache returned a hit for keyB after setting keyA: separator collision detected")
	}
}

func TestSecurityRevocation_PrivateNetworkBlocking(t *testing.T) {
	t.Parallel()

	makeLeafWithOCSP := func(t *testing.T, ocspURL string) (*Certificate, *Certificate) {
		t.Helper()
		caCert, caKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:  pkix.Name{CommonName: "Revocation Test CA"},
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		})
		require.NoError(t, err)

		leafX509, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
			Subject:    pkix.Name{CommonName: "leaf.example.com"},
			DNSNames:   []string{"leaf.example.com"},
			OCSPServer: []string{ocspURL},
		}, caCert, caKey)
		require.NoError(t, err)

		return NewCertificate(leafX509, CertificateSource{Type: SourceTypeFile}),
			NewCertificate(caCert, CertificateSource{Type: SourceTypeFile})
	}

	makeLeafWithCRL := func(t *testing.T, crlURL string) (*Certificate, *Certificate) {
		t.Helper()
		caCert, caKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:  pkix.Name{CommonName: "CRL Test CA"},
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		})
		require.NoError(t, err)

		leafX509, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
			Subject:            pkix.Name{CommonName: "crl-leaf.example.com"},
			DNSNames:           []string{"crl-leaf.example.com"},
			CRLDistributionPts: []string{crlURL},
		}, caCert, caKey)
		require.NoError(t, err)

		return NewCertificate(leafX509, CertificateSource{Type: SourceTypeFile}),
			NewCertificate(caCert, CertificateSource{Type: SourceTypeFile})
	}

	t.Run("OCSP private URL is blocked by default", func(t *testing.T) {
		t.Parallel()

		for _, u := range []string{
			"http://127.0.0.1/ocsp",
			"http://10.0.0.1/ocsp",
			"http://192.168.1.1/ocsp",
		} {
			leaf, issuer := makeLeafWithOCSP(t, u)
			checker := NewRevocationChecker()
			_, err := checker.CheckRevocation(t.Context(), leaf, issuer)
			require.Error(t, err, "expected revocation check to be blocked for OCSP URL %s", u)
			assert.True(t, errors.Is(err, ErrRevocationCheckFailed),
				"expected ErrRevocationCheckFailed for private OCSP URL %s, got: %v", u, err)
		}
	})

	t.Run("CRL private URL is blocked by default", func(t *testing.T) {
		t.Parallel()

		for _, u := range []string{
			"http://127.0.0.1/crl.crl",
			"http://10.0.0.1/crl.crl",
		} {
			leaf, issuer := makeLeafWithCRL(t, u)
			checker := NewRevocationChecker()
			_, err := checker.CheckRevocation(t.Context(), leaf, issuer)
			require.Error(t, err, "expected revocation check to be blocked for CRL URL %s", u)
			assert.True(t, errors.Is(err, ErrRevocationCheckFailed),
				"expected ErrRevocationCheckFailed for private CRL URL %s, got: %v", u, err)
		}
	})

	t.Run("OCSP scheme guard survives AllowPrivateNetworks", func(t *testing.T) {
		t.Parallel()

		leaf, issuer := makeLeafWithOCSP(t, "ftp://127.0.0.1/ocsp")
		checker := NewRevocationChecker(WithRevocationAllowPrivateNetworks(true))
		_, err := checker.CheckRevocation(t.Context(), leaf, issuer)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrRevocationCheckFailed),
			"expected ErrRevocationCheckFailed for ftp:// OCSP URL, got: %v", err)
	})
}

func TestSecurityExpiryCache_ConcurrentGetSet(t *testing.T) {
	t.Parallel()

	expiry := time.Now().Add(time.Hour)
	cache := newExpiryCache(func(e revocationCacheEntry) time.Time {
		return e.expiresAt
	})

	const goroutines = 16
	var wg sync.WaitGroup

	for i := range goroutines {
		idx := i
		wg.Go(func() {
			key := fmt.Sprintf("k%d", idx)
			entry := revocationCacheEntry{expiresAt: expiry}
			if idx == 0 {
				cache.reset()
			} else if idx%2 == 0 {
				_, _ = cache.get(key, time.Time{})
			} else {
				cache.set(key, entry, expiry)
			}
		})
	}

	wg.Wait()
}

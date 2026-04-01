package certree

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// testLogHandler is a function-based slog.Handler that allows per-test callback
// injection. This differs from mockLogHandler in chainbuilder_test.go, which
// captures structured log entries for later assertion. Both exist because
// AIA tests need selective interception (e.g., counting specific warnings)
// while chain builder tests need full log replay.
type testLogHandler struct {
	mu        sync.Mutex
	debugFunc func(msg string, args ...any)
	infoFunc  func(msg string, args ...any)
	warnFunc  func(msg string, args ...any)
	errorFunc func(msg string, args ...any)
}

func (h *testLogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *testLogHandler) Handle(_ context.Context, r slog.Record) error {
	args := make([]any, 0, r.NumAttrs()*2)
	r.Attrs(func(a slog.Attr) bool {
		args = append(args, a.Key, a.Value.Any())
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case r.Level >= slog.LevelError:
		if h.errorFunc != nil {
			h.errorFunc(r.Message, args...)
		}
	case r.Level >= slog.LevelWarn:
		if h.warnFunc != nil {
			h.warnFunc(r.Message, args...)
		}
	case r.Level >= slog.LevelInfo:
		if h.infoFunc != nil {
			h.infoFunc(r.Message, args...)
		}
	default:
		if h.debugFunc != nil {
			h.debugFunc(r.Message, args...)
		}
	}
	return nil
}

func (h *testLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

func (h *testLogHandler) WithGroup(_ string) slog.Handler { return h }

// newTestLogger wraps a testLogHandler in a *slog.Logger for use with With*Logger options.
func newTestLogger(h *testLogHandler) *slog.Logger {
	return slog.New(h)
}

func TestAIAFetcher_InvalidSignatureRejection(t *testing.T) {
	t.Parallel()

	// Generate CA1: the real issuer that signs the leaf certificate.
	ca1Cert, ca1Key, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "CA1 Real Root",
			Organization: []string{"Test Org"},
		},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	if err != nil {
		t.Fatalf("Failed to generate CA1: %v", err)
	}

	// Generate CA2: a different CA whose key creates the fake issuer.
	// Use non-cached generation to ensure CA2 has a different key than CA1.
	_, ca2Key, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "CA2 Different Root",
			Organization: []string{"Different Org"},
		},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	if err != nil {
		t.Fatalf("Failed to generate CA2: %v", err)
	}

	// Create the fake issuer: has CA1's subject name but is self-signed with
	// CA2's key. The certificate is syntactically valid (parseable DER/ASN.1)
	// but its public key cannot verify the leaf's signature.
	fakeTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		Subject:               ca1Cert.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	fakeIssuerCert, err := testutil.CreateAndParseCert(fakeTemplate, fakeTemplate, &ca2Key.PublicKey, ca2Key)
	if err != nil {
		t.Fatalf("Failed to generate fake issuer: %v", err)
	}

	// Serve the fake issuer via a test HTTP server (DER format).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(fakeIssuerCert.Raw)
	}))
	defer server.Close()

	// Generate a leaf certificate signed by CA1 with AIA pointing to the test server.
	leafCert, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:        pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:       []string{"leaf.example.com"},
		IssuingCertURL: []string{server.URL},
	}, ca1Cert, ca1Key)
	if err != nil {
		t.Fatalf("Failed to generate leaf: %v", err)
	}

	wrappedLeaf := NewCertificate(leafCert, CertificateSource{Type: SourceTypeFile})

	// FetchIssuers should succeed because the fake issuer is valid DER.
	fetcher := NewAIAFetcher(WithAIAAllowPrivateNetworks(true))
	fetchedCerts, err := fetcher.FetchIssuers(t.Context(), wrappedLeaf)
	if err != nil {
		t.Fatalf("Expected FetchIssuers to succeed for parseable certificate, got error: %v", err)
	}

	if len(fetchedCerts) == 0 {
		t.Fatal("Expected at least one fetched certificate")
	}
	fetchedCert := fetchedCerts[0]

	if fetchedCert.Raw().Subject.CommonName != ca1Cert.Subject.CommonName {
		t.Errorf("Expected fetched cert CN %q, got %q",
			ca1Cert.Subject.CommonName, fetchedCert.Raw().Subject.CommonName)
	}

	// The critical assertion: the leaf's signature cannot be verified by the
	// fake issuer because the fake issuer has CA2's public key, not CA1's.
	sigErr := leafCert.CheckSignatureFrom(fetchedCert.Raw())
	if sigErr == nil {
		t.Fatal("Expected signature verification to fail: fake issuer has a different key than the real signer")
	}

	// Sanity check: the real CA1 can verify the leaf's signature.
	if err := leafCert.CheckSignatureFrom(ca1Cert); err != nil {
		t.Fatalf("Sanity check failed: real CA1 should verify the leaf signature: %v", err)
	}
}

func TestAIAFetcher_ExpiredCertificateHandling(t *testing.T) {
	t.Parallel()

	// Generate an expired certificate (expired 1 year ago)
	notBefore := time.Now().Add(-2 * 365 * 24 * time.Hour)
	notAfter := time.Now().Add(-365 * 24 * time.Hour)
	expiredCert, _, err := testutil.GenerateCertificateWithExpiry("expired.example.com", notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to generate expired certificate: %v", err)
	}

	if time.Now().Before(expiredCert.NotAfter) {
		t.Fatal("Test certificate is not expired")
	}

	// Create a test server that returns the expired certificate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return PEM-encoded expired certificate
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: expiredCert.Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pemBytes)
	}))
	defer server.Close()

	// Create a certificate with AIA extension pointing to the test server
	certWithAIA, _, err := testutil.GenerateCertificateWithAIA("test.example.com", server.URL)
	if err != nil {
		t.Fatalf("Failed to generate certificate with AIA: %v", err)
	}

	wrappedCert := &Certificate{
		raw:    certWithAIA,
		source: CertificateSource{Type: SourceTypeFile},
	}

	// Create AIA fetcher
	fetcher := NewAIAFetcher(WithAIAAllowPrivateNetworks(true))

	// Fetch the expired certificate
	fetchedCerts, err := fetcher.FetchIssuers(t.Context(), wrappedCert)

	// The fetch should succeed - expired certificates are included
	if err != nil {
		t.Fatalf("Expected successful fetch of expired certificate, got error: %v", err)
	}

	if len(fetchedCerts) == 0 {
		t.Fatal("Expected at least one fetched certificate")
	}
	fetchedCert := fetchedCerts[0]

	if fetchedCert.Source().Type != SourceTypeAIA {
		t.Errorf("Expected source type AIA, got %v", fetchedCert.Source().Type)
	}

	if time.Now().Before(fetchedCert.Raw().NotAfter) {
		t.Error("Fetched certificate should be expired")
	}

	if fetchedCert.Raw().Subject.CommonName != "expired.example.com" {
		t.Errorf("Expected CN 'expired.example.com', got '%s'", fetchedCert.Raw().Subject.CommonName)
	}
}

func TestAIAFetcher_IssuerMismatchExclusion(t *testing.T) {
	t.Parallel()

	// Generate CA1 root with explicit SubjectKeyID so that child certificates
	// get AuthorityKeyId set, enabling the chain builder's AKI/SKI mismatch check.
	ca1Cert, ca1Key, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "CA1 Root",
			Organization: []string{"Test Org"},
		},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyID: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	})
	if err != nil {
		t.Fatalf("Failed to generate CA1: %v", err)
	}

	// Generate intermediate1 signed by CA1 with its own SubjectKeyID.
	// The leaf's AuthorityKeyId will match intermediate1's SubjectKeyID.
	intermediate1Cert, intermediate1Key, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Intermediate CA1",
			Organization: []string{"Test Org"},
		},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyID: []byte{10, 20, 30, 40, 50, 60, 70, 80},
	}, ca1Cert, ca1Key)
	if err != nil {
		t.Fatalf("Failed to generate intermediate1: %v", err)
	}

	// Generate CA2 (different chain) with its own SubjectKeyID.
	ca2Cert, ca2Key, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "CA2 Root",
			Organization: []string{"Different Org"},
		},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyID: []byte{99, 98, 97, 96, 95, 94, 93, 92},
	})
	if err != nil {
		t.Fatalf("Failed to generate CA2: %v", err)
	}

	// Generate wrong intermediate signed by CA2 (entirely different chain).
	// Its SubjectKeyID will NOT match the leaf's AuthorityKeyId.
	wrongIntermediateCert, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Wrong Intermediate CA2",
			Organization: []string{"Different Org"},
		},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyID: []byte{91, 92, 93, 94, 95, 96, 97, 98},
	}, ca2Cert, ca2Key)
	if err != nil {
		t.Fatalf("Failed to generate wrong intermediate: %v", err)
	}

	// Set up a test server that returns the wrong intermediate in DER format.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(wrongIntermediateCert.Raw)
	}))
	defer server.Close()

	// Generate leaf signed by intermediate1 with AIA pointing to the test server.
	// The leaf's AuthorityKeyId = intermediate1's SubjectKeyID = {10,20,30,40,50,60,70,80}.
	leafCert, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:        pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:       []string{"leaf.example.com"},
		IssuingCertURL: []string{server.URL},
	}, intermediate1Cert, intermediate1Key)
	if err != nil {
		t.Fatalf("Failed to generate leaf: %v", err)
	}

	// Track whether the chain builder logs an issuer mismatch exclusion warning.
	var mismatchDetected atomic.Bool
	logger := newTestLogger(&testLogHandler{
		warnFunc: func(msg string, _ ...any) {
			if msg == "excluding fetched certificate from path building due to issuer mismatch" {
				mismatchDetected.Store(true)
			}
		},
	})

	wrappedLeaf := NewCertificate(leafCert, CertificateSource{Type: SourceTypeFile})
	wrappedRoot := NewCertificate(ca1Cert, CertificateSource{Type: SourceTypeFile})

	// Create a real AIA fetcher that hits the test server.
	fetcher := NewAIAFetcher(WithAIAAllowPrivateNetworks(true))

	// Trust store contains CA1's root only.
	trustStore := &mockTrustStoreWithRoot{root: wrappedRoot}

	// Build chains with only the leaf; intermediate1 is intentionally missing
	// so the chain builder must attempt AIA to find it. AIA returns the wrong
	// intermediate from CA2, which should be rejected via AKI/SKI mismatch.
	builder := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAFetcher(fetcher),
		WithChainLogger(logger),
	)

	paths, err := builder.BuildChains(t.Context(), []*Certificate{wrappedLeaf}, trustStore)
	if err != nil {
		t.Fatalf("BuildChains failed: %v", err)
	}

	// The chain builder's AKI/SKI check should have detected the mismatch
	// between the leaf's AuthorityKeyId and the wrong intermediate's SubjectKeyId.
	if !mismatchDetected.Load() {
		t.Error("Expected chain builder to log an issuer mismatch warning for the wrong intermediate")
	}

	wrongFingerprint := NewCertificate(wrongIntermediateCert, CertificateSource{Type: SourceTypeAIA}).FingerprintSHA256()
	for i, path := range paths {
		for _, cert := range path.Certificates {
			if cert.FingerprintSHA256() == wrongFingerprint {
				t.Errorf("Path %d contains the wrong intermediate %q which should have been excluded",
					i, wrongIntermediateCert.Subject.CommonName)
			}
		}
	}

	// Since intermediate1 was never provided and AIA returned the wrong cert,
	// no complete trusted path to CA1 should exist.
	for i, path := range paths {
		if path.Status == PathTrusted {
			t.Errorf("Path %d is trusted, but should be incomplete: correct intermediate was never available", i)
		}
	}
}

func TestAIAFetcher_MalformedCertificateData(t *testing.T) {
	t.Parallel()

	// Create a test server that returns malformed data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return invalid certificate data
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write([]byte("this is not a valid certificate"))
	}))
	defer server.Close()

	// Create a certificate with AIA extension pointing to the test server
	certWithAIA, _, err := testutil.GenerateCertificateWithAIA("test.example.com", server.URL)
	if err != nil {
		t.Fatalf("Failed to generate certificate with AIA: %v", err)
	}

	wrappedCert := &Certificate{
		raw:    certWithAIA,
		source: CertificateSource{Type: SourceTypeFile},
	}

	// Create AIA fetcher
	fetcher := NewAIAFetcher(WithAIAAllowPrivateNetworks(true))

	// Attempt to fetch issuer - should fail due to malformed data
	_, err = fetcher.FetchIssuers(t.Context(), wrappedCert)

	if err == nil {
		t.Error("Expected error when fetching malformed certificate data, got nil")
	}

	if !errors.Is(err, ErrAIAFetchFailed) {
		t.Errorf("Expected error to match ErrAIAFetchFailed, got: %v", err)
	}
}

func TestAIAFetcher_EmptyCertificateResponse(t *testing.T) {
	t.Parallel()

	// Create a test server that returns empty data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		// Return empty response
	}))
	defer server.Close()

	// Create a certificate with AIA extension pointing to the test server
	certWithAIA, _, err := testutil.GenerateCertificateWithAIA("test.example.com", server.URL)
	if err != nil {
		t.Fatalf("Failed to generate certificate with AIA: %v", err)
	}

	wrappedCert := &Certificate{
		raw:    certWithAIA,
		source: CertificateSource{Type: SourceTypeFile},
	}

	// Create AIA fetcher
	fetcher := NewAIAFetcher(WithAIAAllowPrivateNetworks(true))

	// Attempt to fetch issuer - should fail due to empty data
	_, err = fetcher.FetchIssuers(t.Context(), wrappedCert)

	if err == nil {
		t.Error("Expected error when fetching empty certificate data, got nil")
	}
}

func TestAIAFetcher_CertificateWithWrongKeyUsage(t *testing.T) {
	t.Parallel()

	// Generate a certificate with wrong key usage (not a CA)
	priv := testutil.GetCachedKey()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "not-a-ca.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature, // Not KeyUsageCertSign
		BasicConstraintsValid: true,
		IsCA:                  false, // Not a CA
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create a test server that returns the non-CA certificate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pemBytes)
	}))
	defer server.Close()

	// Create a certificate with AIA extension pointing to the test server
	certWithAIA, _, err := testutil.GenerateCertificateWithAIA("test.example.com", server.URL)
	if err != nil {
		t.Fatalf("Failed to generate certificate with AIA: %v", err)
	}

	wrappedCert := &Certificate{
		raw:    certWithAIA,
		source: CertificateSource{Type: SourceTypeFile},
	}

	// Create AIA fetcher
	fetcher := NewAIAFetcher(WithAIAAllowPrivateNetworks(true))

	// Fetch the certificate - should succeed (fetcher doesn't validate key usage)
	fetchedCerts, err := fetcher.FetchIssuers(t.Context(), wrappedCert)

	if err != nil {
		t.Fatalf("Expected successful fetch, got error: %v", err)
	}

	if len(fetchedCerts) == 0 {
		t.Fatal("Expected at least one fetched certificate")
	}
	fetchedCert := fetchedCerts[0]

	if fetchedCert.Source().Type != SourceTypeAIA {
		t.Errorf("Expected source type AIA, got %v", fetchedCert.Source().Type)
	}

	if fetchedCert.Raw().IsCA {
		t.Error("Expected non-CA certificate")
	}
}

func TestAIAFetcher_HTTPErrorCodes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"404 Not Found", http.StatusNotFound, true},
		{"500 Internal Server Error", http.StatusInternalServerError, true},
		{"403 Forbidden", http.StatusForbidden, true},
		{"401 Unauthorized", http.StatusUnauthorized, true},
		{"503 Service Unavailable", http.StatusServiceUnavailable, true},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			certWithAIA, _, err := testutil.GenerateCertificateWithAIA("test.example.com", server.URL)
			if err != nil {
				t.Fatalf("Failed to generate certificate with AIA: %v", err)
			}

			wrappedCert := &Certificate{
				raw:    certWithAIA,
				source: CertificateSource{Type: SourceTypeFile},
			}

			fetcher := NewAIAFetcher(WithAIAAllowPrivateNetworks(true))
			_, err = fetcher.FetchIssuers(t.Context(), wrappedCert)

			if (err != nil) != tt.wantErr {
				t.Errorf("FetchIssuers() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAIAFetcher_CacheOption(t *testing.T) {
	t.Parallel()

	// newCountingServer creates an HTTP test server that serves a fresh
	// self-signed issuer certificate and counts requests via the returned
	// atomic counter. Each subtest gets its own server to avoid races.
	newCountingServer := func(t *testing.T) (*httptest.Server, *atomic.Int32) {
		t.Helper()
		var count atomic.Int32

		tmpl := testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "Issuer"},
			IsCA:    true,
		}
		issuerCert, _, err := testutil.GenerateSelfSignedCert(tmpl)
		if err != nil {
			t.Fatalf("Failed to generate issuer certificate: %v", err)
		}
		issuerDER := NewCertificate(issuerCert, CertificateSource{
			Type:     SourceTypeFile,
			Location: "test",
		}).DER()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			count.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(issuerDER)
		}))
		t.Cleanup(srv.Close)
		return srv, &count
	}

	// fetchN generates n certs all pointing to the same AIA URL, fetches
	// them all, and returns the number of HTTP requests observed.
	fetchN := func(t *testing.T, fetcher AIAFetcher, url string, n int) {
		t.Helper()
		for i := range n {
			cert, _, err := testutil.GenerateCertificateWithAIA(
				fmt.Sprintf("Cert %d", i), url,
			)
			if err != nil {
				t.Fatalf("GenerateCertificateWithAIA: %v", err)
			}
			wrapped := NewCertificate(cert, CertificateSource{
				Type:     SourceTypeFile,
				Location: "test",
			})
			// Error is expected for test certs; only request count matters.
			if _, err := fetcher.FetchIssuers(t.Context(), wrapped); err != nil {
				t.Logf("FetchIssuers[%d]: %v", i, err)
			}
		}
	}

	t.Run("cache enabled deduplicates", func(t *testing.T) {
		t.Parallel()

		srv, count := newCountingServer(t)
		fetcher := NewAIAFetcher(
			WithAIACache(true),
			WithAIAAllowPrivateNetworks(true),
		)

		fetchN(t, fetcher, srv.URL, 5)
		if got := count.Load(); got != 1 {
			t.Errorf("expected 1 HTTP request with cache enabled, got %d", got)
		}
	})

	t.Run("cache disabled fetches every time", func(t *testing.T) {
		t.Parallel()

		srv, count := newCountingServer(t)
		fetcher := NewAIAFetcher(
			WithAIACache(false),
			WithAIAAllowPrivateNetworks(true),
		)

		fetchN(t, fetcher, srv.URL, 5)
		if got := count.Load(); got != 5 {
			t.Errorf("expected 5 HTTP requests with cache disabled, got %d", got)
		}
	})
}

func TestAIAFetcher_ResetCache(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32

	issuerCert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Issuer"}, IsCA: true,
	})
	if err != nil {
		t.Fatalf("generating issuer cert: %v", err)
	}
	issuerDER := NewCertificate(issuerCert, CertificateSource{
		Type: SourceTypeFile, Location: "test",
	}).DER()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(issuerDER)
	}))
	defer srv.Close()

	fetcher := NewAIAFetcher(
		WithAIACache(true),
		WithAIAAllowPrivateNetworks(true),
	)

	cert, _, err := testutil.GenerateCertificateWithAIA("Leaf", srv.URL)
	if err != nil {
		t.Fatalf("generating cert with AIA: %v", err)
	}
	wrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile, Location: "test"})

	// First fetch -- hits the network.
	_, err = fetcher.FetchIssuers(t.Context(), wrapped)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if got := requestCount.Load(); got != 1 {
		t.Fatalf("expected 1 request after first fetch, got %d", got)
	}

	// Second fetch -- served from cache.
	_, err = fetcher.FetchIssuers(t.Context(), wrapped)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := requestCount.Load(); got != 1 {
		t.Fatalf("expected 1 request after cached fetch, got %d", got)
	}

	// Clear cache.
	fetcher.ResetCache()

	// Third fetch -- must hit the network again.
	_, err = fetcher.FetchIssuers(t.Context(), wrapped)
	if err != nil {
		t.Fatalf("fetch after cache reset: %v", err)
	}
	if got := requestCount.Load(); got != 2 {
		t.Errorf("expected 2 requests after cache reset, got %d", got)
	}
}

func TestWithAIATimeout(t *testing.T) {
	t.Parallel()

	t.Run("positive duration sets timeout", func(t *testing.T) {
		t.Parallel()
		f := NewAIAFetcher(WithAIATimeout(5 * time.Second)).(*defaultAIAFetcher)
		if f.opts.timeout != 5*time.Second {
			t.Errorf("timeout = %v, want 5s", f.opts.timeout)
		}
	})

	t.Run("zero duration sets timeout to zero", func(t *testing.T) {
		t.Parallel()
		f := NewAIAFetcher(WithAIATimeout(0)).(*defaultAIAFetcher)
		if f.opts.timeout != 0 {
			t.Errorf("timeout = %v, want 0", f.opts.timeout)
		}
	})

	t.Run("negative duration is ignored", func(t *testing.T) {
		t.Parallel()
		f := NewAIAFetcher(WithAIATimeout(-1 * time.Second)).(*defaultAIAFetcher)
		// Default timeout should remain unchanged.
		if f.opts.timeout < 0 {
			t.Errorf("negative timeout should be ignored, got %v", f.opts.timeout)
		}
	})
}

func TestWithAIALogger_NilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil logger, got none")
		}
	}()
	WithAIALogger(nil)(&defaultAIAFetcher{})
}

func TestSecurityAIAFetcher_PrivateNetworkBlocking(t *testing.T) {
	t.Parallel()

	makeLeafWithAIA := func(t *testing.T, aiaURL string) *Certificate {
		t.Helper()
		x509Cert, _, err := testutil.GenerateCertificateWithAIA("leaf.example.com", aiaURL)
		require.NoError(t, err)
		return NewCertificate(x509Cert, CertificateSource{Type: SourceTypeFile})
	}

	privateURLs := []string{
		"http://127.0.0.1/issuer.crt",
		"http://10.0.0.1/issuer.crt",
		"http://192.168.1.1/issuer.crt",
		"http://[::1]/issuer.crt",
	}

	t.Run("private AIA URLs are blocked by default", func(t *testing.T) {
		t.Parallel()

		fetcher := NewAIAFetcher()
		for _, u := range privateURLs {
			t.Run(u, func(t *testing.T) {
				t.Parallel()
				leaf := makeLeafWithAIA(t, u)
				_, err := fetcher.FetchIssuers(t.Context(), leaf)
				require.Error(t, err, "expected AIA fetch to be blocked for %s", u)
				assert.True(t, errors.Is(err, ErrAIAFetchFailed),
					"expected ErrAIAFetchFailed for blocked URL %s, got: %v", u, err)
			})
		}
	})

	t.Run("scheme guard survives AllowPrivateNetworks", func(t *testing.T) {
		t.Parallel()

		fetcher := NewAIAFetcher(WithAIAAllowPrivateNetworks(true))

		badSchemes := []string{
			"ftp://127.0.0.1/issuer.crt",
			"file:///etc/ssl/certs/issuer.crt",
		}
		for _, u := range badSchemes {
			t.Run(u, func(t *testing.T) {
				t.Parallel()
				leaf := makeLeafWithAIA(t, u)
				_, err := fetcher.FetchIssuers(t.Context(), leaf)
				require.Error(t, err, "expected scheme rejection for %s", u)
				assert.True(t, errors.Is(err, ErrAIAFetchFailed),
					"expected ErrAIAFetchFailed for bad-scheme AIA URL %s, got: %v", u, err)
			})
		}
	})

	t.Run("credential guard survives AllowPrivateNetworks", func(t *testing.T) {
		t.Parallel()

		fetcher := NewAIAFetcher(WithAIAAllowPrivateNetworks(true))
		leaf := makeLeafWithAIA(t, "http://admin:secret@127.0.0.1/issuer.crt")
		_, err := fetcher.FetchIssuers(t.Context(), leaf)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrAIAFetchFailed),
			"expected ErrAIAFetchFailed for credential-bearing AIA URL, got: %v", err)
	})
}

func TestSecurityAIAFetcher_ResponseSizeCap(t *testing.T) {
	t.Parallel()

	bigBody := strings.Repeat("A", maxAIAResponseSize+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, bigBody)
	}))
	defer srv.Close()

	x509Cert, _, err := testutil.GenerateCertificateWithAIA("leaf.example.com", srv.URL)
	require.NoError(t, err)
	leaf := NewCertificate(x509Cert, CertificateSource{Type: SourceTypeFile})

	fetcher := NewAIAFetcher(
		WithAIAAllowPrivateNetworks(true),
		WithAIATimeout(5*time.Second),
	)
	_, err = fetcher.FetchIssuers(t.Context(), leaf)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAIAFetchFailed),
		"expected ErrAIAFetchFailed when AIA response exceeds size limit, got: %v", err)
}

func TestSecurityAIAFetcher_ValidResponseAccepted(t *testing.T) {
	t.Parallel()

	issuerX509, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "Intermediate CA"},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerX509.Raw})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemData)
	}))
	defer srv.Close()

	leafX509, _, err := testutil.GenerateCertificateWithAIA("valid.example.com", srv.URL)
	require.NoError(t, err)
	leaf := NewCertificate(leafX509, CertificateSource{Type: SourceTypeFile})

	fetcher := NewAIAFetcher(
		WithAIAAllowPrivateNetworks(true),
		WithAIATimeout(5*time.Second),
	)
	certs, err := fetcher.FetchIssuers(t.Context(), leaf)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "Intermediate CA", certs[0].CommonName())
}

func TestSecurityAIAFetcher_ConcurrentResetCache(t *testing.T) {
	t.Parallel()

	fetcher := NewAIAFetcher()

	const goroutines = 16
	var wg sync.WaitGroup

	for range goroutines {
		wg.Go(func() {
			fetcher.ResetCache()
		})
	}

	wg.Wait()
}

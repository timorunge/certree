package certree

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

var (
	analyzerSimpleChainOnce sync.Once
	analyzerSimpleChainX509 []*x509.Certificate
)

func getAnalyzerSimpleChain(t *testing.T) []*x509.Certificate {
	t.Helper()
	analyzerSimpleChainOnce.Do(func() {
		certs, _, err := testutil.GenerateSimpleChain()
		if err != nil {
			panic(fmt.Sprintf("generating simple chain: %v", err))
		}
		analyzerSimpleChainX509 = certs
	})
	return analyzerSimpleChainX509
}

// mockChainBuilderErr is a ChainBuilder that always returns an error.
type mockChainBuilderErr struct {
	err error
}

func (m *mockChainBuilderErr) BuildChains(_ context.Context, _ []*Certificate, _ TrustStore) ([]*TrustPath, error) {
	return nil, m.err
}

// mockValidatorErr is a Validator that always returns an error.
type mockValidatorErr struct {
	err error
}

func (m *mockValidatorErr) Validate(_ context.Context, _ []*TrustPath, _ ValidationOptions) error {
	return m.err
}

// analyzerMockTrustStore is a direct mock of TrustStore for analyzer tests.
// It holds pre-wrapped root certificates and implements trust matching by
// fingerprint comparison and issuer-subject byte matching.
type analyzerMockTrustStore struct {
	roots []*Certificate
}

var _ TrustStore = (*analyzerMockTrustStore)(nil)

func (m *analyzerMockTrustStore) IsTrusted(cert *Certificate) bool {
	for _, root := range m.roots {
		if cert.FingerprintSHA256() == root.FingerprintSHA256() {
			return true
		}
	}
	return false
}

func (m *analyzerMockTrustStore) TrustedLocations(cert *Certificate) []string {
	if m.IsTrusted(cert) {
		return []string{"test"}
	}
	return nil
}

func (m *analyzerMockTrustStore) LoadSystemRoots() error { return nil }

func (m *analyzerMockTrustStore) LoadCustomRoots(_ string) error { return nil }

func (m *analyzerMockTrustStore) FindIssuers(cert *Certificate) []*Certificate {
	if cert == nil {
		return nil
	}
	var matched []*Certificate
	for _, root := range m.roots {
		if bytes.Equal(cert.Raw().RawIssuer, root.Raw().RawSubject) {
			matched = append(matched, root)
		}
	}
	return matched
}

func TestDeriveHostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		sni    string
		opts   *ValidationOptions
		want   string
	}{
		{
			name:   "opts hostname set returns empty",
			source: "example.com:443",
			sni:    "override.com",
			opts:   &ValidationOptions{Hostname: "explicit.com"},
			want:   "",
		},
		{
			name:   "SNI set no opts hostname",
			source: "example.com:443",
			sni:    "sni.example.com",
			opts:   &ValidationOptions{},
			want:   "sni.example.com",
		},
		{
			name:   "remote host domain no SNI",
			source: "example.com:443",
			sni:    "",
			opts:   &ValidationOptions{},
			want:   "example.com",
		},
		{
			name:   "remote host IP returns empty",
			source: "1.2.3.4:443",
			sni:    "",
			opts:   &ValidationOptions{},
			want:   "",
		},
		{
			name:   "file path returns empty",
			source: "cert.pem",
			sni:    "",
			opts:   &ValidationOptions{},
			want:   "",
		},
		{
			name:   "both SNI and source SNI wins",
			source: "example.com:443",
			sni:    "sni.example.com",
			opts:   &ValidationOptions{},
			want:   "sni.example.com",
		},
		{
			name:   "nil opts empty SNI file source",
			source: "cert.pem",
			sni:    "",
			opts:   nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := deriveHostname(tt.source, tt.sni, tt.opts)
			if got != tt.want {
				t.Errorf("deriveHostname(%q, %q, %+v) = %q, want %q",
					tt.source, tt.sni, tt.opts, got, tt.want)
			}
		})
	}
}

func TestAnalyzerOptions_NilRejection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fn   func()
	}{
		{"WithChainBuilder nil", func() { WithChainBuilder(nil)(new(Analyzer)) }},
		{"WithParser nil", func() { WithParser(nil)(new(Analyzer)) }},
		{"WithTrustStore nil", func() { WithTrustStore(nil)(new(Analyzer)) }},
		{"WithValidator nil", func() { WithValidator(nil)(new(Analyzer)) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected panic for nil argument, got none")
				}
			}()
			tt.fn()
		})
	}
}

func TestAnalyzeHost_StructuredErrorPassthrough(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))),
		WithRemoteOptions(RemoteOptions{
			Timeout:        2 * time.Second,
			SNI:            "example.com",
			VerifyHostname: false,
		}),
	)
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}

	_, analyzeErr := analyzer.AnalyzeHost(t.Context(), "127.0.0.1:9999")
	if analyzeErr == nil {
		t.Fatal("expected connection error, got nil")
	}

	if !errors.Is(analyzeErr, ErrConnectionFailed) {
		t.Errorf("errors.Is(err, ErrConnectionFailed) = false through wrapping; err = %v", analyzeErr)
	}

	var se *StructuredError
	if !errors.As(analyzeErr, &se) {
		t.Fatalf("errors.As(err, *StructuredError) = false; err = %v", analyzeErr)
	}

	msg := se.UserMessage()
	if !strings.Contains(msg, "127.0.0.1:9999") {
		t.Errorf("UserMessage() should contain host:port, got %q", msg)
	}

	for _, internal := range goErrorInternals {
		if strings.Contains(msg, internal) {
			t.Errorf("UserMessage() contains Go internal %q: %s", internal, msg)
		}
	}

	if se.Category() != ErrConnectionFailed {
		t.Errorf("Category() = %v, want ErrConnectionFailed", se.Category())
	}
}

func TestAnalyzeBytes_StructuredErrorPassthrough(t *testing.T) {
	t.Parallel()

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))),
	)
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}

	_, analyzeErr := analyzer.AnalyzeBytes(t.Context(), nil, "empty-input")
	if analyzeErr == nil {
		t.Fatal("expected empty input error, got nil")
	}

	if !errors.Is(analyzeErr, ErrEmptyInput) {
		t.Errorf("errors.Is(err, ErrEmptyInput) = false through wrapping; err = %v", analyzeErr)
	}

	var se *StructuredError
	if !errors.As(analyzeErr, &se) {
		t.Fatalf("errors.As(err, *StructuredError) = false; err = %v", analyzeErr)
	}

	if se.Category() != ErrEmptyInput {
		t.Errorf("Category() = %v, want ErrEmptyInput", se.Category())
	}
}

func TestAnalyzer_AnalyzeBytes_HappyPath(t *testing.T) {
	t.Parallel()

	certs := getAnalyzerSimpleChain(t)
	pemData := testutil.EncodePEMChain(certs)

	rootWrapped := NewCertificate(certs[2], CertificateSource{
		Type:     SourceTypeFile,
		Location: "test-root",
	})
	ts := &analyzerMockTrustStore{roots: []*Certificate{rootWrapped}}

	analyzer, err := NewAnalyzer(
		WithParser(NewParser()),
		WithTrustStore(ts),
	)
	require.NoError(t, err)

	analysis, err := analyzer.AnalyzeBytes(t.Context(), pemData, "test-source")
	require.NoError(t, err)

	assert.Len(t, analysis.Certificates, 3)
	assert.NotEmpty(t, analysis.TrustPaths)
	assert.Equal(t, "test-source", analysis.Metadata.Source)
	assert.Equal(t, 3, analysis.Metadata.TotalCerts)
	assert.Greater(t, analysis.Metadata.TotalPaths, 0)
}

func TestAnalyzer_AnalyzeFile_HappyPath(t *testing.T) {
	t.Parallel()

	certs := getAnalyzerSimpleChain(t)
	pemData := testutil.EncodePEMChain(certs)

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "chain.pem")
	require.NoError(t, os.WriteFile(certFile, pemData, 0o600))

	rootWrapped := NewCertificate(certs[2], CertificateSource{
		Type:     SourceTypeFile,
		Location: "test-root",
	})
	ts := &analyzerMockTrustStore{roots: []*Certificate{rootWrapped}}

	analyzer, err := NewAnalyzer(
		WithParser(NewParser()),
		WithTrustStore(ts),
	)
	require.NoError(t, err)

	analysis, err := analyzer.AnalyzeFile(t.Context(), certFile)
	require.NoError(t, err)

	assert.Len(t, analysis.Certificates, 3)
	assert.NotEmpty(t, analysis.TrustPaths)
	assert.Equal(t, certFile, analysis.Metadata.Source)
	assert.Equal(t, 3, analysis.Metadata.TotalCerts)
	assert.Greater(t, analysis.Metadata.TotalPaths, 0)
}

func TestAnalyzer_AnalyzeChains_ErrorPaths(t *testing.T) {
	t.Parallel()

	rawCerts := getAnalyzerSimpleChain(t)

	tests := []struct {
		name         string
		chainBuilder ChainBuilder
		validator    Validator
		wantSentinel error
	}{
		{
			name:         "chain builder error wraps as ErrChainBuildFailed",
			chainBuilder: &mockChainBuilderErr{err: errors.New("build failed")},
			validator:    NewValidator(),
			wantSentinel: ErrChainBuildFailed,
		},
		{
			name:         "validator error wraps as ErrValidationFailed",
			chainBuilder: NewChainBuilder(),
			validator:    &mockValidatorErr{err: errors.New("validation failed")},
			wantSentinel: ErrValidationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create fresh wrapped certs per subtest to avoid data races.
			wrappedCerts := make([]*Certificate, len(rawCerts))
			for i, c := range rawCerts {
				wrappedCerts[i] = NewCertificate(c, CertificateSource{Type: SourceTypeFile})
			}

			rootWrapped := NewCertificate(rawCerts[2], CertificateSource{
				Type:     SourceTypeFile,
				Location: "test-root",
			})
			ts := &analyzerMockTrustStore{roots: []*Certificate{rootWrapped}}

			analyzer, err := NewAnalyzer(
				WithParser(NewParser()),
				WithTrustStore(ts),
				WithChainBuilder(tt.chainBuilder),
				WithValidator(tt.validator),
			)
			require.NoError(t, err)

			_, err = analyzer.analyzeChains(t.Context(), wrappedCerts, "test")
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.wantSentinel),
				"expected errors.Is(err, %v) = true, got err = %v", tt.wantSentinel, err)

			se, ok := errors.AsType[*StructuredError](err)
			assert.True(t, ok,
				"expected StructuredError, got %T: %v", err, err)
			_ = se
		})
	}
}

// startLocalTLSServer starts a minimal TLS server on a random loopback port
// using the provided certificate and key. It accepts a single connection,
// completes the handshake, and then closes. The returned address is in
// host:port form. The caller must close the listener when done.
func startLocalTLSServer(t *testing.T, tlsCert tls.Certificate) (addr string, ln net.Listener) {
	t.Helper()

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err, "net.Listen")

	addr = ln.Addr().String()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		srv := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		})
		_ = srv.HandshakeContext(t.Context())
		// Hold the connection open briefly so the client can read the chain.
		time.Sleep(50 * time.Millisecond)
	}()

	return addr, ln
}

func TestAnalyzeFile_CanceledContext(t *testing.T) {
	t.Parallel()

	analyzer, err := NewAnalyzer(
		WithParser(NewParser()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, analyzeErr := analyzer.AnalyzeFile(ctx, "/some/cert.pem")
	require.Error(t, analyzeErr)
	assert.ErrorIs(t, analyzeErr, context.Canceled)
}

func TestAnalyzeHost_Local(t *testing.T) {
	t.Parallel()

	cert, key, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"},
		IsCA:     true,
	})
	require.NoError(t, err, "generating test certificate")

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}

	t.Run("successful connection", func(t *testing.T) {
		t.Parallel()

		addr, ln := startLocalTLSServer(t, tlsCert)
		defer func() { _ = ln.Close() }()

		analyzer, newErr := NewAnalyzer(
			WithParser(NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))),
			WithRemoteOptions(RemoteOptions{
				SNI:            "localhost",
				Timeout:        5 * time.Second,
				VerifyHostname: false,
			}),
		)
		require.NoError(t, newErr, "NewAnalyzer")

		analysis, analyzeErr := analyzer.AnalyzeHost(t.Context(), addr)
		require.NoError(t, analyzeErr, "AnalyzeHost")

		assert.NotEmpty(t, analysis.Certificates, "expected at least one certificate")
		assert.Equal(t, addr, analysis.Metadata.Source)
		assert.Greater(t, analysis.Metadata.TotalCerts, 0)
		assert.Greater(t, analysis.Metadata.TotalPaths, 0)
	})

	t.Run("closed listener returns structured error", func(t *testing.T) {
		t.Parallel()

		// Allocate a port, then immediately close it so nothing is listening.
		lc := &net.ListenConfig{}
		ln, listenErr := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, listenErr, "net.Listen")
		closedAddr := ln.Addr().String()
		require.NoError(t, ln.Close(), "closing listener")

		analyzer, newErr := NewAnalyzer(
			WithParser(NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))),
			WithRemoteOptions(RemoteOptions{
				SNI:            "localhost",
				Timeout:        2 * time.Second,
				VerifyHostname: false,
			}),
		)
		require.NoError(t, newErr, "NewAnalyzer")

		_, analyzeErr := analyzer.AnalyzeHost(t.Context(), closedAddr)
		require.Error(t, analyzeErr, "expected connection error for closed port")

		if !errors.Is(analyzeErr, ErrConnectionFailed) {
			t.Errorf("errors.Is(err, ErrConnectionFailed) = false; err = %v", analyzeErr)
		}

		var se *StructuredError
		if !errors.As(analyzeErr, &se) {
			t.Fatalf("errors.As(err, *StructuredError) = false; err = %v", analyzeErr)
		}

		msg := se.UserMessage()
		if !strings.Contains(msg, closedAddr) {
			t.Errorf("UserMessage() should contain %q, got %q", closedAddr, msg)
		}
		for _, internal := range goErrorInternals {
			if strings.Contains(msg, internal) {
				t.Errorf("UserMessage() contains Go internal %q: %s", internal, msg)
			}
		}
	})
}

func TestResolveValidationOptions_FileSourceDisablesHostname(t *testing.T) {
	t.Parallel()

	a, err := NewAnalyzer(
		WithParser(NewParser()),
	)
	require.NoError(t, err, "NewAnalyzer")

	opts := a.resolveValidationOptions("/tmp/cert.pem")

	if opts.VerifyHostname {
		t.Error("VerifyHostname should be false for a file source with no SNI")
	}
	if opts.Hostname != "" {
		t.Errorf("Hostname should be empty, got %q", opts.Hostname)
	}
}

func TestAnalyzeURL_PEM(t *testing.T) {
	t.Parallel()

	certs := getAnalyzerSimpleChain(t)
	pemData := testutil.EncodePEMChain(certs)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pemData)
	}))
	defer server.Close()

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(
			WithAutoDetectFormat(true),
			WithParserAllowPrivateNetworks(true),
			WithHTTPUpgrade(false),
		)),
	)
	require.NoError(t, err)

	url := server.URL + "/chain.pem"
	analysis, err := analyzer.AnalyzeURL(t.Context(), url)
	require.NoError(t, err)
	assert.NotEmpty(t, analysis.Certificates)
	assert.Equal(t, url, analysis.Metadata.Source)
}

func TestAnalyzeURL_HTTPError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(
			WithAutoDetectFormat(true),
			WithParserAllowPrivateNetworks(true),
			WithHTTPUpgrade(false),
		)),
	)
	require.NoError(t, err)

	_, err = analyzer.AnalyzeURL(t.Context(), server.URL+"/fail.pem")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrURLFetchFailed)
}

func TestAnalyze_URLDetection(t *testing.T) {
	t.Parallel()

	certs := getAnalyzerSimpleChain(t)
	pemData := testutil.EncodePEMChain(certs)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(pemData)
	}))
	defer server.Close()

	analyzer, err := NewAnalyzer(
		WithParser(NewParser(
			WithAutoDetectFormat(true),
			WithParserAllowPrivateNetworks(true),
			WithHTTPUpgrade(false),
		)),
	)
	require.NoError(t, err)

	analysis, err := analyzer.Analyze(t.Context(), server.URL+"/chain.pem")
	require.NoError(t, err)
	assert.NotEmpty(t, analysis.Certificates)
	assert.Contains(t, analysis.Metadata.Source, server.URL)
}

func TestWithSNI(t *testing.T) {
	t.Parallel()

	a, err := NewAnalyzer(WithParser(NewParser()), WithSNI("custom.example.com"))
	require.NoError(t, err)
	assert.Equal(t, "custom.example.com", a.sni)
}

func TestWithAnalyzerLogger(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := NewAnalyzer(WithParser(NewParser()), WithAnalyzerLogger(logger))
	require.NoError(t, err)
	// The logger should have been propagated.
	assert.NotNil(t, a.logger)
}

func TestWithAnalyzerLogger_NilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil logger, got none")
		}
	}()
	WithAnalyzerLogger(nil)(&Analyzer{})
}

func TestWithValidationOptions(t *testing.T) {
	t.Parallel()

	opts := ValidationOptions{VerifyHostname: true, ExpiryWarningDays: 60}
	a, err := NewAnalyzer(WithParser(NewParser()), WithValidationOptions(opts))
	require.NoError(t, err)
	require.NotNil(t, a.validationOpts)
	assert.Equal(t, 60, a.validationOpts.ExpiryWarningDays)
}

func TestSecurityDoubleOptionApplication(t *testing.T) {
	t.Parallel()

	t.Run("WithParser twice last wins", func(t *testing.T) {
		t.Parallel()

		p1 := NewParser(WithMaxCertificates(1))
		p2 := NewParser(WithMaxCertificates(50))

		analyzer, err := NewAnalyzer(
			WithParser(p1),
			WithParser(p2), // must supersede p1
		)
		require.NoError(t, err)
		require.NotNil(t, analyzer)

		assert.Same(t, p2, analyzer.parser,
			"second WithParser call must replace the first")
	})
}

func TestSecurityAnalyzerWithDefaults(t *testing.T) {
	t.Parallel()

	x509Cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "security-test-default.example"},
		IsCA:    true,
	})
	require.NoError(t, err)

	pemData := testutil.EncodePEM(x509Cert)

	parser := NewParser()
	analyzer, err := NewAnalyzer(WithParser(parser))
	require.NoError(t, err)
	require.NotNil(t, analyzer)

	assert.NotNil(t, analyzer.chainBuilder, "chainBuilder must be auto-wired")
	assert.NotNil(t, analyzer.validator, "validator must be auto-wired")
	assert.NotNil(t, analyzer.trustStore, "trustStore must be auto-wired")
	assert.NotNil(t, analyzer.logger, "logger must be set")

	analysis, err := analyzer.AnalyzeBytes(t.Context(), pemData, "security-test")
	require.NoError(t, err)
	require.NotNil(t, analysis)
	assert.NotEmpty(t, analysis.Certificates, "analysis must contain at least one certificate")
}

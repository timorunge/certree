// Security integration tests exercising the public API from an external
// consumer perspective with adversarial inputs, hostile servers, and
// concurrent cache operations.

package certree

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
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
	secIntChainOnce sync.Once
	secIntChainX509 []*x509.Certificate
)

func getSecIntChain(t *testing.T) []*x509.Certificate {
	t.Helper()
	secIntChainOnce.Do(func() {
		certs, _, err := testutil.GenerateSimpleChain()
		if err != nil {
			panic("generating simple chain for security integration tests: " + err.Error())
		}
		secIntChainX509 = certs
	})
	return secIntChainX509
}

func secIntWriteCertFile(t *testing.T, dir, name string) string {
	t.Helper()
	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "secint-" + name},
		IsCA:    true,
	})
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, testutil.EncodePEM(cert), 0o600))
	return path
}

func secIntNewAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	chain := getSecIntChain(t)
	root := NewCertificate(chain[2], CertificateSource{Type: SourceTypeFile, Location: "test-root"})
	ts := &analyzerMockTrustStore{roots: []*Certificate{root}}
	a, err := NewAnalyzer(WithParser(NewParser()), WithTrustStore(ts))
	require.NoError(t, err)
	return a
}

func marshalAndValidateJSON(t *testing.T, analysis *Analysis) []byte {
	t.Helper()
	data, err := analysis.MarshalJSON()
	require.NoError(t, err, "MarshalJSON must not error")
	var v map[string]any
	require.NoError(t, json.Unmarshal(data, &v), "MarshalJSON output must be valid JSON")
	return data
}

func TestSecurityAnalyze_SourceClassificationBypass(t *testing.T) {
	t.Parallel()

	analyzer := secIntNewAnalyzer(t)

	tests := []struct {
		name   string
		source string
	}{
		{"null byte in source", "example.com\x00evil"},
		{"newline in source", "example.com\nevil"},
		{"stdin marker", "-"},
		{"empty string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := analyzer.Analyze(t.Context(), tt.source)
			require.Error(t, err, "Analyze(%q) must return an error", tt.source)
		})
	}
}

func TestSecurityAnalyzeFile_ThroughFullStack(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath := secIntWriteCertFile(t, dir, "valid.pem")

	t.Run("path traversal resolving to valid cert", func(t *testing.T) {
		t.Parallel()

		// Build a traversal path that resolves to the same file.
		traversal := filepath.Join(dir, "subdir", "..", "valid.pem")
		analyzer := secIntNewAnalyzer(t)
		analysis, err := analyzer.AnalyzeFile(t.Context(), traversal)
		require.NoError(t, err)
		assert.NotEmpty(t, analysis.Certificates)
	})

	t.Run("symlink to valid cert", func(t *testing.T) {
		t.Parallel()

		link := filepath.Join(dir, "link-to-cert.pem")
		require.NoError(t, os.Symlink(certPath, link))
		analyzer := secIntNewAnalyzer(t)
		analysis, err := analyzer.AnalyzeFile(t.Context(), link)
		require.NoError(t, err)
		assert.NotEmpty(t, analysis.Certificates)
	})

	t.Run("symlink to directory", func(t *testing.T) {
		t.Parallel()

		subdir := filepath.Join(dir, "subdir-for-symlink")
		require.NoError(t, os.Mkdir(subdir, 0o755))
		link := filepath.Join(dir, "link-to-dir")
		require.NoError(t, os.Symlink(subdir, link))
		analyzer := secIntNewAnalyzer(t)
		_, err := analyzer.AnalyzeFile(t.Context(), link)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidInput), "expected ErrInvalidInput, got: %v", err)
	})

	t.Run("oversized file", func(t *testing.T) {
		t.Parallel()

		bigPath := filepath.Join(dir, "big.pem")
		require.NoError(t, os.WriteFile(bigPath, make([]byte, 10<<20+1), 0o600))
		analyzer := secIntNewAnalyzer(t)
		_, err := analyzer.AnalyzeFile(t.Context(), bigPath)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrFileTooLarge), "expected ErrFileTooLarge, got: %v", err)
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()

		emptyPath := filepath.Join(dir, "empty.pem")
		require.NoError(t, os.WriteFile(emptyPath, []byte{}, 0o600))
		analyzer := secIntNewAnalyzer(t)
		_, err := analyzer.AnalyzeFile(t.Context(), emptyPath)
		require.Error(t, err)
	})

	t.Run("dev null", func(t *testing.T) {
		t.Parallel()

		// os.DevNull is "/dev/null" on Unix and "nul" on Windows; both are
		// non-regular files so the parser must reject them with ErrInvalidInput.
		analyzer := secIntNewAnalyzer(t)
		_, err := analyzer.AnalyzeFile(t.Context(), os.DevNull)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidInput), "expected ErrInvalidInput, got: %v", err)
	})

	t.Run("shell injection path", func(t *testing.T) {
		t.Parallel()

		analyzer := secIntNewAnalyzer(t)
		_, err := analyzer.AnalyzeFile(t.Context(), filepath.Join(dir, "$(whoami).pem"))
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrFileReadFailed), "expected ErrFileReadFailed, got: %v", err)
	})

	t.Run("null byte in path", func(t *testing.T) {
		t.Parallel()

		analyzer := secIntNewAnalyzer(t)
		_, err := analyzer.AnalyzeFile(t.Context(), filepath.Join(dir, "cert\x00evil.pem"))
		require.Error(t, err)
	})
}

func TestSecurityAnalyzeHost_HostileEndpoints(t *testing.T) {
	t.Parallel()

	t.Run("server drops connection before handshake", func(t *testing.T) {
		t.Parallel()

		// Listen and immediately close connections.
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		go func() {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}()

		analyzer := secIntNewAnalyzer(t)
		_, err = analyzer.AnalyzeHost(t.Context(), ln.Addr().String())
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrConnectionFailed), "expected ErrConnectionFailed, got: %v", err)

		if se, ok := errors.AsType[*StructuredError](err); ok {
			msg := se.UserMessage()
			for _, internal := range goErrorInternals {
				assert.NotContains(t, msg, internal, "UserMessage must not contain Go internal %q", internal)
			}
		}
	})

	t.Run("context deadline against hanging server", func(t *testing.T) {
		t.Parallel()

		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		// Accept but never complete the TLS handshake.
		go func() {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			// Hold the connection open until the listener closes.
			<-time.After(10 * time.Second)
			_ = conn.Close()
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()

		analyzer := secIntNewAnalyzer(t)
		_, err = analyzer.AnalyzeHost(ctx, ln.Addr().String())
		require.Error(t, err)
	})

	t.Run("host with control characters", func(t *testing.T) {
		t.Parallel()

		analyzer := secIntNewAnalyzer(t)

		for _, host := range []string{"127.0.0.1:443\n", "127.0.0.1:443\r", "127.0.0.1\t:443"} {
			_, err := analyzer.AnalyzeHost(t.Context(), host)
			require.Error(t, err, "AnalyzeHost(%q) must return an error", host)
		}
	})
}

func TestSecurityAnalyzeBytes_AdversarialData(t *testing.T) {
	t.Parallel()

	analyzer := secIntNewAnalyzer(t)

	tests := []struct {
		name    string
		data    []byte
		source  string
		wantErr error
	}{
		{"nil data", nil, "nil-test", nil},
		{"empty slice", []byte{}, "empty-test", nil},
		{"oversized data", make([]byte, 10<<20+1), "big-test", ErrInputTooLarge},
		{"random garbage", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}, "garbage-test", nil},
		{"private key block only", []byte("-----BEGIN PRIVATE KEY-----\nMIIBvTBXBgkq\n-----END PRIVATE KEY-----\n"), "privkey-test", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := analyzer.AnalyzeBytes(t.Context(), tt.data, tt.source)
			require.Error(t, err)

			if tt.wantErr != nil {
				assert.True(t, errors.Is(err, tt.wantErr), "expected %v, got: %v", tt.wantErr, err)
			}
		})
	}

	t.Run("source string with injection chars is metadata only", func(t *testing.T) {
		t.Parallel()

		cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "injection-source-test"},
			IsCA:    true,
		})
		require.NoError(t, err)

		injectionSource := "test; rm -rf /; $(whoami)"
		analysis, err := analyzer.AnalyzeBytes(t.Context(), testutil.EncodePEM(cert), injectionSource)
		require.NoError(t, err)
		assert.Equal(t, injectionSource, analysis.Metadata.Source,
			"source string must pass through as metadata, not be executed")
	})
}

func TestSecurityAnalyzeURL_HostileServer(t *testing.T) {
	t.Parallel()

	t.Run("server returns HTML with 200 OK", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>Not a certificate</body></html>"))
		}))
		defer srv.Close()

		parser := NewParser(WithParserAllowPrivateNetworks(true), WithHTTPUpgrade(false))
		a, err := NewAnalyzer(WithParser(parser))
		require.NoError(t, err)

		_, err = a.AnalyzeURL(t.Context(), srv.URL+"/cert.pem")
		require.Error(t, err)
	})

	t.Run("server returns oversized body", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Write more than maxParserInputSize without Content-Length.
			buf := make([]byte, 32*1024)
			for written := 0; written <= 10<<20; written += len(buf) {
				if _, writeErr := w.Write(buf); writeErr != nil {
					return
				}
			}
		}))
		defer srv.Close()

		// Plain HTTP server; disable upgrade so the URL is not rewritten to https://.
		parser := NewParser(WithParserAllowPrivateNetworks(true), WithHTTPUpgrade(false))
		a, err := NewAnalyzer(WithParser(parser))
		require.NoError(t, err)

		_, err = a.AnalyzeURL(t.Context(), srv.URL+"/cert.pem")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInputTooLarge), "expected ErrInputTooLarge, got: %v", err)
	})

	t.Run("URL with embedded credentials", func(t *testing.T) {
		t.Parallel()

		parser := NewParser()
		a, err := NewAnalyzer(WithParser(parser))
		require.NoError(t, err)

		_, err = a.AnalyzeURL(t.Context(), "https://user:secret@example.com/cert.pem")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBlockedURL), "expected ErrBlockedURL, got: %v", err)
	})

	t.Run("private network URL without opt-in", func(t *testing.T) {
		t.Parallel()

		parser := NewParser()
		a, err := NewAnalyzer(WithParser(parser))
		require.NoError(t, err)

		_, err = a.AnalyzeURL(t.Context(), "https://127.0.0.1/cert.pem")
		require.Error(t, err)
	})

	t.Run("pre-canceled context", func(t *testing.T) {
		t.Parallel()

		parser := NewParser()
		a, err := NewAnalyzer(WithParser(parser))
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err = a.AnalyzeURL(ctx, "https://example.com/cert.pem")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrContextCanceled), "expected ErrContextCanceled, got: %v", err)
	})
}

func TestSecurityParseRemote_HostileTLSServer(t *testing.T) {
	t.Parallel()

	t.Run("server drops connection before handshake", func(t *testing.T) {
		t.Parallel()

		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()

		go func() {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}()

		parser := NewParser()
		_, err = parser.ParseRemote(t.Context(), ln.Addr().String(), RemoteOptions{
			SNI: "test.example.com",
		})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrConnectionFailed), "expected ErrConnectionFailed, got: %v", err)

		if se, ok := errors.AsType[*StructuredError](err); ok {
			msg := se.UserMessage()
			for _, internal := range goErrorInternals {
				assert.NotContains(t, msg, internal, "UserMessage must not contain Go internal %q", internal)
			}
		}
	})

	t.Run("server with expired certificate", func(t *testing.T) {
		t.Parallel()

		expiredCert, expiredKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject:   pkix.Name{CommonName: "expired.example.com"},
			IsCA:      true,
			NotBefore: time.Now().Add(-48 * time.Hour),
			NotAfter:  time.Now().Add(-24 * time.Hour),
		})
		require.NoError(t, err)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{expiredCert.Raw},
			PrivateKey:  expiredKey,
		}

		addr, ln := startLocalTLSServer(t, tlsCert)
		defer func() { _ = ln.Close() }()

		parser := NewParser()
		// ParseRemote should succeed -- it parses, it does not validate expiry.
		certs, err := parser.ParseRemote(t.Context(), addr, RemoteOptions{
			SNI:            "expired.example.com",
			VerifyHostname: false,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, certs)
	})
}

func TestSecurityParseDERCertificate_AdversarialInputs(t *testing.T) {
	t.Parallel()

	// Generate a valid DER cert for positive and truncation tests.
	validCert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "der-security-test"},
		IsCA:    true,
	})
	require.NoError(t, err)

	source := CertificateSource{Type: SourceTypeFile, Location: "test-der"}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"zero length", []byte{}, true},
		{"single ASN.1 tag byte", []byte{0x30}, true},
		{"ASN.1 SEQUENCE wrapping UTF8String", []byte{0x30, 0x05, 0x0C, 0x03, 0x66, 0x6F, 0x6F}, true},
		{"truncated real DER", validCert.Raw[:len(validCert.Raw)/2], true},
		{"valid DER", validCert.Raw, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert, err := ParseDERCertificate(tt.data, source)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrParseFailed), "expected ErrParseFailed, got: %v", err)

				se, ok := errors.AsType[*StructuredError](err)
				require.True(t, ok, "error must be *StructuredError")
				msg := se.UserMessage()
				for _, internal := range goErrorInternals {
					assert.NotContains(t, msg, internal, "UserMessage must not contain Go internal %q", internal)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, validCert.Raw, cert.Raw().Raw)
			}
		})
	}
}

func TestSecurityAnalysisMarshalJSON_UntrustedFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cn   string
		org  string
		sans []string
	}{
		{
			"XSS payload in CN",
			`</script><script>alert(1)</script>`,
			"Normal Org",
			nil,
		},
		{
			"null byte in CN",
			"test\x00evil",
			"Normal Org",
			nil,
		},
		{
			"quotes and backslashes in SAN",
			"normal-cn",
			"Normal Org",
			[]string{`host"with\quotes.example.com`},
		},
		{
			"control characters in org",
			"normal-cn",
			"Org\twith\rnewlines\nand\ttabs",
			nil,
		},
		{
			"very large serial number",
			"large-serial-test",
			"Normal Org",
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tmpl := testutil.CertificateTemplate{
				Subject: pkix.Name{
					CommonName:   tt.cn,
					Organization: []string{tt.org},
				},
				IsCA:     true,
				DNSNames: tt.sans,
			}
			if tt.name == "very large serial number" {
				tmpl.SerialNumber = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
			}

			x509Cert, _, err := testutil.GenerateSelfSignedCert(tmpl)
			require.NoError(t, err)

			cert := NewCertificate(x509Cert, CertificateSource{
				Type:     SourceTypeFile,
				Location: "json-injection-test",
			})
			analysis := NewAnalysis([]*Certificate{cert}, nil, "json-test")

			data := marshalAndValidateJSON(t, analysis)

			// Verify the JSON is well-formed by re-parsing into a generic structure.
			var parsed map[string]any
			require.NoError(t, json.Unmarshal(data, &parsed))

			// The custom MarshalJSON produces a fingerprint-keyed map, not an array.
			certs, ok := parsed["certificates"].(map[string]any)
			require.True(t, ok, "certificates must be a JSON object (fingerprint-keyed map)")
			assert.NotEmpty(t, certs)
		})
	}
}

func TestSecurityRevocationChecker_ConcurrentResetCache(t *testing.T) {
	t.Parallel()

	checker := NewRevocationChecker(WithRevocationCache(true))

	const goroutines = 16
	var wg sync.WaitGroup

	for range goroutines {
		wg.Go(func() {
			checker.ResetCache()
		})
	}

	wg.Wait()
}

func TestSecurityDetectSource_AdversarialStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   SourceKind
	}{
		{"null byte", "example.com\x00evil", SourceFile},
		{"newline", "example.com\nevil", SourceFile},
		{"etc passwd", "/etc/passwd", SourceFile},
		{"URL with credentials", "https://user:secret@host.com/cert.pem", SourceURL},
		{"empty string", "", SourceFile},
		{"stdin marker", "-", SourceStdin},
		{"bare hostname", "example.com", SourceHost},
		{"shell metacharacters", "$(whoami).pem", SourceFile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := DetectSource(tt.source)
			assert.Equal(t, tt.want, got, "DetectSource(%q)", tt.source)
		})
	}
}

func TestSecurityNormalizeSource_AdversarialStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   string
	}{
		{"hostname with port zero", "example.com:0", "example.com:0"},
		{"hostname with port 99999", "example.com:99999", "example.com:99999"},
		{"double scheme prefix", "https://https://host/cert.pem", "https://https://host/cert.pem"},
		{"oversized string", strings.Repeat("a", 4097), strings.Repeat("a", 4097)},
		{"bare hostname gets port", "example.com", "example.com:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := NormalizeSource(tt.source)
			assert.Equal(t, tt.want, got, "NormalizeSource(%q)", tt.source)
		})
	}
}

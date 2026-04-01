package certree

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPrivateIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ip      string
		private bool
	}{
		// IPv4 private ranges
		{"loopback", "127.0.0.1", true},
		{"loopback high", "127.255.255.255", true},
		{"rfc1918 10.x", "10.0.0.1", true},
		{"rfc1918 172.16.x", "172.16.0.1", true},
		{"rfc1918 172.31.x", "172.31.255.255", true},
		{"rfc1918 192.168.x", "192.168.1.1", true},
		{"link-local", "169.254.1.1", true},
		{"unspecified", "0.0.0.0", true},
		{"current network", "0.1.2.3", true},
		{"cgnat", "100.64.0.1", true},
		{"benchmarking", "198.18.0.1", true},
		{"reserved", "240.0.0.1", true},

		// IPv4 public addresses
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 93.184.216.34", "93.184.216.34", false},
		{"rfc1918 boundary 172.15.x", "172.15.255.255", false},
		{"rfc1918 boundary 172.32.x", "172.32.0.0", false},

		// IPv6
		{"ipv6 loopback", "::1", true},
		{"ipv6 unique local", "fd00::1", true},
		{"ipv6 link-local", "fe80::1", true},
		{"ipv6 public", "2606:4700:4700::1111", false},

		// IPv4-mapped IPv6 (::ffff:x.x.x.x)
		{"ipv4-mapped private", "::ffff:127.0.0.1", true},
		{"ipv4-mapped 10.x", "::ffff:10.0.0.1", true},
		{"ipv4-mapped public", "::ffff:1.1.1.1", false},
		{"ipv4-mapped 8.8.8.8", "::ffff:8.8.8.8", false},

		// NAT64 (64:ff9b::/96) -- encodes IPv4 in last 32 bits
		{"nat64 private 10.x", "64:ff9b::10.0.0.1", true},
		{"nat64 loopback", "64:ff9b::127.0.0.1", true},
		{"nat64 public", "64:ff9b::8.8.8.8", true}, // entire prefix is blocked

		// 6to4 (2002::/16) -- encodes IPv4 in bits 16-47
		{"6to4 encoding 10.0.0.1", "2002:0a00:0001::", true},
		{"6to4 encoding 192.168.1.1", "2002:c0a8:0101::", true},
		{"6to4 encoding public", "2002:0808:0808::", true}, // entire prefix is blocked
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.private {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		url     string
		wantErr error
	}{
		// Valid URLs
		{"http public", "http://example.com/cert.crt", nil},
		{"https public", "https://example.com/cert.crt", nil},
		{"http with port", "http://example.com:8080/cert.crt", nil},

		// Blocked schemes
		{"ftp scheme", "ftp://example.com/cert.crt", ErrUnsupportedScheme},
		{"file scheme", "file:///etc/passwd", ErrUnsupportedScheme},
		{"gopher scheme", "gopher://evil.com", ErrUnsupportedScheme},
		{"ldap scheme", "ldap://evil.com/dc=example", ErrUnsupportedScheme},

		// Private IP addresses
		{"loopback", "http://127.0.0.1/cert.crt", ErrPrivateAddress},
		{"loopback high", "http://127.0.0.255/cert.crt", ErrPrivateAddress},
		{"rfc1918 10.x", "http://10.0.0.1/cert.crt", ErrPrivateAddress},
		{"rfc1918 172.16.x", "http://172.16.0.1/cert.crt", ErrPrivateAddress},
		{"rfc1918 192.168.x", "http://192.168.1.1/cert.crt", ErrPrivateAddress},
		{"link-local", "http://169.254.1.1/cert.crt", ErrPrivateAddress},
		{"ipv6 loopback", "http://[::1]/cert.crt", ErrPrivateAddress},
		{"ipv6 unique local", "http://[fd00::1]/cert.crt", ErrPrivateAddress},
		{"ipv6 link-local", "http://[fe80::1]/cert.crt", ErrPrivateAddress},
		{"unspecified", "http://0.0.0.0/cert.crt", ErrPrivateAddress},

		// IPv6 transition mechanisms
		{"ipv4-mapped private", "http://[::ffff:10.0.0.1]/cert.crt", ErrPrivateAddress},
		{"ipv4-mapped loopback", "http://[::ffff:127.0.0.1]/cert.crt", ErrPrivateAddress},
		{"ipv4-mapped public", "http://[::ffff:8.8.8.8]/cert.crt", nil},
		{"nat64 private", "http://[64:ff9b::10.0.0.1]/cert.crt", ErrPrivateAddress},
		{"6to4 encoding 10.x", "http://[2002:0a00:0001::]/cert.crt", ErrPrivateAddress},

		// Malformed URLs
		{"no host", "http:///cert.crt", ErrBlockedURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateURL(tt.url)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("validateURL(%q) unexpected error: %v", tt.url, err)
				}
				return
			}
			if err == nil {
				t.Errorf("validateURL(%q) = nil, want error wrapping %v", tt.url, tt.wantErr)
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("validateURL(%q) error = %v, want error wrapping %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestSafeTransport_BlocksPrivateDialTargets(t *testing.T) {
	t.Parallel()

	transport := safeTransport()
	if transport.DialContext == nil {
		t.Fatal("expected DialContext to be set")
	}

	// Try to dial a private address -- should fail.
	ctx := t.Context()
	_, err := transport.DialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Error("expected error dialing loopback address, got nil")
	}
	if !errors.Is(err, ErrPrivateAddress) {
		t.Errorf("expected error wrapping ErrPrivateAddress, got: %v", err)
	}
}

func TestNewHTTPClient_Safe(t *testing.T) {
	t.Parallel()

	client := newHTTPClient(5*time.Second, false)
	if client.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Error("expected CheckRedirect to be set for safe client")
	}
	if client.Transport == nil {
		t.Error("expected Transport to be set for safe client")
	}
}

func TestNewHTTPClient_RedirectLimit(t *testing.T) {
	t.Parallel()

	client := newHTTPClient(5*time.Second, false)
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be set for safe client")
	}

	// Build a valid request to pass to CheckRedirect.
	publicReq, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://93.184.216.34/cert.crt", nil)

	// Under the limit: should allow.
	via := make([]*http.Request, maxSafeRedirects-1)
	if err := client.CheckRedirect(publicReq, via); err != nil {
		t.Errorf("expected nil for %d redirects, got: %v", maxSafeRedirects-1, err)
	}

	// At the limit: should block.
	via = make([]*http.Request, maxSafeRedirects)
	err := client.CheckRedirect(publicReq, via)
	if err == nil {
		t.Errorf("expected error for %d redirects, got nil", maxSafeRedirects)
	}
	if !errors.Is(err, ErrBlockedURL) {
		t.Errorf("expected error wrapping ErrBlockedURL, got: %v", err)
	}
}

func TestNewHTTPClient_RedirectBlocksPrivateURL(t *testing.T) {
	t.Parallel()

	client := newHTTPClient(5*time.Second, false)
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be set for safe client")
	}

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"redirect to AWS IMDS", "http://169.254.169.254/latest/meta-data/", true},
		{"redirect to loopback", "http://127.0.0.1/cert.crt", true},
		{"redirect to ipv4-mapped private", "http://[::ffff:10.0.0.1]/cert.crt", true},
		{"redirect to public IP", "http://93.184.216.34/cert.crt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, tt.url, nil)
			err := client.CheckRedirect(req, []*http.Request{{}})
			if tt.wantErr && err == nil {
				t.Errorf("CheckRedirect(%q) = nil, want error", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("CheckRedirect(%q) = %v, want nil", tt.url, err)
			}
		})
	}
}

func TestSafeTransport_DNSResolutionSSRF(t *testing.T) {
	t.Parallel()

	transport := safeTransport()
	ctx := t.Context()

	tests := []struct {
		name string
		addr string
	}{
		{"localhost resolves to loopback", "localhost:443"},
		{"ipv6 loopback literal", "[::1]:443"},
		{"ipv4 loopback literal", "127.0.0.1:443"},
		{"rfc1918 10.x literal", "10.0.0.1:80"},
		{"rfc1918 172.16.x literal", "172.16.0.1:80"},
		{"rfc1918 192.168.x literal", "192.168.1.1:80"},
		{"link-local literal", "169.254.169.254:80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := transport.DialContext(ctx, "tcp", tt.addr)
			if err == nil {
				t.Errorf("DialContext(%q) = nil, want error blocking private address", tt.addr)
			}
			if !errors.Is(err, ErrPrivateAddress) {
				t.Errorf("DialContext(%q) error = %v, want ErrPrivateAddress", tt.addr, err)
			}
		})
	}
}

func TestIsPrivateIP_Multicast(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
	}{
		// One IPv4 and one IPv6 representative -- all hit ip.IsMulticast().
		{"ipv4 multicast", "224.0.0.1"},
		{"ipv6 multicast", "ff02::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			if !isPrivateIP(ip) {
				t.Errorf("isPrivateIP(%s) = false, want true (multicast must be blocked)", tt.ip)
			}
		})
	}
}

// TestIsPrivateIP_TestNetRanges verifies that RFC 5737 TEST-NET documentation
// ranges are blocked by isPrivateIP. These ranges must not be reachable via SSRF.
func TestIsPrivateIP_TestNetRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
	}{
		// Two entries from one range -- all iterate the same privateIPRanges loop.
		{"TEST-NET-1 first", "192.0.2.0"},
		{"TEST-NET-1 last", "192.0.2.255"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			if !isPrivateIP(ip) {
				t.Errorf("isPrivateIP(%s) = false, want true (TEST-NET must be blocked)", tt.ip)
			}
		})
	}
}

func TestNewHTTPClient_AllowPrivate(t *testing.T) {
	t.Parallel()

	client := newHTTPClient(3*time.Second, true)
	if client.Timeout != 3*time.Second {
		t.Errorf("expected timeout 3s, got %v", client.Timeout)
	}
	// allowPrivate clients still enforce redirect limits to prevent loops.
	if client.CheckRedirect == nil {
		t.Error("expected CheckRedirect to be set even for allowPrivate client")
	}
	// Even with allowPrivate, a Transport with TLS 1.2 minimum is set.
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatal("expected custom Transport with TLS config for allowPrivate client")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("expected TLS 1.2 minimum version for allowPrivate client")
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("expected TLSHandshakeTimeout to be set for allowPrivate client")
	}
	if tr.ResponseHeaderTimeout == 0 {
		t.Error("expected ResponseHeaderTimeout to be set for allowPrivate client")
	}
}

func TestSecurityURLValidation_AlternateEncodings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		url      string
		wantErr  error
		wantPass bool
	}{
		{
			name:    "dotted-decimal loopback",
			url:     "http://127.0.0.1/cert.pem",
			wantErr: ErrPrivateAddress,
		},
		// Go's net.ParseIP does not parse non-dotted decimal notation, so the
		// host is treated as a hostname and passes IP validation. The transport's
		// DialContext is the backstop.
		{
			name:     "decimal IP 2130706433 (127.0.0.1 encoded)",
			url:      "http://2130706433/cert.pem",
			wantPass: true, // parsed as hostname, not IP literal; blocked at dial time
		},
		{
			name:     "hex IP 0x7f000001",
			url:      "http://0x7f000001/cert.pem",
			wantPass: true, // parsed as hostname, not IP literal
		},
		{
			name:    "IPv6 loopback [::1]",
			url:     "http://[::1]/cert.pem",
			wantErr: ErrPrivateAddress,
		},
		// Go normalises ::ffff:127.0.0.1 to its IPv4 form, so isPrivateIP catches it.
		{
			name:    "IPv4-mapped IPv6 loopback",
			url:     "http://[::ffff:127.0.0.1]/cert.pem",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "IPv4-mapped IPv6 192.168.1.1",
			url:     "http://[::ffff:192.168.1.1]/cert.pem",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "credentials in URL",
			url:     "http://user:pass@example.com/cert.pem",
			wantErr: ErrBlockedURL,
		},
		{
			name:    "token credential in URL",
			url:     "https://token@example.com/cert.pem",
			wantErr: ErrBlockedURL,
		},
		// Fragment identifiers are stripped before sending; confirm URL is accepted.
		{
			name:     "URL with fragment",
			url:      "https://example.com/cert.pem#fragment",
			wantPass: true,
		},
		{
			name:    "data: URI",
			url:     "data:text/plain,hello",
			wantErr: ErrUnsupportedScheme,
		},
		{
			name:    "file: URI",
			url:     "file:///etc/passwd",
			wantErr: ErrUnsupportedScheme,
		},
		{
			name:    "ftp: URI",
			url:     "ftp://example.com/cert.pem",
			wantErr: ErrUnsupportedScheme,
		},
		{
			name:    "javascript: URI",
			url:     "javascript:alert(1)",
			wantErr: ErrUnsupportedScheme,
		},
		{
			name:    "empty scheme",
			url:     "//example.com/cert.pem",
			wantErr: ErrUnsupportedScheme,
		},
		// Go's url.Parse normalises or rejects embedded whitespace; they must
		// never reach the dialer.
		{
			name:    "newline in host",
			url:     "http://evil.com\nevil2.com/cert.pem",
			wantErr: ErrBlockedURL,
		},
		{
			name:    "tab in host",
			url:     "http://evil.com\tevil2.com/cert.pem",
			wantErr: ErrBlockedURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateURL(tt.url)
			if tt.wantPass {
				assert.NoError(t, err, "expected URL to pass validation")
				return
			}
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.wantErr),
				"expected error wrapping %v, got: %v", tt.wantErr, err)
		})
	}
}

func TestSecurityURLValidation_SchemeOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		url     string
		wantErr error
	}{
		{"loopback allowed", "http://127.0.0.1/ca.crt", nil},
		{"rfc1918 allowed", "http://10.1.2.3/ca.crt", nil},
		{"file blocked", "file:///etc/passwd", ErrUnsupportedScheme},
		{"ftp blocked", "ftp://127.0.0.1/ca.crt", ErrUnsupportedScheme},
		// Credential forwarding from certificate URLs is never safe, even on
		// private networks.
		{"credentials blocked", "http://admin:secret@10.1.2.3/ca.crt", ErrBlockedURL},
		{"token credential blocked", "https://token@internal.ca/ca.crt", ErrBlockedURL},
		{"empty host", "https:///ca.crt", ErrBlockedURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateURLSchemeAndCredentials(tt.url)
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.wantErr),
				"expected error wrapping %v, got: %v", tt.wantErr, err)
		})
	}
}

func TestSecurityRedirect_Policies(t *testing.T) {
	t.Parallel()

	t.Run("HTTPS to HTTP downgrade is blocked", func(t *testing.T) {
		t.Parallel()

		client := newHTTPClient(5*time.Second, false)
		require.NotNil(t, client.CheckRedirect)

		httpTarget, _ := http.NewRequestWithContext(
			t.Context(), http.MethodGet, "http://example.com/cert.crt", nil,
		)
		prevHTTPS, _ := http.NewRequestWithContext(
			t.Context(), http.MethodGet, "https://example.com/cert.crt", nil,
		)
		err := client.CheckRedirect(httpTarget, []*http.Request{prevHTTPS})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBlockedURL),
			"expected ErrBlockedURL for HTTPS→HTTP downgrade, got: %v", err)
	})

	t.Run("HTTPS to HTTPS redirect is allowed", func(t *testing.T) {
		t.Parallel()

		client := newHTTPClient(5*time.Second, false)
		require.NotNil(t, client.CheckRedirect)

		httpsTarget, _ := http.NewRequestWithContext(
			t.Context(), http.MethodGet, "https://example.com/cert2.crt", nil,
		)
		prevHTTPS, _ := http.NewRequestWithContext(
			t.Context(), http.MethodGet, "https://example.com/cert.crt", nil,
		)
		err := client.CheckRedirect(httpsTarget, []*http.Request{prevHTTPS})
		assert.NoError(t, err)
	})

	t.Run("redirect to private RFC-1918 address is blocked", func(t *testing.T) {
		t.Parallel()

		client := newHTTPClient(5*time.Second, false)
		require.NotNil(t, client.CheckRedirect)

		// CheckRedirect pre-validates the target URL before the transport
		// opens a connection.
		for _, privateURL := range []string{
			"http://10.0.0.1/cert.pem",
			"http://192.168.1.1/cert.pem",
			"http://172.16.0.1/cert.pem",
		} {
			req, _ := http.NewRequestWithContext(
				t.Context(), http.MethodGet, privateURL, nil,
			)
			err := client.CheckRedirect(req, []*http.Request{{}})
			assert.True(t, errors.Is(err, ErrPrivateAddress) || errors.Is(err, ErrBlockedURL),
				"redirect to %s must be blocked, got: %v", privateURL, err)
		}
	})

	t.Run("redirect chain is blocked at the live server boundary", func(t *testing.T) {
		t.Parallel()

		const chainLength = maxSafeRedirects + 1
		servers := make([]*httptest.Server, chainLength)
		for i := chainLength - 1; i >= 0; i-- {
			var target string
			if i == chainLength-1 {
				target = ""
			} else {
				target = servers[i+1].URL
			}
			idx := i
			tgt := target
			servers[idx] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tgt == "" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("reached end"))
					return
				}
				http.Redirect(w, r, tgt, http.StatusFound)
			}))
		}
		defer func() {
			for _, s := range servers {
				s.Close()
			}
		}()

		client := newHTTPClient(5*time.Second, true) // allow private for httptest
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, servers[0].URL, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		require.Error(t, err, "expected redirect-limit error, got nil")
		assert.True(t, errors.Is(err, ErrBlockedURL),
			"expected ErrBlockedURL in redirect chain, got: %v", err)
	})
}

func TestSecurityURLValidation_PortEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("port 0 is not a private address", func(t *testing.T) {
		t.Parallel()
		// Go's url.Parse accepts :0; actual connection to port 0 fails in the dialer.
		err := validateURL("http://example.com:0/cert.pem")
		assert.NoError(t, err, "port 0 with public host should not be rejected by validateURL")
	})

	t.Run("port 65536 passes URL validation but fails at the OS TCP layer", func(t *testing.T) {
		t.Parallel()
		// Go's url.Parse accepts port 65536 without error; the OS enforces range
		// at connect time. The important property is no panic or unexpected error
		// category from the validator.
		err := validateURL("http://example.com:65536/cert.pem")
		assert.NoError(t, err, "validateURL should not reject port 65536 - OS enforces port range at connect time")
	})
}

func TestSecurityCheckSchemeDowngrade(t *testing.T) {
	t.Parallel()

	newReq := func(t *testing.T, rawURL string) *http.Request {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
		require.NoError(t, err)
		return req
	}

	t.Run("first redirect has no prior hop so downgrade check is skipped", func(t *testing.T) {
		t.Parallel()
		req := newReq(t, "http://example.com/cert.pem")
		assert.NoError(t, checkSchemeDowngrade(req, nil))
	})

	t.Run("HTTPS to HTTPS is not a downgrade", func(t *testing.T) {
		t.Parallel()
		req := newReq(t, "https://example.com/cert2.pem")
		prev := newReq(t, "https://example.com/cert.pem")
		assert.NoError(t, checkSchemeDowngrade(req, []*http.Request{prev}))
	})

	t.Run("HTTPS to HTTP is a downgrade and must be blocked", func(t *testing.T) {
		t.Parallel()
		req := newReq(t, "http://example.com/cert.pem")
		prev := newReq(t, "https://example.com/cert.pem")
		err := checkSchemeDowngrade(req, []*http.Request{prev})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBlockedURL),
			"expected ErrBlockedURL for HTTPS→HTTP downgrade, got: %v", err)
	})

	t.Run("HTTP to HTTPS upgrade-redirect is not a downgrade", func(t *testing.T) {
		t.Parallel()
		req := newReq(t, "https://example.com/cert.pem")
		prev := newReq(t, "http://example.com/cert.pem")
		assert.NoError(t, checkSchemeDowngrade(req, []*http.Request{prev}))
	})

	t.Run("nil previous request does not panic", func(t *testing.T) {
		t.Parallel()
		req := newReq(t, "http://example.com/cert.pem")
		assert.NoError(t, checkSchemeDowngrade(req, []*http.Request{nil}))
	})
}

func TestSecurityValidateURL_CredentialBypassAttempts(t *testing.T) {
	t.Parallel()

	// Each URL encodes a credential in a way that might evade naive string
	// checks but is caught by url.Parse's structured Userinfo field.
	hostile := []string{
		"http://user@example.com/cert.pem",
		"http://:password@example.com/cert.pem",
		"http://user:@example.com/cert.pem",
		"https://access_token@example.com/cert.pem",
		fmt.Sprintf("http://%s@example.com/cert.pem", strings.Repeat("A", 1024)),
	}

	for _, u := range hostile {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			err := validateURL(u)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrBlockedURL),
				"expected ErrBlockedURL for credential URL %q, got: %v", u, err)
		})
	}
}

func TestSecurityNewHTTPClient_AllowPrivateStillEnforcesRedirects(t *testing.T) {
	t.Parallel()

	client := newHTTPClient(5*time.Second, true)
	require.NotNil(t, client.CheckRedirect,
		"allowPrivate client must still have a CheckRedirect policy")

	publicReq, _ := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com/cert.crt", nil,
	)

	t.Run("redirect limit is enforced", func(t *testing.T) {
		t.Parallel()
		via := make([]*http.Request, maxSafeRedirects)
		err := client.CheckRedirect(publicReq, via)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBlockedURL),
			"expected ErrBlockedURL from allowPrivate client at redirect limit, got: %v", err)
	})

	t.Run("HTTPS to HTTP downgrade is blocked", func(t *testing.T) {
		t.Parallel()
		httpTarget, _ := http.NewRequestWithContext(
			t.Context(), http.MethodGet, "http://example.com/cert.crt", nil,
		)
		prevHTTPS, _ := http.NewRequestWithContext(
			t.Context(), http.MethodGet, "https://example.com/cert.crt", nil,
		)
		err := client.CheckRedirect(httpTarget, []*http.Request{prevHTTPS})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBlockedURL),
			"expected ErrBlockedURL for downgrade on allowPrivate client, got: %v", err)
	})
}

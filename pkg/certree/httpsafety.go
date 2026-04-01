// SSRF protection and safe HTTP client construction for outbound fetches.

package certree

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxSafeRedirects is the maximum number of HTTP redirects followed by
// SSRF-safe clients. This limits redirect-based attacks while still
// accommodating legitimate CA infrastructure that uses redirects.
const maxSafeRedirects = 5

// privateIPRanges contains CIDR blocks for private, loopback, and link-local
// addresses that should be blocked by default when fetching from certificate-
// embedded URLs (AIA, OCSP, CRL). These ranges prevent SSRF attacks where a
// malicious certificate could direct the fetcher to internal services.
var privateIPRanges []*net.IPNet

// init populates privateIPRanges from CIDR strings at startup.
func init() {
	cidrs := []string{
		// IPv4
		"127.0.0.0/8",     // Loopback
		"10.0.0.0/8",      // RFC 1918
		"172.16.0.0/12",   // RFC 1918
		"192.168.0.0/16",  // RFC 1918
		"169.254.0.0/16",  // Link-local
		"0.0.0.0/8",       // Current network
		"100.64.0.0/10",   // Shared address space (CGNAT)
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1 (RFC 5737) -- documentation/testing
		"198.18.0.0/15",   // Benchmarking
		"198.51.100.0/24", // TEST-NET-2 (RFC 5737) -- documentation/testing
		"203.0.113.0/24",  // TEST-NET-3 (RFC 5737) -- documentation/testing
		"240.0.0.0/4",     // Reserved for future use

		// IPv6
		"::1/128",      // Loopback
		"fc00::/7",     // Unique local address
		"fe80::/10",    // Link-local
		"64:ff9b::/96", // NAT64 well-known prefix (RFC 6052)
		"2001::/32",    // Teredo (RFC 4380) -- encodes IPv4 in lower bits
		"2002::/16",    // 6to4 relay (RFC 3056) -- encodes IPv4 in upper bits
	}

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// This is a programming error in the CIDR list above; panic is appropriate.
			panic(fmt.Sprintf("certree: invalid CIDR %q in privateIPRanges: %v", cidr, err))
		}
		privateIPRanges = append(privateIPRanges, network)
	}
}

// isPrivateIP reports whether ip falls within any private, loopback, link-local,
// or multicast range. It also rejects unspecified addresses (0.0.0.0, ::).
// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are handled transparently
// because Go's net.ParseIP normalizes them to their IPv4 equivalents.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, network := range privateIPRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// upgradeHTTPToHTTPS replaces an http:// scheme with https://, leaving all other URLs unchanged.
func upgradeHTTPToHTTPS(rawURL string) string {
	if rest, ok := strings.CutPrefix(rawURL, "http://"); ok {
		return "https://" + rest
	}
	return rawURL
}

// validateURLSchemeAndCredentials checks only scheme (http/https) and
// credential safety. It does not check private IP ranges. Used as the
// minimum validation even when private networks are allowed.
func validateURLSchemeAndCredentials(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing URL %q: %w", rawURL, ErrBlockedURL)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("URL scheme %q not allowed (only http and https): %w", parsed.Scheme, ErrUnsupportedScheme)
	}

	// Block URLs with userinfo to prevent credential forwarding via crafted
	// AIA or CRL URLs (e.g., http://user:token@host/path).
	if parsed.User != nil {
		return fmt.Errorf("URL %q contains credentials: %w", rawURL, ErrBlockedURL)
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("URL %q has no host: %w", rawURL, ErrBlockedURL)
	}

	return nil
}

// validateURL checks that rawURL uses http/https, contains no credentials,
// and does not target a private IP.
// Hostnames are not resolved here; DNS rebinding is prevented by the DialContext hook in [safeTransport].
func validateURL(rawURL string) error {
	if err := validateURLSchemeAndCredentials(rawURL); err != nil {
		return err
	}

	parsed, _ := url.Parse(rawURL) // Already validated above.
	host := parsed.Hostname()

	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("URL %q targets private address %s: %w", rawURL, ip, ErrPrivateAddress)
		}
	}

	// Hostnames pass through -- DialContext in safeTransport is the
	// authoritative guard that resolves and validates before connecting.
	return nil
}

// safeTransport returns an *http.Transport whose DialContext resolves hostnames and blocks private IPs.
func safeTransport() *http.Transport {
	return &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12}, // #nosec G402 -- MinVersion is explicitly set.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("splitting host:port %q: %w", addr, err)
			}

			if ip := net.ParseIP(host); ip != nil {
				if isPrivateIP(ip) {
					return nil, fmt.Errorf("connection to private address %s blocked: %w", ip, ErrPrivateAddress)
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}

			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolving %q: %w", host, err)
			}

			for _, ip := range ips {
				if isPrivateIP(ip.IP) {
					return nil, fmt.Errorf("resolved address %s for %q is private: %w", ip.IP, host, ErrPrivateAddress)
				}
			}

			// Mimics Happy Eyeballs: try each resolved IP in order.
			if len(ips) == 0 {
				return nil, fmt.Errorf("no addresses found for %q", host)
			}

			var d net.Dialer
			var lastErr error
			for _, ip := range ips {
				target := net.JoinHostPort(ip.IP.String(), port)
				conn, err := d.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// limitRedirects enforces the maximum redirect count. It is used as the base
// http.Client.CheckRedirect policy; callers may wrap it with additional checks.
func limitRedirects(_ *http.Request, via []*http.Request) error {
	if len(via) >= maxSafeRedirects {
		return fmt.Errorf("too many redirects (%d): %w", len(via), ErrBlockedURL)
	}
	return nil
}

// checkSchemeDowngrade returns an error if the redirect downgrades from HTTPS
// to HTTP (or any non-TLS scheme). This prevents a redirect-based stripping
// attack where an HTTPS request is silently downgraded to plaintext.
func checkSchemeDowngrade(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if prev == nil || prev.URL == nil {
		return nil
	}
	if strings.EqualFold(prev.URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("cross-scheme redirect from HTTPS to %s blocked: %w", req.URL.Scheme, ErrBlockedURL)
	}
	return nil
}

// newHTTPClient creates an HTTP client with the given timeout and optional SSRF-safe transport.
func newHTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	if allowPrivate {
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				// Timeout guards are still necessary even on trusted internal
				// networks: a slow internal PKI server should not block
				// indefinitely.
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12}, // #nosec G402 -- MinVersion is explicitly set.
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if err := limitRedirects(req, via); err != nil {
					return err
				}
				return checkSchemeDowngrade(req, via)
			},
		}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: safeTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := limitRedirects(req, via); err != nil {
				return err
			}
			if err := checkSchemeDowngrade(req, via); err != nil {
				return err
			}
			// Pre-validate the redirect target URL against the SSRF blocklist.
			// This is belt-and-suspenders: the DialContext hook also checks
			// resolved IPs, but catching bad URLs here avoids forming a request
			// to a blocked target in the first place.
			return validateURL(req.URL.String())
		},
	}
}

// AIA (Authority Information Access) fetcher for retrieving issuer certificates.

package certree

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// AIA fetch limits and defaults.
const (
	// maxAIAResponseSize is the maximum response body size for AIA certificate
	// fetches. DER certificates are typically 1-5 KB; PKCS#7 bundles with a
	// full chain rarely exceed 20 KB. A tight limit prevents a malicious CA
	// from causing large allocations via crafted AIA URLs.
	maxAIAResponseSize = 64 << 10 // 64 KB.

	// DefaultAIATimeout is the per-request HTTP timeout for AIA fetches.
	DefaultAIATimeout = 5 * time.Second
)

// AIAFetcher fetches intermediate certificates from Authority Information Access (AIA) URLs.
// Certificates are cached by URL; each unique URL is fetched at most once per instance.
// Total fetches per analysis are bounded by the [ChainBuilder]'s MaxDepth setting.
type AIAFetcher interface {
	// FetchIssuers fetches issuer certificates from all AIA URLs in the
	// given certificate's extensions. It tries every URL and returns all
	// successfully fetched certificates. This is essential for discovering
	// cross-signed certificates: the same CA key may be served from
	// different AIA URLs with different issuer signatures.
	//
	// Errors from this method may be [*StructuredError] with one of these categories:
	//   - [ErrNoAIAURLs] -- certificate has no AIA URLs
	//   - [ErrAIAFetchFailed] -- all AIA URL fetches failed
	FetchIssuers(ctx context.Context, cert *Certificate) ([]*Certificate, error)

	// ResetCache clears the URL-keyed certificate cache. Subsequent
	// [AIAFetcher.FetchIssuers] calls will re-fetch certificates from the
	// network.
	//
	// Use this when certificates at AIA URLs may have changed (e.g., CA
	// rotated an intermediate) or to reclaim memory between independent
	// analysis batches in long-running services.
	ResetCache()
}

// aiaFetcherOptions holds configuration values for the AIA fetcher.
type aiaFetcherOptions struct {
	timeout time.Duration // Per-request HTTP timeout; default: DefaultAIATimeout.
}

// AIAFetcherOption is a functional option for configuring an [AIAFetcher].
type AIAFetcherOption func(*defaultAIAFetcher)

// WithAIATimeout sets the per-request HTTP timeout for AIA fetches (not total operation time).
// A zero value disables the per-request timeout; context deadline still applies.
// Default: 5 seconds.
func WithAIATimeout(timeout time.Duration) AIAFetcherOption {
	return func(f *defaultAIAFetcher) {
		if timeout >= 0 {
			f.opts.timeout = timeout
		}
	}
}

// WithAIALogger sets the logger for the AIA fetcher. Default: no-op logger.
func WithAIALogger(logger *slog.Logger) AIAFetcherOption {
	return func(f *defaultAIAFetcher) {
		if logger == nil {
			panic("certree: WithAIALogger called with nil logger")
		}
		f.logger = logger
	}
}

// WithAIAAllowPrivateNetworks disables SSRF protection, permitting AIA fetches
// to private/loopback/link-local IP addresses. This is intended for enterprise
// environments where AIA URLs point to internal PKI servers, and for testing.
//
// WARNING: Enabling this in production allows certificate-embedded URLs to reach
// internal services. Only enable when the network environment is trusted.
//
// Default: false (private networks are blocked).
func WithAIAAllowPrivateNetworks(allow bool) AIAFetcherOption {
	return func(f *defaultAIAFetcher) {
		f.allowPrivateNetworks = allow
	}
}

// WithAIACache enables or disables the URL-keyed certificate cache.
// Disable when certificates at AIA URLs are expected to change between fetches.
// Default: true.
func WithAIACache(enabled bool) AIAFetcherOption {
	return func(f *defaultAIAFetcher) {
		f.cacheEnabled = enabled
	}
}

// defaultAIAFetcher implements the AIAFetcher interface.
type defaultAIAFetcher struct {
	opts                 aiaFetcherOptions
	allowPrivateNetworks bool // Disable SSRF URL validation (for testing/enterprise)
	cacheEnabled         bool

	client *http.Client
	logger *slog.Logger

	cacheMu sync.RWMutex              // Protects cache below.
	cache   map[string][]*Certificate // URL -> previously fetched certificates
}

// NewAIAFetcher creates a new AIAFetcher with the given options applied over sensible defaults.
func NewAIAFetcher(opts ...AIAFetcherOption) AIAFetcher {
	f := &defaultAIAFetcher{
		opts: aiaFetcherOptions{
			timeout: DefaultAIATimeout,
		},
		logger:       NewLogger(),
		cacheEnabled: true,
		cache:        make(map[string][]*Certificate),
	}

	for _, opt := range opts {
		opt(f)
	}

	f.client = newHTTPClient(f.opts.timeout, f.allowPrivateNetworks)

	return f
}

var _ AIAFetcher = (*defaultAIAFetcher)(nil)

// ResetCache clears the URL-keyed certificate cache. Subsequent FetchIssuers
// calls will re-fetch certificates from the network.
func (f *defaultAIAFetcher) ResetCache() {
	f.cacheMu.Lock()
	n := len(f.cache)
	f.cache = make(map[string][]*Certificate)
	f.cacheMu.Unlock()
	f.logger.Debug("AIA cache cleared", "evicted", n)
}

// FetchIssuers tries every AIA URL in the certificate and returns all
// successfully fetched issuer certificates marked with [SourceTypeAIA].
// Multiple URLs may yield different cross-signed versions of the same CA key.
// Returns [*StructuredError] with category [ErrNoAIAURLs] or [ErrAIAFetchFailed] on failure.
func (f *defaultAIAFetcher) FetchIssuers(ctx context.Context, cert *Certificate) ([]*Certificate, error) {
	urls := cert.Raw().IssuingCertificateURL
	if len(urls) == 0 {
		return nil, NewStructuredError("certificate has no AIA URLs", ErrNoAIAURLs, nil)
	}

	// Collect cached results and identify URLs that still need fetching.
	var result []*Certificate
	var uncachedURLs []string

	if f.cacheEnabled {
		f.cacheMu.RLock()
		for _, url := range urls {
			if cached, ok := f.cache[url]; ok {
				f.logger.Debug("AIA cache hit", "url", url, "cert", cert.CommonName())
				result = append(result, cached...)
			} else {
				uncachedURLs = append(uncachedURLs, url)
			}
		}
		f.cacheMu.RUnlock()
	} else {
		uncachedURLs = urls
	}

	// Filter uncached URLs for SSRF safety. Even when private networks are
	// allowed, scheme and credential checks are enforced to prevent non-HTTP
	// schemes (ftp://, file://) and credential-bearing URLs from certificates.
	var fetchableURLs []string
	var lastFilterErr error
	if f.allowPrivateNetworks {
		for _, u := range uncachedURLs {
			if err := validateURLSchemeAndCredentials(u); err != nil {
				f.logger.Debug("skipping invalid AIA URL", "url", u, "error", err)
				lastFilterErr = err
				continue
			}
			fetchableURLs = append(fetchableURLs, u)
		}
	} else {
		for _, u := range uncachedURLs {
			if err := validateURL(u); err != nil {
				f.logger.Debug("skipping invalid AIA URL", "url", u, "error", err)
				lastFilterErr = err
				continue
			}
			fetchableURLs = append(fetchableURLs, u)
		}
	}

	if len(fetchableURLs) == 0 && len(result) == 0 {
		return nil, NewStructuredError("no fetchable AIA URLs (all blocked or invalid scheme)", ErrAIAFetchFailed, lastFilterErr)
	}

	if len(fetchableURLs) > 0 {
		f.logger.Debug("found fetchable AIA URLs", "count", len(fetchableURLs), "cert", cert.CommonName())
	}

	var lastErr error
	for _, url := range fetchableURLs {
		f.logger.Debug("attempting to fetch from AIA URL", "url", url)

		certs, err := f.fetchFromURL(ctx, url)
		if err != nil {
			f.logger.Warn("failed to fetch from AIA URL", "url", url, "error", err)
			lastErr = err
			continue
		}

		for _, c := range certs {
			f.logger.Info("successfully fetched issuer from AIA", "url", url, "issuer", c.CommonName())
		}

		if f.cacheEnabled {
			f.cacheMu.Lock()
			f.cache[url] = certs
			f.cacheMu.Unlock()
		}

		result = append(result, certs...)
	}

	if len(result) == 0 {
		return nil, NewStructuredError("could not fetch issuer certificate via AIA", ErrAIAFetchFailed, lastErr)
	}

	return result, nil
}

// fetchFromURL performs an HTTP GET to url and parses the response as certificates.
func (f *defaultAIAFetcher) fetchFromURL(ctx context.Context, url string) ([]*Certificate, error) {
	if f.allowPrivateNetworks {
		if err := validateURLSchemeAndCredentials(url); err != nil {
			return nil, fmt.Errorf("AIA URL validation failed: %w", err)
		}
	} else {
		if err := validateURL(url); err != nil {
			return nil, fmt.Errorf("AIA URL validation failed: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	// RFC 5280 section 4.2.2.1 / CA-Browser Forum: AIA id-ad-caIssuers URLs may serve
	// certificates in DER (application/pkix-cert) or PEM (application/x-x509-ca-cert)
	// format. Advertising both types guides servers to send the right content type.
	req.Header.Set("Accept", "application/pkix-cert, application/x-x509-ca-cert")

	resp, err := f.client.Do(req) // #nosec G107 -- URL validated by validateURL (scheme, IP range); transport uses safeTransport with DialContext SSRF guard
	if err != nil {
		return nil, fmt.Errorf("fetching URL: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			f.logger.Debug("failed to close AIA response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s: %w", resp.StatusCode, resp.Status, ErrAIAFetchFailed)
	}

	limitedReader := io.LimitReader(resp.Body, maxAIAResponseSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	source := CertificateSource{
		Type:     SourceTypeAIA,
		Location: url,
	}

	// AIA responses are typically DER-encoded; try DER first, fall back to PEM.
	cert, derErr := ParseDERCertificate(data, source)
	if derErr == nil {
		return []*Certificate{cert}, nil
	}

	certs, pemErr := ParsePEMCertificates(data, source, DefaultMaxCertificates)
	if pemErr != nil {
		return nil, fmt.Errorf("parsing certificate: DER: %w; PEM: %w", derErr, pemErr)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("parsing certificate: no certificates found in AIA response: %w", ErrNoCertificatesFound)
	}

	return certs, nil
}

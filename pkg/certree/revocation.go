// Certificate revocation checking via OCSP and CRL.

package certree

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Revocation response size limits, timing tolerances, and defaults.
const (
	maxOCSPResponseSize = 1 << 20  // 1 MB.
	maxCRLResponseSize  = 10 << 20 // 10 MB.

	// freshnessClockSkew is the tolerance applied when checking whether a
	// response's ThisUpdate timestamp is in the future. A small tolerance
	// prevents spurious rejections caused by minor clock differences between
	// the responder and the local system.
	freshnessClockSkew = 5 * time.Minute

	// maxOCSPResponseTTL caps the validity of OCSP responses that omit
	// nextUpdate. RFC 6960 section 4.2.2.1 makes nextUpdate optional, but accepting
	// such responses indefinitely allows replaying a captured "Good" status
	// for a revoked certificate. 7 days aligns with the CA/Browser Forum
	// recommended maximum OCSP response validity.
	maxOCSPResponseTTL = 7 * 24 * time.Hour

	// defaultRevocationTimeout is the HTTP client timeout for OCSP and CRL
	// requests when no custom HTTP client is provided.
	defaultRevocationTimeout = 10 * time.Second

	// maxCacheEntries is the maximum number of entries in each revocation
	// cache (OCSP and CRL). When the limit is reached, the entry with the
	// earliest expiry is evicted to make room.
	maxCacheEntries = 10000
)

// RevocationChecker checks certificate revocation status via OCSP or CRL.
// Implementations should check OCSP first (faster) and fall back to CRL if needed.
type RevocationChecker interface {
	// CheckRevocation checks if cert has been revoked by its issuer.
	// Returns RevocationStatus with check results and any errors encountered.
	// The context can be used to cancel long-running network operations.
	CheckRevocation(ctx context.Context, cert *Certificate, issuer *Certificate) (RevocationStatus, error)

	// ResetCache clears the OCSP and CRL response caches. Subsequent
	// [RevocationChecker.CheckRevocation] calls will re-fetch responses from
	// the network. This is a no-op when caching is disabled.
	//
	// Use this when revocation state may have changed (e.g., a certificate
	// was just revoked) or to reclaim memory between independent analysis
	// batches in long-running services.
	ResetCache()
}

// RevocationStatus represents the result of a certificate revocation check.
// It includes whether the certificate is revoked, the revocation time, and metadata about
// how the check was performed.
//
// The Error field is a diagnostic detail, not the primary error signal. When
// CheckRevocation returns a nil error, the revocation check succeeded (possibly
// via fallback) and the fields in RevocationStatus are authoritative. When
// CheckRevocation returns a non-nil error, the check failed entirely and the
// status should not be used. The Error field retains the first failure's detail
// when a fallback path (e.g., CRL after OCSP failure) ultimately succeeds.
type RevocationStatus struct {
	IsRevoked    bool       `json:"is_revoked"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`    // nil if not revoked.
	CheckedVia   string     `json:"checked_via,omitempty"`   // "OCSP" or "CRL".
	ResponderURL string     `json:"responder_url,omitempty"` // URL of the OCSP responder or CRL distribution point.
	Error        error      `json:"-"`                       // Diagnostic detail from the first check method that failed; may be nil.
}

// RevocationCheckerOption is a functional option for configuring a
// RevocationChecker.
type RevocationCheckerOption func(*defaultRevocationChecker)

// WithHTTPClient sets a custom HTTP client for revocation checking.
// This allows customization of timeouts, cookie jars, and redirect policy.
//
// [NewRevocationChecker] replaces the client's Transport with the built-in
// SSRF-safe transport unless [WithRevocationAllowPrivateNetworks] is enabled.
// The client's CheckRedirect is preserved if set; otherwise a default
// redirect limiter is applied.
func WithHTTPClient(client *http.Client) RevocationCheckerOption {
	return func(rc *defaultRevocationChecker) {
		rc.httpClient = client
	}
}

// WithRevocationLogger sets a custom logger for revocation checking.
// The logger receives debug, info, and warning messages about revocation checks.
//
// Panics if logger is nil (programmer error).
func WithRevocationLogger(logger *slog.Logger) RevocationCheckerOption {
	return func(rc *defaultRevocationChecker) {
		if logger == nil {
			panic("certree: WithRevocationLogger called with nil logger")
		}
		rc.logger = logger
	}
}

// WithRevocationAllowPrivateNetworks disables SSRF protection, permitting
// revocation checks (OCSP/CRL) to reach private/loopback/link-local IP
// addresses. This is intended for enterprise environments where OCSP/CRL
// servers are internal, and for testing.
//
// WARNING: Enabling this in production allows certificate-embedded URLs to reach
// internal services. Only enable when the network environment is trusted.
//
// Default: false (private networks are blocked).
func WithRevocationAllowPrivateNetworks(allow bool) RevocationCheckerOption {
	return func(rc *defaultRevocationChecker) {
		rc.allowPrivateNetworks = allow
	}
}

// WithRevocationCache enables or disables in-memory caching of OCSP and CRL
// responses. OCSP responses are cached per-certificate (keyed by responder
// URL + serial + issuer fingerprint). CRLs are cached per-URL so that certificates sharing the
// same CRL distribution point reuse a single parsed CRL, avoiding redundant
// multi-megabyte downloads during batch analysis. Both caches expire entries
// at the response's NextUpdate.
//
// Disabling the cache forces every revocation check to make a network request.
// This is useful for testing or when OCSP/CRL responses are expected to change
// between checks.
//
// Default: true (caching enabled).
func WithRevocationCache(enabled bool) RevocationCheckerOption {
	return func(rc *defaultRevocationChecker) {
		if enabled {
			rc.cache = newExpiryCache(func(e revocationCacheEntry) time.Time { return e.expiresAt })
			rc.crlCache = newExpiryCache(func(e crlCacheEntry) time.Time { return e.expiresAt })
		} else {
			rc.cache = nil
			rc.crlCache = nil
		}
	}
}

// WithRevocationValidationTime overrides the wall clock used for OCSP/CRL
// freshness checks (ThisUpdate/NextUpdate). When set to a non-zero time,
// the revocation checker evaluates response freshness relative to this time
// instead of time.Now(). This is required for temporal simulation so that
// the validation time applies consistently to both expiry and revocation checks.
//
// Default: zero (use wall clock).
func WithRevocationValidationTime(t time.Time) RevocationCheckerOption {
	return func(rc *defaultRevocationChecker) {
		rc.validationTime = t
	}
}

// defaultRevocationChecker implements the RevocationChecker interface with
// automatic fallback from OCSP to CRL when OCSP is unavailable or fails.
type defaultRevocationChecker struct {
	allowPrivateNetworks bool // Disable SSRF URL validation (for testing/enterprise)

	httpClient     *http.Client
	logger         *slog.Logger
	cache          *expiryCache[revocationCacheEntry] // OCSP response cache (per-certificate).
	crlCache       *expiryCache[crlCacheEntry]        // CRL cache (per-URL, shared across certificates).
	validationTime time.Time                          // Overrides time.Now() for freshness checks; zero means use wall clock.
}

// NewRevocationChecker creates a new revocation checker with the given options.
// By default, it uses a 10-second timeout, no-op logger, and enabled caching.
//
// Fail-open behavior is controlled by the caller via [ValidationOptions.RevocationFailOpen],
// not by the revocation checker itself.
func NewRevocationChecker(opts ...RevocationCheckerOption) RevocationChecker {
	rc := &defaultRevocationChecker{
		logger:   NewLogger(),
		cache:    newExpiryCache(func(e revocationCacheEntry) time.Time { return e.expiresAt }),
		crlCache: newExpiryCache(func(e crlCacheEntry) time.Time { return e.expiresAt }),
	}

	for _, opt := range opts {
		opt(rc)
	}

	if rc.httpClient == nil {
		// No custom client: create SSRF-safe by default, plain when private networks allowed.
		rc.httpClient = newHTTPClient(defaultRevocationTimeout, rc.allowPrivateNetworks)
	} else {
		// Custom client provided: shallow-copy to avoid mutating the caller's *http.Client.
		clientCopy := *rc.httpClient
		if !rc.allowPrivateNetworks {
			// Enforce SSRF-safe transport unless private networks are allowed.
			clientCopy.Transport = safeTransport()
		}
		// Always enforce a redirect limit to prevent redirect loops, even when
		// private networks are allowed and the caller's client has no limit.
		if clientCopy.CheckRedirect == nil {
			clientCopy.CheckRedirect = limitRedirects
		}
		rc.httpClient = &clientCopy
	}

	return rc
}

var _ RevocationChecker = (*defaultRevocationChecker)(nil)

// ResetCache clears the OCSP and CRL response caches. This is a no-op when
// caching has been disabled via [WithRevocationCache].
func (rc *defaultRevocationChecker) ResetCache() {
	var ocspEvicted, crlEvicted int
	if rc.cache != nil {
		ocspEvicted = rc.cache.reset()
	}
	if rc.crlCache != nil {
		crlEvicted = rc.crlCache.reset()
	}
	rc.logger.Debug("revocation cache cleared", "ocsp_evicted", ocspEvicted, "crl_evicted", crlEvicted)
}

// CheckRevocation checks the revocation status of cert by trying OCSP first,
// then falling back to CRL if OCSP is unavailable or fails.
func (rc *defaultRevocationChecker) CheckRevocation(ctx context.Context, cert *Certificate, issuer *Certificate) (RevocationStatus, error) {
	if cert == nil || issuer == nil {
		return RevocationStatus{}, NewStructuredError("revocation check requires non-nil certificate and issuer", ErrNilArgument, nil)
	}

	status, err := rc.checkOCSP(ctx, cert, issuer)
	if err == nil {
		return status, nil
	}

	rc.logger.Debug("OCSP check failed, falling back to CRL", "cert", cert.CommonName(), "error", err)

	status, crlErr := rc.checkCRL(ctx, cert, issuer)
	if crlErr == nil {
		return status, nil
	}

	rc.logger.Warn("both OCSP and CRL checks failed", "cert", cert.CommonName(), "ocsp_error", err, "crl_error", crlErr)

	combinedErr := fmt.Errorf("OCSP failed: %w; CRL failed: %w", err, crlErr)
	return RevocationStatus{
			Error: combinedErr,
		}, NewStructuredError(
			"revocation check failed for certificate",
			ErrRevocationCheckFailed,
			combinedErr,
		)
}

// tryRevocationURLs iterates over a list of URLs, calling checkFn for each one,
// returning the first successful result. On total failure it returns an error
// wrapping the last individual error. This eliminates the structural duplication
// between OCSP and CRL retry loops.
func (rc *defaultRevocationChecker) tryRevocationURLs(
	ctx context.Context,
	cert *Certificate,
	urls []string,
	checkFn revocationURLChecker,
	method string,
	noURLsErr error,
	allFailedMsg string,
) (RevocationStatus, error) {
	if len(urls) == 0 {
		return RevocationStatus{}, noURLsErr
	}

	var lastErr error
	for _, url := range urls {
		rc.logger.Debug("checking "+method, "url", url, "cert", cert.CommonName())

		status, err := checkFn(ctx, url)
		if err != nil {
			lastErr = err
			rc.logger.Debug(method+" check failed", "url", url, "error", err)
			continue
		}

		rc.logger.Info(method+" check completed", "url", url, "cert", cert.CommonName(), "revoked", status.IsRevoked)
		return status, nil
	}

	return RevocationStatus{}, fmt.Errorf("%s: %w", allFailedMsg, lastErr)
}

// checkOCSP performs OCSP revocation checking by querying all available OCSP responders.
func (rc *defaultRevocationChecker) checkOCSP(ctx context.Context, cert *Certificate, issuer *Certificate) (RevocationStatus, error) {
	return rc.tryRevocationURLs(
		ctx,
		cert,
		cert.Raw().OCSPServer,
		func(ctx context.Context, url string) (RevocationStatus, error) {
			return rc.queryOCSPResponder(ctx, url, cert, issuer)
		},
		"OCSP",
		ErrNoOCSPResponders,
		"all OCSP responders failed",
	)
}

// queryOCSPResponder queries a single OCSP responder and parses the response.
func (rc *defaultRevocationChecker) queryOCSPResponder(ctx context.Context, responderURL string, cert *Certificate, issuer *Certificate) (RevocationStatus, error) {
	// Include the issuer fingerprint in the cache key so that certificates with
	// the same serial number issued by different CAs are cached separately.
	cacheKey := "ocsp\x00" + responderURL + "\x00" + cert.SerialNumber() + "\x00" + issuer.FingerprintSHA256()
	if rc.cache != nil {
		if cached, ok := rc.cache.get(cacheKey, rc.validationTime); ok {
			rc.logger.Debug("OCSP cache hit", "url", responderURL, "cert", cert.CommonName())
			return cached.status, nil
		}
	}

	if rc.allowPrivateNetworks {
		if err := validateURLSchemeAndCredentials(responderURL); err != nil {
			return RevocationStatus{}, fmt.Errorf("OCSP URL validation failed: %w", err)
		}
	} else {
		if err := validateURL(responderURL); err != nil {
			return RevocationStatus{}, fmt.Errorf("OCSP URL validation failed: %w", err)
		}
	}

	respBody, err := rc.fetchOCSPResponse(ctx, responderURL, cert, issuer)
	if err != nil {
		return RevocationStatus{}, err
	}

	status, nextUpdate, err := parseOCSPResponse(respBody, responderURL, cert, issuer, rc.validationTime)
	if err != nil {
		return RevocationStatus{}, err
	}

	if rc.cache != nil {
		rc.cache.set(cacheKey, revocationCacheEntry{status: status, expiresAt: nextUpdate}, nextUpdate)
	}

	return status, nil
}

// fetchOCSPResponse builds an OCSP request, sends it, and returns the raw response body.
func (rc *defaultRevocationChecker) fetchOCSPResponse(ctx context.Context, responderURL string, cert *Certificate, issuer *Certificate) ([]byte, error) {
	ocspRequest, err := ocsp.CreateRequest(cert.Raw(), issuer.Raw(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating OCSP request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responderURL, bytes.NewReader(ocspRequest))
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	// RFC 6960 section 4.1: Content-Type MUST be "application/ocsp-request" for POST.
	// Accept SHOULD contain "application/ocsp-response".
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")

	// Send OCSP request (URL validated above, transport uses SSRF-safe dialer).
	resp, err := rc.httpClient.Do(req) // #nosec G107 -- URL validated by validateURL; transport uses safeTransport with DialContext SSRF guard
	if err != nil {
		return nil, fmt.Errorf("sending OCSP request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			rc.logger.Debug("failed to close OCSP response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP responder returned status %d: %w", resp.StatusCode, ErrHTTPError)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOCSPResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading OCSP response: %w", err)
	}
	if len(body) > maxOCSPResponseSize {
		return nil, fmt.Errorf("OCSP response exceeds size limit (%d bytes): %w", maxOCSPResponseSize, ErrInputTooLarge)
	}
	return body, nil
}

// parseOCSPResponse parses and validates an OCSP response, returning the revocation
// status, the NextUpdate time (for caching), and any error.
//
// ParseResponseForCert is used instead of ParseResponse to verify that the
// response certID matches the requested certificate (serial number and issuer).
// ParseResponse only verifies the signature; it does not confirm the response
// is for the certificate that was requested. This prevents a malicious or
// misconfigured OCSP responder from returning a valid "Good" response for a
// different certificate.
func parseOCSPResponse(respBody []byte, responderURL string, cert *Certificate, issuer *Certificate, now time.Time) (RevocationStatus, time.Time, error) {
	ocspResp, err := ocsp.ParseResponseForCert(respBody, cert.Raw(), issuer.Raw())
	if err != nil {
		return RevocationStatus{}, time.Time{}, fmt.Errorf("parsing OCSP response: %w", err)
	}

	if err := validateResponseFreshness(ocspResp.ThisUpdate, ocspResp.NextUpdate, now, "OCSP response"); err != nil {
		return RevocationStatus{}, time.Time{}, err
	}

	status := RevocationStatus{
		CheckedVia:   "OCSP",
		ResponderURL: responderURL,
	}

	switch ocspResp.Status {
	case ocsp.Good:
		// IsRevoked defaults to false; no action needed.
	case ocsp.Revoked:
		status.IsRevoked = true
		revokedAt := ocspResp.RevokedAt
		status.RevokedAt = &revokedAt
	case ocsp.Unknown:
		return RevocationStatus{}, time.Time{}, fmt.Errorf("OCSP responder returned unknown status: %w", ErrOCSPUnknownStatus)
	default:
		return RevocationStatus{}, time.Time{}, fmt.Errorf("unexpected OCSP status: %d", ocspResp.Status)
	}

	// When nextUpdate is absent (RFC 6960 permits this), cap response validity
	// at maxOCSPResponseTTL from thisUpdate to prevent indefinite replay of
	// a captured "Good" status for a revoked certificate.
	nextUpdate := ocspResp.NextUpdate
	if nextUpdate.IsZero() {
		base := ocspResp.ThisUpdate
		if base.IsZero() {
			if now.IsZero() {
				base = time.Now()
			} else {
				base = now
			}
		}
		nextUpdate = base.Add(maxOCSPResponseTTL)
	}

	return status, nextUpdate, nil
}

// checkCRL performs CRL revocation checking by downloading and verifying CRLs.
func (rc *defaultRevocationChecker) checkCRL(ctx context.Context, cert *Certificate, issuer *Certificate) (RevocationStatus, error) {
	return rc.tryRevocationURLs(
		ctx,
		cert,
		cert.Raw().CRLDistributionPoints,
		func(ctx context.Context, url string) (RevocationStatus, error) {
			return rc.checkCRLFromURL(ctx, url, cert, issuer)
		},
		"CRL",
		ErrNoCRLDistributionPoints,
		"all CRL distribution points failed",
	)
}

// checkCRLFromURL downloads a CRL from the given URL and checks if the certificate is revoked.
// It downloads the CRL via HTTP GET, parses it, verifies the CRL signature against the issuer,
// and checks if the certificate's serial number appears in the revoked list.
//
// CRLs are cached by URL and verified against the expected issuer on cache hit.
// A single CRL covers all certificates from the same issuer, enabling effective
// batch caching when multiple certificates share the same CRL distribution point.
//
// Note: concurrent cache misses for the same URL may produce duplicate fetches.
// This is benign (both fetches return identical data) and bounded by the number
// of concurrent goroutines. A singleflight coalescer could eliminate the extra
// fetches but adds complexity for minimal benefit in typical CLI usage.
func (rc *defaultRevocationChecker) checkCRLFromURL(ctx context.Context, crlURL string, cert *Certificate, issuer *Certificate) (RevocationStatus, error) {
	if rc.crlCache != nil {
		if cached, ok := rc.crlCache.get(crlURL, rc.validationTime); ok {
			// Verify the cached CRL was issued by the expected issuer to prevent
			// cross-issuer cache poisoning when different issuers share a CRL URL.
			if bytes.Equal(cached.crl.RawIssuer, issuer.Raw().RawSubject) {
				rc.logger.Debug("CRL cache hit", "url", crlURL, "cert", cert.CommonName())
				return checkCertInCRL(cached.crl, crlURL, cert), nil
			}
			rc.logger.Debug("CRL cache issuer mismatch, refetching", "url", crlURL)
		}
	}

	if rc.allowPrivateNetworks {
		if err := validateURLSchemeAndCredentials(crlURL); err != nil {
			return RevocationStatus{}, fmt.Errorf("CRL URL validation failed: %w", err)
		}
	} else {
		if err := validateURL(crlURL); err != nil {
			return RevocationStatus{}, fmt.Errorf("CRL URL validation failed: %w", err)
		}
	}

	crl, err := rc.fetchAndParseCRL(ctx, crlURL, issuer)
	if err != nil {
		return RevocationStatus{}, err
	}

	if rc.crlCache != nil {
		rc.crlCache.set(crlURL, crlCacheEntry{crl: crl, expiresAt: crl.NextUpdate}, crl.NextUpdate)
	}

	return checkCertInCRL(crl, crlURL, cert), nil
}

// fetchAndParseCRL downloads a CRL, parses it, verifies its signature, and checks freshness.
func (rc *defaultRevocationChecker) fetchAndParseCRL(ctx context.Context, crlURL string, issuer *Certificate) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}

	// CRL URL validated above; transport uses SSRF-safe dialer.
	resp, err := rc.httpClient.Do(req) // #nosec G107 -- URL validated by validateURL; transport uses safeTransport with DialContext SSRF guard
	if err != nil {
		return nil, fmt.Errorf("downloading CRL: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			rc.logger.Debug("failed to close CRL response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned status %d: %w", resp.StatusCode, ErrHTTPError)
	}

	crlData, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading CRL data: %w", err)
	}
	if len(crlData) > maxCRLResponseSize {
		return nil, fmt.Errorf("CRL response exceeds size limit (%d bytes): %w", maxCRLResponseSize, ErrInputTooLarge)
	}

	crl, err := x509.ParseRevocationList(crlData)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL: %w", err)
	}

	// RFC 5280 section 5.1.1.2: the CRL issuer field must match the issuing CA's subject.
	// CheckSignatureFrom verifies the cryptographic binding but not the DN match.
	if !bytes.Equal(crl.RawIssuer, issuer.Raw().RawSubject) {
		return nil, fmt.Errorf("CRL issuer DN does not match expected issuer %q: %w", issuer.CommonName(), ErrCRLIssuerMismatch)
	}

	if err := crl.CheckSignatureFrom(issuer.Raw()); err != nil {
		return nil, fmt.Errorf("CRL signature verification failed: %w", err)
	}

	// RFC 5280 section 5.1.2.5 requires CRLs to include nextUpdate. A CRL without
	// it could be replayed indefinitely, so reject it as stale.
	if crl.NextUpdate.IsZero() {
		return nil, fmt.Errorf("CRL has no NextUpdate (required by RFC 5280): %w", ErrResponseStale)
	}

	if err := validateResponseFreshness(crl.ThisUpdate, crl.NextUpdate, rc.validationTime, "CRL"); err != nil {
		return nil, err
	}

	return crl, nil
}

// expiryCache is a thread-safe in-memory cache with time-based expiry.
// When the cache exceeds [maxCacheEntries], the entry with the earliest
// expiry is evicted. Expired entries are not proactively evicted; call
// reset periodically to reclaim memory in long-running services. If the
// O(n) eviction scan becomes a bottleneck, replace with a min-heap.
type expiryCache[V any] struct {
	mu        sync.RWMutex
	entries   map[string]V
	expiresAt func(V) time.Time
}

// newExpiryCache creates an empty cache. The expiresAt function extracts the
// expiry time from a cached value.
func newExpiryCache[V any](expiresAt func(V) time.Time) *expiryCache[V] {
	return &expiryCache[V]{
		entries:   make(map[string]V),
		expiresAt: expiresAt,
	}
}

// get returns a cached value if it exists and has not expired. A zero now
// means use time.Now().
func (c *expiryCache[V]) get(key string, now time.Time) (V, bool) {
	if now.IsZero() {
		now = time.Now()
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	if now.After(c.expiresAt(entry)) {
		var zero V
		return zero, false
	}
	return entry, true
}

// set stores a value with the given expiry time. If expiresAt is zero, the
// entry is not cached (no TTL available). When the cache exceeds
// [maxCacheEntries], the oldest entry is evicted.
func (c *expiryCache[V]) set(key string, value V, expiresAt time.Time) {
	if expiresAt.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxCacheEntries {
		c.evictOldestLocked()
	}
	c.entries[key] = value
}

// evictOldestLocked removes the entry with the earliest expiry.
// Caller must hold c.mu.
func (c *expiryCache[V]) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for k, v := range c.entries {
		t := c.expiresAt(v)
		if oldestKey == "" || t.Before(oldestTime) {
			oldestKey = k
			oldestTime = t
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// reset clears all entries and returns the number evicted.
func (c *expiryCache[V]) reset() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = make(map[string]V)
	return n
}

// revocationCacheEntry stores a cached revocation response with expiry.
type revocationCacheEntry struct {
	status    RevocationStatus
	expiresAt time.Time
}

// crlCacheEntry stores a cached parsed CRL with expiry.
type crlCacheEntry struct {
	crl       *x509.RevocationList
	expiresAt time.Time
}

// revocationURLChecker is a function that checks a single URL for revocation status.
type revocationURLChecker func(ctx context.Context, url string) (RevocationStatus, error)

// checkCertInCRL checks if a certificate's serial number appears in the CRL's revoked list.
// It performs a linear scan comparing serial numbers via big.Int.Cmp for exact numeric
// equality (avoiding string representation ambiguity).
func checkCertInCRL(crl *x509.RevocationList, crlURL string, cert *Certificate) RevocationStatus {
	status := RevocationStatus{
		CheckedVia:   "CRL",
		ResponderURL: crlURL,
	}

	serial := cert.Raw().SerialNumber
	for _, revokedCertEntry := range crl.RevokedCertificateEntries {
		if revokedCertEntry.SerialNumber.Cmp(serial) == 0 {
			status.IsRevoked = true
			revokedAt := revokedCertEntry.RevocationTime
			status.RevokedAt = &revokedAt
			break
		}
	}

	return status
}

// validateResponseFreshness checks that an OCSP response or CRL is current.
// A stale response (past NextUpdate) could be a replay of an old "Good" OCSP
// response or an old CRL that omits recently revoked certificates.
// The label parameter (e.g., "OCSP response", "CRL") is used in error messages.
func validateResponseFreshness(thisUpdate, nextUpdate, now time.Time, label string) error {
	if now.IsZero() {
		now = time.Now()
	}
	if !nextUpdate.IsZero() && now.After(nextUpdate) {
		return fmt.Errorf("%s is stale: NextUpdate %s is in the past: %w", label, nextUpdate.Format(time.RFC3339), ErrResponseStale)
	}
	if !thisUpdate.IsZero() && now.Before(thisUpdate.Add(-freshnessClockSkew)) {
		return fmt.Errorf("%s is not yet valid: ThisUpdate %s is in the future: %w", label, thisUpdate.Format(time.RFC3339), ErrResponseNotYetValid)
	}
	return nil
}

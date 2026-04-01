// Parser interface, option types, and defaultParser implementation.

package certree

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/pkcs12"
)

// Parser size, certificate limits, and defaults.
const (
	// maxParserInputSize is the maximum input data size for file and byte parsing.
	maxParserInputSize = 10 << 20 // 10 MB.

	// DefaultMaxCertificates is the default certificate limit when MaxCertificates is not set.
	DefaultMaxCertificates = 100

	// DefaultConnectTimeout is the default TLS connection timeout for
	// ParseRemote when RemoteOptions.Timeout is zero.
	DefaultConnectTimeout = 5 * time.Second

	// DefaultURLFetchTimeout is the default HTTP client timeout for
	// ParseURL when fetching certificates from a URL.
	DefaultURLFetchTimeout = 5 * time.Second
)

// Parser reads and parses X.509 certificates from various sources.
// It supports PEM, DER, PKCS#7, and PKCS#12 formats with automatic detection,
// and multiple source types: files, remote TLS connections, URLs, and raw bytes.
// Private keys found in PKCS#12 files are silently ignored.
type Parser interface {
	// ParseFile reads and parses certificates from a file.
	// Format is auto-detected regardless of extension (.pem, .crt, .cer, .der, .p7b, .p7c, .p12, .pfx).
	// Errors may be [*StructuredError] with categories [ErrFileReadFailed], [ErrFileTooLarge],
	// [ErrUnknownFormat], or [ErrEmptyInput].
	ParseFile(ctx context.Context, path string) ([]*Certificate, error)

	// ParseRemote connects to a remote TLS server and returns the certificate chain
	// presented during the TLS handshake. AIA fetching is controlled by [ChainBuilder], not the parser.
	// Errors may be [*StructuredError] with categories [ErrConnectionFailed], [ErrInvalidHostFormat],
	// [ErrSNIRequired], or [ErrNoCertificatesFound].
	ParseRemote(ctx context.Context, host string, opts RemoteOptions) ([]*Certificate, error)

	// ParseBytes parses certificates from raw byte data with automatic format detection.
	// It does not accept a context because it operates entirely on in-memory data with no I/O.
	// PKCS#12 is tried with an empty password only; password-protected files return [ErrPasswordRequired].
	// Errors may be [*StructuredError] with categories [ErrEmptyInput] or [ErrUnknownFormat].
	ParseBytes(data []byte) ([]*Certificate, error)

	// ParseURL fetches and parses certificates from an HTTP or HTTPS URL.
	// SSRF protection blocks private/loopback addresses by default; disable with [WithParserAllowPrivateNetworks].
	// Errors may be [*StructuredError] with categories [ErrURLFetchFailed], [ErrUnknownFormat],
	// [ErrEmptyInput], or [ErrInputTooLarge].
	ParseURL(ctx context.Context, rawURL string) ([]*Certificate, error)
}

// parserOptions holds configuration for a defaultParser instance.
type parserOptions struct {
	skipInvalid      bool
	autoDetectFormat bool
	maxCertificates  int
	httpUpgrade      bool
	urlFetchTimeout  time.Duration
}

// RemoteOptions configures a remote TLS connection for [Parser.ParseRemote].
type RemoteOptions struct {
	// SNI overrides the TLS server name. Required when connecting to an IP address.
	SNI string

	// Timeout limits the connection and TLS handshake duration. Zero uses
	// [DefaultConnectTimeout] (5 seconds).
	Timeout time.Duration

	// ClientCert is presented for mutual TLS. If nil, no client certificate is sent.
	ClientCert *tls.Certificate

	// VerifyHostname controls TLS hostname verification. When false (the default for
	// Analyzer-driven calls), the Validator performs hostname checks independently.
	VerifyHostname bool
}

// ParserOption is a functional option for configuring a Parser.
type ParserOption func(*defaultParser)

// WithSkipInvalid controls whether to skip invalid certificates or fail.
// When true, invalid certificates are logged and skipped.
// When false, parsing fails on the first invalid certificate.
// Default: false.
func WithSkipInvalid(skip bool) ParserOption {
	return func(p *defaultParser) {
		p.opts.skipInvalid = skip
	}
}

// WithMaxCertificates limits the maximum number of certificates to parse
// from a single source to prevent memory exhaustion. Values <= 0 are
// clamped to [DefaultMaxCertificates].
func WithMaxCertificates(maxCerts int) ParserOption {
	return func(p *defaultParser) {
		p.opts.maxCertificates = maxCerts
	}
}

// WithAutoDetectFormat enables automatic detection of certificate format.
// When true, the parser tries PEM, DER, PKCS#7, and PKCS#12 in order.
// When false, only PEM and DER are tried.
// Default: false.
func WithAutoDetectFormat(detect bool) ParserOption {
	return func(p *defaultParser) {
		p.opts.autoDetectFormat = detect
	}
}

// WithParserLogger sets the logger for the parser.
// Default: no-op logger (silent).
//
// Panics if logger is nil (programmer error).
func WithParserLogger(logger *slog.Logger) ParserOption {
	return func(p *defaultParser) {
		if logger == nil {
			panic("certree: WithParserLogger called with nil logger")
		}
		p.logger = logger
	}
}

// WithParserAllowPrivateNetworks controls whether ParseURL may fetch from
// private/loopback addresses. When false (default), SSRF protection blocks
// requests to RFC 1918, loopback, and link-local addresses.
func WithParserAllowPrivateNetworks(allow bool) ParserOption {
	return func(p *defaultParser) {
		p.allowPrivateNetworks = allow
	}
}

// WithURLFetchTimeout sets the HTTP client timeout for [Parser.ParseURL].
// Values <= 0 are ignored and the default ([DefaultURLFetchTimeout]) is used.
func WithURLFetchTimeout(d time.Duration) ParserOption {
	return func(p *defaultParser) {
		if d > 0 {
			p.opts.urlFetchTimeout = d
		}
	}
}

// WithHTTPUpgrade controls whether ParseURL automatically upgrades http:// URLs
// to https://. When true (default), HTTP URLs are silently upgraded to HTTPS
// before fetching. Disable this only when accessing endpoints that genuinely
// require plain HTTP (e.g., internal PKI over a trusted network).
func WithHTTPUpgrade(upgrade bool) ParserOption {
	return func(p *defaultParser) {
		p.opts.httpUpgrade = upgrade
	}
}

// defaultParser implements the Parser interface.
type defaultParser struct {
	opts                 parserOptions
	allowPrivateNetworks bool
	logger               *slog.Logger
	dialer               *net.Dialer
}

// NewParser creates a new Parser with the given options.
func NewParser(opts ...ParserOption) Parser {
	p := &defaultParser{
		opts: parserOptions{
			maxCertificates: DefaultMaxCertificates,
			httpUpgrade:     true,
			urlFetchTimeout: DefaultURLFetchTimeout,
		},
		logger: NewLogger(),
		dialer: &net.Dialer{
			KeepAlive: -1, // Disable keepalive; certree closes connections after reading certs.
		},
	}

	for _, opt := range opts {
		opt(p)
	}

	if p.opts.maxCertificates <= 0 {
		p.opts.maxCertificates = DefaultMaxCertificates
	}

	return p
}

var _ Parser = (*defaultParser)(nil)

// ParseFile parses certificates from a file.
func (p *defaultParser) ParseFile(ctx context.Context, path string) ([]*Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, NewStructuredError(fmt.Sprintf("parsing file %s canceled", path), ErrContextCanceled, ctx.Err())
	default:
	}

	path = filepath.Clean(path)

	p.logger.Info("parsing certificate file", "file", path)

	// Stat before reading to detect missing files, directories, and oversized files.
	fi, err := os.Stat(path)
	if err != nil {
		return nil, NewStructuredError(fmt.Sprintf("could not read file %s", path), ErrFileReadFailed, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, NewStructuredError(fmt.Sprintf("%q is not a regular file", path), ErrInvalidInput, nil)
	}
	if fi.Size() > int64(maxParserInputSize) {
		return nil, NewStructuredError(fmt.Sprintf("file %s exceeds size limit (%d bytes)", path, maxParserInputSize), ErrFileTooLarge, nil)
	}

	// #nosec G304 -- File path comes from user input (CLI argument or API call), sanitized by filepath.Clean above.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, NewStructuredError(fmt.Sprintf("could not read file %s", path), ErrFileReadFailed, err)
	}

	certs, err := p.parseWithSource(data, CertificateSource{
		Type:     SourceTypeFile,
		Location: path,
	})
	if err != nil {
		return nil, err
	}

	p.logger.Info("successfully parsed certificates", "file", path, "count", len(certs))
	return certs, nil
}

// ParseRemote parses certificates from a remote TLS connection.
func (p *defaultParser) ParseRemote(ctx context.Context, host string, opts RemoteOptions) ([]*Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, NewStructuredError(fmt.Sprintf("connection to %s canceled", host), ErrContextCanceled, ctx.Err())
	default:
	}

	p.logger.Info("connecting to remote host", "host", host)

	hostname, _, err := parseHostPort(host)
	if err != nil {
		return nil, NewStructuredError("invalid host format", ErrInvalidHostFormat, err)
	}

	if isIPAddress(hostname) && opts.SNI == "" {
		return nil, NewStructuredError(fmt.Sprintf("SNI is required for IP address %s", hostname), ErrSNIRequired, nil)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultConnectTimeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Configure TLS.
	//
	// InsecureSkipVerify is intentionally true when VerifyHostname is false
	// (the default for AnalyzeHost). This is required because certree is a
	// certificate analysis tool that must inspect expired, self-signed, and
	// misconfigured certificates. Standard TLS verification would prevent
	// connecting to the very servers users want to diagnose.
	//
	// Trade-off: an active MitM can substitute certificates without a
	// TLS-level error. Mitigation: certree's Validator performs its own
	// hostname and chain verification on the retrieved certificates.
	// The VerifyPeerCertificate callback below logs a debug warning when
	// standard verification would have failed.
	tlsConfig := &tls.Config{
		ServerName: opts.SNI,
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- InsecureSkipVerify required for certificate analysis; see comment above.
		InsecureSkipVerify: !opts.VerifyHostname,
	}

	// When InsecureSkipVerify is true, add a VerifyConnection callback that
	// attempts standard verification and logs a debug warning on failure.
	// This provides audit visibility for MitM scenarios without rejecting
	// the connection. VerifyConnection is called after the TLS handshake
	// completes, including on resumed sessions.
	if !opts.VerifyHostname {
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return nil
			}
			pool := x509.NewCertPool()
			for _, intermediate := range cs.PeerCertificates[1:] {
				pool.AddCert(intermediate)
			}
			verifyOpts := x509.VerifyOptions{
				Intermediates: pool,
				DNSName:       hostname,
			}
			if _, verifyErr := cs.PeerCertificates[0].Verify(verifyOpts); verifyErr != nil {
				p.logger.Debug("TLS verification would have failed (advisory, connection allowed)",
					"host", host, "error", verifyErr)
			}
			return nil // Never reject; this is advisory only.
		}
	}

	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = hostname
	}

	if opts.ClientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*opts.ClientCert}
	}

	dialer := &tls.Dialer{
		NetDialer: p.dialer,
		Config:    tlsConfig,
	}

	conn, err := dialer.DialContext(dialCtx, "tcp", host)
	if err != nil {
		return nil, NewStructuredError(fmt.Sprintf("could not connect to %s", host), ErrConnectionFailed, err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			p.logger.Debug("closing TLS connection", "error", closeErr)
		}
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, NewStructuredError("unexpected connection type from TLS dialer", ErrConnectionFailed, nil)
	}
	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return nil, NewStructuredError(fmt.Sprintf("no certificates received from %s", host), ErrNoCertificatesFound, nil)
	}

	source := CertificateSource{
		Type:     SourceTypeRemote,
		Location: host,
	}

	certs := make([]*Certificate, 0, len(state.PeerCertificates))
	for _, rawCert := range state.PeerCertificates {
		cert := NewCertificate(rawCert, source)
		certs = append(certs, cert)
	}

	p.logger.Info("successfully retrieved certificates", "host", host, "count", len(certs))
	return certs, nil
}

// ParseBytes parses certificates from raw bytes.
func (p *defaultParser) ParseBytes(data []byte) ([]*Certificate, error) {
	if len(data) > maxParserInputSize {
		return nil, NewStructuredError(
			fmt.Sprintf("input exceeds size limit (%d bytes)", maxParserInputSize),
			ErrInputTooLarge, nil,
		)
	}
	return p.parseWithSource(data, CertificateSource{
		Type: SourceTypeBytes,
	})
}

// ParseURL fetches and parses certificates from an HTTP(S) URL.
func (p *defaultParser) ParseURL(ctx context.Context, rawURL string) ([]*Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, NewStructuredError(fmt.Sprintf("fetching URL %s canceled", rawURL), ErrContextCanceled, ctx.Err())
	default:
	}

	if p.opts.httpUpgrade {
		rawURL = upgradeHTTPToHTTPS(rawURL)
	}

	p.logger.Info("fetching certificates from URL", "url", rawURL)

	if p.allowPrivateNetworks {
		if err := validateURLSchemeAndCredentials(rawURL); err != nil {
			return nil, NewStructuredError(
				fmt.Sprintf("URL %s blocked by security policy", rawURL),
				ErrURLFetchFailed, err,
			)
		}
	} else {
		if err := validateURL(rawURL); err != nil {
			return nil, NewStructuredError(
				fmt.Sprintf("URL %s blocked by security policy", rawURL),
				ErrURLFetchFailed, err,
			)
		}
	}

	client := newHTTPClient(p.opts.urlFetchTimeout, p.allowPrivateNetworks)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, NewStructuredError(
			fmt.Sprintf("could not fetch certificates from %s", rawURL),
			ErrURLFetchFailed, fmt.Errorf("creating request: %w", err),
		)
	}
	req.Header.Set("Accept", "application/x-pem-file, application/pkix-cert, application/x-x509-ca-cert, application/octet-stream")

	resp, err := client.Do(req) // #nosec G107 -- URL validated by validateURL; transport uses safeTransport with DialContext SSRF guard
	if err != nil {
		if errors.Is(err, ErrPrivateAddress) {
			return nil, NewStructuredError(
				fmt.Sprintf("URL %s blocked by security policy", rawURL),
				ErrURLFetchFailed, fmt.Errorf("HTTP request failed: %w", err),
			)
		}
		return nil, NewStructuredError(
			fmt.Sprintf("could not fetch certificates from %s", rawURL),
			ErrURLFetchFailed, fmt.Errorf("HTTP request failed: %w", err),
		)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			p.logger.Debug("failed to close URL response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, NewStructuredError(
			fmt.Sprintf("could not fetch certificates from %s (HTTP %d)", rawURL, resp.StatusCode),
			ErrURLFetchFailed, fmt.Errorf("HTTP %d: %s: %w", resp.StatusCode, resp.Status, ErrHTTPError),
		)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxParserInputSize)+1))
	if err != nil {
		return nil, NewStructuredError(
			fmt.Sprintf("could not read response from %s", rawURL),
			ErrURLFetchFailed, fmt.Errorf("reading response body: %w", err),
		)
	}
	if len(data) > maxParserInputSize {
		return nil, NewStructuredError(
			fmt.Sprintf("response from %s exceeds size limit (%d bytes)", rawURL, maxParserInputSize),
			ErrInputTooLarge, nil,
		)
	}

	certs, err := p.parseWithSource(data, CertificateSource{
		Type:     SourceTypeURL,
		Location: rawURL,
	})
	if err != nil {
		return nil, err
	}

	p.logger.Info("successfully parsed certificates from URL", "url", rawURL, "count", len(certs))
	return certs, nil
}

// parseWithSource parses certificates with auto-format detection.
func (p *defaultParser) parseWithSource(data []byte, source CertificateSource) ([]*Certificate, error) {
	if len(data) == 0 {
		return nil, NewStructuredError("no certificate data provided", ErrEmptyInput, nil)
	}

	// Collect errors from each format attempt so the final error message
	// tells the caller why each format was rejected.
	var parseErrors []error

	certs, err := p.parsePEM(data, source)
	if err == nil && len(certs) > 0 {
		return certs, nil
	}
	if err != nil {
		if errors.Is(err, ErrCertificateLimitExceeded) {
			return nil, NewStructuredError(
				fmt.Sprintf("certificate limit exceeded: file contains more than %d certificates (increase with --max-certificates)", p.opts.maxCertificates),
				ErrCertificateLimitExceeded, err,
			)
		}
		parseErrors = append(parseErrors, fmt.Errorf("PEM: %w", err))
	}

	certs, err = p.parseDER(data, source)
	if err == nil && len(certs) > 0 {
		return certs, nil
	}
	if err != nil {
		parseErrors = append(parseErrors, fmt.Errorf("DER: %w", err))
	}

	if !p.opts.autoDetectFormat {
		return nil, NewStructuredError(formatDetectionMessage(data),
			ErrUnknownFormat, errors.Join(parseErrors...))
	}

	certs, err = p.parsePKCS7(data, source)
	if err == nil && len(certs) > 0 {
		return certs, nil
	}
	if err != nil {
		parseErrors = append(parseErrors, fmt.Errorf("PKCS#7: %w", err))
	}

	certs, err = p.parsePKCS12(data, source, "")
	if err == nil && len(certs) > 0 {
		return certs, nil
	}
	if err != nil {
		parseErrors = append(parseErrors, fmt.Errorf("PKCS#12: %w", err))
	}

	return nil, NewStructuredError(formatDetectionMessage(data),
		ErrUnknownFormat, errors.Join(parseErrors...))
}

// formatDetectionMessage returns a user-friendly message when certificate
// format detection fails. It inspects the data to give a more specific hint
// about why parsing failed (e.g., binary data that is not a certificate,
// text data that is not PEM).
func formatDetectionMessage(data []byte) string {
	if isBinaryData(data) {
		return "file contains binary data but is not a valid certificate (expected PEM, DER, PKCS#7, or PKCS#12)"
	}
	return "file does not contain certificate data (expected PEM-encoded or binary certificate format)"
}

// isBinaryData reports whether data contains non-text bytes, suggesting a
// binary file. Checks the first 512 bytes for null bytes or a high ratio
// of non-printable characters.
func isBinaryData(data []byte) bool {
	n := min(len(data), 512)
	nonPrintable := 0
	for _, b := range data[:n] {
		if b == 0 {
			return true
		}
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}
	return n > 0 && nonPrintable > n/4
}

// parsePEM parses PEM-encoded certificates using the shared parsePEMData implementation.
func (p *defaultParser) parsePEM(data []byte, source CertificateSource) ([]*Certificate, error) {
	return parsePEMData(data, source, pemParseConfig{
		maxCerts:    p.opts.maxCertificates,
		skipInvalid: p.opts.skipInvalid,
		logger:      p.logger,
	})
}

// parseDER parses a DER-encoded certificate.
func (p *defaultParser) parseDER(data []byte, source CertificateSource) ([]*Certificate, error) {
	rawCert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parsing DER certificate: %w", err)
	}

	cert := NewCertificate(rawCert, source)
	return []*Certificate{cert}, nil
}

// parsePKCS7 parses a PKCS#7 bundle.
func (p *defaultParser) parsePKCS7(data []byte, source CertificateSource) ([]*Certificate, error) {
	var pkcs7 struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}

	rest, err := asn1.Unmarshal(data, &pkcs7)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#7 structure: %w", err)
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("extra data after PKCS#7 structure: %w", ErrParseFailed)
	}

	// SignedData OID is 1.2.840.113549.1.7.2
	signedDataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	if !pkcs7.ContentType.Equal(signedDataOID) {
		return nil, fmt.Errorf("not a PKCS#7 SignedData structure: %w", ErrParseFailed)
	}

	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		CRLs             asn1.RawValue `asn1:"optional,tag:1"`
		SignerInfos      asn1.RawValue
	}

	rest, err = asn1.Unmarshal(pkcs7.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#7 SignedData: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("parsing PKCS#7 SignedData: %d trailing bytes after SignedData", len(rest))
	}

	if len(signedData.Certificates.Bytes) == 0 {
		return nil, fmt.Errorf("no certificates found in PKCS#7 bundle: %w", ErrNoCertificatesFound)
	}

	// Parse the certificate SET content by iterating individual TLVs.
	//
	// RFC 5652 section 5.1 / RFC 2315 section 9.1: certificates [0] IMPLICIT SET OF CertificateChoices.
	// With IMPLICIT tagging, the SET tag (0x31) is replaced by context [0] (0xa0).
	// The content inside [0] is therefore the raw concatenation of certificate DER
	// bytes -- there is no inner SEQUENCE or SET wrapper. Using asn1.Unmarshal with
	// a slice target would misinterpret the first certificate's SEQUENCE tag (0x30)
	// as an outer container, returning that certificate's internal fields rather
	// than the certificate itself. We iterate TLV-by-TLV instead.
	var certDERs []asn1.RawValue
	remaining := signedData.Certificates.Bytes
	for len(remaining) > 0 {
		// Enforce certificate limit early during TLV collection to avoid
		// accumulating unbounded raw values before parsing.
		if p.opts.maxCertificates > 0 && len(certDERs) >= p.opts.maxCertificates {
			return nil, certLimitExceededError(p.opts.maxCertificates)
		}
		var entry asn1.RawValue
		rest, parseErr := asn1.Unmarshal(remaining, &entry)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing PKCS#7 certificate entry: %w", parseErr)
		}
		certDERs = append(certDERs, entry)
		remaining = rest
	}

	certs := make([]*Certificate, 0, len(certDERs))
	for _, certDER := range certDERs {
		// Enforce certificate limit before parsing to prevent resource exhaustion.
		if p.opts.maxCertificates > 0 && len(certs) >= p.opts.maxCertificates {
			return nil, certLimitExceededError(p.opts.maxCertificates)
		}

		rawCert, err := x509.ParseCertificate(certDER.FullBytes)
		if err != nil {
			if p.opts.skipInvalid {
				p.logger.Debug("skipping invalid certificate in PKCS#7", "error", err)
				continue
			}
			return nil, fmt.Errorf("parsing certificate from PKCS#7: %w", err)
		}

		cert := NewCertificate(rawCert, source)
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in PKCS#7 bundle: %w", ErrNoCertificatesFound)
	}

	return certs, nil
}

// parsePKCS12 parses a PKCS#12 bundle (extracts only certificates, ignores private keys).
func (p *defaultParser) parsePKCS12(data []byte, source CertificateSource, password string) ([]*Certificate, error) {
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, NewStructuredError(
				"PKCS#12 file is password-protected",
				ErrPasswordRequired,
				err,
			)
		}
		return nil, fmt.Errorf("parsing PKCS#12: %w", err)
	}

	var certs []*Certificate
	for _, block := range blocks {
		if block.Type != "CERTIFICATE" {
			if isPrivateKeyBlock(block.Type) {
				p.logger.Debug("private key found and ignored for security")
			}
			continue
		}

		// Enforce certificate limit before parsing to prevent resource exhaustion.
		if p.opts.maxCertificates > 0 && len(certs) >= p.opts.maxCertificates {
			return nil, certLimitExceededError(p.opts.maxCertificates)
		}

		rawCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			if p.opts.skipInvalid {
				p.logger.Debug("skipping invalid certificate in PKCS#12", "error", err)
				continue
			}
			return nil, fmt.Errorf("parsing certificate from PKCS#12: %w", err)
		}

		cert := NewCertificate(rawCert, source)
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PKCS#12 bundle: %w", ErrNoCertificatesFound)
	}

	return certs, nil
}

// parseHostPort splits a host:port string into hostname and port.
func parseHostPort(hostport string) (host, port string, err error) {
	if strings.HasPrefix(hostport, "[") {
		// IPv6 with port: [::1]:443
		host, port, err = net.SplitHostPort(hostport)
		if err != nil {
			return "", "", fmt.Errorf("parsing bracketed host:port %q: %w", hostport, err)
		}
		return host, port, nil
	}

	host, port, err = net.SplitHostPort(hostport)
	if err != nil {
		if strings.Contains(hostport, ":") {
			return "", "", fmt.Errorf("invalid host:port format (IPv6 addresses must be in brackets): %w", ErrInvalidHostFormat)
		}
		return hostport, "", nil
	}

	return host, port, nil
}

// certLimitExceededError returns a standardized error for certificate limit violations.
func certLimitExceededError(limit int) error {
	return fmt.Errorf("certificate limit exceeded (%d certificates): %w", limit, ErrCertificateLimitExceeded)
}

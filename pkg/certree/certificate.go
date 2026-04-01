// Core Certificate type, constructor, getter methods, and related types.

package certree

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"
)

const hoursPerDay = 24

// OIDs for certificate extensions detected at parse time.
var (
	// oidTLSFeature is the OID for the TLS Feature extension (RFC 7633).
	// It encodes a list of TLS extension IDs that the server MUST support.
	// A value of 5 (status_request) indicates OCSP Must-Staple.
	oidTLSFeature = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

	// oidEmbeddedSCTList is the OID for the embedded Signed Certificate
	// Timestamps extension (RFC 9162 / RFC 6962).
	oidEmbeddedSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// SourceType records where a certificate was obtained during parsing. It
// includes provenance values like [SourceTypeAIA] and [SourceTypeBytes] that
// have no [SourceKind] equivalent. Compare with [SourceKind], which classifies
// the caller-provided input string before analysis begins.
type SourceType int

const (
	// SourceTypeFile indicates the certificate came from a file.
	SourceTypeFile SourceType = iota
	// SourceTypeRemote indicates the certificate came from a remote TLS connection.
	SourceTypeRemote
	// SourceTypeStdin indicates the certificate came from standard input.
	SourceTypeStdin
	// SourceTypeAIA indicates the certificate was fetched via AIA (Authority Information Access).
	SourceTypeAIA
	// SourceTypeBytes indicates the certificate came from raw byte data via ParseBytes.
	SourceTypeBytes
	// SourceTypeURL indicates the certificate was fetched from an HTTP(S) URL.
	SourceTypeURL
)

// String returns the string representation of SourceType.
func (st SourceType) String() string {
	switch st {
	case SourceTypeFile:
		return "file"
	case SourceTypeRemote:
		return "remote"
	case SourceTypeStdin:
		return "stdin"
	case SourceTypeAIA:
		return "aia"
	case SourceTypeBytes:
		return "bytes"
	case SourceTypeURL:
		return "url"
	default:
		return fmt.Sprintf("SourceType(%d)", int(st))
	}
}

// MarshalJSON implements custom JSON serialization for SourceType.
func (st SourceType) MarshalJSON() ([]byte, error) {
	return json.Marshal(st.String())
}

// UnmarshalJSON implements json.Unmarshaler for SourceType.
func (st *SourceType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("unmarshaling SourceType: %w", err)
	}
	switch s {
	case "file":
		*st = SourceTypeFile
	case "remote":
		*st = SourceTypeRemote
	case "stdin":
		*st = SourceTypeStdin
	case "aia":
		*st = SourceTypeAIA
	case "bytes":
		*st = SourceTypeBytes
	case "url":
		*st = SourceTypeURL
	default:
		return fmt.Errorf("unknown SourceType value %q: %w", s, ErrInvalidInput)
	}
	return nil
}

// CertificateSource tracks where a certificate came from.
type CertificateSource struct {
	Type SourceType `json:"type"`

	// Location is the file path, hostname:port, AIA URL, or empty for stdin.
	Location string `json:"location,omitempty"`
}

// CertificateMetadata contains computed analysis state about a certificate.
// All fields are computed in [NewCertificate] and cached. Identity fields
// (fingerprints, serial) are on [Certificate] directly to avoid JSON duplication.
type CertificateMetadata struct {
	IsSelfSigned  bool `json:"is_self_signed"`
	IsExpired     bool `json:"is_expired"`
	IsNotYetValid bool `json:"is_not_yet_valid"`

	// DaysUntilExpiry is positive for days remaining, negative for days past expiry.
	// Use IsExpired for the authoritative check.
	DaysUntilExpiry int `json:"days_until_expiry"`

	// TrustedLocations lists trust stores where this certificate is trusted.
	// Always an empty slice (never nil) so JSON outputs [] not null.
	TrustedLocations []string `json:"trusted_locations"`

	// HasMustStaple is true when the TLS Must-Staple extension is present (RFC 7633).
	HasMustStaple bool `json:"has_must_staple"`

	// SCTCount is the number of embedded Signed Certificate Timestamps (RFC 9162).
	SCTCount int `json:"sct_count"`
}

// CertificateOption is a functional option for configuring certificate construction.
type CertificateOption func(*certificateOptions)

// certificateOptions holds optional configuration for NewCertificate.
type certificateOptions struct {
	now time.Time
}

// WithCertificateTime overrides the reference time for computing expiry metadata.
// Default: time.Now() at construction time.
func WithCertificateTime(t time.Time) CertificateOption {
	return func(o *certificateOptions) {
		o.now = t
	}
}

// Certificate wraps an [x509.Certificate] with precomputed metadata, DER/PEM
// encodings, and fingerprints. All fields are unexported; create via
// [NewCertificate] and access through getter methods.
type Certificate struct {
	raw    *x509.Certificate
	der    []byte
	source CertificateSource

	metadata CertificateMetadata

	fingerprintSHA256 string
	serialNumber      string
	spkiSHA256        string // SHA-256 of RawSubjectPublicKeyInfo for trust store lookups.

	pem     string
	pemOnce sync.Once
}

// NewCertificate creates a [Certificate] from an [x509.Certificate] with all
// metadata computed upfront. PEM encoding is computed lazily on first call to
// [Certificate.PEM]. Panics if raw is nil.
func NewCertificate(raw *x509.Certificate, source CertificateSource, opts ...CertificateOption) *Certificate {
	if raw == nil {
		panic("certree: NewCertificate called with nil x509.Certificate")
	}

	o := certificateOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	now := o.now
	if now.IsZero() {
		now = time.Now()
	}

	cert := &Certificate{
		raw:    raw,
		der:    raw.Raw,
		source: source,
	}

	sum256 := sha256.Sum256(cert.der)
	cert.fingerprintSHA256 = HexEncodeUpper(sum256[:])

	spkiSum := sha256.Sum256(raw.RawSubjectPublicKeyInfo)
	cert.spkiSHA256 = HexEncodeUpper(spkiSum[:])

	if raw.SerialNumber != nil && raw.SerialNumber.Sign() != 0 {
		cert.serialNumber = HexEncodeUpper(raw.SerialNumber.Bytes())
	} else {
		cert.serialNumber = "00"
	}
	cert.metadata.IsSelfSigned = isSelfSigned(raw)
	cert.metadata.IsExpired = now.After(raw.NotAfter)
	cert.metadata.IsNotYetValid = now.Before(raw.NotBefore)

	// DaysUntilExpiry: positive values indicate days remaining, 0 means the
	// certificate expires or expired within the current 24-hour window, and
	// negative values indicate whole days past expiry (e.g., -3 means expired
	// 3+ days ago). Uses integer truncation toward zero. Use IsExpired for the
	// authoritative expiry check.
	cert.metadata.DaysUntilExpiry = int(raw.NotAfter.Sub(now).Hours() / hoursPerDay)

	cert.metadata.TrustedLocations = []string{}

	for i := range raw.Extensions {
		ext := &raw.Extensions[i]
		if ext.Id.Equal(oidTLSFeature) {
			cert.metadata.HasMustStaple = detectMustStaple(ext.Value)
		} else if ext.Id.Equal(oidEmbeddedSCTList) {
			cert.metadata.SCTCount = countSCTs(ext.Value)
		}
	}

	return cert
}

// Raw returns the underlying x509.Certificate for read-only access.
//
// WARNING: The returned certificate must not be modified. Mutating any field
// (e.g., NotAfter, Subject, RawIssuer) will corrupt the Certificate's cached
// state (IsExpired, IsSelfSigned, FingerprintSHA256, etc.) and may cause data
// races if the Certificate is shared across goroutines. Use DER() if you need
// a safe copy of the certificate bytes.
func (c *Certificate) Raw() *x509.Certificate { return c.raw }

// PEM returns the PEM-encoded certificate string, computed lazily and cached.
func (c *Certificate) PEM() string {
	c.pemOnce.Do(func() {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.der,
		}
		c.pem = string(pem.EncodeToMemory(block))
	})
	return c.pem
}

// DER returns a copy of the DER-encoded certificate bytes.
// A copy is returned to prevent external modification of the certificate data.
func (c *Certificate) DER() []byte { return append([]byte(nil), c.der...) }

// Source returns the certificate source information.
func (c *Certificate) Source() CertificateSource { return c.source }

// Metadata returns the computed certificate metadata.
func (c *Certificate) Metadata() CertificateMetadata { return c.metadata }

// WithTrustedLocations returns a new Certificate with updated trust store locations.
// The original certificate is not modified. The locations slice is deep copied
// to prevent external modification.
func (c *Certificate) WithTrustedLocations(locations []string) *Certificate {
	meta := c.metadata
	meta.TrustedLocations = append([]string(nil), locations...)
	// Copy all precomputed fields. Identity and SPKI fields live outside
	// metadata because they are intrinsic certificate properties, not
	// analysis state. PEM is omitted: the copy shares der (immutable) and
	// computes PEM lazily via its own pemOnce if needed, avoiding both a
	// data race on c.pem and a redundant pem.EncodeToMemory call.
	newCert := &Certificate{
		raw:               c.raw,
		der:               c.der,
		source:            c.source,
		metadata:          meta,
		fingerprintSHA256: c.fingerprintSHA256,
		serialNumber:      c.serialNumber,
		spkiSHA256:        c.spkiSHA256,
	}
	return newCert
}

// FingerprintSHA256 returns the hex-encoded SHA-256 fingerprint (uppercase, no separators).
// Use ColonHex to format for display.
func (c *Certificate) FingerprintSHA256() string {
	return c.fingerprintSHA256
}

// SerialNumber returns the serial number as uppercase hex (no separators).
// Use ColonHex to format for display.
func (c *Certificate) SerialNumber() string {
	return c.serialNumber
}

// CommonName returns the Common Name from the certificate's Subject.
func (c *Certificate) CommonName() string {
	return c.raw.Subject.CommonName
}

// IsSelfSigned returns true if the certificate is self-signed.
// A certificate is self-signed if its subject matches its issuer AND it uses
// the same key. When AuthorityKeyId and SubjectKeyId are both present, they
// must match. This correctly identifies cross-signed certificates (same
// subject/issuer names but different signing key) as NOT self-signed.
func (c *Certificate) IsSelfSigned() bool {
	return c.metadata.IsSelfSigned
}

// MarshalJSON implements custom JSON serialization for Certificate.
// It serializes certificate fields from the raw x509.Certificate along with
// certree-specific metadata, excluding the raw certificate object itself.
func (c *Certificate) MarshalJSON() ([]byte, error) {
	if c.raw == nil {
		return []byte("null"), nil
	}

	return json.Marshal(certificateJSON{
		Subject:      c.raw.Subject.String(),
		Issuer:       c.raw.Issuer.String(),
		SerialNumber: ColonHex(c.SerialNumber()),
		Fingerprint:  ColonHex(c.FingerprintSHA256()),
		NotBefore:    c.raw.NotBefore,
		NotAfter:     c.raw.NotAfter,
		DNSNames:     dnsNamesToStrings(c.raw.DNSNames),
		IPAddresses:  ipAddressesToStrings(c.raw.IPAddresses),
		IsCA:         c.raw.IsCA,
		Source:       c.source,
		Metadata:     c.metadata,
	})
}

// certificateJSON is a named struct so encoding/json caches reflection metadata.
type certificateJSON struct {
	Subject      string              `json:"subject"`
	Issuer       string              `json:"issuer"`
	SerialNumber string              `json:"serial_number"`
	Fingerprint  string              `json:"fingerprint_sha256"`
	NotBefore    time.Time           `json:"not_before"`
	NotAfter     time.Time           `json:"not_after"`
	DNSNames     []string            `json:"dns_names"`
	IPAddresses  []string            `json:"ip_addresses"`
	IsCA         bool                `json:"is_ca"`
	Source       CertificateSource   `json:"source"`
	Metadata     CertificateMetadata `json:"metadata"`
}

// isSelfSigned checks subject/issuer + AKI/SKI match (structural, not cryptographic).
// Cross-signed certs with the same subject/issuer but different keys return false.
func isSelfSigned(raw *x509.Certificate) bool {
	if !bytes.Equal(raw.RawSubject, raw.RawIssuer) {
		return false
	}
	// If both AKI and SKI are present, they must match for a true self-signed cert.
	// Cross-signed certs have the same subject/issuer names but different AKI/SKI.
	if len(raw.AuthorityKeyId) > 0 && len(raw.SubjectKeyId) > 0 {
		return bytes.Equal(raw.AuthorityKeyId, raw.SubjectKeyId)
	}
	// If AKI is present but SKI is absent, the AKI references a key identity we
	// cannot verify locally. Conservatively treat as not self-signed to avoid
	// misclassifying cross-signed certificates.
	if len(raw.AuthorityKeyId) > 0 && len(raw.SubjectKeyId) == 0 {
		return false
	}
	// Without AKI (regardless of SKI), fall back to name-only check (legacy certs).
	return true
}

// dnsNamesToStrings returns a non-nil copy so JSON outputs [] not null.
func dnsNamesToStrings(names []string) []string {
	if len(names) == 0 {
		return []string{}
	}
	return slices.Clone(names)
}

// ipAddressesToStrings converts IPs to strings; returns non-nil for JSON [] convention.
func ipAddressesToStrings(ips []net.IP) []string {
	if len(ips) == 0 {
		return []string{}
	}
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

// detectMustStaple parses the DER-encoded TLS Feature extension value (RFC 7633)
// and returns true if it contains status_request (feature ID 5), which indicates
// OCSP Must-Staple. The extension encodes a SEQUENCE OF INTEGER.
func detectMustStaple(der []byte) bool {
	var features []int
	if _, err := asn1.Unmarshal(der, &features); err != nil {
		return false
	}
	return slices.Contains(features, 5) // 5 = status_request (RFC 6066 section 8)
}

// countSCTs parses the DER-encoded embedded SCT list extension value (RFC 9162)
// and returns the number of SCTs it contains. The extension value is an OCTET
// STRING wrapping a list encoded as: uint16 total-length, then repeated
// (uint16 sct-length, sct-bytes). Returns 0 if parsing fails.
func countSCTs(der []byte) int {
	var sctList []byte
	if _, err := asn1.Unmarshal(der, &sctList); err != nil {
		return 0
	}
	if len(sctList) < 2 {
		return 0
	}
	totalLen := int(sctList[0])<<8 | int(sctList[1])
	if totalLen != len(sctList)-2 {
		return 0
	}
	data := sctList[2:]
	count := 0
	for len(data) >= 2 {
		sctLen := int(data[0])<<8 | int(data[1])
		data = data[2:]
		if len(data) < sctLen {
			break
		}
		data = data[sctLen:]
		count++
	}
	return count
}

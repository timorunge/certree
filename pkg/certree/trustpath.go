// TrustPath type, path status, and chain completeness logic.

package certree

import (
	"encoding/json"
	"fmt"
	"strings"
)

// pathKeyFallbackBytes is the number of DER bytes used in the fallback path
// key when a certificate lacks a precomputed fingerprint.
const pathKeyFallbackBytes = 32

// PathStatus represents the trust and completeness status of a certificate chain.
// It encodes three mutually exclusive states that describe a trust path's
// relationship to the system trust store.
type PathStatus int

const (
	// PathTrusted means the chain reaches a root certificate that is in the
	// system trust store. The chain is both structurally complete and trusted.
	PathTrusted PathStatus = iota

	// PathUntrusted means the chain reaches a self-signed root certificate
	// that is NOT in the system trust store. The chain is structurally
	// complete but the root is not a known trust anchor.
	PathUntrusted

	// PathIncomplete means the chain could not be fully built. This occurs
	// when an issuer certificate is missing, a circular reference is detected,
	// or the maximum chain depth is exceeded.
	PathIncomplete
)

// String returns a human-readable representation of the path status.
func (ps PathStatus) String() string {
	switch ps {
	case PathTrusted:
		return "trusted"
	case PathUntrusted:
		return "untrusted"
	case PathIncomplete:
		return "incomplete"
	default:
		return fmt.Sprintf("PathStatus(%d)", int(ps))
	}
}

// IsTrusted reports whether the path status indicates a trusted chain.
func (ps PathStatus) IsTrusted() bool {
	return ps == PathTrusted
}

// MarshalJSON implements json.Marshaler for PathStatus.
// It serializes the status as a string (e.g., "trusted", "untrusted", "incomplete").
func (ps PathStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(ps.String())
}

// UnmarshalJSON implements json.Unmarshaler for PathStatus.
func (ps *PathStatus) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("unmarshaling PathStatus: %w", err)
	}
	switch s {
	case "trusted":
		*ps = PathTrusted
	case "untrusted":
		*ps = PathUntrusted
	case "incomplete":
		*ps = PathIncomplete
	default:
		return fmt.Errorf("unknown PathStatus value %q: %w", s, ErrInvalidInput)
	}
	return nil
}

// TrustPath represents one possible chain from end-entity to root.
type TrustPath struct {
	Certificates []*Certificate      `json:"certificates"`
	Status       PathStatus          `json:"status"`
	Errors       []ValidationError   `json:"errors"`
	Warnings     []ValidationWarning `json:"warnings"`

	// SimulationMetadata holds per-certificate simulation state, keyed by
	// SHA-256 fingerprint (uppercase hex, no separators). In JSON output,
	// keys are formatted with colon separators (e.g., "AA:BB:CC:...") via
	// MarshalJSON. Nil for non-simulated analyses; omitted from JSON when empty.
	SimulationMetadata map[string]CertSimulationState `json:"simulation_metadata,omitempty"`
}

// NewTrustPath creates a TrustPath with the given certificates and status.
// Errors and Warnings are initialized to empty slices so JSON serialization
// produces [] instead of null. Callers may assign non-nil slices to override.
func NewTrustPath(certs []*Certificate, status PathStatus) *TrustPath {
	return &TrustPath{
		Certificates: certs,
		Status:       status,
		Errors:       []ValidationError{},
		Warnings:     []ValidationWarning{},
	}
}

// IsExcluded reports whether the given certificate was directly excluded during simulation.
func (tp *TrustPath) IsExcluded(cert *Certificate) bool {
	if cert == nil {
		return false
	}
	if tp.SimulationMetadata == nil {
		return false
	}
	return tp.SimulationMetadata[cert.FingerprintSHA256()].IsExcluded
}

// IsGhosted reports whether the certificate became unreachable due to an exclusion below it.
func (tp *TrustPath) IsGhosted(cert *Certificate) bool {
	if cert == nil {
		return false
	}
	if tp.SimulationMetadata == nil {
		return false
	}
	return tp.SimulationMetadata[cert.FingerprintSHA256()].IsGhosted
}

// IsInjected reports whether the certificate was added via InjectCertificates.
func (tp *TrustPath) IsInjected(cert *Certificate) bool {
	if cert == nil {
		return false
	}
	if tp.SimulationMetadata == nil {
		return false
	}
	return tp.SimulationMetadata[cert.FingerprintSHA256()].IsInjected
}

// Root returns the root certificate of the trust path (the last certificate
// in the chain), or nil if the path is empty.
//
// For trusted paths, this is the trust anchor (typically a self-signed root,
// but may be a cross-signed certificate present in the trust store).
// For untrusted paths, this is the highest self-signed certificate found.
// For incomplete paths, this is the last certificate before the chain was
// cut short.
func (tp *TrustPath) Root() *Certificate {
	if len(tp.Certificates) == 0 {
		return nil
	}
	return tp.Certificates[len(tp.Certificates)-1]
}

// PathKey returns a string key that uniquely identifies a trust path by the
// ordered SHA-256 fingerprints of its certificates, separated by '|'.
func (tp *TrustPath) PathKey() string {
	var b strings.Builder
	// Each fingerprint is 64 hex chars + 1 separator.
	b.Grow(len(tp.Certificates) * 65)
	for i, cert := range tp.Certificates {
		if i > 0 {
			b.WriteByte('|')
		}
		fp := cert.FingerprintSHA256()
		if fp == "" {
			// Fallback for certs created without NewCertificate (e.g., in tests).
			fp = fmt.Sprintf("raw:%x", cert.Raw().Raw[:min(pathKeyFallbackBytes, len(cert.Raw().Raw))])
		}
		b.WriteString(fp)
	}
	return b.String()
}

// CertSimulationState holds per-certificate simulation flags for a trust path.
type CertSimulationState struct {
	IsExcluded bool `json:"is_excluded,omitempty"`
	IsGhosted  bool `json:"is_ghosted,omitempty"`
	IsInjected bool `json:"is_injected,omitempty"`
}

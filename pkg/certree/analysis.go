// Analysis metadata, result types, and helper methods for analysis output.

package certree

import (
	"encoding/json"
	"maps"
	"slices"
	"time"
)

// AnalysisMetadata contains analysis-level context and summary statistics.
type AnalysisMetadata struct {
	Source       string    `json:"source"`
	Timestamp    time.Time `json:"timestamp"`
	IsSimulated  bool      `json:"is_simulated"`
	TotalCerts   int       `json:"total_certs"`
	TotalPaths   int       `json:"total_paths"`
	TrustedPaths int       `json:"trusted_paths"`
}

// Analysis contains all discovered certificates, trust paths, and metadata.
// Treat as immutable after construction via [NewAnalysis].
type Analysis struct {
	Certificates []*Certificate   `json:"certificates"`
	TrustPaths   []*TrustPath     `json:"trust_paths"`
	Metadata     AnalysisMetadata `json:"metadata"`
}

// AnalysisOption configures optional metadata on an [Analysis] during construction.
type AnalysisOption func(*Analysis)

// WithSimulated marks the analysis as a simulation result.
func WithSimulated(simulated bool) AnalysisOption {
	return func(a *Analysis) { a.Metadata.IsSimulated = simulated }
}

// WithAnalysisSource overrides the source string in the analysis metadata.
func WithAnalysisSource(source string) AnalysisOption {
	return func(a *Analysis) { a.Metadata.Source = source }
}

// NewAnalysis creates an Analysis with computed metadata. It counts trusted
// paths and sets the timestamp automatically. Use [WithSimulated] or
// [WithAnalysisSource] to set optional metadata fields.
// Nil slice arguments are normalized to empty slices so JSON serialization
// produces [] instead of null. TrustPath slices (Errors, Warnings) are
// expected to be non-nil; use [NewTrustPath] to guarantee this.
func NewAnalysis(certs []*Certificate, paths []*TrustPath, source string, opts ...AnalysisOption) *Analysis {
	if certs == nil {
		certs = []*Certificate{}
	}
	if paths == nil {
		paths = []*TrustPath{}
	}

	trustedCount := 0
	for _, p := range paths {
		if p.Status.IsTrusted() {
			trustedCount++
		}
	}
	a := &Analysis{
		Certificates: certs,
		TrustPaths:   paths,
		Metadata: AnalysisMetadata{
			Source:       source,
			Timestamp:    time.Now(),
			TotalCerts:   len(certs),
			TotalPaths:   len(paths),
			TrustedPaths: trustedCount,
		},
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Reversed returns a copy of the Analysis with the top-level Certificates
// pool and each TrustPath's Certificates slice reversed. SimulationMetadata
// maps are deep-copied so mutations to either copy are independent.
// Certificate pointers and scalar TrustPath metadata are shared.
func (a *Analysis) Reversed() *Analysis {
	reversed := *a

	n := len(a.Certificates)
	reversed.Certificates = make([]*Certificate, n)
	for i := range a.Certificates {
		reversed.Certificates[i] = a.Certificates[n-1-i]
	}

	reversed.TrustPaths = make([]*TrustPath, len(a.TrustPaths))
	for i, tp := range a.TrustPaths {
		rp := *tp
		pn := len(tp.Certificates)
		rp.Certificates = make([]*Certificate, pn)
		for j := range tp.Certificates {
			rp.Certificates[j] = tp.Certificates[pn-1-j]
		}
		rp.Errors = slices.Clone(tp.Errors)
		rp.Warnings = slices.Clone(tp.Warnings)
		if tp.SimulationMetadata != nil {
			rp.SimulationMetadata = make(map[string]CertSimulationState, len(tp.SimulationMetadata))
			maps.Copy(rp.SimulationMetadata, tp.SimulationMetadata)
		}
		reversed.TrustPaths[i] = &rp
	}
	return &reversed
}

// HasErrors returns true if any trust path has validation errors.
func (a *Analysis) HasErrors() bool {
	for _, path := range a.TrustPaths {
		if len(path.Errors) > 0 {
			return true
		}
	}
	return false
}

// MarshalJSON implements json.Marshaler for Analysis. It produces a compact
// reference-based format where certificates are defined once in a
// fingerprint-keyed map, and trust paths reference them by fingerprint string.
// This eliminates duplication when the same certificate appears in multiple
// trust paths.
func (a *Analysis) MarshalJSON() ([]byte, error) {
	certMap := make(map[string]*Certificate, len(a.Certificates))
	for _, c := range a.Certificates {
		certMap[ColonHex(c.FingerprintSHA256())] = c
	}
	// Trust paths may contain certificates not in the top-level pool
	// (e.g., trust store roots added during chain building). Errors and
	// warnings may also reference such certificates. Include them all so
	// every fingerprint reference in the output resolves.
	addCert := func(c *Certificate) {
		if c == nil {
			return
		}
		fp := ColonHex(c.FingerprintSHA256())
		existing, ok := certMap[fp]
		if !ok {
			certMap[fp] = c
			return
		}
		// Prefer the version with trust store metadata. The chain builder
		// calls WithTrustedLocations on certs it finds in the trust store,
		// producing a copy with richer metadata than the original pool entry.
		if len(existing.Metadata().TrustedLocations) == 0 && len(c.Metadata().TrustedLocations) > 0 {
			certMap[fp] = c
		}
	}
	for _, tp := range a.TrustPaths {
		for _, c := range tp.Certificates {
			addCert(c)
		}
		for _, e := range tp.Errors {
			addCert(e.Certificate)
		}
		for _, w := range tp.Warnings {
			addCert(w.Certificate)
		}
	}

	paths := make([]trustPathJSON, len(a.TrustPaths))
	for i, tp := range a.TrustPaths {
		fps := make([]string, len(tp.Certificates))
		for j, c := range tp.Certificates {
			fps[j] = ColonHex(c.FingerprintSHA256())
		}
		errs := make([]validationErrorJSON, len(tp.Errors))
		for j, e := range tp.Errors {
			errs[j] = validationErrorJSON{
				Certificate: certFingerprint(e.Certificate),
				Type:        e.Type,
				Message:     e.Message,
				Details:     e.Details,
			}
		}
		warns := make([]validationWarningJSON, len(tp.Warnings))
		for j, w := range tp.Warnings {
			warns[j] = validationWarningJSON{
				Certificate: certFingerprint(w.Certificate),
				Type:        w.Type,
				Message:     w.Message,
			}
		}
		var simMeta map[string]CertSimulationState
		if tp.SimulationMetadata != nil {
			simMeta = make(map[string]CertSimulationState, len(tp.SimulationMetadata))
			for k, v := range tp.SimulationMetadata {
				simMeta[ColonHex(k)] = v
			}
		}
		paths[i] = trustPathJSON{
			Certificates:       fps,
			Status:             tp.Status,
			Errors:             errs,
			Warnings:           warns,
			SimulationMetadata: simMeta,
		}
	}

	return json.Marshal(analysisJSON{
		Certificates: certMap,
		TrustPaths:   paths,
		Metadata:     a.Metadata,
	})
}

// certFingerprint returns a colon-hex fingerprint for a certificate, or empty
// string for nil (path-level errors/warnings without a specific certificate).
func certFingerprint(c *Certificate) string {
	if c == nil {
		return ""
	}
	return ColonHex(c.FingerprintSHA256())
}

// analysisJSON is the wire format for Analysis JSON serialization.
// Certificates are stored in a fingerprint-keyed map (defined once),
// and trust paths reference certificates by fingerprint string.
type analysisJSON struct {
	Certificates map[string]*Certificate `json:"certificates"`
	TrustPaths   []trustPathJSON         `json:"trust_paths"`
	Metadata     AnalysisMetadata        `json:"metadata"`
}

// trustPathJSON is the wire format for a trust path. Certificates are
// referenced by their colon-hex SHA-256 fingerprint instead of being
// embedded as full objects.
type trustPathJSON struct {
	Certificates       []string                       `json:"certificates"`
	Status             PathStatus                     `json:"status"`
	Errors             []validationErrorJSON          `json:"errors"`
	Warnings           []validationWarningJSON        `json:"warnings"`
	SimulationMetadata map[string]CertSimulationState `json:"simulation_metadata,omitempty"`
}

// validationErrorJSON is the wire format for a validation error.
// The Certificate field is a fingerprint string instead of a full object.
type validationErrorJSON struct {
	Certificate string         `json:"certificate,omitempty"`
	Type        ErrorType      `json:"type"`
	Message     string         `json:"message"`
	Details     map[string]any `json:"details,omitempty"`
}

// validationWarningJSON is the wire format for a validation warning.
// The Certificate field is a fingerprint string instead of a full object.
type validationWarningJSON struct {
	Certificate string      `json:"certificate,omitempty"`
	Type        WarningType `json:"type"`
	Message     string      `json:"message"`
}

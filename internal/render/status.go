// Certificate status computation and reason mapping.

package render

import (
	"fmt"

	"github.com/timorunge/certree/pkg/certree"
)

// defaultExpiryWarningDays is the default threshold (in days until expiry)
// below which a certificate triggers a warning.
const defaultExpiryWarningDays = certree.DefaultExpiryWarningDays

// statusLevel represents the severity of a certificate or path status.
type statusLevel int

const (
	statusValid statusLevel = iota
	statusWarning
	statusError
)

// certDisplayStatus holds precomputed status for a certificate on a single path.
type certDisplayStatus struct {
	level   statusLevel
	reasons []string
}

// certStatus computes the display status for a certificate within a single trust path.
//
//nolint:gocyclo,cyclop // linear collection of independent status checks
func certStatus(cert *certree.Certificate, path *certree.TrustPath, expiryWarningDays int) certDisplayStatus {
	if cert == nil || path == nil {
		return certDisplayStatus{level: statusError}
	}

	// Simulation states take priority and are mutually exclusive.
	if path.IsGhosted(cert) {
		return certDisplayStatus{level: statusValid, reasons: []string{"ghosted"}}
	}
	if path.IsExcluded(cert) {
		return certDisplayStatus{level: statusWarning, reasons: []string{"excluded"}}
	}
	if path.IsInjected(cert) {
		return certDisplayStatus{level: statusValid, reasons: []string{"injected"}}
	}

	var reasons []string
	fp := cert.FingerprintSHA256()
	meta := cert.Metadata()
	isTrusted := len(meta.TrustedLocations) > 0

	// Expiry is checked before trust store membership: an expired cert is
	// expired regardless of whether the trust store still contains it.
	if meta.IsExpired {
		reasons = append(reasons, "expired")
		return certDisplayStatus{level: statusError, reasons: reasons}
	}

	threshold := resolveExpiryWarningDays(expiryWarningDays)
	if meta.DaysUntilExpiry == 0 {
		reasons = append(reasons, "expires today")
	} else if meta.DaysUntilExpiry > 0 && meta.DaysUntilExpiry <= threshold {
		reasons = append(reasons, fmt.Sprintf("expires in %d days", meta.DaysUntilExpiry))
	}

	// Trust store membership is authoritative for non-temporal issues:
	// if the store trusts the cert, it is valid regardless of other
	// validation errors (e.g. serial number format).
	if isTrusted {
		for _, e := range path.Errors {
			if e.Certificate == nil || e.Certificate.FingerprintSHA256() != fp {
				continue
			}
			if r := e.Reason(); r != "" {
				reasons = append(reasons, r)
			}
		}
		if len(reasons) > 0 {
			reasons = append(reasons, "trusted")
			return certDisplayStatus{level: statusWarning, reasons: dedup(reasons)}
		}
		return certDisplayStatus{level: statusValid}
	}

	isSelfSigned := cert.IsSelfSigned()
	if isSelfSigned {
		reasons = append(reasons, "self-signed")
	}

	hasError := false
	for _, e := range path.Errors {
		if e.Certificate == nil || e.Certificate.FingerprintSHA256() != fp {
			continue
		}
		hasError = true
		r := e.Reason()
		if r == "" {
			continue
		}
		// "untrusted root" is redundant when we already show "self-signed".
		if r == "untrusted root" && isSelfSigned {
			continue
		}
		reasons = append(reasons, r)
	}

	hasWarning := false
	for _, w := range path.Warnings {
		if w.Certificate != nil && w.Certificate.FingerprintSHA256() == fp {
			hasWarning = true
			if w.Type == certree.WarningExcludedBySimulation {
				reasons = append(reasons, "broken")
				continue
			}
			if r := w.Reason(); r != "" {
				reasons = append(reasons, r)
			}
		}
	}

	level := statusValid
	switch {
	case hasError || isSelfSigned:
		level = statusError
	case hasWarning || len(reasons) > 0:
		level = statusWarning
	}

	return certDisplayStatus{level: level, reasons: dedup(reasons)}
}

// mergedCertStatus computes the aggregate display status for a certificate
// across all contributing trust paths in a merged-view node.
// A cert that is healthy on at least one trusted path is not downgraded by
// simulation-only warnings (WarningExcludedBySimulation) from broken paths.
func mergedCertStatus(cert *certree.Certificate, paths []*certree.TrustPath, expiryWarningDays int) certDisplayStatus {
	healthy := certHealthyOnAnyPath(cert, paths)
	worst := statusValid
	var allReasons []string
	for _, path := range paths {
		if healthy && isSimulationOnlyWarningPath(cert, path) {
			continue
		}
		s := certStatus(cert, path, expiryWarningDays)
		allReasons = append(allReasons, s.reasons...)
		if s.level > worst {
			worst = s.level
		}
	}
	return certDisplayStatus{level: worst, reasons: dedup(allReasons)}
}

// pathStatus returns the aggregate status level for a trust path.
func pathStatus(path *certree.TrustPath, expiryWarningDays int) statusLevel {
	if path == nil || len(path.Certificates) == 0 {
		return statusError
	}

	if !path.Status.IsTrusted() {
		return statusError
	}

	worst := statusValid
	for _, cert := range path.Certificates {
		if cert == nil {
			continue
		}

		// Excluded and ghosted certs are visually removed and must not affect
		// the path header status.
		if certIsExcludedOrGhosted(cert, path) {
			continue
		}

		s := certStatus(cert, path, expiryWarningDays)
		if s.level > worst {
			worst = s.level
		}
		if worst == statusError {
			return statusError
		}

		// Certificates above the trust anchor are informational and must not
		// affect the path header status.
		if len(cert.Metadata().TrustedLocations) > 0 {
			break
		}
	}

	return worst
}

// analysisStatus returns the aggregate status level for the entire analysis.
// Returns valid if any path is fully healthy, warning if trusted paths exist but
// all have warnings/errors, or error if no trusted paths remain.
func analysisStatus(analysis *certree.Analysis, expiryWarningDays int) statusLevel {
	if analysis == nil || len(analysis.TrustPaths) == 0 {
		return statusError
	}

	best := statusError
	for _, path := range analysis.TrustPaths {
		s := pathStatus(path, expiryWarningDays)
		if s == statusValid {
			return statusValid
		}
		if s < best {
			best = s
		}
	}

	return best
}

// pathStatusReason returns a human-readable reason for a path's status, or empty string when valid.
func pathStatusReason(path *certree.TrustPath, expiryWarningDays int) string {
	if path == nil || len(path.Certificates) == 0 {
		return ""
	}

	if path.SimulationMetadata != nil {
		if reason := excludedPathReason(path); reason != "" {
			return reason
		}
	}

	if path.Status == certree.PathIncomplete {
		return "incomplete chain"
	}

	// Check certs for errors and expiry warnings. For untrusted paths, this
	// surfaces the specific reason (e.g., "expired") instead of a generic
	// "untrusted" label.
	for _, cert := range path.Certificates {
		if cert == nil {
			continue
		}
		if certIsExcludedOrGhosted(cert, path) {
			continue
		}

		// Trust store membership is authoritative; skip errors and expiry
		// for trusted certs and stop scanning above the anchor.
		if len(cert.Metadata().TrustedLocations) > 0 {
			break
		}

		for _, e := range path.Errors {
			if e.Certificate != nil && e.Certificate.FingerprintSHA256() == cert.FingerprintSHA256() {
				return e.Reason()
			}
		}

		threshold := resolveExpiryWarningDays(expiryWarningDays)
		if cert.Metadata().DaysUntilExpiry == 0 {
			return "expires today"
		}
		if cert.Metadata().DaysUntilExpiry > 0 && cert.Metadata().DaysUntilExpiry <= threshold {
			return fmt.Sprintf("expires in %d days", cert.Metadata().DaysUntilExpiry)
		}
	}

	// Path-level errors without cert attribution (e.g., future validators).
	for _, e := range path.Errors {
		if e.Certificate == nil {
			return e.Reason()
		}
	}

	if !path.Status.IsTrusted() {
		return "untrusted"
	}

	return ""
}

// excludedPathReason returns the path-level simulation exclusion reason string.
func excludedPathReason(path *certree.TrustPath) string {
	excludedIdx := -1
	var excludedCert *certree.Certificate
	for i, cert := range path.Certificates {
		if cert == nil {
			continue
		}
		if state, ok := path.SimulationMetadata[cert.FingerprintSHA256()]; ok && state.IsExcluded {
			excludedIdx = i
			excludedCert = cert
			break
		}
	}
	if excludedIdx < 0 {
		return ""
	}

	cn := displayName(excludedCert)

	// Lower index = closer to leaf; search below the excluded cert for the anchor.
	if path.Status.IsTrusted() {
		for i := excludedIdx - 1; i >= 0; i-- {
			cert := path.Certificates[i]
			if cert != nil && len(cert.Metadata().TrustedLocations) > 0 {
				return cn + " excluded by simulation, still trusted via " + displayName(cert)
			}
		}
	}

	return cn + " excluded by simulation"
}

// isEffectivelyTrusted reports whether a path is structurally trusted with
// no validation errors (expired certs, hostname mismatch, etc.).
func isEffectivelyTrusted(path *certree.TrustPath, expiryWarningDays int) bool {
	return path.Status.IsTrusted() && pathStatus(path, expiryWarningDays) != statusError
}

// certIsExcludedOrGhosted reports whether cert is excluded or ghosted
// in the given path's simulation metadata.
func certIsExcludedOrGhosted(cert *certree.Certificate, path *certree.TrustPath) bool {
	return path.IsExcluded(cert) || path.IsGhosted(cert)
}

// certHealthyOnAnyPath reports whether cert appears on at least one trusted
// path where it has no simulation warnings or exclusions.
func certHealthyOnAnyPath(cert *certree.Certificate, paths []*certree.TrustPath) bool {
	for _, path := range paths {
		if !path.Status.IsTrusted() {
			continue
		}
		if path.IsExcluded(cert) || path.IsGhosted(cert) {
			continue
		}
		if !isSimulationOnlyWarningPath(cert, path) {
			return true
		}
	}
	return false
}

// isSimulationOnlyWarningPath reports whether the only warning for cert on
// this path is WarningExcludedBySimulation (i.e. the cert is collateral
// damage, not directly excluded).
func isSimulationOnlyWarningPath(cert *certree.Certificate, path *certree.TrustPath) bool {
	fp := cert.FingerprintSHA256()
	found := false
	for _, w := range path.Warnings {
		if w.Certificate == nil || w.Certificate.FingerprintSHA256() != fp {
			continue
		}
		if w.Type != certree.WarningExcludedBySimulation {
			return false
		}
		found = true
	}
	return found
}

// resolveExpiryWarningDays returns days or the default when days is zero or negative.
func resolveExpiryWarningDays(days int) int {
	if days <= 0 {
		return defaultExpiryWarningDays
	}
	return days
}

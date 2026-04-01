// Certificate display formatting: human-readable representations of X.509 fields.

package render

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/timorunge/certree/pkg/certree"
)

// dateDisplayFormat is the standard time format for certificate dates.
const dateDisplayFormat = "2006-01-02 15:04:05 MST"

// wellKnownPolicies maps CA/Browser Forum certificate policy OIDs to human-readable names.
var wellKnownPolicies = map[string]string{
	"2.23.140.1.1":   "EV",
	"2.23.140.1.2.1": "DV",
	"2.23.140.1.2.2": "OV",
	"2.23.140.1.2.3": "IV",
}

var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

// displayName returns a human-readable display name for the certificate.
// It prefers the Common Name, falling back to Organization, Organizational
// Unit, the DN serial number, or "(no CN)" as a last resort.
// The result is sanitized: ANSI escape sequences are stripped to prevent
// terminal injection from malicious certificate DN fields.
func displayName(cert *certree.Certificate) string {
	cn := cert.Raw().Subject.CommonName
	if cn != "" {
		return SanitizeCertString(cn)
	}
	subj := cert.Raw().Subject
	switch {
	case len(subj.Organization) > 0:
		return SanitizeCertString(subj.Organization[0])
	case len(subj.OrganizationalUnit) > 0:
		return SanitizeCertString(subj.OrganizationalUnit[0])
	case subj.SerialNumber != "":
		return SanitizeCertString(subj.SerialNumber)
	default:
		return "(no CN)"
	}
}

// publicKeyInfo returns a human-readable description of the certificate's
// public key algorithm and size (e.g. "RSA 2048-bit", "ECDSA P-256").
func publicKeyInfo(cert *certree.Certificate) string {
	switch pub := cert.Raw().PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", pub.N.BitLen())
	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
		}
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.Raw().PublicKeyAlgorithm.String()
	}
}

// formatNotBefore returns the formatted Not Before date string.
func formatNotBefore(cert *certree.Certificate) string {
	return cert.Raw().NotBefore.Format(dateDisplayFormat)
}

// formatNotAfter returns the formatted Not After date string with a
// parenthesized days-remaining count. dimFn colorizes the suffix;
// pass identityColorFunc when no coloring is desired. For expired
// certificates, the days-remaining suffix is omitted.
func formatNotAfter(cert *certree.Certificate, dimFn colorFunc) string {
	s := cert.Raw().NotAfter.Format(dateDisplayFormat)
	if !cert.Metadata().IsExpired {
		days := cert.Metadata().DaysUntilExpiry
		suffix := fmt.Sprintf("%d days", days)
		if days == 0 {
			suffix = "expires today"
		}
		return fmt.Sprintf("%s (%s)", s, dimFn(suffix))
	}
	return s
}

// trustStoreValue returns a human-readable trust store summary for a certificate.
// Returns the joined trust store locations for trusted certs, "none" for
// untrusted self-signed certs, or empty string when trust store info is not
// applicable (non-self-signed intermediate without trust store membership).
func trustStoreValue(cert *certree.Certificate) string {
	locations := cert.Metadata().TrustedLocations
	if len(locations) > 0 {
		return strings.Join(sanitizeStrings(locations), ", ")
	}
	if cert.Metadata().IsSelfSigned {
		return "none"
	}
	return ""
}

// shortFingerprintPrefix returns a colon-separated prefix of a hex
// fingerprint, suitable for disambiguating certificates with the same name.
func shortFingerprintPrefix(fp string) string {
	if len(fp) >= 12 {
		return certree.ColonHex(fp[:12])
	}
	return certree.ColonHex(fp)
}

// keyUsageNames returns human-readable names for the x509.KeyUsage bitmask.
func keyUsageNames(ku x509.KeyUsage) []string {
	usages := make([]string, 0, 3)
	for _, p := range keyUsageBits {
		if ku&p.bit != 0 {
			usages = append(usages, p.name)
		}
	}
	return usages
}

// policyOIDName returns the human-readable name for a well-known CA/Browser
// Forum certificate policy OID, or empty string if the OID is not recognized.
func policyOIDName(oid string) string {
	return wellKnownPolicies[oid]
}

// disambiguateNames returns a fingerprint -> short-hex-prefix map for
// certificates that share the same display name. Certificates with unique
// names are not included in the result. Returns nil if no disambiguation
// is needed.
func disambiguateNames(certs []*certree.Certificate) map[string]string {
	if len(certs) < 2 {
		return nil
	}

	names := make([]string, len(certs))
	counts := make(map[string]int, len(certs))
	for i, cert := range certs {
		names[i] = displayName(cert)
		counts[names[i]]++
	}

	var result map[string]string
	for i, cert := range certs {
		if counts[names[i]] < 2 {
			continue
		}
		if result == nil {
			result = make(map[string]string)
		}
		fp := cert.FingerprintSHA256()
		result[fp] = shortFingerprintPrefix(fp)
	}
	return result
}

// formatDisambiguated returns display names for the given certificates,
// appending a short fingerprint prefix when multiple certificates share
// the same name.
func formatDisambiguated(certs []*certree.Certificate) []string {
	disambig := disambiguateNames(certs)
	names := make([]string, len(certs))
	for i, cert := range certs {
		name := displayName(cert)
		if d, ok := disambig[cert.FingerprintSHA256()]; ok {
			name += " " + d
		}
		names[i] = name
	}
	return names
}

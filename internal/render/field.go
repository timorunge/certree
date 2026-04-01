// Certificate detail field formatting: section types, X.509 field rendering, and column alignment.

package render

import (
	"crypto/x509/pkix"
	"strconv"
	"strings"

	"github.com/timorunge/certree/pkg/certree"
)

// minValueWidth is the floor below which wrapping is disabled to avoid
// degenerate single-character segments on very narrow terminals.
const minValueWidth = 20

// certSection is implemented by detailField and sectionBlock.
type certSection interface {
	labelWidth() int
	renderLines(maxLabel, availWidth int) []string
}

// detailField holds a "label: value" pair for certificate detail output.
type detailField struct {
	label    string
	value    string
	labelSep string
}

// labelWidth returns the width of the label, used for alignment.
func (f detailField) labelWidth() int { return visibleLen(f.label) }

// renderLines returns the lines to render for this detail field.
func (f detailField) renderLines(maxLabel, availWidth int) []string {
	pad := strings.Repeat(" ", maxLabel-visibleLen(f.label))
	prefix := f.label + ":" + pad + f.labelSep

	if availWidth <= 0 || visibleLen(f.value) <= availWidth {
		return []string{prefix + f.value}
	}

	segments := wrapValue(f.value, availWidth)
	lines := make([]string, len(segments))
	contPad := strings.Repeat(" ", visibleLen(prefix))
	for i, seg := range segments {
		if i == 0 {
			lines[i] = prefix + seg
		} else {
			lines[i] = contPad + seg
		}
	}
	return lines
}

// sectionBlock holds a section header followed by indented sub-field lines.
type sectionBlock struct {
	header   string
	lines    []string
	labelSep string
}

// labelWidth returns 0 for section blocks as they have no label.
func (b sectionBlock) labelWidth() int { return 0 }

// renderLines renders the section block with the given max label width and available width.
func (b sectionBlock) renderLines(maxLabel, availWidth int) []string {
	out := make([]string, 0, 1+len(b.lines))
	out = append(out, b.header)

	if availWidth <= 0 {
		out = append(out, b.lines...)
		return out
	}

	// Sub-lines live in the space that detailField uses for "label:<sep>value".
	// All section builders must set labelSep; the minimum width of 1 is a safety
	// floor so wrap-width calculation never degenerates to zero.
	sepWidth := max(len(b.labelSep), 1)
	lineWidth := maxLabel + 1 + sepWidth + availWidth
	for _, line := range b.lines {
		if visibleLen(line) <= lineWidth {
			out = append(out, line)
			continue
		}
		// Find the value start after the sub-label's ":<sep>" separator,
		// or after the leading whitespace for list items like "  - name".
		contIndent := 0
		if idx := strings.Index(line, ":"+b.labelSep); b.labelSep != "" && idx >= 0 {
			contIndent = idx + 1
			for contIndent < len(line) && line[contIndent] == ' ' {
				contIndent++
			}
		} else {
			for contIndent < len(line) && line[contIndent] == ' ' {
				contIndent++
			}
		}
		valueStart := contIndent
		prefix := line[:valueStart]
		value := line[valueStart:]
		valueWidth := lineWidth - visibleLen(prefix)
		if valueWidth < minValueWidth {
			out = append(out, line)
			continue
		}
		segments := wrapValue(value, valueWidth)
		contPad := strings.Repeat(" ", visibleLen(prefix))
		for i, seg := range segments {
			if i == 0 {
				out = append(out, prefix+seg)
			} else {
				out = append(out, contPad+seg)
			}
		}
	}
	return out
}

// inlineOrList returns a certSection for a label with one or more values.
// Single value: detailField that participates in column alignment.
// Multiple values: sectionBlock with a "label:" header and indented list items.
// Panics if values is empty -- callers must filter before calling.
func inlineOrList(label string, values []string, indent, sep string) certSection {
	if len(values) == 0 {
		panic("render: inlineOrList called with empty values for label " + label)
	}
	if len(values) == 1 {
		return detailField{label: label, value: values[0], labelSep: sep}
	}
	lines := make([]string, len(values))
	for i, v := range values {
		lines[i] = indent + "- " + v
	}
	return sectionBlock{header: label + ":", lines: lines, labelSep: sep}
}

// labelValue holds a label-value pair for column-aligned formatting.
type labelValue struct {
	label string
	value string
}

// valueGroup holds a label with one or more associated values for grouped formatting.
type valueGroup struct {
	label  string
	values []string
}

// alignLabelValues formats label-value pairs as indented, column-aligned lines.
// sep is the spacing between "label:" and value (typically the theme's labelSep).
func alignLabelValues(pairs []labelValue, indent, sep string) []string {
	if len(pairs) == 0 {
		return nil
	}
	maxLen := 0
	for _, p := range pairs {
		if visibleLen(p.label) > maxLen {
			maxLen = visibleLen(p.label)
		}
	}
	lines := make([]string, 0, len(pairs))
	for _, p := range pairs {
		pad := strings.Repeat(" ", maxLen-visibleLen(p.label))
		lines = append(lines, indent+p.label+":"+pad+sep+p.value)
	}
	return lines
}

// formatDNFields returns indented, column-aligned lines for a Distinguished Name.
func formatDNFields(name pkix.Name, indent, sep string) []string {
	var pairs []labelValue
	if name.CommonName != "" {
		pairs = append(pairs, labelValue{"Common Name", SanitizeCertString(name.CommonName)})
	}
	if len(name.Organization) > 0 {
		pairs = append(pairs, labelValue{"Organization", SanitizeCertString(strings.Join(name.Organization, ", "))})
	}
	if len(name.OrganizationalUnit) > 0 {
		pairs = append(pairs, labelValue{"Organizational Unit", SanitizeCertString(strings.Join(name.OrganizationalUnit, ", "))})
	}
	if len(name.Country) > 0 {
		pairs = append(pairs, labelValue{"Country", SanitizeCertString(strings.Join(name.Country, ", "))})
	}
	if len(name.Province) > 0 {
		pairs = append(pairs, labelValue{"State", SanitizeCertString(strings.Join(name.Province, ", "))})
	}
	if len(name.Locality) > 0 {
		pairs = append(pairs, labelValue{"Locality", SanitizeCertString(strings.Join(name.Locality, ", "))})
	}
	if name.SerialNumber != "" {
		pairs = append(pairs, labelValue{"Serial Number", SanitizeCertString(name.SerialNumber)})
	}
	return alignLabelValues(pairs, indent, sep)
}

// buildValiditySection returns a sectionBlock with Not Before and Not After sub-fields.
// The days-remaining suffix is colored: error when expired, warning when
// expiring within expiryWarningDays, dim otherwise.
func buildValiditySection(cert *certree.Certificate, indent, sep string, errColor, warningColor, dimColor colorFunc, expiryWarningDays int) sectionBlock {
	meta := cert.Metadata()
	daysFn := dimColor
	if meta.IsExpired {
		daysFn = errColor
	} else if meta.DaysUntilExpiry <= resolveExpiryWarningDays(expiryWarningDays) {
		daysFn = warningColor
	}
	notBefore := formatNotBefore(cert)
	notAfter := formatNotAfter(cert, daysFn)
	if meta.IsExpired {
		notAfter += " (" + errColor("expired") + ")"
	}
	return sectionBlock{
		header: "Validity:",
		lines: alignLabelValues([]labelValue{
			{"Not Before", notBefore},
			{"Not After", notAfter},
		}, indent, sep),
		labelSep: sep,
	}
}

// buildSANSection returns a sectionBlock for Subject Alternative Names (DNS, IP, Email, URI).
// Single-value types are shown inline; multi-value types use list format.
func buildSANSection(cert *certree.Certificate, indent, sep string) (sectionBlock, bool) {
	raw := cert.Raw()

	var groups []valueGroup
	if len(raw.DNSNames) > 0 {
		groups = append(groups, valueGroup{"DNS", sanitizeStrings(raw.DNSNames)})
	}
	if len(raw.IPAddresses) > 0 {
		ips := make([]string, len(raw.IPAddresses))
		for i, ip := range raw.IPAddresses {
			ips[i] = ip.String()
		}
		groups = append(groups, valueGroup{"IP", ips})
	}
	if len(raw.EmailAddresses) > 0 {
		groups = append(groups, valueGroup{"Email", sanitizeStrings(raw.EmailAddresses)})
	}
	if len(raw.URIs) > 0 {
		uris := make([]string, len(raw.URIs))
		for i, u := range raw.URIs {
			uris[i] = SanitizeCertString(u.String())
		}
		groups = append(groups, valueGroup{"URI", uris})
	}
	if len(groups) == 0 {
		return sectionBlock{}, false
	}

	lines := formatGroupedValues(groups, indent, sep)
	return sectionBlock{
		header:   "Subject Alternative Names:",
		lines:    lines,
		labelSep: sep,
	}, true
}

// formatGroupedValues formats groups of (label, values) as sub-lines within a sectionBlock.
// Single-value groups render inline and are column-aligned with each other.
// Multi-value groups render as a "label:" header followed by indented list items.
func formatGroupedValues(groups []valueGroup, indent, sep string) []string {
	maxLabel := 0
	for _, g := range groups {
		if len(g.values) == 1 && visibleLen(g.label) > maxLabel {
			maxLabel = visibleLen(g.label)
		}
	}

	var lines []string
	for _, g := range groups {
		if len(g.values) == 1 {
			pad := strings.Repeat(" ", maxLabel-visibleLen(g.label))
			lines = append(lines, indent+g.label+":"+pad+sep+g.values[0])
		} else {
			lines = append(lines, indent+g.label+":")
			for _, v := range g.values {
				lines = append(lines, indent+indent+"- "+v)
			}
		}
	}
	return lines
}

// buildExtensionsSection returns a consolidated sectionBlock for all X.509v3 extension data:
// Basic Constraints, Key/Ext Key Usage, Must-Staple, SCTs, key identifiers,
// name constraints, and certificate policies.
//
//nolint:gocyclo,cyclop // linear assembly of independent extension fields
func buildExtensionsSection(cert *certree.Certificate, indent, sep string) (sectionBlock, bool) {
	raw := cert.Raw()
	var pairs []labelValue

	if raw.BasicConstraintsValid {
		bc := "CA:FALSE"
		if raw.IsCA {
			bc = "CA:TRUE"
			if raw.MaxPathLen > 0 || raw.MaxPathLenZero {
				bc += ", pathlen:" + strconv.Itoa(raw.MaxPathLen)
			}
		}
		pairs = append(pairs, labelValue{"Basic Constraints", bc})
	}

	if raw.KeyUsage != 0 {
		usages := keyUsageNames(raw.KeyUsage)
		if len(usages) > 0 {
			pairs = append(pairs, labelValue{"Key Usage", strings.Join(usages, ", ")})
		}
	}

	if len(raw.ExtKeyUsage) > 0 {
		extUsages := make([]string, 0, len(raw.ExtKeyUsage))
		for _, eku := range raw.ExtKeyUsage {
			extUsages = append(extUsages, certree.EKUDisplayName(eku))
		}
		pairs = append(pairs, labelValue{"Ext Key Usage", strings.Join(extUsages, ", ")})
	}

	if cert.Metadata().HasMustStaple {
		pairs = append(pairs, labelValue{"Must-Staple", "yes (RFC 7633)"})
	}

	if cert.Metadata().SCTCount > 0 {
		pairs = append(pairs, labelValue{"SCTs", strconv.Itoa(cert.Metadata().SCTCount)})
	}

	if len(raw.SubjectKeyId) > 0 {
		pairs = append(pairs, labelValue{"Subject Key ID", certree.ColonHexBytes(raw.SubjectKeyId)})
	}
	if len(raw.AuthorityKeyId) > 0 {
		pairs = append(pairs, labelValue{"Authority Key ID", certree.ColonHexBytes(raw.AuthorityKeyId)})
	}

	// Name constraints and policies use grouped format (inline/list hybrid).
	var groups []valueGroup
	if len(raw.PermittedDNSDomains) > 0 {
		groups = append(groups, valueGroup{"Permitted DNS", sanitizeStrings(raw.PermittedDNSDomains)})
	}
	if len(raw.ExcludedDNSDomains) > 0 {
		groups = append(groups, valueGroup{"Excluded DNS", sanitizeStrings(raw.ExcludedDNSDomains)})
	}
	if len(raw.PermittedIPRanges) > 0 {
		ips := make([]string, len(raw.PermittedIPRanges))
		for i, ipNet := range raw.PermittedIPRanges {
			ips[i] = ipNet.String()
		}
		groups = append(groups, valueGroup{"Permitted IP", ips})
	}
	if len(raw.ExcludedIPRanges) > 0 {
		ips := make([]string, len(raw.ExcludedIPRanges))
		for i, ipNet := range raw.ExcludedIPRanges {
			ips[i] = ipNet.String()
		}
		groups = append(groups, valueGroup{"Excluded IP", ips})
	}
	if len(raw.PermittedEmailAddresses) > 0 {
		groups = append(groups, valueGroup{"Permitted Email", sanitizeStrings(raw.PermittedEmailAddresses)})
	}
	if len(raw.ExcludedEmailAddresses) > 0 {
		groups = append(groups, valueGroup{"Excluded Email", sanitizeStrings(raw.ExcludedEmailAddresses)})
	}
	if len(raw.PermittedURIDomains) > 0 {
		groups = append(groups, valueGroup{"Permitted URI", sanitizeStrings(raw.PermittedURIDomains)})
	}
	if len(raw.ExcludedURIDomains) > 0 {
		groups = append(groups, valueGroup{"Excluded URI", sanitizeStrings(raw.ExcludedURIDomains)})
	}
	if len(raw.PolicyIdentifiers) > 0 {
		policies := make([]string, len(raw.PolicyIdentifiers))
		for i, oid := range raw.PolicyIdentifiers {
			s := oid.String()
			if name := policyOIDName(s); name != "" {
				s += " (" + name + ")"
			}
			policies[i] = s
		}
		groups = append(groups, valueGroup{"Policy", policies})
	}

	if len(pairs) == 0 && len(groups) == 0 {
		return sectionBlock{}, false
	}
	lines := alignLabelValues(pairs, indent, sep)
	lines = append(lines, formatGroupedValues(groups, indent, sep)...)
	return sectionBlock{header: "Extensions:", lines: lines, labelSep: sep}, true
}

// buildAIASection returns a sectionBlock for Authority Information Access (OCSP and CA Issuer URLs).
// Single-value types are shown inline; multi-value types use list format.
func buildAIASection(cert *certree.Certificate, indent, sep string) (sectionBlock, bool) {
	raw := cert.Raw()
	if len(raw.OCSPServer) == 0 && len(raw.IssuingCertificateURL) == 0 {
		return sectionBlock{}, false
	}

	var groups []valueGroup
	if len(raw.OCSPServer) > 0 {
		groups = append(groups, valueGroup{"OCSP", sanitizeStrings(raw.OCSPServer)})
	}
	if len(raw.IssuingCertificateURL) > 0 {
		groups = append(groups, valueGroup{"CA Issuer", sanitizeStrings(raw.IssuingCertificateURL)})
	}
	return sectionBlock{
		header:   "AIA:",
		lines:    formatGroupedValues(groups, indent, sep),
		labelSep: sep,
	}, true
}

// buildCRLSection returns a sectionBlock for CRL Distribution Points.
func buildCRLSection(cert *certree.Certificate, indent, sep string) (sectionBlock, bool) {
	if len(cert.Raw().CRLDistributionPoints) == 0 {
		return sectionBlock{}, false
	}
	block := sectionBlock{header: "CRL Distribution Points:", labelSep: sep}
	for _, url := range cert.Raw().CRLDistributionPoints {
		block.lines = append(block.lines, indent+"- "+SanitizeCertString(url))
	}
	return block, true
}

// sanitizeStrings strips ANSI escape codes and control characters from each
// string in a slice, preventing terminal injection from certificate fields
// like SAN, AIA, CRL URLs.
func sanitizeStrings(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = SanitizeCertString(s)
	}
	return out
}

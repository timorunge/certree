// Impact summary computation for before/after simulation analysis.

package render

import (
	"strconv"
	"strings"

	"github.com/timorunge/certree/pkg/certree"
)

// ImpactSummary computes and formats the impact summary between two analyses.
// indent controls sub-field indentation (typically the theme's sectionIndent).
// sep is the spacing between "label:" and value (typically the theme's labelSep).
// expiryWarningDays must match the value used for the root label's path count
// to keep the numbers consistent.
func ImpactSummary(before, after *certree.Analysis, indent, sep string, expiryWarningDays int) string {
	if before == nil || after == nil {
		return ""
	}

	excluded, broken, injected, ghosted := collectSimulationCerts(after)

	// Precompute path signatures once to avoid redundant string builds
	// across writeBrokenPaths and writeNewPaths.
	beforeSigs := buildPathSignatures(before.TrustPaths, expiryWarningDays)
	afterSigs := buildPathSignatures(after.TrustPaths, expiryWarningDays)

	var sections []certSection
	sections = appendCertSection(sections, "Injected", injected, indent, sep)
	sections = appendCertSection(sections, "Excluded", excluded, indent, sep)
	sections = appendCertSection(sections, "Broken", broken, indent, sep)
	sections = appendCertSection(sections, "Ghosted", ghosted, indent, sep)
	sections = appendPathCountSections(sections, before, after, beforeSigs, afterSigs, sep, expiryWarningDays)

	maxLabel := 0
	for _, s := range sections {
		if w := s.labelWidth(); w > maxLabel {
			maxLabel = w
		}
	}

	var b strings.Builder
	b.WriteString("Impact:\n")
	for _, s := range sections {
		for _, line := range s.renderLines(maxLabel, 0) {
			b.WriteString(indent)
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	b.WriteByte('\n')
	return b.String()
}

// collectSimulationCerts partitions simulation-tagged certificates into excluded, broken, injected, and ghosted sets.
// Excluded certs are directly removed by simulation. Broken certs have their trust chain broken as a consequence
// and no remaining healthy trust path.
func collectSimulationCerts(after *certree.Analysis) (excluded, broken, injected, ghosted []*certree.Certificate) {
	seenExcl := make(map[string]struct{})
	seenBroken := make(map[string]struct{})
	seenInj := make(map[string]struct{})
	seenGhost := make(map[string]struct{})

	for _, path := range after.TrustPaths {
		for _, cert := range path.Certificates {
			if cert == nil {
				continue
			}
			fp := cert.FingerprintSHA256()
			if path.IsExcluded(cert) {
				if _, ok := seenExcl[fp]; !ok {
					seenExcl[fp] = struct{}{}
					excluded = append(excluded, cert)
				}
			}
			if path.IsInjected(cert) {
				if _, ok := seenInj[fp]; !ok {
					seenInj[fp] = struct{}{}
					injected = append(injected, cert)
				}
			}
			if path.IsGhosted(cert) {
				if _, ok := seenGhost[fp]; !ok {
					seenGhost[fp] = struct{}{}
					ghosted = append(ghosted, cert)
				}
			}
		}
		// Broken certs: have WarningExcludedBySimulation but are not directly excluded
		// and have no remaining trusted path where they appear healthy.
		for _, w := range path.Warnings {
			if w.Type == certree.WarningExcludedBySimulation && w.Certificate != nil {
				fp := w.Certificate.FingerprintSHA256()
				_, isExcl := seenExcl[fp]
				_, isBroken := seenBroken[fp]
				if !isExcl && !isBroken && !certHealthyOnAnyPath(w.Certificate, after.TrustPaths) {
					seenBroken[fp] = struct{}{}
					broken = append(broken, w.Certificate)
				}
			}
		}
	}
	return excluded, broken, injected, ghosted
}

// appendCertSection appends a certSection for a labeled cert list.
// Single cert: inline detailField. Multiple certs: list sectionBlock.
// Duplicate names are disambiguated with short fingerprint prefixes.
func appendCertSection(sections []certSection, label string, certs []*certree.Certificate, indent, sep string) []certSection {
	if len(certs) == 0 {
		return sections
	}
	return append(sections, inlineOrList(label, formatDisambiguated(certs), indent, sep))
}

// buildPathSignatures precomputes the PathKey signature for each trust path into a map.
// The boolean value reflects effective trust (structural trust + no validation errors).
func buildPathSignatures(paths []*certree.TrustPath, expiryWarningDays int) map[string]bool {
	sigs := make(map[string]bool, len(paths))
	for _, path := range paths {
		sigs[path.PathKey()] = isEffectivelyTrusted(path, expiryWarningDays)
	}
	return sigs
}

// appendPathCountSections appends broken, new, and remaining path count fields.
func appendPathCountSections(sections []certSection, before, after *certree.Analysis, beforeSigs, afterSigs map[string]bool, sep string, expiryWarningDays int) []certSection {
	brokenPaths := 0
	for _, path := range before.TrustPaths {
		if !isEffectivelyTrusted(path, expiryWarningDays) {
			continue
		}
		trusted, exists := afterSigs[path.PathKey()]
		if !exists || !trusted {
			brokenPaths++
		}
	}
	sections = append(sections, detailField{"Broken paths", strconv.Itoa(brokenPaths), sep})

	newPaths := 0
	remainingPaths := 0
	for _, path := range after.TrustPaths {
		if isEffectivelyTrusted(path, expiryWarningDays) {
			remainingPaths++
			if !beforeSigs[path.PathKey()] {
				newPaths++
			}
		}
	}
	if newPaths > 0 {
		sections = append(sections, detailField{"New trusted paths", strconv.Itoa(newPaths), sep})
	}
	sections = append(sections, detailField{"Remaining paths", strconv.Itoa(remainingPaths), sep})

	return sections
}

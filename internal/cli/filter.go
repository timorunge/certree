// Display filtering for certificate analysis results.

package cli

import (
	"slices"

	"github.com/timorunge/certree/pkg/certree"
)

// certFilter pairs a pattern matcher with a function that extracts the
// matching field(s) from a certificate.
type certFilter struct {
	matcher   *certree.PatternMatcher
	extractor func(*certree.Certificate) []string
}

// filterAnalyses applies all active display filters to each analysis.
// The returned slice always has the same length as the input.
func filterAnalyses(analyses []*certree.Analysis, flags nonConfigFlags) []*certree.Analysis {
	filters := buildFilters(flags)
	if len(filters) == 0 {
		return analyses
	}
	filtered := make([]*certree.Analysis, len(analyses))
	for i, a := range analyses {
		filtered[i] = applyFilters(a, filters)
	}
	return filtered
}

// buildFilters constructs certFilters from the active filter flags.
func buildFilters(flags nonConfigFlags) []certFilter {
	var filters []certFilter
	if len(flags.filterCN) > 0 {
		filters = append(filters, certFilter{
			matcher:   certree.NewPatternMatcher(flags.filterCN),
			extractor: func(c *certree.Certificate) []string { return []string{c.CommonName()} },
		})
	}
	if len(flags.filterFingerprint) > 0 {
		filters = append(filters, certFilter{
			matcher:   certree.NewPatternMatcher(flags.filterFingerprint),
			extractor: func(c *certree.Certificate) []string { return []string{c.FingerprintSHA256()} },
		})
	}
	if len(flags.filterSerial) > 0 {
		filters = append(filters, certFilter{
			matcher:   certree.NewPatternMatcher(flags.filterSerial),
			extractor: func(c *certree.Certificate) []string { return []string{c.SerialNumber()} },
		})
	}
	return filters
}

// certMatchesAnyFilter reports whether a certificate matches at least one filter.
func certMatchesAnyFilter(cert *certree.Certificate, filters []certFilter) bool {
	for _, f := range filters {
		if f.matcher.MatchAny(f.extractor(cert)) {
			return true
		}
	}
	return false
}

// applyFilters retains certificates and trust paths where at least one
// certificate matches any of the filters.
func applyFilters(analysis *certree.Analysis, filters []certFilter) *certree.Analysis {
	if analysis == nil {
		return nil
	}

	filteredCerts := make([]*certree.Certificate, 0, len(analysis.Certificates))
	for _, cert := range analysis.Certificates {
		if certMatchesAnyFilter(cert, filters) {
			filteredCerts = append(filteredCerts, cert)
		}
	}

	filteredPaths := make([]*certree.TrustPath, 0, len(analysis.TrustPaths))
	for _, path := range analysis.TrustPaths {
		if slices.ContainsFunc(path.Certificates, func(cert *certree.Certificate) bool {
			return certMatchesAnyFilter(cert, filters)
		}) {
			filteredPaths = append(filteredPaths, path)
		}
	}

	return certree.NewAnalysis(filteredCerts, filteredPaths, analysis.Metadata.Source,
		certree.WithSimulated(analysis.Metadata.IsSimulated))
}

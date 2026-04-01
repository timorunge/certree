// Glob pattern matching with O(1) exact-string fast path.

package certree

import (
	"path"
	"slices"
	"strings"
)

// PatternMatcher pre-classifies patterns into exact strings and glob patterns
// for efficient matching. Exact strings use O(1) map lookup; only patterns
// containing wildcard characters (*, ?, [) use path.Match. Patterns may
// contain pipe-separated alternatives ("a|b") and colons are stripped so
// that colon-separated hex input (e.g. "A8:87:*") matches internal
// colon-free representations.
type PatternMatcher struct {
	exact map[string]struct{}
	globs []string
}

// NewPatternMatcher compiles a pattern list into a matcher. Each pattern
// supports wildcard syntax via [path.Match] (*, ?, [abc]) and may contain
// pipe-separated alternatives (e.g. "GTS Root R4|DigiCert*"). Colons are
// stripped from patterns so that colon-separated hex input matches internal
// colon-free representations. Note that * does not match / per [path.Match]
// semantics; this is only relevant for CN matching when a subject CN
// contains a forward slash (rare in modern PKI). Fingerprints and serial
// numbers never contain /.
func NewPatternMatcher(patterns []string) *PatternMatcher {
	exact := make(map[string]struct{}, len(patterns))
	var globs []string
	for _, p := range patterns {
		for alt := range strings.SplitSeq(p, "|") {
			alt = strings.TrimSpace(alt)
			alt = stripColons(alt)
			if alt == "" {
				continue
			}
			if strings.ContainsAny(alt, "*?[") {
				globs = append(globs, alt)
			} else {
				exact[alt] = struct{}{}
			}
		}
	}
	return &PatternMatcher{exact: exact, globs: globs}
}

// Match returns true if value matches any pattern in the matcher.
// Returns false if the receiver is nil, allowing safe use in optional contexts.
func (m *PatternMatcher) Match(value string) bool {
	if m == nil {
		return false
	}
	if _, ok := m.exact[value]; ok {
		return true
	}
	for _, g := range m.globs {
		if matched, err := path.Match(g, value); err == nil && matched {
			return true
		}
	}
	return false
}

// MatchAny returns true if any of the values matches the matcher.
// Returns false if the receiver is nil.
func (m *PatternMatcher) MatchAny(values []string) bool {
	if m == nil {
		return false
	}
	return slices.ContainsFunc(values, m.Match)
}

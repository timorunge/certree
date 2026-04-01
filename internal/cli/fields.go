// Registry, parsing, and application for the --fields flag.

package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/timorunge/certree/internal/render"
)

// fieldEntry maps a --fields value to the render.Options boolean it enables.
type fieldEntry struct {
	name  string
	apply func(opts *render.Options)
}

var (
	// fields is the single source of truth for all values accepted by --fields.
	// Each entry maps a flag value to the render.Options boolean it enables.
	fields = []fieldEntry{
		{"aia", func(o *render.Options) { o.ShowAIA = true }},
		{"algorithm", func(o *render.Options) { o.ShowAlgorithm = true }},
		{"crl", func(o *render.Options) { o.ShowCRL = true }},
		{"diagnostics", func(o *render.Options) { o.ShowDiagnostics = true }},
		{"extensions", func(o *render.Options) { o.ShowExtensions = true }},
		{"fingerprint", func(o *render.Options) { o.ShowFingerprint = true }},
		{"issuer", func(o *render.Options) { o.ShowIssuer = true }},
		{"san", func(o *render.Options) { o.ShowSAN = true }},
		{"serial", func(o *render.Options) { o.ShowSerial = true }},
		{"source", func(o *render.Options) { o.ShowSource = true }},
		{"subject", func(o *render.Options) { o.ShowSubject = true }},
		{"trust-store", func(o *render.Options) { o.ShowTrustStore = true }},
		{"validity", func(o *render.Options) { o.ShowValidity = true }},
	}

	// validFieldNames is the set of all values accepted by --fields, for O(1)
	// validation. Derived from fields plus the "all" keyword.
	validFieldNames = buildValidFieldNames()
)

// buildValidFieldNames constructs the set of all values accepted by --fields.
func buildValidFieldNames() map[string]struct{} {
	m := make(map[string]struct{}, len(fields)+1)
	for _, f := range fields {
		m[f.name] = struct{}{}
	}
	m["all"] = struct{}{}
	return m
}

// parseFields validates a --fields value (comma-separated names). Returns the
// list of unique names or an error listing unknown ones.
func parseFields(fieldsStr string) ([]string, error) {
	if fieldsStr == "" {
		return []string{}, nil
	}

	tokens := strings.Split(fieldsStr, ",")
	seen := make(map[string]struct{}, len(tokens))
	result := make([]string, 0, len(tokens))
	var unknown []string

	for _, token := range tokens {
		name := strings.TrimSpace(token)
		if name == "" {
			continue
		}
		if _, ok := validFieldNames[name]; !ok {
			unknown = append(unknown, name)
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			result = append(result, name)
		}
	}

	if len(unknown) > 0 {
		quoted := make([]string, 0, len(unknown))
		for _, u := range unknown {
			quoted = append(quoted, fmt.Sprintf("%q", u))
		}
		sorted := sortedFieldNames()
		return nil, fmt.Errorf("unknown field(s) %s; valid fields: %s",
			strings.Join(quoted, ", "),
			strings.Join(sorted, ", "))
	}

	return result, nil
}

// applyParsedFields sets the corresponding Show* booleans on opts from
// a pre-validated field list (returned by parseFields). The "all" keyword
// sets ShowAll; the render package expands it into individual flags during
// resolveRenderEnv.
func applyParsedFields(opts *render.Options, parsed []string) {
	fieldSet := make(map[string]struct{}, len(parsed))
	for _, f := range parsed {
		fieldSet[f] = struct{}{}
	}

	if _, ok := fieldSet["all"]; ok {
		opts.ShowAll = true
		return
	}

	for i := range fields {
		if _, ok := fieldSet[fields[i].name]; ok {
			fields[i].apply(opts)
		}
	}
}

// sortedFieldNames returns all --fields values (including "all") sorted
// alphabetically. Used in help text and error messages.
func sortedFieldNames() []string {
	names := make([]string, 0, len(validFieldNames))
	for name := range validFieldNames {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

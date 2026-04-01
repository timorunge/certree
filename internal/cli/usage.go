// Usage text generation: help output, examples, and version.

package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/timorunge/certree/internal/render"
)

// flagGroup pairs a section heading with an ordered list of flag names
// for --help output.
type flagGroup struct {
	name  string
	flags []string
}

// flagGroups defines the ordered sections and their flags for --help output.
var flagGroups = []flagGroup{
	{"Source", []string{"batch"}},
	{"Configuration", []string{"config"}},
	{"Trust Store", []string{"prefer-custom-roots", "system-roots", "trust-bundle"}},
	{"Connection", []string{"connect-timeout", "fetch-timeout", "sni", "client-cert",
		"client-key", "aia-fetch", "aia-force", "aia-timeout", "allow-private-networks"}},
	{"Validation", []string{
		"verify-signatures",
		"verify-expiry", "expiry-warning-days", "max-validity-days",
		"verify-hostname", "hostname",
		"verify-revocation", "revocation-fail-open",
		"verify-eku", "verify-name-constraints",
		"max-certificates", "max-depth", "skip-invalid",
	}},
	{"Display", []string{"fields", "filter-cn", "filter-fingerprint", "filter-serial",
		"annotations", "expand", "path-index", "reverse", "theme", "wrap"}},
	{"Output", []string{"color", "format", "quiet", "verbose"}},
	{"Simulation", []string{
		"compare", "diff", "exclude-cn", "exclude-fingerprint", "exclude-serial",
		"inject", "validation-time", "impact",
	}},
	{"Info", []string{"help", "version"}},
}

var (
	// noDefaultNames lists flags whose default value should not be shown in usage.
	noDefaultNames = []string{"verbose", "compare", "diff", "impact", "quiet", "help",
		"version"}

	// noDefaultValues lists default values that should not be shown in usage.
	noDefaultValues = []string{"", "0", "false", "[]"}
)

// showDefaultValue reports whether the flag's default should appear in usage output.
func showDefaultValue(f *pflag.Flag) bool {
	if slices.Contains(noDefaultNames, f.Name) || slices.Contains(noDefaultValues, f.DefValue) {
		return false
	}
	return true
}

// writeUsage writes the complete help output including header, sources,
// grouped options, and examples.
func writeUsage(fs *pflag.FlagSet, w io.Writer) {
	_, _ = fmt.Fprint(w, "certree - Certificate chain analyzer and visualizer\n\n")
	_, _ = fmt.Fprint(w, "USAGE:\n")
	_, _ = fmt.Fprint(w, "    certree [OPTIONS] [SOURCE ...]\n\n")

	writeSources(w)
	writeGroupedOptions(fs, w)
	writeExitCodes(w)
	writeExamples(w)
}

// writeVersion writes a single-line version string to the given writer.
func writeVersion(version string, w io.Writer) {
	_, _ = fmt.Fprintf(w, "certree %s\n", version)
}

// writeSources writes the SOURCES section documenting valid input types.
func writeSources(w io.Writer) {
	_, _ = fmt.Fprint(w, "SOURCE:\n")
	_, _ = fmt.Fprint(w, "    One or more positional arguments, each a certificate source:\n\n")
	_, _ = fmt.Fprint(w, "    FILE                          PEM, DER, PKCS#7, or PKCS#12 file\n")
	_, _ = fmt.Fprint(w, "    HOST or HOST:PORT             Remote TLS connection (port defaults to 443)\n")
	_, _ = fmt.Fprint(w, "                                  Note: bare names without dots (e.g. localhost)\n")
	_, _ = fmt.Fprint(w, "                                  are treated as files; use localhost:443 instead\n")
	_, _ = fmt.Fprint(w, "    URL or HOST/PATH              HTTPS certificate fetch (https:// inferred)\n")
	_, _ = fmt.Fprint(w, "    -                             Read from stdin (exclusive, once only)\n\n")
}

// writeGroupedOptions writes the OPTIONS section with flags organized by group.
// Long descriptions are word-wrapped at the detected terminal width with
// continuation lines indented to the description column.
func writeGroupedOptions(fs *pflag.FlagSet, w io.Writer) {
	_, _ = fmt.Fprint(w, "OPTIONS:\n\n")

	const descColumn = 34
	termWidth := usageTerminalWidth()

	for _, group := range flagGroups {
		var flags []*pflag.Flag
		for _, name := range group.flags {
			if f := fs.Lookup(name); f != nil {
				flags = append(flags, f)
			}
		}
		if len(flags) == 0 {
			continue
		}

		_, _ = fmt.Fprintf(w, "  %s:\n", group.name)

		for _, f := range flags {
			usage := f.Usage

			if showDefaultValue(f) {
				usage += fmt.Sprintf(" (default: %s)", f.DefValue)
			}

			var flagStr string
			if f.Shorthand != "" {
				flagStr = fmt.Sprintf("    -%s, --%s", f.Shorthand, f.Name)
			} else {
				flagStr = fmt.Sprintf("    --%s", f.Name)
			}

			typeName := f.Value.Type()
			if typeName != "bool" {
				if typeName == "stringArray" {
					flagStr += " STRING"
				} else {
					flagStr += " " + strings.ToUpper(typeName)
				}
			}

			indent := descColumn
			if len(flagStr) < descColumn {
				flagStr += strings.Repeat(" ", descColumn-len(flagStr))
			} else {
				flagStr += " "
				indent = len(flagStr)
			}

			_, _ = fmt.Fprintf(w, "%s%s\n", flagStr, wrapDescription(usage, indent, termWidth))
		}

		_, _ = fmt.Fprint(w, "\n")
	}
}

// usageTerminalWidth returns the terminal width for help output, with a
// 2-column right margin for visual breathing room.
func usageTerminalWidth() int {
	return render.TerminalWidth() - 2
}

// wrapDescription word-wraps a description string so that the first line
// starts at column indent and subsequent lines are indented to the same
// column. Words are never broken. If the terminal is too narrow for any
// wrapping (indent >= termWidth), the description is returned as-is.
func wrapDescription(desc string, indent, termWidth int) string {
	maxWidth := termWidth - indent
	if maxWidth < 10 || len(desc) <= maxWidth {
		return desc
	}

	continuation := "\n" + strings.Repeat(" ", indent)
	words := strings.Fields(desc)

	var b strings.Builder
	lineLen := 0

	for i, word := range words {
		wl := len(word)
		if i == 0 {
			b.WriteString(word)
			lineLen = wl
			continue
		}
		if lineLen+1+wl > maxWidth {
			b.WriteString(continuation)
			b.WriteString(word)
			lineLen = wl
		} else {
			b.WriteByte(' ')
			b.WriteString(word)
			lineLen += 1 + wl
		}
	}
	return b.String()
}

// writeExitCodes writes the EXIT CODES section documenting process exit values.
func writeExitCodes(w io.Writer) {
	_, _ = fmt.Fprint(w, "EXIT CODES:\n")
	_, _ = fmt.Fprint(w, "    0  All certificates valid\n")
	_, _ = fmt.Fprint(w, "    1  Certificate validation failed (expired, untrusted, etc.)\n")
	_, _ = fmt.Fprint(w, "    2  Invalid arguments or missing sources\n")
	_, _ = fmt.Fprint(w, "    3  Invalid config file or conflicting options\n")
	_, _ = fmt.Fprint(w, "    4  Remote host unreachable or TLS handshake failed\n")
	_, _ = fmt.Fprint(w, "    5  Certificate file could not be parsed\n")
	_, _ = fmt.Fprint(w, "    6  Output rendering failure\n\n")
}

// writeExamples writes the EXAMPLES section with common usage patterns.
func writeExamples(w io.Writer) {
	_, _ = fmt.Fprint(w, "EXAMPLES:\n")
	_, _ = fmt.Fprint(w, "    certree cert.pem                                    # Analyze local file\n")
	_, _ = fmt.Fprint(w, "    certree example.com                                 # Analyze remote host\n")
	_, _ = fmt.Fprint(w, "    certree --fields all example.com                    # Show all fields\n")
	_, _ = fmt.Fprint(w, "    certree --format json cert.pem | jq '.[].metadata'  # JSON for scripting\n")
	_, _ = fmt.Fprint(w, "    certree --exclude-cn \"Old CA\" --compare cert.pem    # Simulate exclusion\n")
}

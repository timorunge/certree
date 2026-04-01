// Source classification, normalization, and validation for certificate analysis inputs.

package certree

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// SourceKind classifies a certificate source string as provided by the caller
// (file path, hostname, URL, or stdin). It represents the input form before
// analysis begins and drives source normalization and validation. Compare with
// [SourceType], which records where a certificate was actually obtained during
// parsing (including AIA-fetched and raw-bytes sources that have no SourceKind
// equivalent).
type SourceKind int

// Source kind constants for [DetectSource] and [NormalizeSource].
const (
	SourceFile  SourceKind = iota // Local file path.
	SourceHost                    // Remote host:port.
	SourceStdin                   // Standard input ("-").
	SourceURL                     // HTTP(S) URL.
)

// certFileExtensions lists file extensions recognized as certificate or key
// material. Shared between source classification and the CLI.
var certFileExtensions = []string{
	".pem", ".crt", ".cer", ".der",
	".p7b", ".p7c", ".p12", ".pfx",
}

// hostnameRegexp validates bare hostnames: DNS labels (alphanumeric +
// hyphens) separated by dots, with an optional :port suffix.
var hostnameRegexp = regexp.MustCompile(
	`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\d{1,5})?$`,
)

// hasCertFileExtension reports whether path ends with a known certificate file
// extension (.pem, .crt, .cer, .der, .p7b, .p7c, .p12, .pfx).
// The check is case-insensitive.
func hasCertFileExtension(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range certFileExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// isURL reports whether source starts with http:// or https://.
func isURL(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

// isFilePath reports whether source is an absolute, relative, or Windows path.
func isFilePath(source string) bool {
	if source == "" {
		return false
	}
	if source[0] == '/' || source[0] == '.' {
		return true
	}
	// Windows: C:\path or C:/path
	if len(source) >= 3 && source[1] == ':' && (source[2] == '\\' || source[2] == '/') {
		return true
	}
	return strings.ContainsRune(source, '\\')
}

// isHostname reports whether source matches a strict hostname pattern.
// Requires at least one dot (to exclude bare words like "localhost") and
// rejects known certificate file extensions. Port values are validated
// to be within the 1-65535 range.
func isHostname(source string) bool {
	if !strings.Contains(source, ".") {
		return false
	}
	if hasCertFileExtension(source) {
		return false
	}
	if !hostnameRegexp.MatchString(source) {
		return false
	}
	// Validate port range when present.
	if idx := strings.LastIndexByte(source, ':'); idx >= 0 {
		port, err := strconv.Atoi(source[idx+1:])
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return true
}

// isIPAddress reports whether source is an IPv4/IPv6 address, with or without
// a port suffix (e.g., "192.168.1.1", "192.168.1.1:443", "[::1]:443").
func isIPAddress(source string) bool {
	if host, _, err := net.SplitHostPort(source); err == nil {
		return net.ParseIP(host) != nil
	}
	return net.ParseIP(source) != nil
}

// classifySource determines what kind of certificate source a string
// represents. For ambiguous bare names (e.g., "go.mod"), this function
// classifies purely by string analysis -- it does not access the filesystem.
// Callers that need local-file-takes-precedence behavior should use
// [DetectSource], which adds an os.Stat fallback for [SourceHost] results.
func classifySource(source string) SourceKind {
	if source == "-" {
		return SourceStdin
	}
	if isURL(source) {
		return SourceURL
	}
	if isFilePath(source) {
		return SourceFile
	}
	// host/path form: "example.com/certs/ca.pem"
	if slashIdx := strings.IndexByte(source, '/'); slashIdx > 0 {
		if isHostname(source[:slashIdx]) {
			return SourceURL
		}
		return SourceFile
	}
	if strings.Contains(source, ":") {
		return SourceHost
	}
	if isHostname(source) {
		return SourceHost
	}
	return SourceFile
}

// DetectSource classifies a source string with filesystem awareness.
// It delegates to [classifySource] for string analysis, then checks the
// filesystem: if the result is [SourceHost] but a local file with that
// name exists, the file takes precedence. This handles ambiguous names
// like "go.mod" that look like hostnames but are local files.
func DetectSource(source string) SourceKind {
	kind := classifySource(source)
	if kind == SourceHost {
		if _, err := os.Stat(source); err == nil {
			return SourceFile
		}
	}
	return kind
}

// NormalizeSource returns the source in the canonical form expected by
// [Analyzer] methods. Bare hostnames get ":443" appended; bare host/path
// forms (classified as [SourceURL]) get "https://" prepended.
// Uses [DetectSource] (with filesystem fallback) to match [Analyze]'s
// classification, ensuring files named like hostnames are not normalized
// as network sources.
func NormalizeSource(source string) string {
	return normalizeByKind(source, DetectSource(source))
}

// normalizeByKind applies kind-specific normalization to source.
// Extracted so [Analyze] can reuse the result of a single [DetectSource] call.
func normalizeByKind(source string, kind SourceKind) string {
	switch kind {
	case SourceHost:
		if !strings.Contains(source, ":") {
			return source + ":443"
		}
	case SourceURL:
		if !isURL(source) {
			return "https://" + source
		}
	}
	return source
}

// maxSourceLength is the maximum length for a source string. Hostnames are
// limited to 253 chars by DNS, and file paths are limited to 4096 on most
// systems. This generous limit catches accidental misuse (e.g., piping file
// content as an argument) while allowing all legitimate paths.
const maxSourceLength = 4096

// ValidateSource checks that source is a recognized format: stdin, HTTPS URL,
// hostname, IP address, or file path. For file sources that exist on disk,
// it sniffs the first bytes to verify PEM or DER content.
//
// Errors from this function may be [*StructuredError] with [ErrInvalidInput].
func ValidateSource(source string) error {
	if len(source) > maxSourceLength {
		return NewStructuredError(
			fmt.Sprintf("source is too long (%d characters, maximum %d)", len(source), maxSourceLength),
			ErrInvalidInput, nil,
		)
	}
	kind := DetectSource(source)
	switch kind {
	case SourceStdin:
		return nil
	case SourceURL:
		normalized := NormalizeSource(source)
		if !strings.HasPrefix(normalized, "https://") {
			return NewStructuredError(
				fmt.Sprintf("unsupported URL scheme in %q: use https:// instead of http://", source),
				ErrInvalidInput, nil,
			)
		}
		return nil
	case SourceHost:
		if isHostname(source) || isIPAddress(source) {
			return nil
		}
	case SourceFile:
		if err := validateFileSource(source); err != nil {
			return NewStructuredError(err.Error(), ErrInvalidInput, err)
		}
		return nil
	}
	return NewStructuredError(
		fmt.Sprintf("unrecognized source %q: expected a hostname, IP address, HTTPS URL, or certificate file", source),
		ErrInvalidInput, nil,
	)
}

// validateFileSource sniffs existing files for PEM/DER content. Non-existent
// files with a cert extension pass through to the parser.
func validateFileSource(source string) error {
	if err := sniffCertFile(source); err != nil {
		return err
	}
	// sniffCertFile returns nil for both valid files and non-existent files.
	if _, err := os.Stat(source); err != nil && !hasCertFileExtension(source) {
		return fmt.Errorf("unrecognized source %q: expected a hostname, IP address, HTTPS URL, or certificate file", source)
	}
	return nil
}

// sniffCertFile peeks at the first bytes of an existing file to detect PEM
// ("-----BEGIN") or DER (ASN.1 SEQUENCE tag 0x30) format markers. PEM
// bundles may have comment lines before the first BEGIN block (e.g., the
// macOS system cert bundle), so up to 4 KB is scanned. Returns nil for
// non-existent files so the parser can produce a proper StructuredError.
func sniffCertFile(path string) error {
	// #nosec G304 -- Path comes from user-supplied argument, validated upstream.
	f, err := os.Open(path)
	if err != nil {
		return nil // non-existent or inaccessible; let parser handle
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("file %q is empty", path)
	}

	var buf [4096]byte
	n, readErr := f.Read(buf[:])
	if n == 0 {
		if readErr != nil {
			return nil
		}
		return fmt.Errorf("file %q is empty", path)
	}

	data := buf[:n]
	if buf[0] == 0x30 || bytes.Contains(data, []byte("-----BEGIN")) {
		return nil
	}
	return fmt.Errorf("file %q does not contain certificate data (expected PEM or DER format)", path)
}

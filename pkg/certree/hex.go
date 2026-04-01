// Hex string normalization helpers for certificate fingerprint formatting.

package certree

import "strings"

// ColonHex inserts colons between every pair of hex characters.
// For example, "A887602F" becomes "A8:87:60:2F". A trailing
// odd character is preserved without a preceding colon separator.
func ColonHex(s string) string {
	if len(s) <= 2 {
		return s
	}
	// Upper bound: each pair adds one colon except the first.
	pairs := (len(s) + 1) / 2
	dst := make([]byte, 0, len(s)+pairs-1)
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			dst = append(dst, ':')
		}
		dst = append(dst, s[i])
		if i+1 < len(s) {
			dst = append(dst, s[i+1])
		}
	}
	return string(dst)
}

// HexEncodeUpper encodes src as uppercase hexadecimal with only one allocation
// (the final string). This avoids the 3-4 allocations of fmt.Sprintf("%X", ...).
func HexEncodeUpper(src []byte) string {
	const hextable = "0123456789ABCDEF"
	dst := make([]byte, len(src)*2)
	for i, v := range src {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}

// ColonHexBytes encodes src as uppercase hex with colon separators.
// Equivalent to ColonHex(HexEncodeUpper(src)).
func ColonHexBytes(src []byte) string {
	return ColonHex(HexEncodeUpper(src))
}

// stripColons removes all colon characters from s.
// Used to normalize user input (e.g., "A8:87:60:2F" -> "A887602F") before
// pattern matching against internal hex values.
func stripColons(s string) string {
	if !strings.ContainsRune(s, ':') {
		return s
	}
	dst := make([]byte, 0, len(s))
	for i := range len(s) {
		if s[i] != ':' {
			dst = append(dst, s[i])
		}
	}
	return string(dst)
}

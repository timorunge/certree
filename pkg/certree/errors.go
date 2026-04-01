// Sentinel errors and the StructuredError type for the certree package.

package certree

import (
	"errors"
)

// Input errors.
var (
	ErrEmptyInput   = errors.New("certree: empty input")
	ErrNilArgument  = errors.New("certree: nil argument")
	ErrInvalidInput = errors.New("certree: invalid input")
)

// Format and parsing errors.
var (
	ErrUnknownFormat    = errors.New("certree: unknown certificate format")
	ErrParseFailed      = errors.New("certree: parse failed")
	ErrPasswordRequired = errors.New("certree: PKCS#12 password required")
)

// File I/O errors.
var (
	ErrFileReadFailed = errors.New("certree: file read failed")
)

// Size and limit errors.
var (
	ErrFileTooLarge             = errors.New("certree: file too large")
	ErrInputTooLarge            = errors.New("certree: input too large")
	ErrCertificateLimitExceeded = errors.New("certree: certificate limit exceeded")
)

// Certificate discovery errors.
var (
	ErrNoCertificatesFound = errors.New("certree: no certificates found")
)

// Network and connection errors.
var (
	ErrConnectionFailed  = errors.New("certree: connection failed")
	ErrHTTPError         = errors.New("certree: HTTP error")
	ErrInvalidHostFormat = errors.New("certree: invalid host format")
	ErrSNIRequired       = errors.New("certree: SNI required")
)

// Revocation checking errors.
var (
	ErrRevocationCheckFailed   = errors.New("certree: revocation check failed")
	ErrResponseStale           = errors.New("certree: stale response")
	ErrResponseNotYetValid     = errors.New("certree: response not yet valid")
	ErrNoOCSPResponders        = errors.New("certree: no OCSP responders")
	ErrNoCRLDistributionPoints = errors.New("certree: no CRL distribution points")
	ErrOCSPUnknownStatus       = errors.New("certree: OCSP unknown status")
	ErrCRLIssuerMismatch       = errors.New("certree: CRL issuer mismatch")
)

// AIA (Authority Information Access) errors.
var (
	ErrNoAIAURLs      = errors.New("certree: no AIA URLs")
	ErrAIAFetchFailed = errors.New("certree: AIA fetch failed")
)

// URL errors.
var (
	ErrURLFetchFailed    = errors.New("certree: URL fetch failed")
	ErrBlockedURL        = errors.New("certree: blocked URL")
	ErrUnsupportedScheme = errors.New("certree: unsupported URL scheme")
	ErrPrivateAddress    = errors.New("certree: private address")
)

// Platform errors.
var (
	ErrPlatformNotSupported = errors.New("certree: platform not supported")
)

// Constructor errors.
var (
	ErrParserRequired = errors.New("certree: parser required")
)

// Context errors.
var (
	ErrContextCanceled = errors.New("certree: context canceled")
)

// Analysis pipeline errors.
var (
	ErrChainBuildFailed = errors.New("certree: chain build failed")
	ErrValidationFailed = errors.New("certree: validation failed")
)

// StructuredError carries a user-facing message, a sentinel error category,
// and the underlying cause error. It implements the error interface with
// sentinel matching via Is and cause chain traversal via Unwrap.
type StructuredError struct {
	message  string // short, actionable, no internal details
	category error  // sentinel error (e.g., ErrConnectionFailed)
	cause    error  // raw Go error with full diagnostic detail
}

// NewStructuredError creates a structured error with a user message,
// sentinel category, and underlying cause. Panics if category is nil
// since sentinel matching via Is would silently fail.
func NewStructuredError(message string, category error, cause error) *StructuredError {
	if category == nil {
		panic("certree: NewStructuredError called with nil category")
	}
	return &StructuredError{
		message:  message,
		category: category,
		cause:    cause,
	}
}

var _ error = (*StructuredError)(nil)

// Error returns the user-facing message (same as [StructuredError.UserMessage]).
func (se *StructuredError) Error() string {
	return se.message
}

// UserMessage returns the short, actionable message for display to end users.
func (se *StructuredError) UserMessage() string {
	return se.message
}

// Detail returns the underlying cause error with full diagnostic detail.
func (se *StructuredError) Detail() error {
	return se.cause
}

// Category returns the sentinel error category for programmatic matching.
func (se *StructuredError) Category() error {
	return se.category
}

// Unwrap returns the underlying cause error for errors.Is/errors.As traversal.
func (se *StructuredError) Unwrap() error {
	return se.cause
}

// Is reports whether target matches the sentinel category of this error.
func (se *StructuredError) Is(target error) bool {
	return se.category != nil && errors.Is(se.category, target)
}

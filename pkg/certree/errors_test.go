package certree

import (
	"errors"
	"fmt"
	"testing"
)

func TestStructuredError_ErrorMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		message string
		cause   error
		want    string
	}{
		{
			name:    "with cause returns message only",
			message: "could not connect to example.com:443",
			cause:   errors.New("dial tcp: lookup example.com: no such host"),
			want:    "could not connect to example.com:443",
		},
		{
			name:    "without cause",
			message: "SNI is required for IP address 1.2.3.4",
			cause:   nil,
			want:    "SNI is required for IP address 1.2.3.4",
		},
		{
			name:    "empty message with cause",
			message: "",
			cause:   errors.New("underlying error"),
			want:    "",
		},
		{
			name:    "empty message without cause",
			message: "",
			cause:   nil,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			se := NewStructuredError(tt.message, ErrConnectionFailed, tt.cause)
			if got := se.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
			if got := se.UserMessage(); got != tt.want {
				t.Errorf("UserMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStructuredError_NilCategory(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil category, got none")
		}
		msg, ok := r.(string)
		if !ok || msg != "certree: NewStructuredError called with nil category" {
			t.Fatalf("unexpected panic value: %v", r)
		}
	}()

	cause := errors.New("underlying error")
	_ = NewStructuredError("something failed", nil, cause)
}

func TestStructuredError_IsMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		category error
		target   error
		want     bool
	}{
		{
			name:     "matching category",
			category: ErrConnectionFailed,
			target:   ErrConnectionFailed,
			want:     true,
		},
		{
			name:     "non-matching category",
			category: ErrConnectionFailed,
			target:   ErrParseFailed,
			want:     false,
		},
		{
			name:     "different sentinel same group",
			category: ErrResponseStale,
			target:   ErrResponseNotYetValid,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			se := NewStructuredError("test message", tt.category, nil)

			if got := se.Is(tt.target); got != tt.want {
				t.Errorf("Is(%v) = %v, want %v", tt.target, got, tt.want)
			}

			// Also verify via errors.Is which calls the custom Is method.
			if got := errors.Is(se, tt.target); got != tt.want {
				t.Errorf("errors.Is(se, %v) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestStructuredError_ExistingSentinels(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		ErrEmptyInput,
		ErrNilArgument,
		ErrInvalidInput,
		ErrUnknownFormat,
		ErrParseFailed,
		ErrFileReadFailed,
		ErrFileTooLarge,
		ErrInputTooLarge,
		ErrCertificateLimitExceeded,
		ErrNoCertificatesFound,
		ErrConnectionFailed,
		ErrHTTPError,
		ErrInvalidHostFormat,
		ErrSNIRequired,
		ErrRevocationCheckFailed,
		ErrResponseStale,
		ErrResponseNotYetValid,
		ErrNoOCSPResponders,
		ErrNoCRLDistributionPoints,
		ErrOCSPUnknownStatus,
		ErrNoAIAURLs,
		ErrAIAFetchFailed,
		ErrURLFetchFailed,
		ErrBlockedURL,
		ErrUnsupportedScheme,
		ErrPrivateAddress,
		ErrPlatformNotSupported,
		ErrParserRequired,
		ErrChainBuildFailed,
		ErrValidationFailed,
	}

	cause := errors.New("test cause")

	for _, sentinel := range sentinels {
		t.Run(sentinel.Error(), func(t *testing.T) {
			t.Parallel()

			se := NewStructuredError("test message", sentinel, cause)

			if !errors.Is(se, sentinel) {
				t.Errorf("errors.Is(se, %v) = false, want true", sentinel)
			}

			if got := se.Category(); got != sentinel {
				t.Errorf("Category() = %v, want %v", got, sentinel)
			}
		})
	}
}

func TestStructuredError_WrappedExtraction(t *testing.T) {
	t.Parallel()

	const userMsg = "could not connect to example.com:443"

	se := NewStructuredError(userMsg, ErrConnectionFailed, errors.New("dial error"))
	wrapped := fmt.Errorf("parsing certificates: %w", se)

	var extracted *StructuredError
	if !errors.As(wrapped, &extracted) {
		t.Fatal("errors.As failed to extract StructuredError through wrapping")
	}

	if got := extracted.UserMessage(); got != userMsg {
		t.Errorf("UserMessage() = %q, want %q", got, userMsg)
	}

	if !errors.Is(wrapped, ErrConnectionFailed) {
		t.Error("errors.Is(wrapped, ErrConnectionFailed) = false after wrapping, want true")
	}
}

func TestStructuredError_CauseChainTraversal(t *testing.T) {
	t.Parallel()

	innerSentinel := errors.New("inner sentinel")
	wrappedCause := fmt.Errorf("layer 1: %w", fmt.Errorf("layer 2: %w", innerSentinel))

	se := NewStructuredError("operation failed", ErrConnectionFailed, wrappedCause)

	// The inner sentinel should be reachable through the cause chain.
	if !errors.Is(se, innerSentinel) {
		t.Error("errors.Is(se, innerSentinel) = false, want true via cause chain")
	}

	// The category should also be reachable via Is method.
	if !errors.Is(se, ErrConnectionFailed) {
		t.Error("errors.Is(se, ErrConnectionFailed) = false, want true via Is method")
	}

	// A sentinel that is neither the category nor in the cause chain should not match.
	if errors.Is(se, ErrParseFailed) {
		t.Error("errors.Is(se, ErrParseFailed) = true, want false")
	}
}

// TestStructuredError_IsSymmetry documents that two StructuredErrors with the
// same category do NOT match each other via errors.Is. The Is method only
// matches sentinel errors (category), not other StructuredError instances.
func TestStructuredError_IsSymmetry(t *testing.T) {
	t.Parallel()

	se1 := NewStructuredError("msg one", ErrConnectionFailed, nil)
	se2 := NewStructuredError("msg two", ErrConnectionFailed, nil)

	// Two StructuredErrors never match each other, even with the same category.
	if errors.Is(se1, se2) {
		t.Error("errors.Is(se1, se2) = true, want false: StructuredErrors match sentinels only")
	}
	if errors.Is(se2, se1) {
		t.Error("errors.Is(se2, se1) = true, want false: StructuredErrors match sentinels only")
	}
}

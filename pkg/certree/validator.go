// Validation types, error categories, and certificate/chain validation logic.

package certree

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
)

// ErrorType categorizes validation errors.
type ErrorType int

const (
	// Certificate validity errors.

	// ErrorExpired indicates the certificate has expired.
	ErrorExpired ErrorType = iota
	// ErrorNotYetValid indicates the certificate is not yet valid.
	ErrorNotYetValid

	// Cryptographic verification errors.

	// ErrorSignatureInvalid indicates the certificate signature verification failed.
	ErrorSignatureInvalid
	// ErrorInvalidBasicConstraints indicates an intermediate certificate lacks CA:TRUE.
	ErrorInvalidBasicConstraints
	// ErrorMissingKeyUsage indicates an issuer certificate lacks the KeyUsageCertSign bit.
	ErrorMissingKeyUsage

	// Revocation errors.

	// ErrorRevoked indicates the certificate has been revoked.
	ErrorRevoked
	// ErrorRevocationCheckFailed indicates the revocation check could not be completed.
	// This is distinct from ErrorRevoked which indicates a confirmed revocation.
	// A revocation check failure means the OCSP/CRL check encountered an error
	// (network timeout, server error, stale response) and fail-closed mode is active.
	//
	// Note: This is an [ErrorType] constant (validation classification), not a
	// sentinel error. The sentinel for errors.Is matching is [ErrRevocationCheckFailed].
	ErrorRevocationCheckFailed

	// Chain structure errors.

	// ErrorCircularReference indicates a circular reference was detected in the chain.
	ErrorCircularReference
	// ErrorDepthExceeded indicates the maximum chain depth was exceeded.
	ErrorDepthExceeded
	// ErrorPathLenExceeded indicates a certificate violates its issuer's path length constraint.
	ErrorPathLenExceeded
	// ErrorUntrustedRoot indicates the root certificate is not trusted.
	ErrorUntrustedRoot

	// Hostname verification errors.

	// ErrorHostnameMismatch indicates the certificate hostname does not match.
	ErrorHostnameMismatch

	// EKU chaining errors.

	// ErrorInvalidEKU indicates that a certificate's Extended Key Usage contains
	// values not permitted by its issuer's EKU constraint (RFC 5280 section 4.2.1.12).
	// If an intermediate CA has an EKU extension, any certificate it issues must
	// carry only EKU values present in that extension.
	ErrorInvalidEKU

	// Name constraint errors.

	// ErrorNameConstraintViolation indicates that a certificate violates a name
	// constraint imposed by a CA in the chain (RFC 5280 section 4.2.1.10). Name
	// constraints restrict the permitted DNS names, IP ranges, email addresses,
	// or URIs that subordinate certificates may use.
	ErrorNameConstraintViolation

	// Key usage errors.

	// ErrorInvalidKeyUsage indicates that a TLS server certificate's Key Usage
	// extension does not include any of the usages required for TLS authentication
	// (RFC 5280 section 4.2.1.3): KeyUsageDigitalSignature, KeyUsageKeyEncipherment, or
	// KeyUsageKeyAgreement.
	ErrorInvalidKeyUsage

	// Serial number errors.

	// ErrorInvalidSerialNumber indicates that a certificate's serial number
	// violates RFC 5280 section 4.1.2.2: it must be a positive integer of at most 20 octets.
	ErrorInvalidSerialNumber
)

// String returns the string representation of ErrorType.
func (et ErrorType) String() string {
	switch et {
	case ErrorExpired:
		return "expired"
	case ErrorNotYetValid:
		return "not_yet_valid"
	case ErrorSignatureInvalid:
		return "signature_invalid"
	case ErrorInvalidBasicConstraints:
		return "invalid_basic_constraints"
	case ErrorMissingKeyUsage:
		return "missing_key_usage"
	case ErrorRevoked:
		return "revoked"
	case ErrorRevocationCheckFailed:
		return "revocation_check_failed"
	case ErrorCircularReference:
		return "circular_reference"
	case ErrorDepthExceeded:
		return "depth_exceeded"
	case ErrorPathLenExceeded:
		return "path_length_exceeded"
	case ErrorUntrustedRoot:
		return "untrusted_root"
	case ErrorHostnameMismatch:
		return "hostname_mismatch"
	case ErrorInvalidEKU:
		return "invalid_eku"
	case ErrorNameConstraintViolation:
		return "name_constraint_violation"
	case ErrorInvalidKeyUsage:
		return "invalid_key_usage"
	case ErrorInvalidSerialNumber:
		return "invalid_serial_number"
	default:
		return fmt.Sprintf("ErrorType(%d)", int(et))
	}
}

// MarshalJSON implements custom JSON serialization for ErrorType.
func (et ErrorType) MarshalJSON() ([]byte, error) {
	return json.Marshal(et.String())
}

// UnmarshalJSON implements json.Unmarshaler for ErrorType.
func (et *ErrorType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("unmarshaling ErrorType: %w", err)
	}
	switch s {
	case "expired":
		*et = ErrorExpired
	case "not_yet_valid":
		*et = ErrorNotYetValid
	case "signature_invalid":
		*et = ErrorSignatureInvalid
	case "invalid_basic_constraints":
		*et = ErrorInvalidBasicConstraints
	case "missing_key_usage":
		*et = ErrorMissingKeyUsage
	case "revoked":
		*et = ErrorRevoked
	case "revocation_check_failed":
		*et = ErrorRevocationCheckFailed
	case "circular_reference":
		*et = ErrorCircularReference
	case "depth_exceeded":
		*et = ErrorDepthExceeded
	case "path_length_exceeded":
		*et = ErrorPathLenExceeded
	case "untrusted_root":
		*et = ErrorUntrustedRoot
	case "hostname_mismatch":
		*et = ErrorHostnameMismatch
	case "invalid_eku":
		*et = ErrorInvalidEKU
	case "name_constraint_violation":
		*et = ErrorNameConstraintViolation
	case "invalid_key_usage":
		*et = ErrorInvalidKeyUsage
	case "invalid_serial_number":
		*et = ErrorInvalidSerialNumber
	default:
		return fmt.Errorf("unknown ErrorType value %q: %w", s, ErrInvalidInput)
	}
	return nil
}

// ValidationError represents a validation failure with structured information
// about the certificate that failed, the error type, and additional details.
type ValidationError struct {
	Certificate *Certificate   `json:"certificate,omitempty"`
	Type        ErrorType      `json:"type"`
	Message     string         `json:"message"`
	Details     map[string]any `json:"details,omitempty"`
}

// Error implements the error interface.
func (ve ValidationError) Error() string {
	if ve.Certificate != nil {
		return fmt.Sprintf("%s: %s (cert: %s)", ve.Type, ve.Message, ve.Certificate.CommonName())
	}
	return fmt.Sprintf("%s: %s", ve.Type, ve.Message)
}

// Reason returns a short human-readable label for display annotations.
func (ve ValidationError) Reason() string {
	switch ve.Type {
	case ErrorExpired:
		return "expired"
	case ErrorNotYetValid:
		return "not yet valid"
	case ErrorSignatureInvalid:
		return "signature invalid"
	case ErrorInvalidBasicConstraints:
		return "invalid basic constraints"
	case ErrorMissingKeyUsage:
		return "missing key usage"
	case ErrorRevoked:
		return "revoked"
	case ErrorRevocationCheckFailed:
		return "revocation check failed"
	case ErrorCircularReference:
		return "circular reference"
	case ErrorDepthExceeded:
		return "depth exceeded"
	case ErrorPathLenExceeded:
		return "path length exceeded"
	case ErrorUntrustedRoot:
		return "untrusted root"
	case ErrorHostnameMismatch:
		return "hostname mismatch"
	case ErrorInvalidEKU:
		return "extended key usage not permitted by issuer"
	case ErrorNameConstraintViolation:
		return "name constraint violation"
	case ErrorInvalidKeyUsage:
		return "invalid key usage"
	case ErrorInvalidSerialNumber:
		return "invalid serial number"
	default:
		return ""
	}
}

var _ error = ValidationError{}

// WarningType categorizes warnings.
type WarningType int

const (
	// Certificate-level warnings.

	// WarningExpiringSoon indicates the certificate will expire soon.
	WarningExpiringSoon WarningType = iota
	// WarningRevocationCheckFailed indicates the revocation check failed.
	WarningRevocationCheckFailed

	// Chain-level warnings.

	// WarningIncompleteChain indicates the certificate chain is incomplete.
	WarningIncompleteChain
	// WarningDuplicateCertificate indicates a duplicate certificate was found in the input pool.
	WarningDuplicateCertificate

	// Simulation warnings.

	// WarningExcludedBySimulation indicates the certificate was excluded by simulation.
	WarningExcludedBySimulation

	// Key security warnings.

	// WarningWeakKey indicates the certificate uses a public key that is too
	// small to provide adequate security (e.g., RSA < 2048 bits, EC < 224 bits).
	WarningWeakKey
	// WarningWeakAlgorithm indicates the certificate uses a deprecated signature
	// algorithm such as MD5 or SHA-1 that is no longer considered secure.
	WarningWeakAlgorithm

	// Certificate content warnings.

	// WarningMissingSAN indicates the end-entity certificate has no Subject
	// Alternative Names extension. Relying on the Subject CN for hostname
	// matching is deprecated per RFC 6125.
	WarningMissingSAN

	// Certificate lifetime warnings.

	// WarningCertLifetime indicates the certificate validity period exceeds
	// the configured maximum. The CA/Browser Forum Baseline Requirements
	// cap TLS server certificate validity at 398 days.
	WarningCertLifetime
)

// String returns the string representation of WarningType.
func (wt WarningType) String() string {
	switch wt {
	case WarningExpiringSoon:
		return "expiring_soon"
	case WarningRevocationCheckFailed:
		return "revocation_check_failed"
	case WarningIncompleteChain:
		return "incomplete_chain"
	case WarningDuplicateCertificate:
		return "duplicate_certificate"
	case WarningExcludedBySimulation:
		return "excluded_by_simulation"
	case WarningWeakKey:
		return "weak_key"
	case WarningWeakAlgorithm:
		return "weak_algorithm"
	case WarningMissingSAN:
		return "missing_san"
	case WarningCertLifetime:
		return "cert_lifetime_exceeded"
	default:
		return fmt.Sprintf("WarningType(%d)", int(wt))
	}
}

// MarshalJSON implements custom JSON serialization for WarningType.
func (wt WarningType) MarshalJSON() ([]byte, error) {
	return json.Marshal(wt.String())
}

// UnmarshalJSON implements json.Unmarshaler for WarningType.
func (wt *WarningType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("unmarshaling WarningType: %w", err)
	}
	switch s {
	case "expiring_soon":
		*wt = WarningExpiringSoon
	case "revocation_check_failed":
		*wt = WarningRevocationCheckFailed
	case "incomplete_chain":
		*wt = WarningIncompleteChain
	case "duplicate_certificate":
		*wt = WarningDuplicateCertificate
	case "excluded_by_simulation":
		*wt = WarningExcludedBySimulation
	case "weak_key":
		*wt = WarningWeakKey
	case "weak_algorithm":
		*wt = WarningWeakAlgorithm
	case "missing_san":
		*wt = WarningMissingSAN
	case "cert_lifetime_exceeded":
		*wt = WarningCertLifetime
	default:
		return fmt.Errorf("unknown WarningType value %q: %w", s, ErrInvalidInput)
	}
	return nil
}

// ValidationWarning represents a non-fatal issue.
type ValidationWarning struct {
	// Certificate is the certificate that triggered this warning; nil for path-level warnings.
	Certificate *Certificate `json:"certificate,omitempty"`
	Type        WarningType  `json:"type"`
	Message     string       `json:"message"`
}

// Reason returns a short human-readable label for display annotations.
func (w ValidationWarning) Reason() string {
	switch w.Type {
	case WarningExpiringSoon:
		if w.Certificate != nil {
			return fmt.Sprintf("expires in %d days", w.Certificate.Metadata().DaysUntilExpiry)
		}
		return "expiring soon"
	case WarningRevocationCheckFailed:
		return "revocation check failed"
	case WarningIncompleteChain:
		return "incomplete chain"
	case WarningDuplicateCertificate:
		return "duplicate certificate"
	case WarningExcludedBySimulation:
		return "broken"
	case WarningWeakKey:
		return weakKeyReason(w.Certificate)
	case WarningWeakAlgorithm:
		return "deprecated signature algorithm"
	case WarningMissingSAN:
		return "no Subject Alternative Names"
	case WarningCertLifetime:
		return "validity period exceeds maximum"
	default:
		return ""
	}
}

// weakKeyReason returns a short label for a weak public key warning.
func weakKeyReason(cert *Certificate) string {
	if cert == nil {
		return "weak public key"
	}
	switch pub := cert.Raw().PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("weak RSA key (%d bits)", pub.N.BitLen())
	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			return fmt.Sprintf("weak EC key (%d bits)", pub.Curve.Params().BitSize)
		}
		return "weak EC key"
	default:
		return "weak public key"
	}
}

// Validator validates certificate chains according to configurable rules.
// It can verify signatures, check expiry dates, verify hostnames, and check
// revocation status via OCSP or CRL.
type Validator interface {
	// Validate validates all trust paths according to the provided options.
	// It checks each certificate in each path for signature validity, expiry,
	// hostname match, and revocation status based on the options.
	// Returns an error if validation fails or context is canceled.
	Validate(ctx context.Context, paths []*TrustPath, opts ValidationOptions) error
}

// ValidationOptions configures validation behavior for certificate chains.
// All boolean fields default to false, meaning no validation is performed
// unless explicitly enabled.
type ValidationOptions struct {
	// VerifyExpiry enables expiry date validation. Certificates are checked to
	// ensure they are currently valid (not expired and not yet valid).
	VerifyExpiry bool

	// ExpiryWarningDays specifies how many days before expiry to generate warnings.
	// For example, if set to 30, certificates expiring within 30 days will
	// generate warnings (but not errors). A value of 0 disables expiring-soon
	// warnings while still detecting already-expired certificates. The zero
	// value disables the warning; [Analyzer] defaults to [DefaultExpiryWarningDays]
	// (30) when constructing ValidationOptions internally.
	ExpiryWarningDays int

	// VerifyHostname enables hostname verification for the end-entity certificate.
	// The certificate's Subject Alternative Names and Common Name are checked
	// against the Hostname field.
	VerifyHostname bool

	// Hostname is the hostname to verify against the end-entity certificate.
	// Only used when VerifyHostname is true.
	Hostname string

	// VerifyRevocation enables revocation checking via OCSP or CRL.
	// Requires a RevocationChecker to be configured.
	VerifyRevocation bool

	// RevocationFailOpen controls behavior when revocation checks fail.
	// If true, failed checks result in warnings but don't fail validation.
	// If false, failed checks result in validation errors.
	RevocationFailOpen bool

	// VerifySignatures enables cryptographic signature verification for each
	// certificate in the chain. Each certificate's signature is verified against
	// its issuer's public key.
	VerifySignatures bool

	// VerifyEKU enables Extended Key Usage chaining validation per RFC 5280 section 4.2.1.12.
	// When true, each certificate's EKU must be a subset of its issuer's EKU (when
	// the issuer has an EKU extension that does not include anyExtendedKeyUsage).
	// Certificates without an EKU extension are not flagged (legacy compatibility).
	VerifyEKU bool

	// VerifyNameConstraints enables name constraint validation per RFC 5280 section 4.2.1.10.
	// When true, the chain is checked against any name constraints imposed by CA
	// certificates. Name constraints restrict the permitted DNS names, IP ranges,
	// email addresses, or URIs that subordinate certificates may use. Enforcement
	// is delegated to Go's x509 stdlib (RFC 5280 section 6.1 state machine).
	//
	// Limitation: when ValidationTime is set and a certificate is expired at
	// that time, the stdlib verifier returns an expiry error before evaluating
	// name constraints. Name constraint checking is therefore unavailable for
	// temporal simulations involving expired certificates.
	VerifyNameConstraints bool

	// MaxValidityDays warns if a non-CA certificate's validity period exceeds this
	// many days. Zero disables the check. The CA/Browser Forum Baseline Requirements
	// cap TLS server certificate validity at 398 days.
	MaxValidityDays int

	// ValidationTime overrides the current time for expiry and freshness checks.
	// Zero value (default) uses time.Now().
	// This enables deterministic testing and "what-if" analysis at a given point in time.
	ValidationTime time.Time
}

// ValidatorOption is a functional option for configuring a Validator.
type ValidatorOption func(*defaultValidator)

// WithValidatorTrustStore sets the trust store for the validator.
// The trust store is used to verify certificate chains terminate at trusted roots.
// Panics if ts is nil (programmer error).
func WithValidatorTrustStore(ts TrustStore) ValidatorOption {
	return func(v *defaultValidator) {
		if ts == nil {
			panic("certree: WithValidatorTrustStore called with nil trust store")
		}
		v.trustStore = ts
	}
}

// WithRevocationChecker sets the revocation checker for the validator.
// If nil, revocation checking will be skipped even if enabled in validation options.
func WithRevocationChecker(rc RevocationChecker) ValidatorOption {
	return func(v *defaultValidator) {
		v.revocationChecker = rc
	}
}

// WithValidatorLogger sets the logger for the validator.
// Default: no-op logger (silent).
func WithValidatorLogger(logger *slog.Logger) ValidatorOption {
	return func(v *defaultValidator) {
		if logger == nil {
			panic("certree: WithValidatorLogger called with nil logger")
		}
		v.logger = logger
	}
}

// defaultValidator implements the Validator interface.
type defaultValidator struct {
	trustStore        TrustStore
	revocationChecker RevocationChecker
	logger            *slog.Logger
}

// NewValidator creates a new validator with the given options.
// A trust store is required for path trust status determination; without
// [WithValidatorTrustStore], no path will be marked as trusted.
// The revocation checker is optional; if nil, revocation checking is skipped
// even when enabled in ValidationOptions.
func NewValidator(opts ...ValidatorOption) Validator {
	v := &defaultValidator{
		logger: NewLogger(),
	}

	for _, opt := range opts {
		opt(v)
	}

	return v
}

var _ Validator = (*defaultValidator)(nil)

// Validate validates all trust paths according to the provided options.
// Validation errors and warnings are appended to each TrustPath's Errors and Warnings fields.
func (v *defaultValidator) Validate(ctx context.Context, paths []*TrustPath, opts ValidationOptions) error {
	for _, path := range paths {
		select {
		case <-ctx.Done():
			return fmt.Errorf("validating trust paths: %w", ctx.Err())
		default:
		}

		if err := v.validatePath(ctx, path, opts); err != nil {
			return fmt.Errorf("validating path: %w", err)
		}
	}

	return nil
}

// validatePath validates a single trust path by checking each certificate in the chain.
// It applies the validation rules specified in opts to each certificate, checking
// signatures, expiry, hostname, and revocation status as configured.
// Validation errors and warnings are appended to the path's Errors and Warnings fields.
//
// Trust evaluation stops at the first trusted root in the chain. Certificates
// above the trust anchor (e.g., an expired cross-signed root that issued the
// trust anchor) are informational and do not affect the path's trust or
// validation status.
//
//nolint:gocyclo,cyclop // validation loop applying four independent check categories per certificate
func (v *defaultValidator) validatePath(ctx context.Context, path *TrustPath, opts ValidationOptions) error {
	if len(path.Certificates) == 0 {
		return nil
	}

	// Find the index of the first trusted root in the chain. Certificates
	// at indices beyond the trust anchor are informational and should not
	// be validated for expiry, signatures, or revocation.
	trustAnchorIdx := v.findTrustAnchorIndex(path)

	// Validate each certificate in the chain up to (and including) the trust anchor.
	for i, cert := range path.Certificates {
		// Stop validation beyond the trust anchor.
		if trustAnchorIdx >= 0 && i > trustAnchorIdx {
			break
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("validating certificate %s: %w", cert.CommonName(), ctx.Err())
		default:
		}

		var issuer *Certificate
		if i+1 < len(path.Certificates) {
			issuer = path.Certificates[i+1]
		} else if cert.IsSelfSigned() {
			issuer = cert
		}

		// Skip signature verification for self-signed trust anchors -- their
		// self-signature is not meaningful for chain validation and
		// CheckSignatureFrom may reject them due to CA/KeyUsage constraints.
		if opts.VerifySignatures && issuer != nil {
			isTrustAnchor := cert.IsSelfSigned() && v.trustStore != nil && v.trustStore.IsTrusted(cert)
			if !isTrustAnchor {
				if err := v.verifySignature(cert, issuer); err != nil {
					path.Errors = append(path.Errors, ValidationError{
						Certificate: cert,
						Type:        ErrorSignatureInvalid,
						Message:     err.Error(),
					})
				}
			}
		}

		// Validate issuer constraints (BasicConstraints, KeyUsage, pathLen).
		// These checks apply to issuer certificates -- any cert that signs
		// another cert must have CA:TRUE (RFC 5280 section 4.2.1.9) and
		// KeyUsageCertSign (RFC 5280 section 4.2.1.3). These are structural PKI
		// checks independent of cryptographic signature verification.
		if issuer != nil && issuer != cert {
			v.checkIssuerConstraints(cert, issuer, path, i)
		}

		if opts.VerifyEKU && issuer != nil && issuer != cert {
			v.checkEKUChaining(cert, issuer, path)
		}

		if opts.VerifyExpiry {
			v.checkExpiry(cert, path, opts.ExpiryWarningDays, opts.ValidationTime)
		}

		if opts.VerifyHostname && i == 0 && opts.Hostname != "" {
			if err := v.verifyHostname(cert, opts.Hostname); err != nil {
				path.Errors = append(path.Errors, ValidationError{
					Certificate: cert,
					Type:        ErrorHostnameMismatch,
					Message:     err.Error(),
				})
			}
		}

		if opts.VerifyRevocation && issuer != nil && !cert.IsSelfSigned() {
			v.checkRevocation(ctx, cert, issuer, path, opts.RevocationFailOpen)
		}

		// Serial number and end-entity key usage are structural PKI checks
		// (RFC 5280 section 4.1.2.2, section 4.2.1.3) -- always verify regardless of
		// VerifySignatures.
		v.checkSerialNumber(cert, path)

		if i == 0 {
			v.checkEndEntityKeyUsage(cert, path)
		}

		// Always-on: warn on weak public keys or deprecated signature algorithms.
		v.checkWeakKey(cert, path)

		// Always-on: warn if end-entity cert has no Subject Alternative Names.
		if i == 0 {
			v.checkMissingSAN(cert, path)
		}

		if opts.MaxValidityDays > 0 && i == 0 {
			v.checkCertLifetime(cert, path, opts.MaxValidityDays)
		}
	}

	// Check name constraints for the entire path using stdlib RFC 5280 section 6.1.
	if opts.VerifyNameConstraints {
		v.checkNameConstraints(path, opts, trustAnchorIdx)
	}

	return nil
}

// findTrustAnchorIndex returns the index of the first trusted certificate in
// the path, whether self-signed or cross-signed; -1 means no anchor.
func (v *defaultValidator) findTrustAnchorIndex(path *TrustPath) int {
	if v.trustStore == nil {
		return -1
	}
	for i, cert := range path.Certificates {
		if v.trustStore.IsTrusted(cert) {
			return i
		}
	}
	return -1
}

// verifySignature verifies that cert's signature was created by issuer.
func (v *defaultValidator) verifySignature(cert *Certificate, issuer *Certificate) error {
	if err := cert.Raw().CheckSignatureFrom(issuer.Raw()); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// checkIssuerConstraints validates that the issuer certificate is authorized to
// sign other certificates. It checks:
//   - BasicConstraints (RFC 5280 section 4.2.1.9): the issuer must have IsCA=true
//   - KeyUsage (RFC 5280 section 4.2.1.3): the issuer must have the KeyUsageCertSign bit set
//   - MaxPathLen (RFC 5280 section 4.2.1.9): the number of intermediates between issuer
//     and leaf must not exceed the issuer's MaxPathLen constraint
//
// Errors are appended to path.Errors.
func (v *defaultValidator) checkIssuerConstraints(cert *Certificate, issuer *Certificate, path *TrustPath, certIndex int) {
	issuerRaw := issuer.Raw()

	if issuerRaw.BasicConstraintsValid && !issuerRaw.IsCA {
		path.Errors = append(path.Errors, ValidationError{
			Certificate: issuer,
			Type:        ErrorInvalidBasicConstraints,
			Message:     fmt.Sprintf("issuer %q is not a CA (BasicConstraints CA:FALSE)", issuer.CommonName()),
			Details: map[string]any{
				"issuer_cn": issuer.CommonName(),
				"issued_to": cert.CommonName(),
			},
		})
	}

	// Only check if KeyUsage is present (non-zero). Some legacy certificates
	// omit KeyUsage entirely, which is treated as "all usages permitted."
	if issuerRaw.KeyUsage != 0 && issuerRaw.KeyUsage&x509.KeyUsageCertSign == 0 {
		path.Errors = append(path.Errors, ValidationError{
			Certificate: issuer,
			Type:        ErrorMissingKeyUsage,
			Message:     fmt.Sprintf("issuer %q lacks KeyUsageCertSign", issuer.CommonName()),
			Details: map[string]any{
				"issuer_cn": issuer.CommonName(),
				"key_usage": issuerRaw.KeyUsage,
			},
		})
	}

	// Check MaxPathLen constraint. MaxPathLen limits the number of
	// non-self-issued intermediate CA certificates that may follow this
	// issuer in a valid chain (RFC 5280 section 4.2.1.9). certIndex is
	// the 0-based distance from the leaf, so certIndex equals the count
	// of intermediate certificates between the issuer and the leaf
	// (position 0 is the leaf itself, which is not an intermediate).
	if issuerRaw.BasicConstraintsValid && issuerRaw.IsCA &&
		(issuerRaw.MaxPathLen > 0 || issuerRaw.MaxPathLenZero) {
		intermediatesBetween := certIndex
		if intermediatesBetween > issuerRaw.MaxPathLen {
			path.Errors = append(path.Errors, ValidationError{
				Certificate: issuer,
				Type:        ErrorPathLenExceeded,
				Message: fmt.Sprintf("issuer %q MaxPathLen is %d but %d intermediates exist below it",
					issuer.CommonName(), issuerRaw.MaxPathLen, intermediatesBetween),
				Details: map[string]any{
					"issuer_cn":     issuer.CommonName(),
					"max_path_len":  issuerRaw.MaxPathLen,
					"intermediates": intermediatesBetween,
				},
			},
			)
		}
	}
}

// checkExpiry adds an error if cert is expired or not yet valid, and a warning
// if it expires within warningDays days.
func (v *defaultValidator) checkExpiry(cert *Certificate, path *TrustPath, warningDays int, validationTime time.Time) {
	now := validationTime
	if now.IsZero() {
		now = time.Now()
	}

	// When ValidationTime is set, append it to the message so the temporal
	// context is clear (e.g., "not valid until 2023-… (at 2020-…)").
	atTime := ""
	if !validationTime.IsZero() {
		atTime = fmt.Sprintf(" (at %s)", validationTime.Format(time.RFC3339))
	}

	if now.After(cert.Raw().NotAfter) {
		path.Errors = append(path.Errors, ValidationError{
			Certificate: cert,
			Type:        ErrorExpired,
			Message:     fmt.Sprintf("certificate expired on %s", cert.Raw().NotAfter.Format(time.RFC3339)) + atTime,
			Details: map[string]any{
				"not_after": cert.Raw().NotAfter,
			},
		})
		return
	}

	if now.Before(cert.Raw().NotBefore) {
		path.Errors = append(path.Errors, ValidationError{
			Certificate: cert,
			Type:        ErrorNotYetValid,
			Message:     fmt.Sprintf("certificate not valid until %s", cert.Raw().NotBefore.Format(time.RFC3339)) + atTime,
			Details: map[string]any{
				"not_before": cert.Raw().NotBefore,
			},
		})
		return
	}

	if warningDays <= 0 {
		return
	}
	daysUntilExpiry := int(cert.Raw().NotAfter.Sub(now).Hours() / hoursPerDay)
	if daysUntilExpiry <= warningDays {
		path.Warnings = append(path.Warnings, ValidationWarning{
			Certificate: cert,
			Type:        WarningExpiringSoon,
			Message:     fmt.Sprintf("certificate expires in %d days", daysUntilExpiry),
		})
	}
}

// verifyHostname verifies that the certificate is valid for the given hostname.
func (v *defaultValidator) verifyHostname(cert *Certificate, hostname string) error {
	if err := cert.Raw().VerifyHostname(hostname); err != nil {
		// Build a user-friendly message without raw x509 internals.
		sans := cert.Raw().DNSNames
		if len(sans) == 0 {
			return fmt.Errorf("certificate is not valid for %q (no SANs present)", hostname)
		}
		return fmt.Errorf("certificate is not valid for %q (SANs: %v)", hostname, sans)
	}
	return nil
}

// checkEKUChaining validates Extended Key Usage chaining per RFC 5280 section 4.2.1.12.
//
// If the issuer has an EKU extension that does not contain anyExtendedKeyUsage,
// every EKU present in the cert must also appear in the issuer's EKU. Certificates
// with no EKU extension are not flagged for legacy compatibility -- an absent EKU
// means the certificate is unconstrained, which is common in older PKIs.
//
// Unknown OID EKUs (not mapped by Go's x509 package) are compared by OID string
// to handle custom or future EKU values correctly.
//
// Errors are appended to path.Errors.
func (v *defaultValidator) checkEKUChaining(cert *Certificate, issuer *Certificate, path *TrustPath) {
	issuerRaw := issuer.Raw()

	if len(issuerRaw.ExtKeyUsage) == 0 && len(issuerRaw.UnknownExtKeyUsage) == 0 {
		return
	}

	if slices.Contains(issuerRaw.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return
	}

	certRaw := cert.Raw()

	// No EKU on the cert: treat as unconstrained (legacy compatibility).
	// Many older end-entity and intermediate certs omit EKU entirely.
	if len(certRaw.ExtKeyUsage) == 0 && len(certRaw.UnknownExtKeyUsage) == 0 {
		return
	}

	issuerEKUs := make(map[x509.ExtKeyUsage]struct{}, len(issuerRaw.ExtKeyUsage))
	for _, eku := range issuerRaw.ExtKeyUsage {
		issuerEKUs[eku] = struct{}{}
	}
	issuerUnknown := make(map[string]struct{}, len(issuerRaw.UnknownExtKeyUsage))
	for _, oid := range issuerRaw.UnknownExtKeyUsage {
		issuerUnknown[oid.String()] = struct{}{}
	}

	var violations []string
	for _, eku := range certRaw.ExtKeyUsage {
		if _, ok := issuerEKUs[eku]; !ok {
			violations = append(violations, EKUShortName(eku))
		}
	}
	for _, oid := range certRaw.UnknownExtKeyUsage {
		if _, ok := issuerUnknown[oid.String()]; !ok {
			violations = append(violations, oid.String())
		}
	}

	if len(violations) > 0 {
		path.Errors = append(path.Errors, ValidationError{
			Certificate: cert,
			Type:        ErrorInvalidEKU,
			Message: fmt.Sprintf(
				"certificate EKU [%s] not permitted by issuer %q EKU constraint",
				strings.Join(violations, ", "), issuer.CommonName(),
			),
			Details: map[string]any{
				"issuer_cn":  issuer.CommonName(),
				"violations": violations,
			},
		})
	}
}

// checkNameConstraints validates name constraints for the trust path by delegating
// to Go's x509 stdlib, which implements the full RFC 5280 section 6.1 state machine.
//
// It constructs a pool containing only the certificates from the built path,
// so that x509.Verify is forced to use the exact chain certree assembled.
// Only x509.CertificateInvalidError values with reason NameConstraintsViolation
// are translated to path errors -- all other errors from x509.Verify are ignored
// because they represent conditions already checked by the per-cert validation
// loop (signatures, expiry, hostname, etc.).
//
// Errors are appended to path.Errors.
func (v *defaultValidator) checkNameConstraints(path *TrustPath, opts ValidationOptions, trustAnchorIdx int) {
	if len(path.Certificates) < 2 {
		// A single certificate has no issuer to impose constraints.
		return
	}

	if trustAnchorIdx < 0 {
		// No trusted root found; use the last cert as the boundary.
		trustAnchorIdx = len(path.Certificates) - 1
	}

	leaf := path.Certificates[0].Raw()

	roots := x509.NewCertPool()
	roots.AddCert(path.Certificates[trustAnchorIdx].Raw())

	intermediates := x509.NewCertPool()
	for i := 1; i < trustAnchorIdx; i++ {
		intermediates.AddCert(path.Certificates[i].Raw())
	}

	validationTime := opts.ValidationTime
	if validationTime.IsZero() {
		validationTime = time.Now()
	}

	// Call stdlib Verify with an empty DNSName and no KeyUsages so that only
	// name constraint enforcement (and the structural checks needed to reach
	// it) runs. Hostname and EKU are already checked by the per-cert loop.
	//
	// Note: x509.Verify may return early on expired certificates before
	// evaluating name constraints. In that case, the expiry error is already
	// reported by the per-cert validation loop, and name constraint checking
	// is best-effort. This is acceptable because expired certificates are
	// already flagged as errors.
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   validationTime,
	})
	if err == nil {
		return
	}

	// Walk the error tree to collect NameConstraintsViolation entries.
	// Go 1.20+ may return a joined error wrapping multiple chain failures.
	collectNameConstraintViolations(err, path)
}

// collectNameConstraintViolations recursively walks an error tree and appends
// a ValidationError for each x509.CertificateInvalidError with reason
// NameConstraintsViolation. Non-matching errors are silently ignored because
// they represent conditions already reported by the per-cert validation loop.
func collectNameConstraintViolations(err error, path *TrustPath) {
	// Handle errors.Join / multi-error wrappers (Go 1.20+) first so that
	// all branches are explored, not just the first errors.As match.
	type unwrapMulti interface{ Unwrap() []error }
	if multi, ok := err.(unwrapMulti); ok {
		for _, e := range multi.Unwrap() {
			collectNameConstraintViolations(e, path)
		}
		return
	}

	if certErr, ok := errors.AsType[x509.CertificateInvalidError](err); ok && certErr.Reason == x509.CANotAuthorizedForThisName {
		path.Errors = append(path.Errors, ValidationError{
			Type:    ErrorNameConstraintViolation,
			Message: fmt.Sprintf("name constraint violation: %s", certErr.Detail),
		})
	}
}

// checkWeakKey warns about weak public keys (RSA < 2048 bits, EC < 224 bits)
// and deprecated signature algorithms (MD5, SHA-1). These checks are always-on
// regardless of validation options because weak keys and algorithms are never
// correct.
func (v *defaultValidator) checkWeakKey(cert *Certificate, path *TrustPath) {
	raw := cert.Raw()

	switch raw.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA:
		path.Warnings = append(path.Warnings, ValidationWarning{
			Certificate: cert,
			Type:        WarningWeakAlgorithm,
			Message:     fmt.Sprintf("certificate uses deprecated %s signature algorithm", raw.SignatureAlgorithm),
		})
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		path.Warnings = append(path.Warnings, ValidationWarning{
			Certificate: cert,
			Type:        WarningWeakAlgorithm,
			Message:     fmt.Sprintf("certificate uses deprecated %s signature algorithm (SHA-1 sunset)", raw.SignatureAlgorithm),
		})
	}

	switch pub := raw.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			path.Warnings = append(path.Warnings, ValidationWarning{
				Certificate: cert,
				Type:        WarningWeakKey,
				Message:     fmt.Sprintf("RSA key size %d bits is below minimum of 2048 bits", pub.N.BitLen()),
			})
		}
	case *ecdsa.PublicKey:
		if pub.Curve != nil && pub.Curve.Params().BitSize < 224 {
			path.Warnings = append(path.Warnings, ValidationWarning{
				Certificate: cert,
				Type:        WarningWeakKey,
				Message:     fmt.Sprintf("EC key size %d bits is below minimum of 224 bits", pub.Curve.Params().BitSize),
			})
		}
	default:
		// Detect DSA keys via type name to avoid importing the deprecated
		// crypto/dsa package (SA1019). %T includes the full package path
		// (e.g., "*crypto/dsa.PublicKey"), which is stable across Go
		// versions since dsa.PublicKey is a frozen stdlib type.
		if fmt.Sprintf("%T", pub) == "*crypto/dsa.PublicKey" {
			path.Warnings = append(path.Warnings, ValidationWarning{
				Certificate: cert,
				Type:        WarningWeakKey,
				Message:     "DSA key type is deprecated",
			})
		}
	}
}

// checkMissingSAN warns if an end-entity certificate has no Subject Alternative
// Names extension. Relying solely on the Subject CN for hostname matching is
// deprecated per RFC 6125 and rejected by modern TLS implementations.
// This check is always-on for end-entity (non-CA) certificates.
func (v *defaultValidator) checkMissingSAN(cert *Certificate, path *TrustPath) {
	raw := cert.Raw()
	if raw.IsCA {
		return
	}
	if len(raw.DNSNames) == 0 && len(raw.IPAddresses) == 0 &&
		len(raw.EmailAddresses) == 0 && len(raw.URIs) == 0 {
		path.Warnings = append(path.Warnings, ValidationWarning{
			Certificate: cert,
			Type:        WarningMissingSAN,
			Message:     "certificate has no Subject Alternative Names (deprecated reliance on Subject CN per RFC 6125)",
		})
	}
}

// checkCertLifetime warns if a non-CA certificate's validity period exceeds
// maxDays. The CA/Browser Forum Baseline Requirements cap TLS server
// certificate validity at 398 days.
func (v *defaultValidator) checkCertLifetime(cert *Certificate, path *TrustPath, maxDays int) {
	if cert.Raw().IsCA {
		return
	}
	validityDays := int(cert.Raw().NotAfter.Sub(cert.Raw().NotBefore).Hours() / hoursPerDay)
	if validityDays > maxDays {
		path.Warnings = append(path.Warnings, ValidationWarning{
			Certificate: cert,
			Type:        WarningCertLifetime,
			Message: fmt.Sprintf("certificate validity period %d days exceeds maximum %d days",
				validityDays, maxDays),
		})
	}
}

// checkEndEntityKeyUsage validates the Key Usage extension for end-entity TLS
// server certificates per RFC 5280 section 4.2.1.3. When the Key Usage extension is
// present and the certificate carries the serverAuth EKU, at least one of
// KeyUsageDigitalSignature, KeyUsageKeyEncipherment, or KeyUsageKeyAgreement
// must be set. Certificates without a Key Usage extension are not flagged.
func (v *defaultValidator) checkEndEntityKeyUsage(cert *Certificate, path *TrustPath) {
	raw := cert.Raw()
	if raw.IsCA || raw.KeyUsage == 0 {
		return
	}
	if !slices.Contains(raw.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return
	}
	hasUsableKU := raw.KeyUsage&x509.KeyUsageDigitalSignature != 0 ||
		raw.KeyUsage&x509.KeyUsageKeyEncipherment != 0 ||
		raw.KeyUsage&x509.KeyUsageKeyAgreement != 0
	if !hasUsableKU {
		path.Errors = append(path.Errors, ValidationError{
			Certificate: cert,
			Type:        ErrorInvalidKeyUsage,
			Message: "TLS server certificate Key Usage must include at least one of " +
				"KeyUsageDigitalSignature, KeyUsageKeyEncipherment, or KeyUsageKeyAgreement " +
				"(RFC 5280 section 4.2.1.3)",
		})
	}
}

// checkSerialNumber validates the certificate serial number per RFC 5280 section 4.1.2.2.
// The serial number must be a positive integer of at most 20 octets in DER encoding.
func (v *defaultValidator) checkSerialNumber(cert *Certificate, path *TrustPath) {
	serial := cert.Raw().SerialNumber
	if serial == nil {
		return
	}
	if serial.Sign() <= 0 {
		path.Errors = append(path.Errors, ValidationError{
			Certificate: cert,
			Type:        ErrorInvalidSerialNumber,
			Message:     "certificate serial number must be a positive integer (RFC 5280 section 4.1.2.2)",
		})
		return
	}
	// RFC 5280 section 4.1.2.2 limits the DER-encoded INTEGER value to 20 octets.
	// big.Int.Bytes() returns the minimum-length unsigned representation, omitting
	// the leading 0x00 that DER adds when the most significant bit is set. We must
	// account for that byte to correctly reject 21-DER-octet serials.
	b := serial.Bytes()
	derLen := len(b)
	if len(b) > 0 && b[0]&0x80 != 0 {
		derLen++ // DER prepends 0x00 to keep the sign bit clear.
	}
	if derLen > 20 {
		path.Errors = append(path.Errors, ValidationError{
			Certificate: cert,
			Type:        ErrorInvalidSerialNumber,
			Message: fmt.Sprintf("certificate serial number DER encoding %d octets exceeds maximum 20 octets (RFC 5280 section 4.1.2.2)",
				derLen),
		})
	}
}

// checkRevocation checks certificate revocation status via OCSP or CRL.
// If the revocation checker is not configured, the check is skipped.
// The failOpen parameter controls behavior when checks fail:
//   - true: Failed checks generate warnings but don't fail validation
//   - false: Failed checks generate errors and fail validation
//
// Revocation status is checked using the configured RevocationChecker, which
// typically tries OCSP first and falls back to CRL if OCSP is unavailable.
func (v *defaultValidator) checkRevocation(ctx context.Context, cert *Certificate, issuer *Certificate, path *TrustPath, failOpen bool) {
	if v.revocationChecker == nil {
		v.logger.Debug("revocation checker not configured, skipping revocation check")
		return
	}

	status, err := v.revocationChecker.CheckRevocation(ctx, cert, issuer)
	if err != nil {
		if failOpen {
			path.Warnings = append(path.Warnings, ValidationWarning{
				Certificate: cert,
				Type:        WarningRevocationCheckFailed,
				Message:     fmt.Sprintf("revocation check failed: %v", err),
			})
			v.logger.Warn("revocation check failed (fail-open mode)", "cert", cert.CommonName(), "error", err)
		} else {
			path.Errors = append(path.Errors, ValidationError{
				Certificate: cert,
				Type:        ErrorRevocationCheckFailed,
				Message:     fmt.Sprintf("revocation check failed: %v", err),
				Details: map[string]any{
					"error": err.Error(),
				},
			})
			v.logger.Error("revocation check failed (fail-closed mode)", "cert", cert.CommonName(), "error", err)
		}
		return
	}

	if status.IsRevoked {
		revokedAt := "unknown"
		if status.RevokedAt != nil {
			revokedAt = status.RevokedAt.Format(time.RFC3339)
		}
		path.Errors = append(path.Errors, ValidationError{
			Certificate: cert,
			Type:        ErrorRevoked,
			Message:     fmt.Sprintf("certificate revoked at %s", revokedAt),
			Details: map[string]any{
				"revoked_at":    revokedAt,
				"checked_via":   status.CheckedVia,
				"responder_url": status.ResponderURL,
			},
		})
		v.logger.Info("certificate is revoked", "cert", cert.CommonName(), "revoked_at", revokedAt)
	}
}

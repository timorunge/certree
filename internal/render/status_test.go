package render

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree"
	"github.com/timorunge/certree/pkg/certree/testutil"
)

// cachedTestCerts holds pre-generated certificates to avoid expensive key
// generation inside test iterations.
type cachedTestCerts struct {
	expired, expiringSoon, valid, validLeaf *certree.Certificate
	leafIssuerCert                          *x509.Certificate
}

var (
	statusTestCertsOnce sync.Once
	statusTestCerts     *cachedTestCerts
)

// getCachedCerts returns shared test certificates, generating them once.
func getCachedCerts(t *testing.T) *cachedTestCerts {
	t.Helper()
	statusTestCertsOnce.Do(func() {
		now := time.Now()
		src := certree.CertificateSource{Type: certree.SourceTypeFile}

		expiredRaw, _, err := testutil.GenerateCertificateWithExpiry("expired.example.com", now.Add(-365*24*time.Hour), now.Add(-24*time.Hour))
		if err != nil {
			panic(fmt.Sprintf("generating expired cert: %v", err))
		}
		expiringSoonRaw, _, err := testutil.GenerateCertificateWithExpiry("expiring.example.com", now.Add(-24*time.Hour), now.Add(15*24*time.Hour))
		if err != nil {
			panic(fmt.Sprintf("generating expiring-soon cert: %v", err))
		}
		validRaw, validKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "valid.example.com"}, IsCA: true,
		})
		if err != nil {
			panic(fmt.Sprintf("generating valid cert: %v", err))
		}
		leafRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "leaf.example.com"}, SerialNumber: big.NewInt(42),
		}, validRaw, validKey)
		if err != nil {
			panic(fmt.Sprintf("generating leaf cert: %v", err))
		}

		statusTestCerts = &cachedTestCerts{
			expired: certree.NewCertificate(expiredRaw, src), expiringSoon: certree.NewCertificate(expiringSoonRaw, src),
			valid: certree.NewCertificate(validRaw, src), validLeaf: certree.NewCertificate(leafRaw, src),
			leafIssuerCert: validRaw,
		}
	})
	return statusTestCerts
}

func TestCertStatus_AllBranches(t *testing.T) {
	t.Parallel()

	now := time.Now()
	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	caRaw, caKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Branch Test CA"},
		IsCA:    true,
	})
	require.NoError(t, err, "generating CA cert")

	leafRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Branch Test Leaf"},
		SerialNumber: big.NewInt(100),
	}, caRaw, caKey)
	require.NoError(t, err, "generating leaf cert")

	validLeaf := certree.NewCertificate(leafRaw, src)

	selfSignedRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Self-Signed Untrusted"},
		IsCA:    true,
	})
	require.NoError(t, err, "generating self-signed cert")
	selfSignedCert := certree.NewCertificate(selfSignedRaw, src)

	trustedCert := certree.NewCertificate(caRaw, src).WithTrustedLocations([]string{"system"})

	expiredRaw, _, err := testutil.GenerateCertificateWithExpiry(
		"expired.branch.test",
		now.Add(-365*24*time.Hour),
		now.Add(-24*time.Hour),
	)
	require.NoError(t, err, "generating expired cert")
	expiredCert := certree.NewCertificate(expiredRaw, src)

	// Expiring-soon cert must be CA-signed (not self-signed) to isolate the
	// expiry warning from the self-signed error status.
	expiringSoonRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Expiring Branch Leaf"},
		SerialNumber: big.NewInt(101),
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(15 * 24 * time.Hour),
	}, caRaw, caKey)
	require.NoError(t, err, "generating expiring-soon cert")
	expiringSoonCert := certree.NewCertificate(expiringSoonRaw, src)

	// Cert expiring later today: NotAfter is within the next 24 hours, so
	// DaysUntilExpiry==0 but IsExpired==false. Must trigger "expires today".
	expiresTodayRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Expires Today Leaf"},
		SerialNumber: big.NewInt(102),
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(6 * time.Hour),
	}, caRaw, caKey)
	require.NoError(t, err, "generating expires-today cert")
	expiresTodayCert := certree.NewCertificate(expiresTodayRaw, src)

	tests := []struct {
		name string
		cert *certree.Certificate
		path *certree.TrustPath
		want statusLevel
	}{
		{
			name: "path error for this cert",
			cert: validLeaf,
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{validLeaf},
				Status:       certree.PathTrusted,
				Errors: []certree.ValidationError{
					{
						Certificate: validLeaf,
						Type:        certree.ErrorSignatureInvalid,
						Message:     "signature invalid",
					},
				},
			},
			want: statusError,
		},
		{
			name: "excluded",
			cert: validLeaf,
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{validLeaf},
				Status:       certree.PathTrusted,
				SimulationMetadata: map[string]certree.CertSimulationState{
					validLeaf.FingerprintSHA256(): {IsExcluded: true},
				},
			},
			want: statusWarning,
		},
		{
			name: "in trust store",
			cert: trustedCert,
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{trustedCert},
				Status:       certree.PathTrusted,
			},
			want: statusValid,
		},
		{
			name: "expired",
			cert: expiredCert,
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{expiredCert},
				Status:       certree.PathUntrusted,
			},
			want: statusError,
		},
		{
			name: "expiring within threshold",
			cert: expiringSoonCert,
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{expiringSoonCert},
				Status:       certree.PathTrusted,
			},
			want: statusWarning,
		},
		{
			name: "expires today (DaysUntilExpiry==0)",
			cert: expiresTodayCert,
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{expiresTodayCert},
				Status:       certree.PathTrusted,
			},
			want: statusWarning,
		},
		{
			name: "path warning for this cert",
			cert: validLeaf,
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{validLeaf},
				Status:       certree.PathTrusted,
				Warnings: []certree.ValidationWarning{
					{
						Certificate: validLeaf,
						Type:        certree.WarningIncompleteChain,
						Message:     "incomplete chain",
					},
				},
			},
			want: statusWarning,
		},
		{
			name: "self-signed not in trust store",
			cert: selfSignedCert,
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{selfSignedCert},
				Status:       certree.PathUntrusted,
			},
			want: statusError,
		},
		{
			name: "otherwise valid",
			cert: validLeaf,
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{validLeaf},
				Status:       certree.PathTrusted,
			},
			want: statusValid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := certStatus(tt.cert, tt.path, 0)
			assert.Equal(t, tt.want, got.level)
		})
	}
}

func TestCertStatus_NilInputs(t *testing.T) {
	t.Parallel()

	got := certStatus(nil, &certree.TrustPath{Status: certree.PathTrusted}, 0)
	assert.Equal(t, statusError, got.level)
}

func TestCertStatus_Reasons_AllErrorTypes(t *testing.T) {
	t.Parallel()

	tc := getCachedCerts(t)

	// Update this count when adding new ErrorType values.
	const totalErrorTypes = 16

	tests := []struct {
		name     string
		errType  certree.ErrorType
		expected string
	}{
		{"ErrorExpired", certree.ErrorExpired, "expired"},
		{"ErrorNotYetValid", certree.ErrorNotYetValid, "not yet valid"},
		{"ErrorSignatureInvalid", certree.ErrorSignatureInvalid, "signature invalid"},
		{"ErrorInvalidBasicConstraints", certree.ErrorInvalidBasicConstraints, "invalid basic constraints"},
		{"ErrorMissingKeyUsage", certree.ErrorMissingKeyUsage, "missing key usage"},
		{"ErrorRevoked", certree.ErrorRevoked, "revoked"},
		{"ErrorRevocationCheckFailed", certree.ErrorRevocationCheckFailed, "revocation check failed"},
		{"ErrorCircularReference", certree.ErrorCircularReference, "circular reference"},
		{"ErrorDepthExceeded", certree.ErrorDepthExceeded, "depth exceeded"},
		{"ErrorPathLenExceeded", certree.ErrorPathLenExceeded, "path length exceeded"},
		{"ErrorUntrustedRoot", certree.ErrorUntrustedRoot, "untrusted root"},
		{"ErrorHostnameMismatch", certree.ErrorHostnameMismatch, "hostname mismatch"},
		{"ErrorInvalidEKU", certree.ErrorInvalidEKU, "extended key usage not permitted by issuer"},
		{"ErrorNameConstraintViolation", certree.ErrorNameConstraintViolation, "name constraint violation"},
		{"ErrorInvalidKeyUsage", certree.ErrorInvalidKeyUsage, "invalid key usage"},
		{"ErrorInvalidSerialNumber", certree.ErrorInvalidSerialNumber, "invalid serial number"},
	}

	if len(tests) != totalErrorTypes {
		t.Fatalf("exhaustiveness guard: got %d test cases, want %d (update when adding ErrorType values)", len(tests), totalErrorTypes)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := &certree.TrustPath{
				Certificates: []*certree.Certificate{tc.validLeaf},
				Status:       certree.PathTrusted,
				Errors: []certree.ValidationError{
					{
						Certificate: tc.validLeaf,
						Type:        tt.errType,
						Message:     "test error",
					},
				},
			}
			got := certStatus(tc.validLeaf, path, 0)
			assert.Contains(t, got.reasons, tt.expected,
				"certStatus().reasons should contain %q", tt.expected)
		})
	}
}

func TestCertStatus_Reasons_AllWarningTypes(t *testing.T) {
	t.Parallel()

	tc := getCachedCerts(t)

	// Update this count when adding new WarningType values.
	// WarningExpiringSoon and WarningWeakKey are tested separately because they
	// require specific certificates (expiring-soon cert and RSA-1024 cert).
	const totalNonDynamicWarningTypes = 7

	tests := []struct {
		name     string
		warnType certree.WarningType
		expected string
	}{
		{"WarningRevocationCheckFailed", certree.WarningRevocationCheckFailed, "revocation check failed"},
		{"WarningIncompleteChain", certree.WarningIncompleteChain, "incomplete chain"},
		{"WarningDuplicateCertificate", certree.WarningDuplicateCertificate, "duplicate certificate"},
		{"WarningExcludedBySimulation", certree.WarningExcludedBySimulation, "broken"},
		{"WarningWeakAlgorithm", certree.WarningWeakAlgorithm, "deprecated signature algorithm"},
		{"WarningMissingSAN", certree.WarningMissingSAN, "no Subject Alternative Names"},
		{"WarningCertLifetime", certree.WarningCertLifetime, "validity period exceeds maximum"},
	}

	if len(tests) != totalNonDynamicWarningTypes {
		t.Fatalf("exhaustiveness guard: got %d test cases, want %d (update when adding WarningType values)", len(tests), totalNonDynamicWarningTypes)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := &certree.TrustPath{
				Certificates: []*certree.Certificate{tc.validLeaf},
				Status:       certree.PathTrusted,
				Warnings: []certree.ValidationWarning{
					{
						Certificate: tc.validLeaf,
						Type:        tt.warnType,
						Message:     "test warning",
					},
				},
			}
			got := certStatus(tc.validLeaf, path, 0)
			assert.Contains(t, got.reasons, tt.expected,
				"certStatus().reasons should contain %q", tt.expected)
		})
	}
}

func TestCertStatus_Reasons_WarningExpiringSoon(t *testing.T) {
	t.Parallel()

	tc := getCachedCerts(t)
	path := &certree.TrustPath{
		Certificates: []*certree.Certificate{tc.expiringSoon},
		Status:       certree.PathTrusted,
		Warnings: []certree.ValidationWarning{
			{
				Certificate: tc.expiringSoon,
				Type:        certree.WarningExpiringSoon,
				Message:     "certificate expires soon",
			},
		},
	}

	got := certStatus(tc.expiringSoon, path, 0)
	assert.NotEmpty(t, got.reasons, "expected non-empty reasons for WarningExpiringSoon")
	found := false
	for _, r := range got.reasons {
		if strings.Contains(r, "expires in") {
			found = true
			break
		}
	}
	assert.True(t, found, "reasons %v should contain an 'expires in' entry", got.reasons)
}

func TestCertStatus_Reasons_WarningWeakKey(t *testing.T) {
	t.Parallel()

	raw, _, err := testutil.GenerateSelfSignedCertRSA1024(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Weak Key Cert"},
	})
	require.NoError(t, err, "generating RSA-1024 cert")
	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	weakCert := certree.NewCertificate(raw, src)

	path := &certree.TrustPath{
		Certificates: []*certree.Certificate{weakCert},
		Status:       certree.PathTrusted,
		Warnings: []certree.ValidationWarning{
			{
				Certificate: weakCert,
				Type:        certree.WarningWeakKey,
				Message:     "weak key",
			},
		},
	}

	got := certStatus(weakCert, path, 0)
	joined := strings.Join(got.reasons, " ")
	assert.Contains(t, joined, "weak RSA key", "reasons should contain 'weak RSA key'")
	assert.Contains(t, joined, "1024", "reasons should contain '1024'")
}

func TestCertStatus_Reasons_BothErrorAndWarning(t *testing.T) {
	t.Parallel()

	tc := getCachedCerts(t)

	path := &certree.TrustPath{
		Certificates: []*certree.Certificate{tc.validLeaf},
		Status:       certree.PathTrusted,
		Errors: []certree.ValidationError{
			{
				Certificate: tc.validLeaf,
				Type:        certree.ErrorRevoked,
				Message:     "revoked",
			},
		},
		Warnings: []certree.ValidationWarning{
			{
				Certificate: tc.validLeaf,
				Type:        certree.WarningIncompleteChain,
				Message:     "incomplete chain",
			},
		},
	}

	got := certStatus(tc.validLeaf, path, 0)
	assert.Contains(t, got.reasons, "revoked", "reasons should contain the error")
	assert.Contains(t, got.reasons, "incomplete chain", "reasons should contain the warning")
}

func TestPathStatusReason(t *testing.T) {
	t.Parallel()

	now := time.Now()
	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	caRaw, caKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "PathReason CA"},
		IsCA:    true,
	})
	require.NoError(t, err, "generating CA cert")

	leafRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "PathReason Leaf"},
		SerialNumber: big.NewInt(200),
	}, caRaw, caKey)
	require.NoError(t, err, "generating leaf cert")

	validLeaf := certree.NewCertificate(leafRaw, src)
	trustedRoot := certree.NewCertificate(caRaw, src).WithTrustedLocations([]string{"system"})

	expiredRaw, _, err := testutil.GenerateCertificateWithExpiry(
		"expired.pathreason.test",
		now.Add(-365*24*time.Hour),
		now.Add(-24*time.Hour),
	)
	require.NoError(t, err, "generating expired cert")
	expiredCert := certree.NewCertificate(expiredRaw, src)

	tests := []struct {
		name string
		path *certree.TrustPath
		want string
	}{
		{
			name: "nil path",
			path: nil,
			want: "",
		},
		{
			name: "empty path",
			path: &certree.TrustPath{},
			want: "",
		},
		{
			name: "simulation with excluded cert",
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{validLeaf},
				Status:       certree.PathTrusted,
				SimulationMetadata: map[string]certree.CertSimulationState{
					validLeaf.FingerprintSHA256(): {IsExcluded: true},
				},
			},
			want: "PathReason Leaf excluded by simulation",
		},
		{
			name: "untrusted path",
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{validLeaf},
				Status:       certree.PathUntrusted,
			},
			want: "untrusted",
		},
		{
			name: "incomplete path",
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{validLeaf},
				Status:       certree.PathIncomplete,
			},
			want: "incomplete chain",
		},
		{
			name: "path with expired cert error",
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{expiredCert, trustedRoot},
				Status:       certree.PathTrusted,
				Errors: []certree.ValidationError{
					{
						Certificate: expiredCert,
						Type:        certree.ErrorExpired,
						Message:     "expired",
					},
				},
			},
			want: "expired",
		},
		{
			name: "valid trusted path",
			path: &certree.TrustPath{
				Certificates: []*certree.Certificate{validLeaf, trustedRoot},
				Status:       certree.PathTrusted,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := pathStatusReason(tt.path, 0)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPathStatus_TrustedPathWithExcludedCert(t *testing.T) {
	t.Parallel()

	tc := getCachedCerts(t)

	trustedRoot := tc.valid.WithTrustedLocations([]string{"system"})

	excludedRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Excluded Root CA"},
		IsCA:    true,
	})
	if err != nil {
		t.Fatalf("generating excluded cert: %v", err)
	}
	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	excludedCert := certree.NewCertificate(excludedRaw, src)

	path := &certree.TrustPath{
		Certificates: []*certree.Certificate{tc.validLeaf, trustedRoot, excludedCert},
		Status:       certree.PathTrusted,
		SimulationMetadata: map[string]certree.CertSimulationState{
			excludedCert.FingerprintSHA256(): {IsExcluded: true, IsGhosted: false},
		},
	}

	got := pathStatus(path, 0)
	assert.Equal(t, statusValid, got, "excluded cert should not affect trusted path header")

	reason := pathStatusReason(path, 0)
	wantReason := "Excluded Root CA excluded by simulation, still trusted via " + displayName(trustedRoot)
	assert.Equal(t, wantReason, reason)
}

func TestAnalysisStatus(t *testing.T) {
	t.Parallel()

	tc := getCachedCerts(t)

	trustedRoot := tc.valid.WithTrustedLocations([]string{"system"})

	tests := []struct {
		name     string
		analysis *certree.Analysis
		want     statusLevel
	}{
		{
			name:     "nil analysis",
			analysis: nil,
			want:     statusError,
		},
		{
			name:     "empty paths",
			analysis: &certree.Analysis{TrustPaths: []*certree.TrustPath{}},
			want:     statusError,
		},
		{
			name: "single trusted path",
			analysis: &certree.Analysis{
				TrustPaths: []*certree.TrustPath{
					{
						Certificates: []*certree.Certificate{tc.validLeaf, trustedRoot},
						Status:       certree.PathTrusted,
					},
				},
			},
			want: statusValid,
		},
		{
			name: "all paths untrusted",
			analysis: &certree.Analysis{
				TrustPaths: []*certree.TrustPath{
					{
						Certificates: []*certree.Certificate{tc.validLeaf},
						Status:       certree.PathUntrusted,
					},
				},
			},
			want: statusError,
		},
		{
			name: "mixed: one trusted, one untrusted",
			analysis: &certree.Analysis{
				TrustPaths: []*certree.TrustPath{
					{
						Certificates: []*certree.Certificate{tc.validLeaf},
						Status:       certree.PathUntrusted,
					},
					{
						Certificates: []*certree.Certificate{tc.validLeaf, trustedRoot},
						Status:       certree.PathTrusted,
					},
				},
			},
			want: statusValid,
		},
		{
			name: "trusted path with warning only",
			analysis: &certree.Analysis{
				TrustPaths: []*certree.TrustPath{
					{
						// Use the non-self-signed validLeaf with an expiring-soon
						// warning to isolate the warning from self-signed error.
						Certificates: []*certree.Certificate{tc.validLeaf, trustedRoot},
						Status:       certree.PathTrusted,
						Warnings: []certree.ValidationWarning{
							{
								Certificate: tc.validLeaf,
								Type:        certree.WarningExpiringSoon,
								Message:     "expiring soon",
							},
						},
					},
				},
			},
			want: statusWarning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := analysisStatus(tt.analysis, 0)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPathStatus_ExpiredCertAboveTrustAnchor(t *testing.T) {
	t.Parallel()

	now := time.Now()
	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	trustedRaw, trustedKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Trusted CA"},
		IsCA:    true,
	})
	if err != nil {
		t.Fatalf("generating trusted cert: %v", err)
	}
	cert2 := certree.NewCertificate(trustedRaw, src).WithTrustedLocations([]string{"system"})

	leafRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "leaf.example.com"},
		DNSNames: []string{"leaf.example.com"},
	}, trustedRaw, trustedKey)
	if err != nil {
		t.Fatalf("generating leaf cert: %v", err)
	}
	cert1 := certree.NewCertificate(leafRaw, src)

	expiredRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:   pkix.Name{CommonName: "Expired Root"},
		IsCA:      true,
		NotBefore: now.Add(-730 * 24 * time.Hour),
		NotAfter:  now.Add(-365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("generating expired cert: %v", err)
	}
	cert3 := certree.NewCertificate(expiredRaw, src)

	if !cert3.Metadata().IsExpired {
		t.Fatal("test precondition failed: cert3 should be expired")
	}
	if len(cert2.Metadata().TrustedLocations) == 0 {
		t.Fatal("test precondition failed: cert2 should be trusted")
	}

	path := &certree.TrustPath{
		Certificates: []*certree.Certificate{cert1, cert2, cert3},
		Status:       certree.PathTrusted,
	}

	got := pathStatus(path, 0)
	assert.Equal(t, statusValid, got, "expired cert above trust anchor should not affect path status")
}

func TestCertStatus_Reasons_TrustedCertWithError(t *testing.T) {
	t.Parallel()

	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Trusted With Error"},
		IsCA:    true,
	})
	require.NoError(t, err)
	trustedCert := certree.NewCertificate(raw, src).WithTrustedLocations([]string{"system"})

	path := &certree.TrustPath{
		Certificates: []*certree.Certificate{trustedCert},
		Status:       certree.PathTrusted,
		Errors: []certree.ValidationError{
			{Certificate: trustedCert, Type: certree.ErrorInvalidSerialNumber, Message: "invalid serial"},
		},
	}

	got := certStatus(trustedCert, path, 0)
	if got.level != statusWarning {
		t.Fatalf("expected statusWarning, got %v", got.level)
	}
	assert.Contains(t, got.reasons, "invalid serial number", "should contain the error reason")
	assert.Contains(t, got.reasons, "trusted", "should contain 'trusted' suffix")
	assert.Len(t, got.reasons, 2, "should have exactly error reason + trusted")
}

func TestDedup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, []string{}},
		{"single", []string{"a"}, []string{"a"}},
		{"no duplicates", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"adjacent duplicates", []string{"a", "a", "b"}, []string{"a", "b"}},
		{"non-adjacent duplicates", []string{"a", "b", "a"}, []string{"a", "b"}},
		{"all same", []string{"x", "x", "x"}, []string{"x"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := dedup(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

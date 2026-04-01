package cli

import (
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree"
	"github.com/timorunge/certree/pkg/certree/testutil"
)

// cnFilterTestCerts caches generated certificates with different CNs, reused
// across all filter tests to avoid repeated key generation.
var (
	cnFilterTestCertsOnce sync.Once
	cnFilterTestCerts     []*certree.Certificate
	cnFilterTestCertsErr  error
)

// filterTestAnalysisSameOnce caches the analysis for the ("GTS Root R1",
// "GTS Root R1") pair used by TestFilterAnalysisByCN_BothPathsMatch.
var (
	filterTestAnalysisSameOnce sync.Once
	filterTestAnalysisSame     [2]*certree.Certificate
	filterTestAnalysisSameErr  error
)

// filterTestAnalysisDiffOnce caches the certs for the ("GTS Root R1",
// "Other CA") pair used by TestFilterAnalysisByCN_PreservesMetadata.
var (
	filterTestAnalysisDiffOnce sync.Once
	filterTestAnalysisDiff     [2]*certree.Certificate
	filterTestAnalysisDiffErr  error
)

// getCNFilterTestCerts returns certificates with different CNs, generated once
// and reused across all tests to avoid repeated key generation.
func getCNFilterTestCerts(t *testing.T) []*certree.Certificate {
	t.Helper()
	cnFilterTestCertsOnce.Do(func() {
		cnFilterTestCerts, cnFilterTestCertsErr = buildCNFilterTestCerts()
	})
	if cnFilterTestCertsErr != nil {
		t.Fatal(cnFilterTestCertsErr)
	}
	return cnFilterTestCerts
}

// buildCNFilterTestCerts generates certificates with different CNs for filter tests.
func buildCNFilterTestCerts() ([]*certree.Certificate, error) {
	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	now := time.Now()

	cns := []string{
		"valid.example.com",
		"expiring.example.com",
		"expired.example.com",
		"api.example.com",
		"mail.other.org",
		"www.different.net",
	}

	certs := make([]*certree.Certificate, 0, len(cns))
	for _, cn := range cns {
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject:   pkix.Name{CommonName: cn},
			NotBefore: now.Add(-24 * time.Hour),
			NotAfter:  now.Add(365 * 24 * time.Hour),
		})
		if err != nil {
			return nil, fmt.Errorf("generating cert %s: %w", cn, err)
		}
		certs = append(certs, certree.NewCertificate(raw, src))
	}
	return certs, nil
}

// buildFilterTestAnalysis creates an Analysis from the given certificates,
// with trust paths that contain various combinations of certificates.
func buildFilterTestAnalysis(certs []*certree.Certificate) *certree.Analysis {
	paths := make([]*certree.TrustPath, 0, len(certs))
	// One path per certificate (single-cert paths).
	for _, cert := range certs {
		paths = append(paths, &certree.TrustPath{
			Certificates: []*certree.Certificate{cert},
			Status:       certree.PathTrusted,
		})
	}
	if len(certs) >= 2 {
		paths = append(paths, &certree.TrustPath{
			Certificates: []*certree.Certificate{certs[0], certs[1]},
			Status:       certree.PathTrusted,
		})
	}
	if len(certs) >= 5 {
		paths = append(paths, &certree.TrustPath{
			Certificates: []*certree.Certificate{certs[0], certs[4]},
			Status:       certree.PathTrusted,
		})
	}
	return &certree.Analysis{
		Certificates: certs,
		TrustPaths:   paths,
	}
}

// getFilterTestAnalysis returns a freshly constructed Analysis whose two
// certificates were generated once (keyed by same/diff variant) and cached.
// A new Analysis is returned each time so callers can mutate metadata safely.
func getFilterTestAnalysis(t *testing.T, variant string) *certree.Analysis {
	t.Helper()

	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	var cert1, cert2 *certree.Certificate

	switch variant {
	case "same":
		filterTestAnalysisSameOnce.Do(func() {
			filterTestAnalysisSame, filterTestAnalysisSameErr = buildFilterTestPair("GTS Root R1", "GTS Root R1", src)
		})
		if filterTestAnalysisSameErr != nil {
			t.Fatal(filterTestAnalysisSameErr)
		}
		cert1, cert2 = filterTestAnalysisSame[0], filterTestAnalysisSame[1]
	default: // "diff"
		filterTestAnalysisDiffOnce.Do(func() {
			filterTestAnalysisDiff, filterTestAnalysisDiffErr = buildFilterTestPair("GTS Root R1", "Other CA", src)
		})
		if filterTestAnalysisDiffErr != nil {
			t.Fatal(filterTestAnalysisDiffErr)
		}
		cert1, cert2 = filterTestAnalysisDiff[0], filterTestAnalysisDiff[1]
	}

	return certree.NewAnalysis(
		[]*certree.Certificate{cert1, cert2},
		[]*certree.TrustPath{
			{Certificates: []*certree.Certificate{cert1}, Status: certree.PathTrusted},
			{Certificates: []*certree.Certificate{cert2}, Status: certree.PathTrusted},
		},
		"test",
	)
}

// buildFilterTestPair generates a pair of self-signed CA certificates with the given CNs.
func buildFilterTestPair(cn1, cn2 string, src certree.CertificateSource) ([2]*certree.Certificate, error) {
	raw1, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: cn1}, IsCA: true,
	})
	if err != nil {
		return [2]*certree.Certificate{}, fmt.Errorf("generating cert1 (%s): %w", cn1, err)
	}
	raw2, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: cn2}, IsCA: true,
	})
	if err != nil {
		return [2]*certree.Certificate{}, fmt.Errorf("generating cert2 (%s): %w", cn2, err)
	}
	return [2]*certree.Certificate{
		certree.NewCertificate(raw1, src),
		certree.NewCertificate(raw2, src),
	}, nil
}

func TestFilterAnalyses_ByCN_BothPathsMatch(t *testing.T) {
	t.Parallel()

	analysis := getFilterTestAnalysis(t, "same")
	results := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
		filterCN: []string{"GTS Root R1"},
	})
	require.Len(t, results, 1)
	require.Len(t, results[0].TrustPaths, 2)
}

func TestFilterAnalyses_ByCN_OnePathMatches(t *testing.T) {
	t.Parallel()

	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	matchRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "GTS Root R1"}, IsCA: true,
	})
	require.NoError(t, err, "generating matching cert")

	otherRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "DigiCert Global Root"}, IsCA: true,
	})
	require.NoError(t, err, "generating other cert")

	matchCert := certree.NewCertificate(matchRaw, src)
	otherCert := certree.NewCertificate(otherRaw, src)

	analysis := &certree.Analysis{
		Certificates: []*certree.Certificate{matchCert, otherCert},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{matchCert}, Status: certree.PathTrusted},
			{Certificates: []*certree.Certificate{otherCert}, Status: certree.PathTrusted},
		},
	}

	results := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
		filterCN: []string{"GTS Root R1"},
	})
	require.Len(t, results, 1)
	require.Len(t, results[0].TrustPaths, 1)
	assert.Equal(t, "GTS Root R1", results[0].TrustPaths[0].Certificates[0].CommonName())
}

func TestFilterAnalyses_ByCN_WildcardMatch(t *testing.T) {
	t.Parallel()

	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	raw1, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "GTS Root R1"}, IsCA: true,
	})
	require.NoError(t, err, "generating cert1")

	raw2, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "GTS Root R4"}, IsCA: true,
	})
	require.NoError(t, err, "generating cert2")

	cert1 := certree.NewCertificate(raw1, src)
	cert2 := certree.NewCertificate(raw2, src)

	analysis := &certree.Analysis{
		Certificates: []*certree.Certificate{cert1, cert2},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{cert1}, Status: certree.PathTrusted},
			{Certificates: []*certree.Certificate{cert2}, Status: certree.PathTrusted},
		},
	}

	results := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
		filterCN: []string{"GTS*"},
	})
	require.Len(t, results, 1)
	require.Len(t, results[0].TrustPaths, 2)
}

func TestFilterAnalyses_ByCN_PreservesMetadata(t *testing.T) {
	t.Parallel()

	analysis := getFilterTestAnalysis(t, "diff")
	analysis.Metadata.Source = "example.com:443"

	results := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
		filterCN: []string{"GTS Root R1"},
	})
	require.Len(t, results, 1)
	assert.Equal(t, "example.com:443", results[0].Metadata.Source)
}

func TestFilterAnalyses_ByCN_AllPatterns(t *testing.T) {
	t.Parallel()

	cached := getCNFilterTestCerts(t)
	analysis := buildFilterTestAnalysis(cached)

	patterns := []string{
		"*.example.com",
		"valid.example.com",
		"expired.example.com",
		"mail.other.org",
		"*.other.org",
		"www.different.net",
		"*.net",
		"nonexistent.example.com",
		"*",
	}

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			m := certree.NewPatternMatcher([]string{pattern})
			results := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
				filterCN: []string{pattern},
			})
			require.Len(t, results, 1)
			result := results[0]

			// Every certificate in the result must match the pattern.
			for _, cert := range result.Certificates {
				assert.True(t, m.Match(cert.CommonName()),
					"cert CN %q should match pattern %q", cert.CommonName(), pattern)
			}

			// No matching certificate from the original should be missing.
			resultFingerprints := make(map[string]bool, len(result.Certificates))
			for _, cert := range result.Certificates {
				resultFingerprints[cert.FingerprintSHA256()] = true
			}
			for _, cert := range analysis.Certificates {
				if m.Match(cert.CommonName()) {
					assert.True(t, resultFingerprints[cert.FingerprintSHA256()],
						"matching cert %q missing from result", cert.CommonName())
				}
			}

			// Every trust path in the result must contain at least one matching cert.
			for i, tp := range result.TrustPaths {
				hasMatch := false
				for _, cert := range tp.Certificates {
					if m.Match(cert.CommonName()) {
						hasMatch = true
						break
					}
				}
				assert.True(t, hasMatch, "trust path %d has no matching cert", i)
			}

			// Metadata must be preserved.
			assert.Equal(t, analysis.Metadata.Source, result.Metadata.Source)
		})
	}
}

func TestFilterAnalyses_EmptyPatternsReturnsOriginal(t *testing.T) {
	t.Parallel()

	cached := getCNFilterTestCerts(t)
	analysis := buildFilterTestAnalysis(cached)

	results := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{})
	require.Len(t, results, 1)
	assert.Equal(t, len(analysis.Certificates), len(results[0].Certificates))
	assert.Equal(t, len(analysis.TrustPaths), len(results[0].TrustPaths))
}

func TestFilterAnalyses_ByFingerprint(t *testing.T) {
	t.Parallel()

	cached := getCNFilterTestCerts(t)
	analysis := buildFilterTestAnalysis(cached)
	fp := cached[0].FingerprintSHA256()

	result := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
		filterFingerprint: []string{fp},
	})
	require.Len(t, result, 1)
	require.Len(t, result[0].Certificates, 1)
	assert.Equal(t, fp, result[0].Certificates[0].FingerprintSHA256())
}

func TestFilterAnalyses_BySerial(t *testing.T) {
	t.Parallel()

	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	raw1, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Serial One"},
		SerialNumber: big.NewInt(111),
	})
	require.NoError(t, err)
	raw2, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Serial Two"},
		SerialNumber: big.NewInt(222),
	})
	require.NoError(t, err)

	cert1 := certree.NewCertificate(raw1, src)
	cert2 := certree.NewCertificate(raw2, src)

	analysis := &certree.Analysis{
		Certificates: []*certree.Certificate{cert1, cert2},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{cert1}, Status: certree.PathTrusted},
			{Certificates: []*certree.Certificate{cert2}, Status: certree.PathTrusted},
		},
	}

	result := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
		filterSerial: []string{cert1.SerialNumber()},
	})
	require.Len(t, result, 1)
	require.Len(t, result[0].Certificates, 1)
	assert.Equal(t, cert1.SerialNumber(), result[0].Certificates[0].SerialNumber())
}

func TestFilterAnalyses_CombinedFiltersUseOR(t *testing.T) {
	t.Parallel()

	cached := getCNFilterTestCerts(t)
	analysis := buildFilterTestAnalysis(cached)

	// Filter by CN of first cert OR fingerprint of second cert.
	result := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
		filterCN:          []string{cached[0].CommonName()},
		filterFingerprint: []string{cached[1].FingerprintSHA256()},
	})
	require.Len(t, result, 1)
	assert.GreaterOrEqual(t, len(result[0].Certificates), 2)
}

func TestApplyFilters_PreservesIsSimulated(t *testing.T) {
	t.Parallel()

	analysis := getFilterTestAnalysis(t, "diff")
	analysis = certree.NewAnalysis(
		analysis.Certificates,
		analysis.TrustPaths,
		analysis.Metadata.Source,
		certree.WithSimulated(true),
	)

	results := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
		filterCN: []string{"GTS Root R1"},
	})
	require.Len(t, results, 1)
	assert.True(t, results[0].Metadata.IsSimulated, "IsSimulated should be preserved through filtering")
}

func TestApplyFilters_NonSimulatedStaysFalse(t *testing.T) {
	t.Parallel()

	analysis := getFilterTestAnalysis(t, "diff")

	results := filterAnalyses([]*certree.Analysis{analysis}, nonConfigFlags{
		filterCN: []string{"GTS Root R1"},
	})
	require.Len(t, results, 1)
	assert.False(t, results[0].Metadata.IsSimulated, "IsSimulated should remain false for non-simulated analysis")
}

func TestApplyFilters_NilAnalysisReturnsNil(t *testing.T) {
	t.Parallel()

	filters := buildFilters(nonConfigFlags{filterCN: []string{"*.example.com"}})
	assert.Nil(t, applyFilters(nil, filters))
}

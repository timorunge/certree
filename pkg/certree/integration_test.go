package certree

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// integrationMockTrustStoreMultipleRoots trusts multiple root certificates.
type integrationMockTrustStoreMultipleRoots struct {
	roots []*Certificate
}

func (m *integrationMockTrustStoreMultipleRoots) IsTrusted(cert *Certificate) bool {
	for _, root := range m.roots {
		if cert.FingerprintSHA256() == root.FingerprintSHA256() {
			return true
		}
	}
	return false
}

func (m *integrationMockTrustStoreMultipleRoots) TrustedLocations(cert *Certificate) []string {
	if m.IsTrusted(cert) {
		return []string{"test"}
	}
	return nil
}

func (m *integrationMockTrustStoreMultipleRoots) LoadSystemRoots() error { return nil }

func (m *integrationMockTrustStoreMultipleRoots) LoadCustomRoots(_ string) error { return nil }

func (m *integrationMockTrustStoreMultipleRoots) FindIssuers(cert *Certificate) []*Certificate {
	if cert == nil {
		return nil
	}
	var issuers []*Certificate
	for _, root := range m.roots {
		if bytes.Equal(cert.Raw().RawIssuer, root.Raw().RawSubject) {
			issuers = append(issuers, root)
		}
	}
	return issuers
}

// integrationMockEmptyTrustStore trusts no certificates.
type integrationMockEmptyTrustStore struct{}

func (m *integrationMockEmptyTrustStore) IsTrusted(_ *Certificate) bool { return false }

func (m *integrationMockEmptyTrustStore) TrustedLocations(_ *Certificate) []string { return nil }

func (m *integrationMockEmptyTrustStore) LoadSystemRoots() error { return nil }

func (m *integrationMockEmptyTrustStore) LoadCustomRoots(_ string) error { return nil }

func (m *integrationMockEmptyTrustStore) FindIssuers(_ *Certificate) []*Certificate { return nil }

// integrationMockAIAFetcherCircular creates circular references.
type integrationMockAIAFetcherCircular struct {
	cert1 *Certificate
	cert2 *Certificate
}

// FetchIssuers implements AIAFetcher interface with circular reference behavior.
func (m *integrationMockAIAFetcherCircular) FetchIssuers(_ context.Context, cert *Certificate) ([]*Certificate, error) {
	if cert.FingerprintSHA256() == m.cert1.FingerprintSHA256() {
		return []*Certificate{m.cert2}, nil
	}
	if cert.FingerprintSHA256() == m.cert2.FingerprintSHA256() {
		return []*Certificate{m.cert1}, nil
	}
	return nil, fmt.Errorf("no issuer found")
}

func (m *integrationMockAIAFetcherCircular) ResetCache() {}

// integrationMockAIAFetcherWithCert returns a specific certificate on fetch.
type integrationMockAIAFetcherWithCert struct {
	cert *Certificate
}

func (m *integrationMockAIAFetcherWithCert) FetchIssuers(_ context.Context, _ *Certificate) ([]*Certificate, error) {
	return []*Certificate{m.cert}, nil
}

func (m *integrationMockAIAFetcherWithCert) ResetCache() {}

func TestIntegration_LocalFileWithCrossSignedIntermediates_AIADisabled(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	root1Cert, root1Key, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Root CA 1"}, IsCA: true,
	})
	if err != nil {
		t.Fatalf("Failed to generate root1: %v", err)
	}

	root2Cert, root2Key, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Root CA 2"}, IsCA: true,
	})
	if err != nil {
		t.Fatalf("Failed to generate root2: %v", err)
	}

	intermediate1Cert, intermediate1Key, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Intermediate CA"}, IsCA: true},
		root1Cert, root1Key,
	)
	if err != nil {
		t.Fatalf("Failed to generate intermediate1: %v", err)
	}

	intermediate2Cert, _, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Intermediate CA"}, IsCA: true},
		root2Cert, root2Key,
	)
	if err != nil {
		t.Fatalf("Failed to generate intermediate2: %v", err)
	}

	endEntityCert, _, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "example.com"}, IsCA: false},
		intermediate1Cert, intermediate1Key,
	)
	if err != nil {
		t.Fatalf("Failed to generate end-entity: %v", err)
	}

	fileSource := CertificateSource{Type: SourceTypeFile}
	certs := []*Certificate{
		NewCertificate(endEntityCert, fileSource),
		NewCertificate(intermediate1Cert, fileSource),
		NewCertificate(intermediate2Cert, fileSource),
		NewCertificate(root1Cert, fileSource),
		NewCertificate(root2Cert, fileSource),
	}

	trustStore := &integrationMockTrustStoreMultipleRoots{
		roots: []*Certificate{
			NewCertificate(root1Cert, fileSource),
			NewCertificate(root2Cert, fileSource),
		},
	}

	builder := NewChainBuilder(WithAIAFetch(false))

	paths, err := builder.BuildChains(t.Context(), certs, trustStore)
	if err != nil {
		t.Fatalf("BuildChains failed: %v", err)
	}

	if len(paths) < 2 {
		t.Errorf("Expected at least 2 paths (cross-signing), got %d", len(paths))
	}

	for i, path := range paths {
		if path.Status == PathIncomplete {
			t.Errorf("Path %d should be complete", i)
		}
		if !path.Status.IsTrusted() {
			t.Errorf("Path %d should be trusted", i)
		}
	}

	for _, path := range paths {
		for _, cert := range path.Certificates {
			if cert.Source().Type == SourceTypeAIA {
				t.Error("Found AIA-fetched certificate when AIA was disabled")
			}
		}
	}
}

func TestIntegration_MultiplePathsDiscoveredViaAIA(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Scenario: leaf -> intermediate -> root1 (self-signed, provided in pool)
	// AIA fetching for root1 discovers root2, a cross-signed version of root1
	// (same subject + same public key, signed by a different CA).
	// This creates two paths:
	//   Path 1: leaf -> intermediate -> root1 (self-signed)
	//   Path 2: leaf -> intermediate -> root1-cross (signed by root2CA)
	root1Cert, root1Key, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Root CA 1"}, IsCA: true,
	})
	if err != nil {
		t.Fatalf("Failed to generate root1: %v", err)
	}

	intermediateCert, intermediateKey, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Intermediate CA"}, IsCA: true},
		root1Cert, root1Key,
	)
	if err != nil {
		t.Fatalf("Failed to generate intermediate: %v", err)
	}

	leafCert, _, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "leaf.example.com"}},
		intermediateCert, intermediateKey,
	)
	if err != nil {
		t.Fatalf("Failed to generate leaf: %v", err)
	}

	// Create an external CA that will cross-sign root1.
	externalCA, externalKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "External CA"}, IsCA: true,
	})
	if err != nil {
		t.Fatalf("Failed to generate external CA: %v", err)
	}

	// Cross-sign root1: same subject + same public key, signed by externalCA.
	crossTemplate := testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Root CA 1"},
		IsCA:    true,
	}
	testutil.ApplyTemplateDefaults(&crossTemplate)
	crossX509 := testutil.ToX509Template(crossTemplate)
	root1Cross, err := testutil.CreateAndParseCert(crossX509, externalCA, &root1Key.PublicKey, externalKey)
	if err != nil {
		t.Fatalf("Failed to create cross-signed root: %v", err)
	}

	wrappedLeaf := NewCertificate(leafCert, CertificateSource{Type: SourceTypeFile})
	wrappedIntermediate := NewCertificate(intermediateCert, CertificateSource{Type: SourceTypeFile})
	wrappedRoot1 := NewCertificate(root1Cert, CertificateSource{Type: SourceTypeFile})
	wrappedRoot1Cross := NewCertificate(root1Cross, CertificateSource{Type: SourceTypeAIA})

	// Mock fetcher returns the cross-signed root when asked for an issuer.
	mockFetcher := &integrationMockAIAFetcherWithCert{cert: wrappedRoot1Cross}

	// Trust store trusts both the self-signed root and the cross-signed version.
	trustStore := &integrationMockTrustStoreMultipleRoots{
		roots: []*Certificate{wrappedRoot1, wrappedRoot1Cross},
	}

	// Provide only leaf and intermediate in the pool. The root is NOT in the pool,
	// so the chain builder must use AIA to discover the cross-signed root.
	inputCerts := []*Certificate{wrappedLeaf, wrappedIntermediate}

	builder := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAFetcher(mockFetcher),
	)

	paths, err := builder.BuildChains(t.Context(), inputCerts, trustStore)
	if err != nil {
		t.Fatalf("BuildChains failed: %v", err)
	}

	leafPaths := 0
	hasAIACert := false
	for _, path := range paths {
		if len(path.Certificates) > 0 && path.Certificates[0].FingerprintSHA256() == wrappedLeaf.FingerprintSHA256() {
			leafPaths++
			for _, c := range path.Certificates {
				if c.Source().Type == SourceTypeAIA {
					hasAIACert = true
				}
			}
		}
	}

	if leafPaths == 0 {
		t.Fatal("expected at least one path for leaf")
	}

	if !hasAIACert {
		t.Error("expected AIA-fetched certificate in at least one path; root was not in pool so AIA should have been triggered")
	}
}

func TestIntegration_CircularReferencesWithAIA(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a chain where AIA fetching creates a circular reference.
	// We need an end-entity cert whose issuer is NOT in the pool, so AIA is triggered.
	// The mock fetcher returns certificates that point back to each other.
	rootCert, rootKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Root CA"}, IsCA: true,
	})
	if err != nil {
		t.Fatalf("Failed to generate root: %v", err)
	}

	intermediateCert, intermediateKey, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Intermediate CA"}, IsCA: true},
		rootCert, rootKey,
	)
	if err != nil {
		t.Fatalf("Failed to generate intermediate: %v", err)
	}

	leafCert, _, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Leaf Cert"}},
		intermediateCert, intermediateKey,
	)
	if err != nil {
		t.Fatalf("Failed to generate leaf: %v", err)
	}

	// Only provide the leaf - no intermediate or root in the pool.
	wrappedLeaf := NewCertificate(leafCert, CertificateSource{Type: SourceTypeFile})
	wrappedIntermediate := NewCertificate(intermediateCert, CertificateSource{Type: SourceTypeAIA})

	// Mock fetcher always returns the intermediate, creating a cycle:
	// leaf -> (AIA fetch) intermediate -> (AIA fetch) intermediate (same cert = circular).
	mockFetcher := &integrationMockAIAFetcherCircular{
		cert1: wrappedLeaf,
		cert2: wrappedIntermediate,
	}

	trustStore := &integrationMockEmptyTrustStore{}

	builder := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAFetcher(mockFetcher),
		WithMaxDepth(10),
	)

	paths, err := builder.BuildChains(t.Context(), []*Certificate{wrappedLeaf}, trustStore)

	if err != nil {
		t.Fatalf("BuildChains should handle circular references: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("Expected at least one path")
	}

	// All paths should be incomplete because the root is not in the trust store
	// and the AIA fetcher creates a cycle (intermediate -> intermediate).
	for i, path := range paths {
		if path.Status.IsTrusted() {
			t.Errorf("Path %d should not be trusted (root not in trust store), got status %v", i, path.Status)
		}
	}
}

func TestChainBuilder_TrustedCertHasLocations(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	x509Certs, _, err := testutil.GenerateChainWithDepth(3)
	if err != nil {
		t.Fatalf("Failed to generate chain: %v", err)
	}

	certs := make([]*Certificate, len(x509Certs))
	for i, c := range x509Certs {
		certs[i] = NewCertificate(c, CertificateSource{
			Type:     SourceTypeFile,
			Location: "test",
		})
	}

	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "root.pem")
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x509Certs[2].Raw})
	err = os.WriteFile(bundlePath, rootPEM, 0600)
	if err != nil {
		t.Fatalf("Failed to write PEM file: %v", err)
	}

	ts := NewTrustStore()
	err = ts.LoadCustomRoots(bundlePath)
	if err != nil {
		t.Fatalf("LoadCustomRoots() error = %v", err)
	}

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), certs, ts)
	if err != nil {
		t.Fatalf("BuildChains() error = %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("Expected at least one trust path")
	}

	for _, path := range paths {
		if !path.Status.IsTrusted() {
			continue
		}
		rootCert := path.Root()
		locs := rootCert.Metadata().TrustedLocations
		if len(locs) == 0 {
			t.Errorf("Trusted root %q should have TrustedLocations populated, got empty", rootCert.CommonName())
		}
		if locs[0] != bundlePath {
			t.Errorf("Expected TrustedLocations[0] = %q, got %q", bundlePath, locs[0])
		}
	}
}

func TestChainBuilder_UntrustedCertHasEmptyLocations(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	x509Certs, _, err := testutil.GenerateChainWithDepth(3)
	if err != nil {
		t.Fatalf("Failed to generate chain: %v", err)
	}

	certs := make([]*Certificate, len(x509Certs))
	for i, c := range x509Certs {
		certs[i] = NewCertificate(c, CertificateSource{
			Type:     SourceTypeFile,
			Location: "test",
		})
	}

	ts := NewTrustStore()

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), certs, ts)
	if err != nil {
		t.Fatalf("BuildChains() error = %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("Expected at least one trust path")
	}

	for _, path := range paths {
		if path.Status.IsTrusted() {
			t.Error("Expected no trusted paths with empty trust store")
		}
		for _, cert := range path.Certificates {
			locs := cert.Metadata().TrustedLocations
			if locs == nil {
				t.Errorf("TrustedLocations should never be nil for cert %q, got nil", cert.CommonName())
			}
			if len(locs) != 0 {
				t.Errorf("Untrusted cert %q should have empty TrustedLocations, got %v", cert.CommonName(), locs)
			}
		}
	}
}

func TestChainBuilder_MultipleTrustStoresPopulateAllLocations(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpl := testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Multi-Store Root CA"},
		IsCA:    true,
	}
	rootX509, _, err := testutil.GenerateSelfSignedCertUniqueKey(tmpl)
	if err != nil {
		t.Fatalf("Failed to generate root: %v", err)
	}

	root := NewCertificate(rootX509, CertificateSource{Type: SourceTypeFile, Location: "test"})

	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "custom-ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootX509.Raw})
	err = os.WriteFile(bundlePath, pemData, 0600)
	if err != nil {
		t.Fatalf("Failed to write PEM file: %v", err)
	}

	bundlePath2 := filepath.Join(tmpDir, "custom-ca-2.pem")
	err = os.WriteFile(bundlePath2, pemData, 0600)
	if err != nil {
		t.Fatalf("Failed to write second PEM file: %v", err)
	}

	ts := NewTrustStore()
	err = ts.LoadCustomRoots(bundlePath)
	if err != nil {
		t.Fatalf("LoadCustomRoots(bundlePath) error = %v", err)
	}
	err = ts.LoadCustomRoots(bundlePath2)
	if err != nil {
		t.Fatalf("LoadCustomRoots(bundlePath2) error = %v", err)
	}

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), []*Certificate{root}, ts)
	if err != nil {
		t.Fatalf("BuildChains() error = %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("Expected at least one trust path")
	}

	for _, path := range paths {
		if !path.Status.IsTrusted() {
			t.Error("Expected path to be trusted")
			continue
		}
		rootCert := path.Root()
		locs := rootCert.Metadata().TrustedLocations
		if len(locs) != 2 {
			t.Fatalf("Expected 2 locations (custom bundle + custom bundle), got %d: %v", len(locs), locs)
		}
		if locs[0] != bundlePath {
			t.Errorf("Expected first location %q, got %q", bundlePath, locs[0])
		}
		if locs[1] != bundlePath2 {
			t.Errorf("Expected second location %q, got %q", bundlePath2, locs[1])
		}
	}
}

// These tests exercise the contract that Parser errors pass through the
// Analyzer unchanged -- no wrapping, no prefix, no loss of StructuredError
// fields. This boundary was explicitly redesigned in the error handling v2
// refactor (S2: parser returns errors directly). A unit test for the Parser
// alone cannot catch an Analyzer that silently wraps the error; a unit test
// for the Analyzer alone uses mocks that bypass real Parser errors. Only an
// integration test that wires real components catches regressions at the seam.

// TestIntegration_ParserAnalyzerPassthrough verifies that a real Parser error
// survives the Analyzer boundary intact. The StructuredError created by the
// Parser for a nonexistent file must be extractable via errors.As, must match
// the ErrFileReadFailed sentinel via errors.Is, must carry the OS cause in
// Detail(), and must NOT have an Analyzer-added wrapping prefix. This catches
// regressions where the Analyzer accidentally wraps parser errors with
// fmt.Errorf, which would bury the StructuredError and break CLI formatting.
func TestIntegration_ParserAnalyzerPassthrough(t *testing.T) {
	t.Parallel()

	p := NewParser()
	analyzer, err := NewAnalyzer(WithParser(p))
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}

	// Use a path rooted in t.TempDir() so it is absolute on all platforms,
	// including Windows where "/nonexistent/..." is not absolute.
	certPath := filepath.Join(t.TempDir(), "nonexistent", "cert.pem")
	_, analyzeErr := analyzer.AnalyzeFile(t.Context(), certPath)
	if analyzeErr == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}

	// errors.As must extract the *StructuredError.
	var se *StructuredError
	if !errors.As(analyzeErr, &se) {
		t.Fatalf("errors.As failed to extract *StructuredError from: %v", analyzeErr)
	}

	// The user message must contain the file path.
	if !strings.Contains(se.UserMessage(), certPath) {
		t.Errorf("UserMessage() = %q, should contain file path", se.UserMessage())
	}

	// The sentinel must be ErrFileReadFailed.
	if !errors.Is(analyzeErr, ErrFileReadFailed) {
		t.Errorf("errors.Is(err, ErrFileReadFailed) = false, want true; err = %v", analyzeErr)
	}

	// The cause (Detail) must be non-nil (OS error).
	if se.Detail() == nil {
		t.Error("Detail() = nil, want non-nil OS error")
	}

	// The error should NOT have any wrapping prefix from the Analyzer.
	// Previously it would have "parsing certificates: " prefix.
	if strings.Contains(analyzeErr.Error(), "parsing certificates:") {
		t.Errorf("error should not contain wrapping prefix, got %q", analyzeErr.Error())
	}
}

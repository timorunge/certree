package certree

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// generateTestCertificatesForSimulator generates 5 test certificates with sequential naming.
func generateTestCertificatesForSimulator(t *testing.T) []*Certificate {
	t.Helper()

	const count = 5
	certs := make([]*Certificate, count)
	for i := range count {
		template := testutil.CertificateTemplate{
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("test-%d.example.com", i+1),
			},
			SerialNumber: big.NewInt(int64(i + 1)),
		}
		cert, _, err := testutil.GenerateSelfSignedCertUniqueKey(template)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
			return nil
		}
		certs[i] = NewCertificate(cert, CertificateSource{Type: SourceTypeFile, Location: "test"})
	}
	return certs
}

func createSimpleTestAnalysis(certs []*Certificate) *Analysis {
	return NewAnalysis(certs, []*TrustPath{}, "test")
}

func TestSimulator_ExcludeByFingerprint(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificatesForSimulator(t)
	analysis := createSimpleTestAnalysis(certs)

	targetFingerprint := certs[0].FingerprintSHA256()
	simulator := NewSimulator()
	simulated, err := simulator.ExcludeByFingerprint(targetFingerprint).Simulate(t.Context(), analysis)

	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}

	for _, cert := range simulated.Certificates {
		if cert.FingerprintSHA256() == targetFingerprint {
			t.Errorf("Certificate with fingerprint %s was not excluded", targetFingerprint)
		}
	}
}

func TestSimulator_MultipleExclusions(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificatesForSimulator(t)
	analysis := createSimpleTestAnalysis(certs)

	simulator := NewSimulator()
	simulated, err := simulator.
		ExcludeByCommonName(certs[0].CommonName()).
		ExcludeByFingerprint(certs[1].FingerprintSHA256()).
		ExcludeBySerial(certs[2].SerialNumber()).
		Simulate(t.Context(), analysis)

	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}

	excludedCount := 0
	for _, cert := range analysis.Certificates {
		found := false
		for _, simCert := range simulated.Certificates {
			if cert.FingerprintSHA256() == simCert.FingerprintSHA256() {
				found = true
				break
			}
		}
		if !found {
			excludedCount++
		}
	}

	if excludedCount < 3 {
		t.Errorf("Expected at least 3 certificates excluded, got %d", excludedCount)
	}
}

func TestSimulator_NilAnalysis(t *testing.T) {
	t.Parallel()

	simulator := NewSimulator()
	_, err := simulator.Simulate(t.Context(), nil)

	if err == nil {
		t.Error("Expected error for nil analysis")
	}
}

func TestSimulator_ContextCancellation(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificatesForSimulator(t)
	analysis := createSimpleTestAnalysis(certs)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	simulator := NewSimulator()
	_, err := simulator.ExcludeByCommonName("test").Simulate(ctx, analysis)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

// TestSimulator_CrossSignedRootExclusion verifies that excluding the signing root
// in a cross-signed chain keeps the path trusted when the cert below it is
// independently in the system trust store.
//
// Scenario: leaf -> intermediate -> Root A -> Root B (path root).
// Root A has TrustedLocations (it exists in the system trust store independently).
// Root B is excluded.
//
// Per RFC 5280 Section 6, path validation terminates at a trust anchor (any cert
// in the system trust store). Root A is independently in the trust store, so it
// is a valid trust anchor. Excluding Root B above it should NOT break the chain.
// Root B is ghosted, but the path remains trusted with Root A as the effective
// trust anchor.
func TestSimulator_CrossSignedRootExclusion(t *testing.T) {
	t.Parallel()

	// Generate a 4-cert chain: leaf -> intermediate -> rootA -> rootB.
	rootBTemplate := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Root B"},
		SerialNumber: big.NewInt(1),
		IsCA:         true,
	}
	rootBRaw, rootBKey, err := testutil.GenerateSelfSignedCert(rootBTemplate)
	if err != nil {
		t.Fatalf("generate Root B: %v", err)
	}

	rootATemplate := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Root A"},
		SerialNumber: big.NewInt(2),
		IsCA:         true,
	}
	rootARaw, rootAKey, err := testutil.GenerateSignedCert(rootATemplate, rootBRaw, rootBKey)
	if err != nil {
		t.Fatalf("generate Root A: %v", err)
	}

	intermediateTemplate := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Intermediate"},
		SerialNumber: big.NewInt(3),
		IsCA:         true,
	}
	intermediateRaw, intermediateKey, err := testutil.GenerateSignedCert(intermediateTemplate, rootARaw, rootAKey)
	if err != nil {
		t.Fatalf("generate Intermediate: %v", err)
	}

	leafTemplate := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Leaf"},
		SerialNumber: big.NewInt(4),
	}
	leafRaw, _, err := testutil.GenerateSignedCert(leafTemplate, intermediateRaw, intermediateKey)
	if err != nil {
		t.Fatalf("generate Leaf: %v", err)
	}

	// Wrap as certree Certificates.
	src := CertificateSource{Type: SourceTypeFile, Location: "test"}
	leaf := NewCertificate(leafRaw, src)
	intermediate := NewCertificate(intermediateRaw, src)
	rootA := NewCertificate(rootARaw, src)
	rootB := NewCertificate(rootBRaw, src)

	// Root A is independently in the system trust store.
	rootA = rootA.WithTrustedLocations([]string{"system"})

	// Build the original path with Root B as the path root.
	originalPath := &TrustPath{
		Certificates: []*Certificate{leaf, intermediate, rootA, rootB},
		Status:       PathTrusted,
	}

	analysis := NewAnalysis(
		[]*Certificate{leaf, intermediate, rootA, rootB},
		[]*TrustPath{originalPath},
		"test",
	)

	// Exclude Root B.
	simulator := NewSimulator()
	simulated, err := simulator.ExcludeByCommonName("Root B").Simulate(t.Context(), analysis)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}

	if len(simulated.TrustPaths) != 1 {
		t.Fatalf("expected 1 trust path, got %d", len(simulated.TrustPaths))
	}

	simPath := simulated.TrustPaths[0]

	// The path must be trusted: Root A is independently in the system trust
	// store, making it a valid trust anchor per RFC 5280. Excluding Root B
	// above it does not break the chain.
	if !simPath.Status.IsTrusted() {
		t.Errorf("path should be trusted (Root A is in trust store), but Status = %v", simPath.Status)
	}

	// All 4 certs should still be present (ghost visualization).
	if len(simPath.Certificates) != 4 {
		t.Errorf("expected 4 certificates (structural alignment), got %d", len(simPath.Certificates))
	}

	// Root() returns the structural last cert (Root B), which is ghosted.
	if simPath.Root() == nil {
		t.Fatal("simulated path Root() is nil")
	}
	if simPath.Root().FingerprintSHA256() != rootB.FingerprintSHA256() {
		t.Errorf("Root() should return structural last cert (Root B), got %s", simPath.Root().CommonName())
	}

	// Root B must be excluded in SimulationMetadata (it matched the exclusion criteria).
	rootBState, ok := simPath.SimulationMetadata[rootB.FingerprintSHA256()]
	if !ok {
		t.Fatal("Root B should be in SimulationMetadata")
	}
	if !rootBState.IsExcluded {
		t.Error("Root B should be excluded")
	}

	// Root A is the effective trust anchor: it is independently in the
	// trust store and is the highest non-ghosted/non-excluded cert.
	if len(rootA.Metadata().TrustedLocations) == 0 {
		t.Error("Root A should have trusted locations (effective trust anchor)")
	}
}

func TestSimulator_CombinedExclusions(t *testing.T) {
	t.Parallel()

	// Generate a 4-cert chain: leaf -> intA -> intB -> root.
	x509Certs, _, err := testutil.GenerateChainWithDepth(4)
	if err != nil {
		t.Fatalf("generate chain: %v", err)
	}

	src := CertificateSource{Type: SourceTypeFile, Location: "test"}
	certs := make([]*Certificate, len(x509Certs))
	for i, raw := range x509Certs {
		certs[i] = NewCertificate(raw, src)
	}

	// Exclude intB (index 2) by fingerprint and root (index 3) by CN.
	intBFP := certs[2].FingerprintSHA256()
	rootCN := certs[3].CommonName()

	tp := &TrustPath{
		Certificates: certs,
		Status:       PathTrusted,
	}

	analysis := NewAnalysis(certs, []*TrustPath{tp}, "test")

	simulator := NewSimulator()
	simulated, err := simulator.
		ExcludeByFingerprint(intBFP).
		ExcludeByCommonName(rootCN).
		Simulate(t.Context(), analysis)
	if err != nil {
		t.Fatalf("Simulate() error = %v", err)
	}

	if len(simulated.TrustPaths) != 1 {
		t.Fatalf("expected 1 trust path, got %d", len(simulated.TrustPaths))
	}

	simPath := simulated.TrustPaths[0]

	// The first excluded cert in the path is intB (index 2). simulatePath
	// stops at the first exclusion match, so intB gets IsExcluded.
	// Root (index 3) is above intB and gets IsGhosted.
	if !simPath.IsExcluded(certs[2]) {
		t.Errorf("intB (fingerprint excluded) missing IsExcluded in SimulationMetadata")
	}
}

func TestSimulator_InjectCertificates(t *testing.T) {
	t.Parallel()

	// Generate a 3-cert chain: leaf -> intermediate -> root.
	x509Chain, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("GenerateSimpleChain: %v", err)
	}

	src := CertificateSource{Type: SourceTypeFile, Location: "test"}
	leaf := NewCertificate(x509Chain[0], src)
	intermediate := NewCertificate(x509Chain[1], src)
	root := NewCertificate(x509Chain[2], src)

	// Write the root cert to a temp file so we can load it as a custom trust bundle.
	rootPEM := testutil.EncodePEM(x509Chain[2])
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "root.pem")
	err = os.WriteFile(bundlePath, rootPEM, 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Build trust store with the root as a custom root.
	ts := NewTrustStore()
	err = ts.LoadCustomRoots(bundlePath)
	if err != nil {
		t.Fatalf("LoadCustomRoots: %v", err)
	}
	cb := NewChainBuilder(WithMaxDepth(10))

	// Create an analysis with only leaf (no intermediate, no root in certs).
	// This simulates "we only have the leaf, chain is incomplete."
	incompletePaths, err := cb.BuildChains(t.Context(), []*Certificate{leaf}, ts)
	if err != nil {
		t.Fatalf("BuildChains: %v", err)
	}
	analysis := NewAnalysis([]*Certificate{leaf}, incompletePaths, "test")

	// Verify the original analysis has no trusted paths.
	if analysis.Metadata.TrustedPaths > 0 {
		t.Fatalf("expected 0 trusted paths without intermediate, got %d", analysis.Metadata.TrustedPaths)
	}

	// Inject the intermediate and simulate.
	sim := NewSimulator(
		WithSimulatorChainBuilder(cb),
		WithSimulatorTrustStore(ts),
	)
	sim.InjectCertificates([]*Certificate{intermediate})

	simulated, err := sim.Simulate(t.Context(), analysis)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}

	// The simulated analysis should have trusted paths now.
	if simulated.Metadata.TrustedPaths == 0 {
		t.Errorf("expected trusted paths after injection, got 0")
	}

	// Verify the intermediate is marked as injected in SimulationMetadata.
	found := false
	for _, path := range simulated.TrustPaths {
		if path.IsInjected(intermediate) {
			found = true
			break
		}
		// Also check by fingerprint since the chain builder may create new Certificate objects.
		for _, cert := range path.Certificates {
			if cert.FingerprintSHA256() == intermediate.FingerprintSHA256() {
				if state, ok := path.SimulationMetadata[cert.FingerprintSHA256()]; ok && state.IsInjected {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("intermediate cert not marked as injected in any trust path")
	}

	// Verify IsSimulated flag.
	if !simulated.Metadata.IsSimulated {
		t.Errorf("simulated analysis should have IsSimulated = true")
	}

	// Verify intermediate is in the final cert list.
	certFPs := make(map[string]bool)
	for _, c := range simulated.Certificates {
		certFPs[c.FingerprintSHA256()] = true
	}
	if !certFPs[intermediate.FingerprintSHA256()] {
		t.Errorf("intermediate cert not in simulated.Certificates")
	}
	_ = root // root is loaded via trust store, may or may not be in certs
}

func TestSimulator_InjectWithExclusion(t *testing.T) {
	t.Parallel()

	// Generate two separate chains sharing the same root but different intermediates.
	rootRaw, rootKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Root CA"},
		IsCA:         true,
		SerialNumber: big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	oldIntRaw, oldIntKey, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "Old Intermediate"},
		IsCA:         true,
		SerialNumber: big.NewInt(2),
	}, rootRaw, rootKey)
	if err != nil {
		t.Fatalf("GenerateSignedCert (old int): %v", err)
	}

	// The new intermediate reuses the old intermediate's key pair so that the
	// leaf's AKI (which points to old intermediate's SKI) also matches the new
	// intermediate's SKI. This simulates a real CA rotation where the
	// intermediate certificate is re-issued with a new subject/serial but the
	// same key.
	newIntTmpl := testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "New Intermediate"},
		IsCA:         true,
		SerialNumber: big.NewInt(3),
	}
	testutil.ApplyTemplateDefaults(&newIntTmpl)
	newIntX509 := testutil.ToX509Template(newIntTmpl)
	newIntRaw, err := testutil.CreateAndParseCert(newIntX509, rootRaw, &oldIntKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateAndParseCert (new int): %v", err)
	}

	leafRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		SerialNumber: big.NewInt(4),
	}, oldIntRaw, oldIntKey)
	if err != nil {
		t.Fatalf("GenerateSignedCert (leaf): %v", err)
	}

	src := CertificateSource{Type: SourceTypeFile, Location: "test"}
	leaf := NewCertificate(leafRaw, src)
	oldInt := NewCertificate(oldIntRaw, src)
	newInt := NewCertificate(newIntRaw, src)

	// Trust store with the root.
	rootPEM := testutil.EncodePEM(rootRaw)
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "root.pem")
	err = os.WriteFile(bundlePath, rootPEM, 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ts := NewTrustStore()
	err = ts.LoadCustomRoots(bundlePath)
	if err != nil {
		t.Fatalf("LoadCustomRoots: %v", err)
	}
	cb := NewChainBuilder(WithMaxDepth(10))

	// Build original analysis with leaf + old intermediate.
	origPaths, err := cb.BuildChains(t.Context(), []*Certificate{leaf, oldInt}, ts)
	if err != nil {
		t.Fatalf("BuildChains: %v", err)
	}
	analysis := NewAnalysis([]*Certificate{leaf, oldInt}, origPaths, "test")

	if analysis.Metadata.TrustedPaths == 0 {
		t.Fatalf("expected trusted paths with old intermediate, got 0")
	}

	// Simulate rotation: inject new intermediate, exclude old one.
	sim := NewSimulator(
		WithSimulatorChainBuilder(cb),
		WithSimulatorTrustStore(ts),
	)
	sim.InjectCertificates([]*Certificate{newInt}).ExcludeByCommonName("Old Intermediate")

	simulated, err := sim.Simulate(t.Context(), analysis)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}

	// Should still have trusted paths via the new intermediate.
	if simulated.Metadata.TrustedPaths == 0 {
		t.Errorf("expected trusted paths after rotation, got 0")
	}

	// Old intermediate should not be in the final cert list.
	for _, c := range simulated.Certificates {
		if c.CommonName() == "Old Intermediate" {
			t.Errorf("old intermediate should have been excluded from Certificates")
		}
	}

	// New intermediate should be in the cert list.
	foundNew := false
	for _, c := range simulated.Certificates {
		if c.FingerprintSHA256() == newInt.FingerprintSHA256() {
			foundNew = true
			break
		}
	}
	if !foundNew {
		t.Errorf("new intermediate not found in simulated.Certificates")
	}
}

func TestSimulator_InjectWithoutChainBuilder(t *testing.T) {
	t.Parallel()

	certs := generateTestCertificatesForSimulator(t)
	analysis := NewAnalysis(certs, []*TrustPath{}, "test")

	sim := NewSimulator() // No ChainBuilder or TrustStore.
	sim.InjectCertificates(certs[:1])

	_, err := sim.Simulate(t.Context(), analysis)
	if err == nil {
		t.Fatal("expected error when injecting without ChainBuilder/TrustStore")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestWithSimulatorLogger_NilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil logger, got none")
		}
	}()
	WithSimulatorLogger(nil)(&defaultSimulator{})
}

func TestWithSimulatorValidator(t *testing.T) {
	t.Parallel()

	v := NewValidator()
	sim := NewSimulator(WithSimulatorValidator(v)).(*defaultSimulator)
	if sim.validator == nil {
		t.Error("expected validator to be set")
	}
}

func TestWithSimulatorValidator_NilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil validator, got none")
		}
	}()
	WithSimulatorValidator(nil)(&defaultSimulator{})
}

func TestWithSimulatorValidationOptions(t *testing.T) {
	t.Parallel()

	opts := ValidationOptions{ExpiryWarningDays: 90}
	sim := NewSimulator(WithSimulatorValidationOptions(opts)).(*defaultSimulator)
	if sim.validationOpts == nil {
		t.Fatal("expected validationOpts to be set")
	}
	if sim.validationOpts.ExpiryWarningDays != 90 {
		t.Errorf("ExpiryWarningDays = %d, want 90", sim.validationOpts.ExpiryWarningDays)
	}
}

func TestSecuritySimulatorEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("exclude all certificates yields empty simulation without crash", func(t *testing.T) {
		t.Parallel()

		rawCerts, _, err := testutil.GenerateChainWithDepth(3)
		require.NoError(t, err)

		src := CertificateSource{Type: SourceTypeBytes}
		certs := make([]*Certificate, len(rawCerts))
		for i, rc := range rawCerts {
			certs[i] = NewCertificate(rc, src)
		}
		rootCert := certs[len(certs)-1]

		// Use a mock trust store with the root so BuildChains can find a trusted path.
		ts := &mockSimTrustStoreWithRoot{root: rootCert}
		cb := NewChainBuilder()
		paths, err := cb.BuildChains(t.Context(), certs, ts)
		require.NoError(t, err)
		require.NotEmpty(t, paths)

		analysis := NewAnalysis(certs, paths, "test")

		// Exclude every certificate by CN. Excluding the leaf drops its path
		// entirely; subsequent certs may also be excluded but must not panic.
		sim := NewSimulator()
		for _, c := range certs {
			sim.ExcludeByCommonName(c.CommonName())
		}

		result, err := sim.Simulate(t.Context(), analysis)
		require.NoError(t, err, "simulating all-excluded certs must not return an error")
		assert.NotNil(t, result, "result must be non-nil even when all certs are excluded")
	})
}

// mockSimTrustStoreWithRoot is a minimal TrustStore for simulator security tests.
type mockSimTrustStoreWithRoot struct {
	root *Certificate
}

func (m *mockSimTrustStoreWithRoot) IsTrusted(cert *Certificate) bool {
	if m.root == nil {
		return false
	}
	return cert.FingerprintSHA256() == m.root.FingerprintSHA256()
}

func (m *mockSimTrustStoreWithRoot) TrustedLocations(cert *Certificate) []string {
	if m.IsTrusted(cert) {
		return []string{"test"}
	}
	return nil
}

func (m *mockSimTrustStoreWithRoot) LoadSystemRoots() error { return nil }

func (m *mockSimTrustStoreWithRoot) LoadCustomRoots(_ string) error { return nil }

func (m *mockSimTrustStoreWithRoot) FindIssuers(cert *Certificate) []*Certificate {
	if m.root == nil || cert == nil {
		return nil
	}
	if string(cert.Raw().RawIssuer) == string(m.root.Raw().RawSubject) {
		return []*Certificate{m.root}
	}
	return nil
}

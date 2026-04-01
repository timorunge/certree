package render

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/timorunge/certree/pkg/certree"
	"github.com/timorunge/certree/pkg/certree/testutil"
)

// visualizeComparison renders a single before/after pair for testing.
func (cv *comparisonVisualizer) visualizeComparison(before, after *certree.Analysis) (string, error) {
	if before == nil || after == nil {
		return "", errNoAnalysis
	}

	rp, err := cv.renderPair(before, after)
	if err != nil {
		return "", err
	}
	leftContent := maxLineWidth(rp.before)
	rightContent := maxLineWidth(rp.after)
	leftWidth, rightWidth := columnWidths(cv.width, leftContent, rightContent)

	var builder strings.Builder
	builder.WriteString(formatHeader("Before", "After", leftWidth, rightWidth))
	builder.WriteString(formatSeparator(leftWidth, rightWidth))
	builder.WriteString("\n")
	builder.WriteString(renderSideBySide(rp.before, rp.after, leftWidth, rightWidth))
	if cv.treeVis.opts.Impact {
		builder.WriteString("\n")
		builder.WriteString(ImpactSummary(before, after, cv.treeVis.theme.treeChars.sectionIndent, cv.treeVis.theme.treeChars.labelSep, cv.treeVis.opts.ExpiryWarningDays))
	}
	return builder.String(), nil
}

// extractImpactSection extracts the "Impact:" section from comparison output.
func extractImpactSection(output string) string {
	idx := strings.Index(output, "Impact:")
	if idx < 0 {
		return ""
	}
	return output[idx:]
}

func TestVisualizeComparison_NilAfterAnalysis(t *testing.T) {
	t.Parallel()
	cv := newComparisonVisualizer(&renderEnv{opts: Options{}, theme: classicTheme, width: 80})
	_, err := cv.visualizeComparison(&certree.Analysis{}, nil)
	if err != errNoAnalysis {
		t.Fatalf("expected errNoAnalysis, got: %v", err)
	}
}

func TestVisualizeComparison_ImpactHiddenByDefault(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	cv := newComparisonVisualizer(&renderEnv{opts: Options{}, theme: classicTheme, width: 120})
	output, err := cv.visualizeComparison(analysis, analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(output, "Impact:") {
		t.Errorf("expected no 'Impact:' when Impact is false, got:\n%s", output)
	}
}

func TestVisualizeComparison_IdenticalAnalyses(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
	trustedChain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}
	analysis := &certree.Analysis{
		Certificates: trustedChain,
		TrustPaths:   []*certree.TrustPath{{Certificates: trustedChain, Status: certree.PathTrusted}},
	}
	cv := newComparisonVisualizer(&renderEnv{opts: Options{Impact: true}, theme: classicTheme, width: 120})
	output, err := cv.visualizeComparison(analysis, analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Impact:") {
		t.Errorf("expected output to contain 'Impact:', got:\n%s", output)
	}
	if !strings.Contains(output, "Remaining paths:") {
		t.Errorf("expected 'Remaining paths:1', got:\n%s", output)
	}
	if !strings.Contains(output, "Broken paths:") {
		t.Errorf("expected 'Broken paths:0', got:\n%s", output)
	}
	if strings.Contains(output, "Excluded:") {
		t.Errorf("expected no 'Excluded:' for identical analyses, got:\n%s", output)
	}
}

func TestVisualizeComparison_InheritsReverseOrder(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}

	cvForward := newComparisonVisualizer(&renderEnv{opts: Options{ReverseOrder: false}, theme: classicTheme, width: 120})
	outputForward, err := cvForward.visualizeComparison(analysis, analysis)
	if err != nil {
		t.Fatalf("unexpected error (forward): %v", err)
	}

	cvReverse := newComparisonVisualizer(&renderEnv{opts: Options{ReverseOrder: true}, theme: classicTheme, width: 120})
	outputReverse, err := cvReverse.visualizeComparison(analysis, analysis)
	if err != nil {
		t.Fatalf("unexpected error (reverse): %v", err)
	}

	if outputForward == outputReverse {
		t.Error("expected different output for forward vs reverse order")
	}

	leafCN := cached.chain3[0].CommonName()
	rootCN := cached.chain3[2].CommonName()

	fwdLeaf := strings.Index(outputForward, leafCN)
	fwdRoot := strings.Index(outputForward, rootCN)
	revLeaf := strings.Index(outputReverse, leafCN)
	revRoot := strings.Index(outputReverse, rootCN)

	if fwdLeaf >= fwdRoot {
		t.Errorf("forward: leaf should appear before root")
	}
	if revRoot >= revLeaf {
		t.Errorf("reverse: root should appear before leaf")
	}
}

func TestVisualizeComparison_ExcludedCertificates(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)

	beforeAnalysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	simMeta := map[string]certree.CertSimulationState{
		cached.chain3[1].FingerprintSHA256(): {IsExcluded: true},
		cached.chain3[2].FingerprintSHA256(): {IsExcluded: true},
	}
	afterAnalysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{{
			Certificates:       cached.chain3,
			Status:             certree.PathIncomplete,
			SimulationMetadata: simMeta,
		}},
	}

	cv := newComparisonVisualizer(&renderEnv{opts: Options{Impact: true}, theme: classicTheme, width: 120})
	output, err := cv.visualizeComparison(beforeAnalysis, afterAnalysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Excluded:") {
		t.Errorf("expected 'Excluded:', got:\n%s", output)
	}
}

func TestVisualizeComparison_BrokenPaths(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)

	extraRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Extra Root CA"}, IsCA: true,
	})
	if err != nil {
		t.Fatalf("generating extra cert: %v", err)
	}
	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	extraRoot := certree.NewCertificate(extraRaw, src).WithTrustedLocations([]string{"system"})
	trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
	trustedChain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}

	path1 := &certree.TrustPath{Certificates: trustedChain, Status: certree.PathTrusted}
	path2 := &certree.TrustPath{
		Certificates: []*certree.Certificate{cached.chain3[0], cached.chain3[1], extraRoot},
		Status:       certree.PathTrusted,
	}
	allCerts := append(append([]*certree.Certificate{}, trustedChain...), extraRoot)
	beforeAnalysis := &certree.Analysis{Certificates: allCerts, TrustPaths: []*certree.TrustPath{path1, path2}}
	afterAnalysis := &certree.Analysis{Certificates: trustedChain, TrustPaths: []*certree.TrustPath{path1}}

	cv := newComparisonVisualizer(&renderEnv{opts: Options{Impact: true}, theme: classicTheme, width: 120})
	output, err := cv.visualizeComparison(beforeAnalysis, afterAnalysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Broken paths:") {
		t.Errorf("expected 'Broken paths:1', got:\n%s", output)
	}
}

func TestVisualizeComparison_GhostedCertificates(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)

	beforeAnalysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	afterPath := &certree.TrustPath{
		Certificates: cached.chain3, Status: certree.PathIncomplete,
		SimulationMetadata: map[string]certree.CertSimulationState{
			cached.chain3[1].FingerprintSHA256(): {IsGhosted: true},
			cached.chain3[2].FingerprintSHA256(): {IsGhosted: true},
		},
	}
	afterAnalysis := &certree.Analysis{Certificates: cached.chain3, TrustPaths: []*certree.TrustPath{afterPath}}

	cv := newComparisonVisualizer(&renderEnv{opts: Options{Impact: true}, theme: classicTheme, width: 120})
	output, err := cv.visualizeComparison(beforeAnalysis, afterAnalysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Ghosted:") {
		t.Errorf("expected 'Ghosted:', got:\n%s", output)
	}
}

func TestVisualizeComparison_ImpactSummaryIndependence(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)

	tests := []struct {
		name        string
		removeCerts bool
		breakPath   bool
	}{
		{"identical analyses", false, false},
		{"excluded certs", true, false},
		{"broken path", false, true},
		{"excluded and broken", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			beforeAnalysis := &certree.Analysis{
				Certificates: cached.chain3,
				TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
			}

			var afterCerts []*certree.Certificate
			var afterPath *certree.TrustPath
			switch {
			case tt.removeCerts:
				afterCerts = []*certree.Certificate{cached.chain3[0]}
				afterPath = &certree.TrustPath{Certificates: afterCerts, Status: certree.PathIncomplete}
			case tt.breakPath:
				afterCerts = cached.chain3
				afterPath = &certree.TrustPath{Certificates: afterCerts, Status: certree.PathIncomplete}
			default:
				afterCerts = cached.chain3
				afterPath = &certree.TrustPath{Certificates: afterCerts, Status: certree.PathTrusted}
			}
			afterAnalysis := &certree.Analysis{Certificates: afterCerts, TrustPaths: []*certree.TrustPath{afterPath}}

			cvFwd := newComparisonVisualizer(&renderEnv{opts: Options{Impact: true, ReverseOrder: false}, theme: classicTheme, width: 120})
			cvRev := newComparisonVisualizer(&renderEnv{opts: Options{Impact: true, ReverseOrder: true}, theme: classicTheme, width: 120})

			outFwd, err := cvFwd.visualizeComparison(beforeAnalysis, afterAnalysis)
			if err != nil {
				t.Fatalf("forward render: %v", err)
			}
			outRev, err := cvRev.visualizeComparison(beforeAnalysis, afterAnalysis)
			if err != nil {
				t.Fatalf("reverse render: %v", err)
			}

			if extractImpactSection(outFwd) != extractImpactSection(outRev) {
				t.Errorf("impact sections differ:\nforward:\n%s\nreverse:\n%s",
					extractImpactSection(outFwd), extractImpactSection(outRev))
			}
		})
	}
}

func TestVisualizeComparison_InjectedCertificates(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)

	// Generate an extra certificate to act as the injected intermediate.
	injRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Injected Intermediate"}, IsCA: true,
	})
	if err != nil {
		t.Fatalf("generating injected cert: %v", err)
	}
	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	injCert := certree.NewCertificate(injRaw, src)

	beforeAnalysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}

	afterCerts := append(append([]*certree.Certificate{}, cached.chain3...), injCert)
	afterPath := &certree.TrustPath{
		Certificates: append(append([]*certree.Certificate{}, cached.chain3...), injCert),
		Status:       certree.PathTrusted,
		SimulationMetadata: map[string]certree.CertSimulationState{
			injCert.FingerprintSHA256(): {IsInjected: true},
		},
	}
	afterAnalysis := &certree.Analysis{Certificates: afterCerts, TrustPaths: []*certree.TrustPath{afterPath}}

	cv := newComparisonVisualizer(&renderEnv{opts: Options{Impact: true}, theme: classicTheme, width: 120})
	output, err := cv.visualizeComparison(beforeAnalysis, afterAnalysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Injected:") {
		t.Errorf("expected 'Injected:', got:\n%s", output)
	}
	if !strings.Contains(output, "Injected Intermediate") {
		t.Errorf("expected injected cert CN in output, got:\n%s", output)
	}
}

func TestVisualizeComparison_NewPaths(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)

	// Generate an extra root to create a second, distinct trust path.
	extraRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "New Root CA"}, IsCA: true,
	})
	if err != nil {
		t.Fatalf("generating extra root: %v", err)
	}
	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	extraRoot := certree.NewCertificate(extraRaw, src).WithTrustedLocations([]string{"system"})
	trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
	trustedChain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}

	path1 := &certree.TrustPath{Certificates: trustedChain, Status: certree.PathTrusted}
	beforeAnalysis := &certree.Analysis{
		Certificates: trustedChain,
		TrustPaths:   []*certree.TrustPath{path1},
	}

	// After has the original path plus a new trusted path through the extra root.
	newPathCerts := []*certree.Certificate{cached.chain3[0], cached.chain3[1], extraRoot}
	path2 := &certree.TrustPath{Certificates: newPathCerts, Status: certree.PathTrusted}
	allCerts := append(append([]*certree.Certificate{}, trustedChain...), extraRoot)
	afterAnalysis := &certree.Analysis{
		Certificates: allCerts,
		TrustPaths:   []*certree.TrustPath{path1, path2},
	}

	cv := newComparisonVisualizer(&renderEnv{opts: Options{Impact: true}, theme: classicTheme, width: 120})
	output, err := cv.visualizeComparison(beforeAnalysis, afterAnalysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "New trusted paths:") {
		t.Errorf("expected 'New trusted paths:1', got:\n%s", output)
	}
	if !strings.Contains(output, "Remaining paths:") {
		t.Errorf("expected 'Remaining paths:2', got:\n%s", output)
	}
}

func TestImpactSummary_NoNewPathsOmitted(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)

	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{{Certificates: cached.chain3, Status: certree.PathTrusted}},
	}
	result := ImpactSummary(analysis, analysis, "  ", "  ", 30)
	if strings.Contains(result, "New trusted paths") {
		t.Errorf("expected no 'New trusted paths' for identical analyses, got:\n%s", result)
	}
}

func TestRenderSideBySide_EmptyInput(t *testing.T) {
	t.Parallel()

	someLines := "hello\nworld\n"

	tests := []struct {
		name      string
		left      string
		right     string
		wantEmpty bool
	}{
		{name: "both empty", left: "", right: "", wantEmpty: true},
		{name: "one empty", left: someLines, right: "", wantEmpty: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			output := renderSideBySide(tt.left, tt.right, 20, 20)
			if tt.wantEmpty {
				if output != "" {
					t.Errorf("expected empty output, got:\n%q", output)
				}
				return
			}
			lines := splitLines(output)
			if len(lines) == 0 {
				t.Fatalf("expected non-empty output, got empty")
			}
			if !strings.Contains(lines[0], "hello") {
				t.Errorf("expected first line to contain 'hello', got: %q", lines[0])
			}
		})
	}
}

func TestImpactSummary_NilInputs(t *testing.T) {
	t.Parallel()

	result := ImpactSummary(nil, &certree.Analysis{}, "  ", "  ", 30)
	if result != "" {
		t.Errorf("expected empty string for nil input, got %q", result)
	}
}

func TestImpactSummary_DuplicateCNDisambiguation(t *testing.T) {
	t.Parallel()
	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	// Create a self-signed root.
	selfSignedRoot, rootKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "Shared Root CA"},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a cross-signed version of the same CN, signed by a different issuer.
	otherIssuer, otherKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "Other Root CA"},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	if err != nil {
		t.Fatal(err)
	}
	crossSigned, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "Shared Root CA"},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, otherIssuer, otherKey)
	if err != nil {
		t.Fatal(err)
	}

	// Create a leaf signed by the self-signed root.
	leafRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "leaf.example.com"},
		DNSNames: []string{"leaf.example.com"},
	}, selfSignedRoot, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	leaf := certree.NewCertificate(leafRaw, src)
	rootSS := certree.NewCertificate(selfSignedRoot, src)
	rootCS := certree.NewCertificate(crossSigned, src)

	// Build two paths sharing the leaf, each ending at a different "Shared Root CA".
	simMeta := map[string]certree.CertSimulationState{
		rootSS.FingerprintSHA256(): {IsExcluded: true},
		rootCS.FingerprintSHA256(): {IsExcluded: true},
	}
	before := &certree.Analysis{
		Certificates: []*certree.Certificate{leaf, rootSS, rootCS},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{leaf, rootSS}, Status: certree.PathTrusted},
			{Certificates: []*certree.Certificate{leaf, rootCS}, Status: certree.PathTrusted},
		},
	}
	after := &certree.Analysis{
		Certificates: []*certree.Certificate{leaf, rootSS, rootCS},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{leaf, rootSS}, Status: certree.PathUntrusted, SimulationMetadata: simMeta},
			{Certificates: []*certree.Certificate{leaf, rootCS}, Status: certree.PathUntrusted, SimulationMetadata: simMeta},
		},
	}

	result := ImpactSummary(before, after, "  ", "  ", 30)

	// Both excluded certs have CN "Shared Root CA" -- they must be disambiguated
	// with short fingerprint prefixes.
	ssFP := rootSS.FingerprintSHA256()
	csFP := rootCS.FingerprintSHA256()
	if !strings.Contains(result, "Shared Root CA "+certree.ColonHex(ssFP[:12])) {
		t.Errorf("expected fingerprint disambiguator for self-signed root, got:\n%s", result)
	}
	if !strings.Contains(result, "Shared Root CA "+certree.ColonHex(csFP[:12])) {
		t.Errorf("expected fingerprint disambiguator for cross-signed root, got:\n%s", result)
	}
}

func TestImpactSummary_BrokenOmittedWhenHealthyPathExists(t *testing.T) {
	t.Parallel()
	cached := getUnitTestCerts(t)
	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	// Create an alternative root for a second path.
	altRootRaw, altRootKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "Alt Root CA"},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Create an alternative intermediate signed by the alt root.
	altIntRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "Alt Intermediate CA"},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, altRootRaw, altRootKey)
	if err != nil {
		t.Fatal(err)
	}
	altInt := certree.NewCertificate(altIntRaw, src)
	altRoot := certree.NewCertificate(altRootRaw, src)

	leaf := cached.chain3[0]
	intermediate := cached.chain3[1]
	root := cached.chain3[2]

	// Path 1: leaf -> intermediate -> root (excluded, broken)
	// Path 2: leaf -> altInt -> altRoot (healthy, trusted)
	simMeta := map[string]certree.CertSimulationState{
		intermediate.FingerprintSHA256(): {IsExcluded: true},
	}
	brokenPath := &certree.TrustPath{
		Certificates:       []*certree.Certificate{leaf, intermediate, root},
		Status:             certree.PathIncomplete,
		SimulationMetadata: simMeta,
		Warnings: []certree.ValidationWarning{
			{Type: certree.WarningExcludedBySimulation, Certificate: leaf},
		},
	}
	healthyPath := &certree.TrustPath{
		Certificates:       []*certree.Certificate{leaf, altInt, altRoot},
		Status:             certree.PathTrusted,
		SimulationMetadata: simMeta,
	}

	before := &certree.Analysis{
		Certificates: []*certree.Certificate{leaf, intermediate, root, altInt, altRoot},
		TrustPaths: []*certree.TrustPath{
			{Certificates: []*certree.Certificate{leaf, intermediate, root}, Status: certree.PathTrusted},
			{Certificates: []*certree.Certificate{leaf, altInt, altRoot}, Status: certree.PathTrusted},
		},
	}
	after := &certree.Analysis{
		Certificates: []*certree.Certificate{leaf, intermediate, root, altInt, altRoot},
		TrustPaths:   []*certree.TrustPath{brokenPath, healthyPath},
	}

	result := ImpactSummary(before, after, "  ", "  ", 30)

	// The leaf appears healthy on path 2, so it must NOT be listed as broken.
	if strings.Contains(result, "Broken: ") {
		t.Errorf("leaf with surviving healthy path should not be listed as broken, got:\n%s", result)
	}
	// The intermediate must still be listed as excluded.
	if !strings.Contains(result, "Excluded:") {
		t.Errorf("expected excluded intermediate, got:\n%s", result)
	}
}

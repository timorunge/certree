package render

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/fatih/color"

	"github.com/timorunge/certree/pkg/certree"
	"github.com/timorunge/certree/pkg/certree/testutil"
)

// cachedUnitTestCerts holds pre-generated certificates for tree unit tests.
// Certificate generation is expensive (RSA key generation), so certs are
// created once for the entire package and reused across all tests.
type cachedUnitTestCerts struct {
	singleCert *certree.Certificate
	chain3     []*certree.Certificate
}

// unitTestCerts caches pre-generated certificates for tree unit tests,
// created once and reused across all tests to avoid repeated key generation.
var (
	unitTestCertsOnce sync.Once
	unitTestCerts     *cachedUnitTestCerts
	unitTestCertsErr  error
)

// getUnitTestCerts returns shared test certificates, generating them once.
func getUnitTestCerts(t *testing.T) *cachedUnitTestCerts {
	t.Helper()
	unitTestCertsOnce.Do(func() {
		unitTestCerts, unitTestCertsErr = buildUnitTestCerts()
	})
	if unitTestCertsErr != nil {
		t.Fatal(unitTestCertsErr)
	}
	return unitTestCerts
}

// buildUnitTestCerts generates a single self-signed cert and a 3-cert chain for tree tests.
func buildUnitTestCerts() (*cachedUnitTestCerts, error) {
	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	singleRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Single Cert"},
		IsCA:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("generating single cert: %w", err)
	}

	rawChain, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		return nil, fmt.Errorf("generating simple chain: %w", err)
	}

	chain3 := make([]*certree.Certificate, len(rawChain))
	for i, raw := range rawChain {
		chain3[i] = certree.NewCertificate(raw, src)
	}

	return &cachedUnitTestCerts{
		singleCert: certree.NewCertificate(singleRaw, src),
		chain3:     chain3,
	}, nil
}

// trustStoreOutputCase is a single test case for trust-store-related output assertions.
type trustStoreOutputCase struct {
	name           string
	theme          renderTheme
	showTrustStore bool
	want           bool
}

// allThemeTrustStoreCases returns 6 test cases covering all themes with
// ShowTrustStore true and false.
func allThemeTrustStoreCases(wantWhenOff, wantWhenOn bool) []trustStoreOutputCase {
	return []trustStoreOutputCase{
		{"classic/no-flag", classicTheme, false, wantWhenOff},
		{"classic/with-flag", classicTheme, true, wantWhenOn},
		{"terse/no-flag", terseTheme, false, wantWhenOff},
		{"terse/with-flag", terseTheme, true, wantWhenOn},
		{"minimal/no-flag", minimalTheme, false, wantWhenOff},
		{"minimal/with-flag", minimalTheme, true, wantWhenOn},
	}
}

// buildTrustedChain creates a 3-cert chain with the root trusted in "system".
func buildTrustedChain(t *testing.T) []*certree.Certificate {
	t.Helper()
	cached := getUnitTestCerts(t)
	trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
	return []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}
}

func TestTreeVisualize_NilAnalysis(t *testing.T) {
	t.Parallel()

	tv := newTreeVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})

	_, err := tv.visualize(nil)
	if err == nil {
		t.Fatal("expected error for nil analysis, got nil")
	}
	if err != errNoAnalysis {
		t.Fatalf("expected errNoAnalysis, got: %v", err)
	}
}

func TestTreeVisualize_EmptyAnalysis(t *testing.T) {
	t.Parallel()

	tv := newTreeVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
	analysis := &certree.Analysis{
		Certificates: []*certree.Certificate{},
		TrustPaths:   []*certree.TrustPath{},
	}

	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "No trust paths found") {
		t.Errorf("expected output to contain 'No trust paths found', got:\n%s", output)
	}
}

func TestTreeVisualize_DefaultVsDetailed(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: cached.chain3,
				Status:       certree.PathTrusted,
			},
		},
	}

	tests := []struct {
		name         string
		opts         Options
		expectCN     bool
		expectIssuer bool
	}{
		{
			name:         "default flat view has no CN/Issuer lines",
			opts:         Options{},
			expectCN:     false,
			expectIssuer: false,
		},
		{
			name:         "detailed mode with ShowIssuer has Issuer lines",
			opts:         Options{ShowIssuer: true},
			expectCN:     false,
			expectIssuer: true,
		},
		{
			name:         "detailed mode with ShowSubject has Subject section but no Issuer",
			opts:         Options{ShowSubject: true},
			expectCN:     false,
			expectIssuer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tv := newTreeVisualizer(&renderEnv{opts: tt.opts, theme: classicTheme})

			output, err := tv.visualize(analysis)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			hasCN := strings.Contains(output, "CN:")
			hasIssuer := strings.Contains(output, "Issuer:")

			if hasCN != tt.expectCN {
				t.Errorf("CN: line present=%v, want=%v\nOutput:\n%s",
					hasCN, tt.expectCN, output)
			}
			if hasIssuer != tt.expectIssuer {
				t.Errorf("Issuer: line present=%v, want=%v\nOutput:\n%s",
					hasIssuer, tt.expectIssuer, output)
			}
		})
	}
}

func TestTreeBuild_SourceInHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		source          string
		wantContains    string
		wantNotContains string
	}{
		{name: "with source", source: "example.com:443", wantContains: "example.com:443"},
		{name: "without source", source: "", wantNotContains: "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cached := getUnitTestCerts(t)

			analysis := &certree.Analysis{
				Certificates: cached.chain3,
				TrustPaths: []*certree.TrustPath{
					{
						Certificates: cached.chain3,
						Status:       certree.PathTrusted,
					},
				},
				Metadata: certree.AnalysisMetadata{
					Source: tt.source,
				},
			}

			tv := newTreeVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
			tree := tv.buildFromAnalysis(analysis)

			if tree.root == nil {
				t.Fatal("expected non-nil root node")
			}

			if tt.wantContains != "" && !strings.Contains(tree.root.label, tt.wantContains) {
				t.Errorf("root label = %q, want to contain %q", tree.root.label, tt.wantContains)
			}
			if tt.wantNotContains != "" && strings.Contains(tree.root.label, tt.wantNotContains) {
				t.Errorf("root label = %q, want NOT to contain %q", tree.root.label, tt.wantNotContains)
			}
			// Header must have a status icon prefix (any icon).
			hasIcon := strings.Contains(tree.root.label, classicTheme.statusIcons.valid) ||
				strings.Contains(tree.root.label, classicTheme.statusIcons.warning) ||
				strings.Contains(tree.root.label, classicTheme.statusIcons.err)
			if !hasIcon {
				t.Errorf("root label = %q, want to contain a status icon", tree.root.label)
			}
		})
	}
}

func TestTreeBuild_HeaderStatusIcon(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	t.Run("trusted analysis shows valid icon", func(t *testing.T) {
		t.Parallel()
		trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
		chain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}
		analysis := &certree.Analysis{
			Certificates: chain,
			TrustPaths: []*certree.TrustPath{
				{Certificates: chain, Status: certree.PathTrusted},
			},
		}
		tv := newTreeVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
		output, err := tv.visualize(analysis)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		lines := strings.Split(output, "\n")
		if len(lines) == 0 || !strings.HasPrefix(lines[0], classicTheme.statusIcons.valid+" ") {
			t.Errorf("header should start with valid icon, got: %s", lines[0])
		}
	})

	t.Run("untrusted analysis shows error icon", func(t *testing.T) {
		t.Parallel()
		analysis := &certree.Analysis{
			Certificates: cached.chain3,
			TrustPaths: []*certree.TrustPath{
				{Certificates: cached.chain3, Status: certree.PathUntrusted},
			},
		}
		tv := newTreeVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
		output, err := tv.visualize(analysis)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		lines := strings.Split(output, "\n")
		if len(lines) == 0 || !strings.HasPrefix(lines[0], classicTheme.statusIcons.err+" ") {
			t.Errorf("header should start with error icon, got: %s", lines[0])
		}
	})
}

func TestBuildPathNode_TrustedPath(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
	chain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}

	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: chain,
				Status:       certree.PathTrusted,
			},
		},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ExpandedView: true}, theme: classicTheme})

	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the path header line.
	lines := strings.Split(output, "\n")
	found := false
	for _, line := range lines {
		if strings.Contains(line, "Trust Path 1") {
			found = true
			// Should have [+ ] status indicator.
			if !strings.Contains(line, classicTheme.statusIcons.valid) {
				t.Errorf("expected status indicator %q on path header, got: %s",
					classicTheme.statusIcons.valid, line)
			}
			// Should NOT have "(trusted)" suffix.
			if strings.Contains(line, "(trusted)") {
				t.Errorf("trusted path should not have '(trusted)' suffix, got: %s", line)
			}
			break
		}
	}
	if !found {
		t.Errorf("path header 'Trust Path 1' not found in output:\n%s", output)
	}
}

func TestBuildPathNode_UntrustedPath(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: cached.chain3,
				Status:       certree.PathIncomplete,
			},
		},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ExpandedView: true}, theme: classicTheme})

	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(output, "\n")
	found := false
	for _, line := range lines {
		if strings.Contains(line, "Trust Path 1") {
			found = true
			// Should have [x ] error status indicator.
			if !strings.Contains(line, classicTheme.statusIcons.err) {
				t.Errorf("expected error status indicator %q on untrusted path header, got: %s",
					classicTheme.statusIcons.err, line)
			}
			break
		}
	}
	if !found {
		t.Errorf("path header 'Trust Path 1' not found in output:\n%s", output)
	}
}

func TestBuildPathNode_Reverse_EmptyTrustPath(t *testing.T) {
	t.Parallel()

	tv := newTreeVisualizer(&renderEnv{opts: Options{
		ReverseOrder: true,
	}, theme: classicTheme})

	// Nil path.
	node := tv.buildPathNode(nil, 0)
	if !strings.Contains(node.label, "Empty") {
		t.Errorf("expected 'Empty' label for nil path, got: %s", node.label)
	}

	// empty certificates slice.
	emptyPath := &certree.TrustPath{
		Certificates: []*certree.Certificate{},
		Status:       certree.PathIncomplete,
	}
	node = tv.buildPathNode(emptyPath, 0)
	if !strings.Contains(node.label, "Empty") {
		t.Errorf("expected 'Empty' label for empty path, got: %s", node.label)
	}
}

func TestBuildPathNode_Reverse_SingleCertPath(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	chain := []*certree.Certificate{cached.singleCert}

	path := &certree.TrustPath{
		Certificates: chain,
		Status:       certree.PathTrusted,
	}

	// Forward mode.
	tvFwd := newTreeVisualizer(&renderEnv{opts: Options{ReverseOrder: false}, theme: classicTheme})
	fwdNode := tvFwd.buildPathNode(path, 0)
	fwdCerts := collectCertNodes(fwdNode)

	// Reverse mode.
	tvRev := newTreeVisualizer(&renderEnv{opts: Options{ReverseOrder: true}, theme: classicTheme})
	revNode := tvRev.buildPathNode(path, 0)
	revCerts := collectCertNodes(revNode)

	if len(fwdCerts) != 1 || len(revCerts) != 1 {
		t.Fatalf("expected 1 cert node each, got fwd=%d rev=%d", len(fwdCerts), len(revCerts))
	}

	// Same certificate should be rendered.
	fwdCert := fwdCerts[0].metadata.certificate
	revCert := revCerts[0].metadata.certificate
	if fwdCert.FingerprintSHA256() != revCert.FingerprintSHA256() {
		t.Error("single-cert path should render the same cert in both modes")
	}

	// Index should be 0 in both modes.
	fwdIdx := fwdCerts[0].metadata.index
	revIdx := revCerts[0].metadata.index
	if fwdIdx != 0 || revIdx != 0 {
		t.Errorf("expected index 0 in both modes, got fwd=%d rev=%d", fwdIdx, revIdx)
	}
}

func TestBuildPathNode_Reverse_CertOrder(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	path := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}

	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{path},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ReverseOrder: true}, theme: classicTheme})
	tree := tv.buildFromAnalysis(analysis)

	pathNode := tree.root.children[0]
	certNodes := collectCertNodes(pathNode)

	if len(certNodes) != 3 {
		t.Fatalf("expected 3 cert nodes, got %d", len(certNodes))
	}

	// Verify the reversed order: first rendered cert should be the root (index 2).
	firstCert := certNodes[0].metadata.certificate
	if firstCert.FingerprintSHA256() != cached.chain3[2].FingerprintSHA256() {
		t.Error("first rendered cert in reverse mode should be the root (chain3[2])")
	}
}

func TestTreeVisualize_FullFingerprint(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	chain := []*certree.Certificate{cached.singleCert}

	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{Certificates: chain, Status: certree.PathTrusted},
		},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ShowFingerprint: true}, theme: classicTheme})

	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the fingerprint line.
	lines := strings.Split(output, "\n")
	found := false
	for _, line := range lines {
		if strings.Contains(line, "Fingerprint:") {
			found = true
			// Should NOT contain "..." (truncation marker).
			if strings.Contains(line, "...") {
				t.Errorf("fingerprint should not be truncated, got: %s", line)
			}
			// Extract the fingerprint value after "Fingerprint:".
			_, after, ok := strings.Cut(line, "Fingerprint:")
			if !ok {
				t.Errorf("could not find 'Fingerprint:' prefix in line: %s", line)
				break
			}
			fpValue := strings.TrimSpace(after)
			// SHA-256 colon-hex = 64 hex chars + 31 colons = 95 characters.
			if len(fpValue) != 95 {
				t.Errorf("expected 95-char colon-hex fingerprint, got %d chars: %q", len(fpValue), fpValue)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected 'Fingerprint:' line in output:\n%s", output)
	}
}

func TestTreeVisualize_DetailedAllFields(t *testing.T) {
	t.Parallel()

	src := certree.CertificateSource{Type: certree.SourceTypeFile, Location: "/tmp/test.pem"}

	// Generate a cert with rich DN fields and DNS names.
	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:         "Test Cert",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
			Country:            []string{"DE"},
			Province:           []string{"Bavaria"},
			Locality:           []string{"Munich"},
			SerialNumber:       "12345678",
		},
		IsCA:     true,
		DNSNames: []string{"example.com", "www.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	cert := certree.NewCertificate(raw, src)
	chain := []*certree.Certificate{cert}

	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: chain,
				Status:       certree.PathTrusted,
				Warnings: []certree.ValidationWarning{
					{Certificate: cert, Message: "expiring soon"},
				},
				Errors: []certree.ValidationError{
					{Certificate: cert, Message: "signature weak"},
				},
			},
		},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{
		ShowAll:         true,
		ShowSubject:     true,
		ShowIssuer:      true,
		ShowValidity:    true,
		ShowFingerprint: true,
		ShowSerial:      true,
		ShowSource:      true,
		ShowSAN:         true,
	}, theme: classicTheme})

	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify detail fields are present.
	checks := []string{
		"Subject:",
		"Common Name:",
		"Test Cert",
		"Organization:",
		"Test Org",
		"Organizational Unit:",
		"Test Unit",
		"Country:",
		"DE",
		"State:",
		"Bavaria",
		"Locality:",
		"Munich",
		"Serial Number:",
		"12345678",
		"Issuer:",
		"Validity:",
		"Not Before:",
		"Not After:",
		"Fingerprint:",
		"Serial:",
		"Source:",
		"/tmp/test.pem",
		"Subject Alternative Names:",
		"example.com",
		"Warnings:",
		"expiring soon",
		"Errors:",
		"signature weak",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in output:\n%s", check, output)
		}
	}
}

func TestTreeVisualize_ColoredWarningErrors(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	src := certree.CertificateSource{Type: certree.SourceTypeFile, Location: "/tmp/test.pem"}

	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Detail Test Cert"},
		IsCA:    true,
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	cert := certree.NewCertificate(raw, src)
	chain := []*certree.Certificate{cert}

	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: chain,
				Status:       certree.PathTrusted,
				Warnings: []certree.ValidationWarning{
					{Certificate: cert, Message: "expiring soon"},
				},
				Errors: []certree.ValidationError{
					{Certificate: cert, Message: "weak signature"},
				},
			},
		},
	}

	colorTheme := classicTheme.WithColor()
	tv := newTreeVisualizer(&renderEnv{opts: Options{
		ShowAll:        true,
		ShowSubject:    true,
		ShowIssuer:     true,
		ShowValidity:   true,
		ShowSource:     true,
		ShowTrustStore: true,
	}, theme: colorTheme})

	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(output, "\n")

	// Check warning line is colored.
	warningFound := false
	for _, line := range lines {
		stripped := stripANSICodes(line)
		if strings.Contains(stripped, "expiring soon") {
			warningFound = true
			if line == stripped {
				t.Errorf("warning detail line has no ANSI codes: %q", line)
			}
			break
		}
	}
	if !warningFound {
		t.Errorf("warning detail line not found in output:\n%s", output)
	}

	// Check error line is colored.
	errorFound := false
	for _, line := range lines {
		stripped := stripANSICodes(line)
		if strings.Contains(stripped, "weak signature") {
			errorFound = true
			if line == stripped {
				t.Errorf("error detail line has no ANSI codes: %q", line)
			}
			break
		}
	}
	if !errorFound {
		t.Errorf("error detail line not found in output:\n%s", output)
	}
}

func TestTreeVisualize_NoInlineTrustAnnotation(t *testing.T) {
	t.Parallel()

	// Default output: no inline trust annotation on label.
	t.Run("system_no_inline", func(t *testing.T) {
		t.Parallel()
		chain := buildTrustedChain(t)
		output := renderChainOutput(chain, Options{}, classicTheme)
		if strings.Contains(output, "(system)") || strings.Contains(output, "(trust store:") {
			t.Errorf("default output should not show inline trust annotation\noutput:\n%s", output)
		}
	})

	// Custom trust bundle: also no inline annotation.
	t.Run("custom_no_inline", func(t *testing.T) {
		t.Parallel()
		cached := getUnitTestCerts(t)
		customRoot := cached.chain3[2].WithTrustedLocations([]string{"/etc/ssl/custom.pem"})
		customChain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], customRoot}
		output := renderChainOutput(customChain, Options{}, classicTheme)
		if strings.Contains(output, "(trust store:") {
			t.Errorf("default output should not show inline trust annotation\noutput:\n%s", output)
		}
	})
}

func TestTreeVisualize_TrustStoreDetailLine(t *testing.T) {
	t.Parallel()

	trustedChain := buildTrustedChain(t)

	for _, tt := range allThemeTrustStoreCases(false, true) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			output := renderChainOutput(trustedChain, Options{ShowTrustStore: tt.showTrustStore}, tt.theme)
			hasDetail := strings.Contains(output, "Trust Store:")
			if hasDetail != tt.want {
				t.Errorf("ShowTrustStore=%v: want detail=%v, got=%v\noutput:\n%s",
					tt.showTrustStore, tt.want, hasDetail, output)
			}
		})
	}
}

func TestTreeVisualize_ShowTrustStore_SelfSignedUntrusted(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	// Use the root cert without WithTrustedLocations -- self-signed but untrusted.
	untrustedRoot := cached.chain3[2]
	chain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], untrustedRoot}

	output := renderChainOutput(chain, Options{ShowTrustStore: true}, classicTheme)
	if !strings.Contains(output, "Trust Store:") {
		t.Errorf("expected 'Trust Store:' detail line for self-signed untrusted cert, got:\n%s", output)
	}
	if !strings.Contains(output, "none") {
		t.Errorf("expected 'none' for self-signed untrusted cert, got:\n%s", output)
	}
}

// TestTreeVisualize_EachFieldProducesOutput renders a 3-cert chain with each
// Show* flag individually enabled and checks that the expected detail line
// appears in the output.
func TestTreeVisualize_EachFieldProducesOutput(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	// Rebuild chain with a file location so ShowSource has something to render.
	src := certree.CertificateSource{
		Type:     certree.SourceTypeFile,
		Location: "/tmp/test.pem",
	}
	rawChain, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("generating chain: %v", err)
	}
	chain := make([]*certree.Certificate, len(rawChain))
	for i, raw := range rawChain {
		chain[i] = certree.NewCertificate(raw, src)
	}
	_ = cached // cert generation is expensive; reuse where possible
	trustedRoot := chain[2].WithTrustedLocations([]string{"system"})
	chain = []*certree.Certificate{chain[0], chain[1], trustedRoot}

	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: chain,
				Status:       certree.PathTrusted,
			},
		},
	}

	tests := []struct {
		name     string
		opts     Options
		contains string // substring that must appear in output
	}{
		{
			name:     "serial",
			opts:     Options{ShowSerial: true},
			contains: "Serial:",
		},
		{
			name:     "validity",
			opts:     Options{ShowValidity: true},
			contains: "Validity:",
		},
		{
			name:     "extensions",
			opts:     Options{ShowExtensions: true},
			contains: "Extensions:",
		},
		{
			name:     "source",
			opts:     Options{ShowSource: true},
			contains: "Source:",
		},
		{
			name:     "subject",
			opts:     Options{ShowSubject: true},
			contains: "Subject:",
		},
		{
			name:     "issuer",
			opts:     Options{ShowIssuer: true},
			contains: "Issuer:",
		},
		{
			name:     "san",
			opts:     Options{ShowSAN: true},
			contains: "Subject Alternative Names:",
		},
		{
			name:     "trust-store",
			opts:     Options{ShowTrustStore: true},
			contains: "Trust Store:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tv := newTreeVisualizer(&renderEnv{opts: tt.opts, theme: classicTheme})

			output, err := tv.visualize(analysis)
			if err != nil {
				t.Fatalf("Visualize() error: %v", err)
			}

			if !strings.Contains(output, tt.contains) {
				t.Errorf("field %q: expected output to contain %q, got:\n%s",
					tt.name, tt.contains, output)
			}
		})
	}
}

func TestTreeVisualize_ExtensionsContent(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	chain := cached.chain3
	// chain[0] = end-entity (IsCA:false, DigitalSignature|KeyEncipherment, ServerAuth)
	// chain[1] = intermediate (IsCA:true, CertSign|CRLSign)
	// chain[2] = root (IsCA:true, CertSign|CRLSign)

	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: chain,
				Status:       certree.PathUntrusted,
			},
		},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ShowExtensions: true}, theme: classicTheme})

	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("Visualize() error: %v", err)
	}

	// End-entity should show CA:FALSE, Digital Signature, Key Encipherment, Server Authentication.
	for _, want := range []string{
		"Basic Constraints:",
		"CA:FALSE",
		"Digital Signature",
		"Key Encipherment",
		"Server Authentication",
		"Ext Key Usage:",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected output to contain %q (end-entity extensions)", want)
		}
	}

	// CA certs should show CA:TRUE, Certificate Sign, CRL Sign.
	for _, want := range []string{
		"Basic Constraints:",
		"CA:TRUE",
		"Certificate Sign",
		"CRL Sign",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected output to contain %q (CA extensions)", want)
		}
	}
}

func isHexContinuation(line string) bool {
	stripped := strings.TrimSpace(stripTreePrefix(line))
	if len(stripped) < 5 {
		return false
	}
	for i, c := range stripped[:5] {
		if i == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func stripTreePrefix(s string) string {
	for i, c := range s {
		if c != ' ' && c != '|' && c != '`' && c != '-' && c != '│' && c != '├' && c != '└' && c != '─' {
			return s[i:]
		}
	}
	return ""
}

func TestTreeVisualize_FingerprintWrappedAtNarrowWidth(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	chain := []*certree.Certificate{cached.singleCert}
	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{Certificates: chain, Status: certree.PathTrusted},
		},
	}

	tv := newTreeVisualizer(&renderEnv{
		opts:  Options{ShowFingerprint: true, WrapLines: true},
		theme: classicTheme,
		width: 80,
	})

	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var fpLines []string
	for line := range strings.SplitSeq(output, "\n") {
		stripped := strings.TrimSpace(line)
		if strings.Contains(stripped, "Fingerprint:") || isHexContinuation(stripped) {
			fpLines = append(fpLines, stripped)
		}
	}

	if len(fpLines) < 2 {
		t.Errorf("expected fingerprint to wrap onto multiple lines at width 80, got %d line(s):\n%s", len(fpLines), output)
	}

	var hexParts []string
	for _, line := range fpLines {
		_, after, ok := strings.Cut(line, "Fingerprint:")
		if ok {
			hexParts = append(hexParts, strings.TrimSpace(after))
		} else {
			hexParts = append(hexParts, strings.TrimSpace(stripTreePrefix(line)))
		}
	}
	reconstructed := strings.Join(hexParts, "")
	if len(reconstructed) != 95 {
		t.Errorf("reconstructed fingerprint has %d chars, want 95: %q", len(reconstructed), reconstructed)
	}
}

func TestTreeVisualize_FingerprintNoWrapWideTerminal(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	chain := []*certree.Certificate{cached.singleCert}
	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{Certificates: chain, Status: certree.PathTrusted},
		},
	}

	tv := newTreeVisualizer(&renderEnv{
		opts:  Options{ShowFingerprint: true, WrapLines: true},
		theme: classicTheme,
		width: 200,
	})

	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fpCount := 0
	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, "Fingerprint:") {
			fpCount++
		}
	}
	if fpCount != 1 {
		t.Errorf("expected exactly 1 fingerprint line at wide width, got %d", fpCount)
	}
}

func TestSectionBlock_RenderLinesWraps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		block  sectionBlock
		wantFn func(lines []string) bool
		errMsg string
	}{
		{
			name: "label:value line wraps at narrow width",
			block: sectionBlock{
				header: "Subject:",
				lines: []string{
					"  Organization:  AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK LLLL",
				},
			},
			wantFn: func(lines []string) bool { return len(lines) >= 3 && lines[0] == "Subject:" },
			errMsg: "expected at least 3 lines (header + wrapped) with 'Subject:' header",
		},
		{
			name: "list item wraps at narrow width",
			block: sectionBlock{
				header: "Subject Alternative Names:",
				lines: []string{
					"  - very-long-subdomain.deeply-nested.example.organization.com",
				},
			},
			wantFn: func(lines []string) bool { return len(lines) >= 3 },
			errMsg: "expected at least 3 lines (header + wrapped list item)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lines := tt.block.renderLines(12, 30)
			if !tt.wantFn(lines) {
				t.Errorf("%s, got %d: %v", tt.errMsg, len(lines), lines)
			}
		})
	}
}

func TestSectionBlock_RenderLinesNoWrapWhenDisabled(t *testing.T) {
	t.Parallel()

	block := sectionBlock{
		header: "Subject:",
		lines:  []string{"  Organization:  Very Long Value"},
	}

	lines := block.renderLines(12, 0)

	if len(lines) != 2 {
		t.Errorf("expected 2 lines (header + 1 sub-line), got %d: %v", len(lines), lines)
	}
}

func TestBuildMergedTree_EmptyPaths(t *testing.T) {
	t.Parallel()

	root := buildMergedTree(nil, false)
	if len(root.children) != 0 {
		t.Errorf("expected 0 children for empty input, got %d", len(root.children))
	}
}

func TestBuildMergedTree_SinglePath(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	path := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}

	root := buildMergedTree([]*certree.TrustPath{path}, false)

	// Should produce a linear chain with one child at each level.
	if len(root.order) != 1 {
		t.Fatalf("expected 1 root child, got %d", len(root.order))
	}
	node := root.children[root.order[0]]
	if node.cert.FingerprintSHA256() != cached.chain3[0].FingerprintSHA256() {
		t.Errorf("expected first cert to be chain3[0]")
	}
	if len(node.paths) != 1 {
		t.Errorf("expected 1 path through first node, got %d", len(node.paths))
	}
	// Walk to depth 3.
	for i := 1; i < len(cached.chain3); i++ {
		if len(node.order) != 1 {
			t.Fatalf("at depth %d: expected 1 child, got %d", i, len(node.order))
		}
		node = node.children[node.order[0]]
		if node.cert.FingerprintSHA256() != cached.chain3[i].FingerprintSHA256() {
			t.Errorf("at depth %d: wrong cert fingerprint", i)
		}
	}
	// Leaf should have no children.
	if len(node.children) != 0 {
		t.Errorf("leaf node should have 0 children, got %d", len(node.children))
	}
}

func TestBuildMergedTree_SharedPrefix(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	// Two paths sharing the first two certs, diverging at the third.
	path1 := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}

	// Create a different root cert for path2.
	altRoot := cached.singleCert
	path2Certs := []*certree.Certificate{cached.chain3[0], cached.chain3[1], altRoot}
	path2 := &certree.TrustPath{
		Certificates: path2Certs,
		Status:       certree.PathTrusted,
	}

	root := buildMergedTree([]*certree.TrustPath{path1, path2}, false)

	// Root should have 1 child (shared leaf).
	if len(root.order) != 1 {
		t.Fatalf("expected 1 root child (shared leaf), got %d", len(root.order))
	}

	leaf := root.children[root.order[0]]
	if len(leaf.paths) != 2 {
		t.Errorf("shared leaf should have 2 paths, got %d", len(leaf.paths))
	}

	// Leaf's child (shared intermediate) should also have 1 child.
	if len(leaf.order) != 1 {
		t.Fatalf("expected 1 intermediate child, got %d", len(leaf.order))
	}

	intermediate := leaf.children[leaf.order[0]]
	if len(intermediate.paths) != 2 {
		t.Errorf("shared intermediate should have 2 paths, got %d", len(intermediate.paths))
	}

	// Intermediate should have 2 children (diverging roots).
	if len(intermediate.order) != 2 {
		t.Fatalf("expected 2 root children after divergence, got %d", len(intermediate.order))
	}
}

func TestBuildMergedTree_IdenticalPaths(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)

	path1 := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}
	path2 := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}

	root := buildMergedTree([]*certree.TrustPath{path1, path2}, false)

	// Identical paths merge completely -- should be a single linear chain.
	if len(root.order) != 1 {
		t.Fatalf("expected 1 root child, got %d", len(root.order))
	}
	node := root.children[root.order[0]]
	if len(node.paths) != 2 {
		t.Errorf("merged leaf should have 2 paths, got %d", len(node.paths))
	}
	for i := 1; i < len(cached.chain3); i++ {
		if len(node.order) != 1 {
			t.Fatalf("at depth %d: expected 1 child (fully merged), got %d", i, len(node.order))
		}
		node = node.children[node.order[0]]
	}
	if len(node.children) != 0 {
		t.Errorf("terminal node should have 0 children, got %d", len(node.children))
	}
}

func TestBuildMergedTree_ReverseOrder(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	path := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}

	forward := buildMergedTree([]*certree.TrustPath{path}, false)
	reverse := buildMergedTree([]*certree.TrustPath{path}, true)

	// Forward: first node is chain3[0], reverse: first node is chain3[2].
	fwdFirst := forward.children[forward.order[0]]
	revFirst := reverse.children[reverse.order[0]]

	if fwdFirst.cert.FingerprintSHA256() != cached.chain3[0].FingerprintSHA256() {
		t.Errorf("forward tree first cert should be chain3[0]")
	}
	last := len(cached.chain3) - 1
	if revFirst.cert.FingerprintSHA256() != cached.chain3[last].FingerprintSHA256() {
		t.Errorf("reverse tree first cert should be chain3[%d]", last)
	}
}

func TestMergedView_PathCount(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
	chain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}

	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{Certificates: chain, Status: certree.PathTrusted},
			{Certificates: chain, Status: certree.PathTrusted},
		},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "2 trusted") {
		t.Errorf("expected '2 trusted' in root label, got:\n%s", output)
	}
}

func TestMergedView_DifferentiatedPathCount(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
	trustedChain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}

	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{
			{Certificates: trustedChain, Status: certree.PathTrusted},
			{Certificates: cached.chain3, Status: certree.PathIncomplete},
		},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{}, theme: classicTheme})
	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "1 trusted") {
		t.Errorf("expected '1 trusted' in root label, got:\n%s", output)
	}
	if !strings.Contains(output, "1 incomplete") {
		t.Errorf("expected '1 incomplete' in root label, got:\n%s", output)
	}
}

func TestMergedView_ExpandedViewFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		expanded      bool
		wantTrustPath bool
	}{
		{name: "merged mode hides trust path nodes", expanded: false, wantTrustPath: false},
		{name: "expanded mode shows trust path nodes", expanded: true, wantTrustPath: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cached := getUnitTestCerts(t)
			trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
			chain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}

			analysis := &certree.Analysis{
				Certificates: chain,
				TrustPaths: []*certree.TrustPath{
					{Certificates: chain, Status: certree.PathTrusted},
				},
			}

			tv := newTreeVisualizer(&renderEnv{opts: Options{ExpandedView: tt.expanded}, theme: classicTheme})
			output, err := tv.visualize(analysis)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			hasTrustPath := strings.Contains(output, "Trust Path")
			if hasTrustPath != tt.wantTrustPath {
				t.Errorf("expanded=%v: wantTrustPath=%v, got hasTrustPath=%v\noutput:\n%s",
					tt.expanded, tt.wantTrustPath, hasTrustPath, output)
			}
		})
	}
}

func TestMergedView_ReverseOrder(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	trustedRoot := cached.chain3[2].WithTrustedLocations([]string{"system"})
	chain := []*certree.Certificate{cached.chain3[0], cached.chain3[1], trustedRoot}

	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{Certificates: chain, Status: certree.PathTrusted},
		},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ReverseOrder: true}, theme: classicTheme})
	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// In reverse mode, the root cert should appear before the leaf in the output.
	lines := strings.Split(output, "\n")
	rootIdx, leafIdx := -1, -1
	rootCN := displayName(trustedRoot)
	leafCN := displayName(chain[0])
	for i, line := range lines {
		if strings.Contains(line, rootCN) && rootIdx < 0 {
			rootIdx = i
		}
		if strings.Contains(line, leafCN) && leafIdx < 0 {
			leafIdx = i
		}
	}
	if rootIdx < 0 || leafIdx < 0 {
		t.Fatalf("could not find root (%q) or leaf (%q) in output:\n%s", rootCN, leafCN, output)
	}
	if rootIdx >= leafIdx {
		t.Errorf("in reverse mode, root should appear before leaf: rootIdx=%d, leafIdx=%d", rootIdx, leafIdx)
	}
}

func TestBuildAIASection(t *testing.T) {
	t.Parallel()

	t.Run("cert with OCSP and CA Issuer", func(t *testing.T) {
		t.Parallel()
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject:        pkix.Name{CommonName: "aia-test"},
			IsCA:           true,
			OCSPServer:     []string{"http://ocsp.example.com"},
			IssuingCertURL: []string{"http://ca.example.com/issuer.crt"},
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{})
		section, ok := buildAIASection(cert, "  ", " ")
		if !ok {
			t.Fatal("buildAIASection returned false for cert with AIA")
		}
		if section.header != "AIA:" {
			t.Errorf("header = %q, want %q", section.header, "AIA:")
		}
		joined := strings.Join(section.lines, "\n")
		if !strings.Contains(joined, "OCSP") {
			t.Errorf("expected OCSP in lines: %v", section.lines)
		}
		if !strings.Contains(joined, "CA Issuer") {
			t.Errorf("expected CA Issuer in lines: %v", section.lines)
		}
	})

	t.Run("cert without AIA returns false", func(t *testing.T) {
		t.Parallel()
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "no-aia"},
			IsCA:    true,
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{})
		_, ok := buildAIASection(cert, "  ", " ")
		if ok {
			t.Error("buildAIASection returned true for cert without AIA")
		}
	})
}

func TestBuildCRLSection(t *testing.T) {
	t.Parallel()

	t.Run("cert with CRL distribution points", func(t *testing.T) {
		t.Parallel()
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject:            pkix.Name{CommonName: "crl-test"},
			IsCA:               true,
			CRLDistributionPts: []string{"http://crl.example.com/ca.crl"},
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{})
		section, ok := buildCRLSection(cert, "  ", " ")
		if !ok {
			t.Fatal("buildCRLSection returned false for cert with CRL")
		}
		if section.header != "CRL Distribution Points:" {
			t.Errorf("header = %q, want %q", section.header, "CRL Distribution Points:")
		}
		if len(section.lines) != 1 {
			t.Fatalf("expected 1 line, got %d", len(section.lines))
		}
		if !strings.Contains(section.lines[0], "crl.example.com") {
			t.Errorf("line %q does not contain CRL URL", section.lines[0])
		}
	})

	t.Run("cert without CRL returns false", func(t *testing.T) {
		t.Parallel()
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "no-crl"},
			IsCA:    true,
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{})
		_, ok := buildCRLSection(cert, "  ", " ")
		if ok {
			t.Error("buildCRLSection returned true for cert without CRL")
		}
	})
}

func TestPathIndex_MergedView(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	altRoot := cached.singleCert

	// Two paths sharing leaf+intermediate, diverging at root.
	path1 := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}
	path2 := &certree.TrustPath{
		Certificates: []*certree.Certificate{cached.chain3[0], cached.chain3[1], altRoot},
		Status:       certree.PathTrusted,
	}

	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{path1, path2},
		Metadata:     certree.AnalysisMetadata{Source: "test.pem"},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ShowPathIndex: true}, theme: classicTheme})
	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "#1") {
		t.Errorf("expected #1 in output, got:\n%s", output)
	}
	if !strings.Contains(output, "#2") {
		t.Errorf("expected #2 in output, got:\n%s", output)
	}

	// Path indices should not contain raw markers.
	if strings.Contains(output, pathIndexMarker) {
		t.Errorf("output contains raw path index marker:\n%s", output)
	}
}

func TestPathIndex_Disabled(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{
			{Certificates: cached.chain3, Status: certree.PathTrusted},
		},
		Metadata: certree.AnalysisMetadata{Source: "test.pem"},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ShowPathIndex: false}, theme: classicTheme})
	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(output, "#1") {
		t.Errorf("path index should not appear when disabled, got:\n%s", output)
	}
}

func TestPathIndex_ExpandedView(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths: []*certree.TrustPath{
			{Certificates: cached.chain3, Status: certree.PathTrusted},
			{Certificates: cached.chain3, Status: certree.PathTrusted},
		},
		Metadata: certree.AnalysisMetadata{Source: "test.pem"},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ShowPathIndex: true, ExpandedView: true}, theme: classicTheme})
	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "#1") {
		t.Errorf("expected #1 in expanded output, got:\n%s", output)
	}
	if !strings.Contains(output, "#2") {
		t.Errorf("expected #2 in expanded output, got:\n%s", output)
	}
	if strings.Contains(output, pathIndexMarker) {
		t.Errorf("output contains raw path index marker:\n%s", output)
	}
}

func TestPathIndex_RightAlignment(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	altRoot := cached.singleCert

	path1 := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}
	path2 := &certree.TrustPath{
		Certificates: []*certree.Certificate{cached.chain3[0], cached.chain3[1], altRoot},
		Status:       certree.PathTrusted,
	}

	analysis := &certree.Analysis{
		Certificates: cached.chain3,
		TrustPaths:   []*certree.TrustPath{path1, path2},
		Metadata:     certree.AnalysisMetadata{Source: "test.pem"},
	}

	tv := newTreeVisualizer(&renderEnv{opts: Options{ShowPathIndex: true}, theme: classicTheme})
	output, err := tv.visualize(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both #1 and #2 lines should have the same visible column for the '#'.
	var hashColumns []int
	for line := range strings.SplitSeq(output, "\n") {
		idx := strings.LastIndex(line, "#")
		if idx < 0 {
			continue
		}
		// Only count lines where # is a path index (followed by digit).
		rest := line[idx+1:]
		if len(rest) > 0 && rest[0] >= '1' && rest[0] <= '9' {
			col := visibleLen(line[:idx])
			hashColumns = append(hashColumns, col)
		}
	}

	if len(hashColumns) < 2 {
		t.Fatalf("expected at least 2 path index lines, got %d\noutput:\n%s", len(hashColumns), output)
	}
	for i := 1; i < len(hashColumns); i++ {
		if hashColumns[i] != hashColumns[0] {
			t.Errorf("path index columns not aligned: %v\noutput:\n%s", hashColumns, output)
			break
		}
	}
}

func TestAlignPathIndices_NoMarkers(t *testing.T) {
	t.Parallel()

	input := "line one\nline two\n"
	got := alignPathIndices(input, identityColorFunc)
	if got != input {
		t.Errorf("expected unchanged output, got:\n%s", got)
	}
}

func TestAlignPathIndices_MultipleMarkers(t *testing.T) {
	t.Parallel()

	// Short line with #1, longer line with #2.
	input := "short" + pathIndexMarker + "#1" + pathIndexEnd + "\n" +
		"much longer line" + pathIndexMarker + "#2" + pathIndexEnd + "\n"

	got := alignPathIndices(input, identityColorFunc)

	lines := strings.Split(got, "\n")
	// Find columns where # appears.
	var cols []int
	for _, line := range lines {
		idx := strings.Index(line, "#")
		if idx >= 0 {
			cols = append(cols, idx)
		}
	}
	if len(cols) != 2 {
		t.Fatalf("expected 2 lines with #, got %d\noutput:\n%s", len(cols), got)
	}
	if cols[0] != cols[1] {
		t.Errorf("columns not aligned: %v\noutput:\n%s", cols, got)
	}
}

func TestTerminalPathMarker_NonTerminalNode(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	path := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}

	// Build a merged node for the leaf cert (not the terminal).
	mn := &mergedTreeNode{
		cert:     cached.chain3[0],
		paths:    []*certree.TrustPath{path},
		children: make(map[string]*mergedTreeNode),
	}
	pathIndices := map[*certree.TrustPath]int{path: 1}

	got := terminalPathMarker(mn, pathIndices)
	if got != "" {
		t.Errorf("expected empty marker for non-terminal node, got %q", got)
	}
}

func TestTerminalPathMarker_TerminalNode(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	path := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}

	// The marker always goes on the root cert (last in the leaf-to-root slice).
	mn := &mergedTreeNode{
		cert:     cached.chain3[2],
		paths:    []*certree.TrustPath{path},
		children: make(map[string]*mergedTreeNode),
	}
	pathIndices := map[*certree.TrustPath]int{path: 3}

	got := terminalPathMarker(mn, pathIndices)
	if got == "" {
		t.Fatal("expected non-empty marker for root node")
	}
	if !strings.Contains(got, "#3") {
		t.Errorf("expected #3 in marker, got %q", got)
	}
}

func TestTerminalPathMarker_RootMarkedInBothOrders(t *testing.T) {
	t.Parallel()

	cached := getUnitTestCerts(t)
	path := &certree.TrustPath{
		Certificates: cached.chain3,
		Status:       certree.PathTrusted,
	}

	// The marker goes on the root cert regardless of display order.
	// In default view, the root is at the bottom; in reverse, at the top.
	rootMN := &mergedTreeNode{
		cert:     cached.chain3[2],
		paths:    []*certree.TrustPath{path},
		children: make(map[string]*mergedTreeNode),
	}
	pathIndices := map[*certree.TrustPath]int{path: 1}

	got := terminalPathMarker(rootMN, pathIndices)
	if got == "" {
		t.Fatal("expected non-empty marker on root node")
	}
	if !strings.Contains(got, "#1") {
		t.Errorf("expected #1 in marker, got %q", got)
	}

	// The leaf should NOT get a marker.
	leafMN := &mergedTreeNode{
		cert:     cached.chain3[0],
		paths:    []*certree.TrustPath{path},
		children: make(map[string]*mergedTreeNode),
	}
	got = terminalPathMarker(leafMN, pathIndices)
	if got != "" {
		t.Errorf("expected empty marker on leaf node, got %q", got)
	}
}

package render

import (
	"crypto/x509/pkix"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"github.com/timorunge/certree/pkg/certree"
	"github.com/timorunge/certree/pkg/certree/testutil"
)

// cachedTreeTestCerts holds pre-generated certificates for tree property tests.
// Certificate generation is expensive (RSA key generation), so certs are
// created once and reused across all property iterations.
type cachedTreeTestCerts struct {
	// chain is a 3-cert chain: [end-entity, intermediate, root].
	chain []*certree.Certificate
}

// setupTreeTestCerts generates certificates once for reuse in property tests.
func setupTreeTestCerts(t *testing.T) *cachedTreeTestCerts {
	t.Helper()

	rawCerts, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("generating simple chain: %v", err)
		return nil
	}

	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	chain := make([]*certree.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		chain[i] = certree.NewCertificate(raw, src)
	}

	return &cachedTreeTestCerts{chain: chain}
}

// renderChainOutput renders a trusted chain with the given options and theme.
// Returns empty string on error.
func renderChainOutput(chain []*certree.Certificate, opts Options, theme renderTheme) string {
	analysis := &certree.Analysis{
		Certificates: chain,
		TrustPaths: []*certree.TrustPath{
			{Certificates: chain, Status: certree.PathTrusted},
		},
	}
	tv := newTreeVisualizer(&renderEnv{opts: opts, theme: theme})

	output, err := tv.visualize(analysis)
	if err != nil {
		return ""
	}
	return output
}

// collectCertNodes walks the tree node hierarchy depth-first and returns
// the certificate metadata from each cert node in render order.
// It skips the path-level node and collects only cert nodes (those with
// a Certificate in Metadata).
func collectCertNodes(pathNode *treeNode) []*treeNode {
	if len(pathNode.children) == 0 {
		return nil
	}
	var nodes []*treeNode
	current := pathNode.children[0]
	for current != nil {
		if current.metadata != nil && current.metadata.certificate != nil {
			nodes = append(nodes, current)
		}
		if len(current.children) > 0 {
			current = current.children[0]
		} else {
			current = nil
		}
	}
	return nodes
}

// cachedReverseTestCerts holds pre-generated certificate chains of various
// depths for reverse iteration property tests.
type cachedReverseTestCerts struct {
	// chains maps depth -> certree.Certificate slice.
	chains map[int][]*certree.Certificate
}

// setupReverseTestCerts generates chains of depth 1..5 for reuse.
func setupReverseTestCerts(t *testing.T) *cachedReverseTestCerts {
	t.Helper()

	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	cached := &cachedReverseTestCerts{chains: make(map[int][]*certree.Certificate)}

	for depth := 1; depth <= 5; depth++ {
		rawChain, _, err := testutil.GenerateChainWithDepth(depth)
		if err != nil {
			t.Fatalf("generating chain with depth %d: %v", depth, err)
			return nil
		}
		chain := make([]*certree.Certificate, len(rawChain))
		for i, raw := range rawChain {
			chain[i] = certree.NewCertificate(raw, src)
		}
		cached.chains[depth] = chain
	}

	return cached
}

func TestGhostDisplayAnnotation(t *testing.T) {
	t.Parallel()

	cached := setupReverseTestCerts(t)

	// Enumerate all meaningful (depth, excludeIdx) combinations.
	// depth 3: excludeIdx 1..2, depth 4: 1..3, depth 5: 1..4.
	for depth := 3; depth <= 5; depth++ {
		for excludeIdx := 1; excludeIdx < depth; excludeIdx++ {
			t.Run(
				"depth"+string(rune('0'+depth))+"_exclude"+string(rune('0'+excludeIdx)),
				func(t *testing.T) {
					t.Parallel()

					chain := cached.chains[depth]
					certs := make([]*certree.Certificate, len(chain))
					copy(certs, chain)

					ghostedCount := 0
					simMeta := make(map[string]certree.CertSimulationState)
					simMeta[certs[excludeIdx].FingerprintSHA256()] = certree.CertSimulationState{IsExcluded: true}
					for i := excludeIdx + 1; i < len(certs); i++ {
						simMeta[certs[i].FingerprintSHA256()] = certree.CertSimulationState{IsGhosted: true}
						ghostedCount++
					}

					path := &certree.TrustPath{
						Certificates:       certs,
						Status:             certree.PathTrusted,
						SimulationMetadata: simMeta,
					}

					analysis := &certree.Analysis{
						Certificates: certs,
						TrustPaths:   []*certree.TrustPath{path},
					}

					tv := newTreeVisualizer(&renderEnv{opts: Options{ShowAnnotations: true}, theme: classicTheme})

					output, err := tv.visualize(analysis)
					if err != nil {
						t.Fatalf("visualize: %v", err)
					}

					actual := strings.Count(output, "(ghosted)")
					if actual != ghostedCount {
						t.Errorf("ghosted count = %d, want %d\noutput:\n%s", actual, ghostedCount, output)
					}
				},
			)
		}
	}
}

// TestVisibleTextInvariantAcrossColorModes verifies that stripping ANSI escape
// sequences from color-enabled output produces the same text as color-disabled
// output, for all 9 combinations of 3 themes x 3 option modes.
// Not parallel because it mutates the global color.NoColor flag.
func TestVisibleTextInvariantAcrossColorModes(t *testing.T) {
	cached := setupTreeTestCerts(t)

	// Force color output so fatih/color emits ANSI codes regardless of TTY.
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	// Build a chain with a trusted root for richer output.
	trustedRoot := cached.chain[2].WithTrustedLocations([]string{"system"})
	trustedChain := []*certree.Certificate{cached.chain[0], cached.chain[1], trustedRoot}

	analysis := &certree.Analysis{
		Certificates: trustedChain,
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: trustedChain,
				Status:       certree.PathTrusted,
			},
		},
	}

	themes := []struct {
		name  string
		theme renderTheme
	}{
		{"classic", classicTheme},
		{"terse", terseTheme},
		{"minimal", minimalTheme},
	}
	modes := []struct {
		name string
		opts Options
	}{
		{"default", Options{}},
		{"show-all", Options{ShowAll: true}},
		{"show-subject", Options{ShowSubject: true}},
	}

	for _, th := range themes {
		for _, mo := range modes {
			t.Run(th.name+"/"+mo.name, func(t *testing.T) {
				// Render with color disabled (plain theme).
				tvPlain := newTreeVisualizer(&renderEnv{opts: mo.opts, theme: th.theme})
				plainOutput, err := tvPlain.visualize(analysis)
				if err != nil {
					t.Fatalf("plain render: %v", err)
				}

				// Render with color enabled (color theme).
				colorTheme := th.theme.WithColor()
				tvColor := newTreeVisualizer(&renderEnv{opts: mo.opts, theme: colorTheme})
				colorOutput, err := tvColor.visualize(analysis)
				if err != nil {
					t.Fatalf("color render: %v", err)
				}

				// Strip ANSI codes from color output -- must equal plain output.
				strippedColor := stripANSICodes(colorOutput)
				if plainOutput != strippedColor {
					t.Errorf("stripped color output differs from plain output")
				}
			})
		}
	}
}

func TestReasonAnnotationColoring(t *testing.T) {
	// Force color output so fatih/color emits ANSI codes regardless of TTY.
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	// Generate an expired certificate to trigger an error reason annotation.
	expiredRaw, _, err := testutil.GenerateCertificateWithExpiry(
		"Expired Cert",
		time.Now().Add(-365*24*time.Hour),
		time.Now().Add(-1*time.Hour),
	)
	if err != nil {
		t.Fatalf("generating expired cert: %v", err)
	}
	src := certree.CertificateSource{Type: certree.SourceTypeFile}
	expiredCert := certree.NewCertificate(expiredRaw, src)

	// Generate a valid root (self-signed, trusted).
	rootRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Root CA"},
		IsCA:    true,
	})
	if err != nil {
		t.Fatalf("generating root cert: %v", err)
	}
	rootCert := certree.NewCertificate(rootRaw, src).WithTrustedLocations([]string{"system"})

	analysisWithExpired := &certree.Analysis{
		Certificates: []*certree.Certificate{expiredCert, rootCert},
		TrustPaths: []*certree.TrustPath{
			{
				Certificates: []*certree.Certificate{expiredCert, rootCert},
				Status:       certree.PathTrusted,
			},
		},
	}

	redCode := "\x1b[31m"

	themes := []struct {
		name  string
		theme renderTheme
	}{
		{"classic", classicTheme},
		{"terse", terseTheme},
		{"minimal", minimalTheme},
	}

	for _, tt := range themes {
		t.Run(tt.name, func(t *testing.T) {
			colorTheme := tt.theme.WithColor()
			tv := newTreeVisualizer(&renderEnv{opts: Options{ShowAnnotations: true}, theme: colorTheme})
			output, err := tv.visualize(analysisWithExpired)
			if err != nil {
				t.Fatalf("visualize error: %v", err)
			}

			found := false
			for line := range strings.SplitSeq(output, "\n") {
				stripped := stripANSICodes(line)
				if strings.Contains(stripped, "Expired Cert") && strings.Contains(stripped, "expired") {
					if strings.Contains(line, redCode) {
						found = true
						break
					}
				}
			}
			if !found {
				t.Error("expired cert reason annotation should contain red ANSI code")
			}
		})
	}
}

// Not parallel because it mutates the global color.NoColor flag.
func TestGhostedLinesDimStyling(t *testing.T) {
	noColorMu.Lock()
	origNoColor := color.NoColor
	color.NoColor = false
	t.Cleanup(func() {
		color.NoColor = origNoColor
		noColorMu.Unlock()
	})

	dimCode := "\x1b[2m"
	cached := setupReverseTestCerts(t)

	// Enumerate all (depth, excludeIdx) combinations that produce ghosted certs.
	for depth := 3; depth <= 5; depth++ {
		for excludeIdx := 1; excludeIdx < depth-1; excludeIdx++ {
			t.Run(
				"depth"+string(rune('0'+depth))+"_exclude"+string(rune('0'+excludeIdx)),
				func(t *testing.T) {
					chain := cached.chains[depth]
					certs := make([]*certree.Certificate, len(chain))
					copy(certs, chain)

					simMeta := make(map[string]certree.CertSimulationState)
					simMeta[certs[excludeIdx].FingerprintSHA256()] = certree.CertSimulationState{IsExcluded: true}
					ghostedCount := 0
					for i := excludeIdx + 1; i < len(certs); i++ {
						simMeta[certs[i].FingerprintSHA256()] = certree.CertSimulationState{IsGhosted: true}
						ghostedCount++
					}

					path := &certree.TrustPath{
						Certificates:       certs,
						Status:             certree.PathTrusted,
						SimulationMetadata: simMeta,
					}

					analysis := &certree.Analysis{
						Certificates: certs,
						TrustPaths:   []*certree.TrustPath{path},
					}

					colorTheme := classicTheme.WithColor()
					tv := newTreeVisualizer(&renderEnv{opts: Options{ShowAnnotations: true}, theme: colorTheme})

					output, err := tv.visualize(analysis)
					if err != nil {
						t.Fatalf("visualize: %v", err)
					}

					dimCount := 0
					for line := range strings.SplitSeq(output, "\n") {
						stripped := stripANSICodes(line)
						if !strings.Contains(stripped, "(ghosted)") {
							continue
						}
						dimCount++
						if !strings.Contains(line, dimCode) {
							t.Errorf("ghosted line missing dim code: %s", line)
						}
					}

					if dimCount != ghostedCount {
						t.Errorf("dim ghosted lines = %d, want %d", dimCount, ghostedCount)
					}
				},
			)
		}
	}
}

func TestProperty_DetailFieldOrdering(t *testing.T) {
	t.Parallel()

	parameters := gopter.DefaultTestParameters()
	if testing.Short() {
		parameters.MinSuccessfulTests = 10
	} else {
		parameters.MinSuccessfulTests = 100
	}

	properties := gopter.NewProperties(parameters)

	src := certree.CertificateSource{Type: certree.SourceTypeFile}

	// Generate a cert with rich fields for ordering tests.
	richRaw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Ordering Test",
			Organization: []string{"Order Org"},
			Country:      []string{"US"},
		},
		IsCA:     true,
		DNSNames: []string{"order.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	richCert := certree.NewCertificate(richRaw, src).WithTrustedLocations([]string{"system"})
	richChain := []*certree.Certificate{richCert}

	// canonicalOrder defines the expected order of detail line prefixes.
	canonicalOrder := []string{
		"Subject:", "Subject Alternative Names:", "Issuer:", "Validity:", "Trust Store:",
		"Serial:", "Fingerprint:", "Extensions:", "AIA:",
		"CRL Distribution Points:", "Source:", "Warnings:", "Errors:",
	}

	// Generate flag combinations with at least two detail sections enabled.
	genOpts := gen.Struct(reflect.TypeFor[Options](), map[string]gopter.Gen{
		"ShowFingerprint": gen.Bool(),
		"ShowSerial":      gen.Bool(),
		"ShowValidity":    gen.Bool(),
		"ShowSource":      gen.Bool(),
		"ShowSubject":     gen.Bool(),
		"ShowIssuer":      gen.Bool(),
		"ShowSAN":         gen.Bool(),
		"ShowTrustStore":  gen.Bool(),
	}).SuchThat(func(v any) bool {
		opts := v.(Options)
		count := 0
		if opts.ShowSubject {
			count++
		}
		if opts.ShowIssuer {
			count++
		}
		if opts.ShowValidity {
			count++
		}
		if opts.ShowFingerprint {
			count++
		}
		if opts.ShowSerial {
			count++
		}
		if opts.ShowSource {
			count++
		}
		if opts.ShowSAN {
			count++
		}
		if opts.ShowTrustStore {
			count++
		}
		return count >= 2
	})

	properties.Property("detail fields appear in canonical order", prop.ForAll(
		func(opts Options) bool {
			output := renderChainOutput(richChain, opts, classicTheme)
			if output == "" {
				return false
			}

			// Collect the order of detail prefixes found in the output.
			var foundOrder []int
			for line := range strings.SplitSeq(output, "\n") {
				trimmed := strings.TrimSpace(line)
				for i, prefix := range canonicalOrder {
					if strings.HasPrefix(trimmed, prefix) {
						foundOrder = append(foundOrder, i)
						break
					}
				}
			}

			// Verify the found order is non-decreasing.
			for i := 1; i < len(foundOrder); i++ {
				if foundOrder[i] < foundOrder[i-1] {
					return false
				}
			}
			return true
		},
		genOpts,
	))

	properties.TestingRun(t)
}

package certree

import (
	"crypto/x509/pkix"
	"encoding/json"
	"testing"
	"time"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// unmarshalJSON serializes an Analysis to JSON and unmarshals it into a map for field inspection.
func unmarshalJSON(t *testing.T, analysis *Analysis) map[string]any {
	t.Helper()
	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
		return nil
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal: %v", err)
		return nil
	}
	return result
}

func TestAnalysis_CertificateFiltering(t *testing.T) {
	t.Parallel()

	cert1, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "trusted1.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	cert2, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "trusted2.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	cert3, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "untrusted.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	c1 := NewCertificate(cert1, CertificateSource{Type: SourceTypeFile})
	c1 = c1.WithTrustedLocations([]string{"system", "/etc/ssl/custom.crt"})

	c2 := NewCertificate(cert2, CertificateSource{Type: SourceTypeFile})
	c2 = c2.WithTrustedLocations([]string{"system"})

	c3 := NewCertificate(cert3, CertificateSource{Type: SourceTypeFile})

	analysis := NewAnalysis(
		[]*Certificate{c1, c2, c3},
		[]*TrustPath{
			{Status: PathTrusted},
			{Status: PathUntrusted},
			{Status: PathTrusted},
		},
		"test",
	)

	if analysis.Metadata.TrustedPaths != 2 {
		t.Errorf("TrustedPaths: expected 2, got %d", analysis.Metadata.TrustedPaths)
	}

	if analysis.HasErrors() {
		t.Error("HasErrors: expected false for paths without errors")
	}

	analysis.TrustPaths[1].Errors = []ValidationError{
		{Type: ErrorExpired, Message: "expired"},
	}
	if !analysis.HasErrors() {
		t.Error("HasErrors: expected true after adding error")
	}
}

func TestAnalysis_JSONSerialization_TopLevel(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	wrapped := NewCertificate(cert, CertificateSource{
		Type:     SourceTypeFile,
		Location: "/path/to/cert.pem",
	})

	analysis := &Analysis{
		Certificates: []*Certificate{wrapped},
		TrustPaths: []*TrustPath{
			{
				Certificates: []*Certificate{wrapped},
				Status:       PathTrusted,
				Errors:       []ValidationError{},
				Warnings:     []ValidationWarning{},
			},
		},
		Metadata: AnalysisMetadata{
			Source:       "/path/to/cert.pem",
			Timestamp:    time.Now(),
			TotalCerts:   1,
			TotalPaths:   1,
			TrustedPaths: 1,
		},
	}

	prettyJSON, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	var prettyResult map[string]any
	err = json.Unmarshal(prettyJSON, &prettyResult)
	if err != nil {
		t.Fatalf("Unmarshal pretty JSON: %v", err)
	}

	compactJSON, err := json.Marshal(analysis)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var compactResult map[string]any
	err = json.Unmarshal(compactJSON, &compactResult)
	if err != nil {
		t.Fatalf("Unmarshal compact JSON: %v", err)
	}

	for _, field := range []string{"certificates", "trust_paths", "metadata"} {
		if _, ok := prettyResult[field]; !ok {
			t.Errorf("Missing top-level field %q", field)
		}
	}

	// Certificates is now a fingerprint-keyed map.
	certsMap, ok := prettyResult["certificates"].(map[string]any)
	if !ok {
		t.Fatal("certificates is not a map")
	}
	fp := ColonHex(wrapped.FingerprintSHA256())
	if _, found := certsMap[fp]; !found {
		t.Errorf("certificate map missing fingerprint key %q", fp)
	}

	// Trust path certificates are fingerprint references.
	paths := prettyResult["trust_paths"].([]any)
	path := paths[0].(map[string]any)
	pathCerts := path["certificates"].([]any)
	if pathCerts[0] != fp {
		t.Errorf("path certificate reference: expected %q, got %v", fp, pathCerts[0])
	}

	metadata, ok := prettyResult["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata is not an object")
	}
	if metadata["source"] != "/path/to/cert.pem" {
		t.Errorf("metadata.source: expected /path/to/cert.pem, got %v", metadata["source"])
	}
}

func TestAnalysis_JSONCanonicalLeafToRootOrder(t *testing.T) {
	t.Parallel()

	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("GenerateSimpleChain: %v", err)
	}

	leaf := NewCertificate(x509Certs[0], CertificateSource{Type: SourceTypeRemote, Location: "example.com:443"})
	intermediate := NewCertificate(x509Certs[1], CertificateSource{Type: SourceTypeRemote, Location: "example.com:443"})
	root := NewCertificate(x509Certs[2], CertificateSource{Type: SourceTypeFile, Location: "/etc/ssl/certs/root.pem"})

	analysis := NewAnalysis(
		[]*Certificate{leaf, intermediate, root},
		[]*TrustPath{
			{
				Certificates: []*Certificate{leaf, intermediate, root},
				Status:       PathTrusted,
			},
		},
		"example.com:443",
	)

	expectedFingerprints := []string{
		ColonHex(leaf.FingerprintSHA256()),
		ColonHex(intermediate.FingerprintSHA256()),
		ColonHex(root.FingerprintSHA256()),
	}

	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}

	var result map[string]any
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Certificates map should contain all 3 certs keyed by fingerprint.
	certsMap, ok := result["certificates"].(map[string]any)
	if !ok || len(certsMap) != 3 {
		t.Fatalf("expected 3 certificates in map, got %v", len(certsMap))
	}

	paths, ok := result["trust_paths"].([]any)
	if !ok || len(paths) != 1 {
		t.Fatalf("expected 1 trust path, got %v", len(paths))
	}

	path := paths[0].(map[string]any)
	pathCerts, ok := path["certificates"].([]any)
	if !ok || len(pathCerts) != 3 {
		t.Fatalf("expected 3 fingerprint references in path, got %d", len(pathCerts))
	}

	// Verify trust path references are in leaf-to-root order.
	for i, ref := range pathCerts {
		fp, ok := ref.(string)
		if !ok {
			t.Fatalf("path certificate %d: expected string fingerprint, got %T", i, ref)
		}
		if fp != expectedFingerprints[i] {
			t.Errorf("path certificate %d: expected %s, got %s", i, expectedFingerprints[i], fp)
		}
		// Verify the fingerprint exists in the certificate map.
		if _, ok := certsMap[fp]; !ok {
			t.Errorf("path certificate %d: fingerprint %s not found in certificates map", i, fp)
		}
	}
}

func TestAnalysis_JSONSerialization(t *testing.T) {
	t.Parallel()

	t.Run("multiple paths", func(t *testing.T) {
		t.Parallel()

		cert1, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "example.com"},
		})
		if err != nil {
			t.Fatalf("generating cert: %v", err)
		}
		cert2, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "intermediate1.com"},
		})
		if err != nil {
			t.Fatalf("generating cert: %v", err)
		}
		cert3, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "intermediate2.com"},
		})
		if err != nil {
			t.Fatalf("generating cert: %v", err)
		}
		root, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "root.com"},
		})
		if err != nil {
			t.Fatalf("generating cert: %v", err)
		}

		w1 := NewCertificate(cert1, CertificateSource{Type: SourceTypeRemote, Location: "example.com:443"})
		w2 := NewCertificate(cert2, CertificateSource{Type: SourceTypeRemote, Location: "example.com:443"})
		w3 := NewCertificate(cert3, CertificateSource{Type: SourceTypeAIA, Location: "http://issuer.com/cert"})
		wr := NewCertificate(root, CertificateSource{Type: SourceTypeFile, Location: "/etc/ssl/certs/root.pem"})

		analysis := NewAnalysis(
			[]*Certificate{w1, w2, w3, wr},
			[]*TrustPath{
				{Certificates: []*Certificate{w1, w2, wr}, Status: PathTrusted},
				{Certificates: []*Certificate{w1, w3, wr}, Status: PathTrusted},
			},
			"example.com:443",
		)

		result := unmarshalJSON(t, analysis)
		paths, ok := result["trust_paths"].([]any)
		if !ok || len(paths) != 2 {
			t.Fatalf("Expected 2 trust paths, got %v", paths)
		}
		for i, p := range paths {
			path := p.(map[string]any)
			certs := path["certificates"].([]any)
			if len(certs) != 3 {
				t.Errorf("Path %d: expected 3 fingerprint refs, got %d", i, len(certs))
			}
			// Each reference should be a string.
			for j, ref := range certs {
				if _, ok := ref.(string); !ok {
					t.Errorf("Path %d cert %d: expected string, got %T", i, j, ref)
				}
			}
		}

		// Certificates map should contain all 4 unique certs.
		certsMap := result["certificates"].(map[string]any)
		if len(certsMap) != 4 {
			t.Errorf("Expected 4 certs in map, got %d", len(certsMap))
		}
	})

	t.Run("source information", func(t *testing.T) {
		t.Parallel()

		sources := []struct {
			sourceType     SourceType
			sourceLocation string
			expectedType   string
		}{
			{SourceTypeFile, "/path/to/cert.pem", "file"},
			{SourceTypeRemote, "example.com:443", "remote"},
			{SourceTypeStdin, "-", "stdin"},
			{SourceTypeAIA, "http://issuer.com/cert", "aia"},
		}

		for _, s := range sources {
			cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
				Subject: pkix.Name{CommonName: "example.com"},
			})
			if err != nil {
				t.Fatalf("generating cert: %v", err)
			}
			wrapped := NewCertificate(cert, CertificateSource{Type: s.sourceType, Location: s.sourceLocation})
			analysis := NewAnalysis(
				[]*Certificate{wrapped},
				[]*TrustPath{},
				s.sourceLocation,
			)

			result := unmarshalJSON(t, analysis)
			certsMap := result["certificates"].(map[string]any)
			fp := ColonHex(wrapped.FingerprintSHA256())
			certObj := certsMap[fp].(map[string]any)
			source := certObj["source"].(map[string]any)
			if source["type"] != s.expectedType {
				t.Errorf("Source type for %s: expected %q, got %v", s.sourceLocation, s.expectedType, source["type"])
			}
		}
	})

	t.Run("path metadata", func(t *testing.T) {
		t.Parallel()

		cert1, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "example.com"},
		})
		if err != nil {
			t.Fatalf("generating cert: %v", err)
		}
		cert2, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "intermediate.com"},
		})
		if err != nil {
			t.Fatalf("generating cert: %v", err)
		}
		root, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "root.com"},
		})
		if err != nil {
			t.Fatalf("generating cert: %v", err)
		}

		w1 := NewCertificate(cert1, CertificateSource{Type: SourceTypeRemote})
		w2 := NewCertificate(cert2, CertificateSource{Type: SourceTypeRemote})
		wr := NewCertificate(root, CertificateSource{Type: SourceTypeFile})

		analysis := NewAnalysis(
			[]*Certificate{w1, w2, wr},
			[]*TrustPath{
				{Certificates: []*Certificate{w1, w2, wr}, Status: PathTrusted, Errors: []ValidationError{}, Warnings: []ValidationWarning{}},
			},
			"example.com:443",
		)

		result := unmarshalJSON(t, analysis)
		paths := result["trust_paths"].([]any)
		path := paths[0].(map[string]any)

		if path["status"] != "trusted" {
			t.Errorf("status: expected trusted, got %v", path["status"])
		}
		pathCerts := path["certificates"].([]any)
		if len(pathCerts) != 3 {
			t.Errorf("Expected 3 fingerprint refs in path, got %d", len(pathCerts))
		}
	})

	t.Run("trust store locations", func(t *testing.T) {
		t.Parallel()

		cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "root.com"},
		})
		if err != nil {
			t.Fatalf("generating cert: %v", err)
		}
		wrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})
		wrapped = wrapped.WithTrustedLocations([]string{"system", "/etc/ssl/certs/ca-bundle.crt"})

		analysis := NewAnalysis(
			[]*Certificate{wrapped},
			[]*TrustPath{},
			"/path/to/cert.pem",
		)

		result := unmarshalJSON(t, analysis)
		certsMap := result["certificates"].(map[string]any)
		fp := ColonHex(wrapped.FingerprintSHA256())
		certObj := certsMap[fp].(map[string]any)
		metadata := certObj["metadata"].(map[string]any)
		locations := metadata["trusted_locations"].([]any)
		if len(locations) != 2 {
			t.Errorf("Expected 2 trusted locations, got %d", len(locations))
		}
	})

	t.Run("empty analysis", func(t *testing.T) {
		t.Parallel()

		analysis := NewAnalysis(
			[]*Certificate{},
			[]*TrustPath{},
			"empty",
		)

		result := unmarshalJSON(t, analysis)
		certsMap := result["certificates"].(map[string]any)
		if len(certsMap) != 0 {
			t.Errorf("Expected empty certificates map, got %d entries", len(certsMap))
		}
		paths := result["trust_paths"].([]any)
		if len(paths) != 0 {
			t.Errorf("Expected empty trust_paths, got %d", len(paths))
		}
	})
}

func TestAnalysis_WarningsWithoutErrors(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "warn-test.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	wrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})

	analysis := NewAnalysis(
		[]*Certificate{wrapped},
		[]*TrustPath{
			{
				Certificates: []*Certificate{wrapped},
				Status:       PathTrusted,
				Warnings: []ValidationWarning{
					{
						Type:    WarningExpiringSoon,
						Message: "certificate expires in 10 days",
					},
				},
			},
		},
		"test",
	)

	if analysis.HasErrors() {
		t.Error("HasErrors: expected false for paths with only warnings")
	}

	if len(analysis.TrustPaths[0].Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(analysis.TrustPaths[0].Warnings))
	}

	if analysis.TrustPaths[0].Warnings[0].Type != WarningExpiringSoon {
		t.Errorf("expected WarningExpiringSoon, got %v", analysis.TrustPaths[0].Warnings[0].Type)
	}

	result := unmarshalJSON(t, analysis)
	paths, ok := result["trust_paths"].([]any)
	if !ok || len(paths) != 1 {
		t.Fatalf("expected 1 trust path in JSON, got %v", len(paths))
	}
	path := paths[0].(map[string]any)
	warnings, ok := path["warnings"].([]any)
	if !ok || len(warnings) != 1 {
		t.Fatalf("expected 1 warning in JSON, got %v", warnings)
	}

	// Warning should not have a certificate reference (nil cert -- omitted).
	w := warnings[0].(map[string]any)
	if _, hasCert := w["certificate"]; hasCert {
		t.Error("warning with nil certificate should omit certificate field")
	}
}

func TestReversed_OrderAndSimulationMetadata(t *testing.T) {
	t.Parallel()

	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("GenerateSimpleChain: %v", err)
	}
	leaf := NewCertificate(x509Certs[0], CertificateSource{Type: SourceTypeRemote})
	inter := NewCertificate(x509Certs[1], CertificateSource{Type: SourceTypeRemote})
	root := NewCertificate(x509Certs[2], CertificateSource{Type: SourceTypeFile})

	simMeta := map[string]CertSimulationState{
		root.FingerprintSHA256(): {IsExcluded: true},
	}
	analysis := NewAnalysis(
		[]*Certificate{leaf, inter, root},
		[]*TrustPath{
			{
				Certificates:       []*Certificate{leaf, inter, root},
				Status:             PathTrusted,
				SimulationMetadata: simMeta,
			},
		},
		"test",
		WithSimulated(true),
	)

	reversed := analysis.Reversed()

	// Top-level certificates should be reversed.
	if reversed.Certificates[0].FingerprintSHA256() != root.FingerprintSHA256() {
		t.Error("reversed.Certificates[0] should be root")
	}
	if reversed.Certificates[2].FingerprintSHA256() != leaf.FingerprintSHA256() {
		t.Error("reversed.Certificates[2] should be leaf")
	}

	// Trust path certificates should be reversed.
	rp := reversed.TrustPaths[0]
	if rp.Certificates[0].FingerprintSHA256() != root.FingerprintSHA256() {
		t.Error("reversed path[0] should be root")
	}

	// SimulationMetadata should be deep-copied.
	if !rp.IsExcluded(root) {
		t.Error("reversed path should preserve SimulationMetadata")
	}

	// Mutating the reversed copy's SimulationMetadata should not affect the original.
	rp.SimulationMetadata[leaf.FingerprintSHA256()] = CertSimulationState{IsGhosted: true}
	if analysis.TrustPaths[0].IsGhosted(leaf) {
		t.Error("mutating reversed SimulationMetadata should not affect original")
	}

	// Metadata should be preserved.
	if !reversed.Metadata.IsSimulated {
		t.Error("reversed analysis should preserve IsSimulated")
	}
}

func TestWithSimulated_Option(t *testing.T) {
	t.Parallel()

	a := NewAnalysis(nil, nil, "test", WithSimulated(true))
	if !a.Metadata.IsSimulated {
		t.Error("WithSimulated(true) should set IsSimulated")
	}

	b := NewAnalysis(nil, nil, "test", WithSimulated(false))
	if b.Metadata.IsSimulated {
		t.Error("WithSimulated(false) should leave IsSimulated false")
	}
}

func TestWithAnalysisSource_Option(t *testing.T) {
	t.Parallel()

	a := NewAnalysis(nil, nil, "original", WithAnalysisSource("override"))
	if a.Metadata.Source != "override" {
		t.Errorf("WithAnalysisSource should override source, got %q", a.Metadata.Source)
	}
}

func TestAnalysis_JSON_ReferenceIntegrity(t *testing.T) {
	t.Parallel()

	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("GenerateSimpleChain: %v", err)
	}
	leaf := NewCertificate(x509Certs[0], CertificateSource{Type: SourceTypeRemote, Location: "example.com:443"})
	inter := NewCertificate(x509Certs[1], CertificateSource{Type: SourceTypeRemote, Location: "example.com:443"})
	root := NewCertificate(x509Certs[2], CertificateSource{Type: SourceTypeFile, Location: "/etc/ssl/certs/root.pem"})

	analysis := NewAnalysis(
		[]*Certificate{leaf, inter, root},
		[]*TrustPath{
			{
				Certificates: []*Certificate{leaf, inter, root},
				Status:       PathTrusted,
				Errors:       []ValidationError{},
				Warnings: []ValidationWarning{
					{Certificate: leaf, Type: WarningExpiringSoon, Message: "expires soon"},
				},
			},
			{
				Certificates: []*Certificate{leaf, root},
				Status:       PathUntrusted,
				Errors: []ValidationError{
					{Certificate: root, Type: ErrorUntrustedRoot, Message: "untrusted root"},
				},
				Warnings: []ValidationWarning{},
			},
		},
		"example.com:443",
	)

	result := unmarshalJSON(t, analysis)
	certsMap := result["certificates"].(map[string]any)

	// Every fingerprint reference in trust paths must exist in the certificates map.
	paths := result["trust_paths"].([]any)
	for i, p := range paths {
		path := p.(map[string]any)
		for j, ref := range path["certificates"].([]any) {
			fp := ref.(string)
			if _, ok := certsMap[fp]; !ok {
				t.Errorf("path %d cert %d: fingerprint %q not in certificates map", i, j, fp)
			}
		}

		// Error certificate references must resolve.
		for j, e := range path["errors"].([]any) {
			errMap := e.(map[string]any)
			if fp, ok := errMap["certificate"].(string); ok {
				if _, found := certsMap[fp]; !found {
					t.Errorf("path %d error %d: fingerprint %q not in certificates map", i, j, fp)
				}
			}
		}

		// Warning certificate references must resolve.
		for j, w := range path["warnings"].([]any) {
			warnMap := w.(map[string]any)
			if fp, ok := warnMap["certificate"].(string); ok {
				if _, found := certsMap[fp]; !found {
					t.Errorf("path %d warning %d: fingerprint %q not in certificates map", i, j, fp)
				}
			}
		}
	}

	// Certificates defined once: map size equals unique cert count.
	if len(certsMap) != 3 {
		t.Errorf("expected 3 unique certificates, got %d", len(certsMap))
	}
}

func TestAnalysis_JSON_SimulationMetadataOmitempty(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "sim-test.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	wrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})
	fp := wrapped.FingerprintSHA256()

	t.Run("omitted when nil", func(t *testing.T) {
		t.Parallel()

		analysis := NewAnalysis(
			[]*Certificate{wrapped},
			[]*TrustPath{{
				Certificates: []*Certificate{wrapped},
				Status:       PathTrusted,
				Errors:       []ValidationError{},
				Warnings:     []ValidationWarning{},
			}},
			"test",
		)

		result := unmarshalJSON(t, analysis)
		path := result["trust_paths"].([]any)[0].(map[string]any)
		if _, has := path["simulation_metadata"]; has {
			t.Error("simulation_metadata should be omitted when nil")
		}
	})

	t.Run("present with values", func(t *testing.T) {
		t.Parallel()

		analysis := NewAnalysis(
			[]*Certificate{wrapped},
			[]*TrustPath{{
				Certificates: []*Certificate{wrapped},
				Status:       PathTrusted,
				Errors:       []ValidationError{},
				Warnings:     []ValidationWarning{},
				SimulationMetadata: map[string]CertSimulationState{
					fp: {IsExcluded: true},
				},
			}},
			"test",
			WithSimulated(true),
		)

		result := unmarshalJSON(t, analysis)
		path := result["trust_paths"].([]any)[0].(map[string]any)
		simMeta, ok := path["simulation_metadata"].(map[string]any)
		if !ok {
			t.Fatal("simulation_metadata should be present")
		}

		state := simMeta[ColonHex(fp)].(map[string]any)
		if state["is_excluded"] != true {
			t.Error("is_excluded should be true")
		}
		// is_ghosted and is_injected should be omitted (false + omitempty).
		if _, has := state["is_ghosted"]; has {
			t.Error("is_ghosted=false should be omitted with omitempty")
		}
		if _, has := state["is_injected"]; has {
			t.Error("is_injected=false should be omitted with omitempty")
		}
	})
}

func TestNewTrustPath_InitializesSlices(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "init-test.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	wrapped := NewCertificate(cert, CertificateSource{Type: SourceTypeFile})

	path := NewTrustPath([]*Certificate{wrapped}, PathTrusted)

	if len(path.Errors) != 0 {
		t.Errorf("NewTrustPath Errors has %d elements, expected 0", len(path.Errors))
	}
	if len(path.Warnings) != 0 {
		t.Errorf("NewTrustPath Warnings has %d elements, expected 0", len(path.Warnings))
	}
}

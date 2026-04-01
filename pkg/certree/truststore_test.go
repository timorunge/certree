package certree

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// setupTrustStoreTest creates a cert with the given CN and adds it to the specified trust store locations.
func setupTrustStoreTest(t *testing.T, commonName string, addToSystem, addToCustom bool) (*Certificate, TrustStore) {
	t.Helper()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		IsCA: true,
	}
	rootCert, _, err := testutil.GenerateSelfSignedCert(template)
	if err != nil {
		t.Fatalf("Failed to generate root certificate: %v", err)
		return nil, nil
	}

	cert := NewCertificate(rootCert, CertificateSource{Type: SourceTypeFile})

	ts := NewTrustStore()

	defaultTS := ts.(*defaultTrustStore)
	defaultTS.mu.Lock()
	if addToSystem {
		defaultTS.systemRoots[cert.FingerprintSHA256()] = cert
	}
	if addToCustom {
		defaultTS.customCerts[cert.FingerprintSHA256()] = cert
		defaultTS.customPaths[cert.FingerprintSHA256()] = []string{"/test/custom-bundle.pem"}
	}
	defaultTS.mu.Unlock()

	return cert, ts
}

func TestTrustStoreIndication_TrustedRootDisplay(t *testing.T) {
	t.Parallel()

	cert, ts := setupTrustStoreTest(t, "Test Root CA", true, false)

	if !ts.IsTrusted(cert) {
		t.Error("Expected certificate to be trusted")
	}

	locations := ts.TrustedLocations(cert)
	if len(locations) != 1 {
		t.Errorf("Expected 1 trust store location, got %d: %v", len(locations), locations)
	}

	if locations[0] != "system" {
		t.Errorf("Expected trust store location 'system', got '%s'", locations[0])
	}
}

func TestTrustStoreIndication_MultipleTrustStores(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		preferCustom bool
		wantOrder    []string
	}{
		{
			name:         "system preferred",
			preferCustom: false,
			wantOrder:    []string{"system", "/test/custom-bundle.pem"},
		},
		{
			name:         "custom preferred",
			preferCustom: true,
			wantOrder:    []string{"/test/custom-bundle.pem", "system"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			template := testutil.CertificateTemplate{
				Subject: pkix.Name{CommonName: "Multi-Store Root CA"},
				IsCA:    true,
			}
			rootCert, _, err := testutil.GenerateSelfSignedCert(template)
			if err != nil {
				t.Fatalf("Failed to generate root certificate: %v", err)
			}

			cert := NewCertificate(rootCert, CertificateSource{Type: SourceTypeFile})

			ts := NewTrustStore(WithCustomRootsPrecedence(tt.preferCustom))

			defaultTS := ts.(*defaultTrustStore)
			defaultTS.mu.Lock()
			defaultTS.systemRoots[cert.FingerprintSHA256()] = cert
			defaultTS.customCerts[cert.FingerprintSHA256()] = cert
			defaultTS.customPaths[cert.FingerprintSHA256()] = []string{"/test/custom-bundle.pem"}
			defaultTS.mu.Unlock()

			if !ts.IsTrusted(cert) {
				t.Error("Expected certificate to be trusted")
			}

			locations := ts.TrustedLocations(cert)
			if len(locations) != 2 {
				t.Errorf("Expected 2 trust store locations, got %d: %v", len(locations), locations)
			}

			if len(locations) == 2 {
				if locations[0] != tt.wantOrder[0] || locations[1] != tt.wantOrder[1] {
					t.Errorf("Expected order %v, got %v", tt.wantOrder, locations)
				}
			}
		})
	}
}

func TestTrustStoreIndication_CustomOnly(t *testing.T) {
	t.Parallel()

	cert, ts := setupTrustStoreTest(t, "Custom Only Root CA", false, true)

	if !ts.IsTrusted(cert) {
		t.Error("Expected certificate to be trusted")
	}

	locations := ts.TrustedLocations(cert)
	if len(locations) != 1 {
		t.Errorf("Expected 1 trust store location, got %d: %v", len(locations), locations)
	}

	if locations[0] != "/test/custom-bundle.pem" {
		t.Errorf("Expected trust store location '/test/custom-bundle.pem', got '%s'", locations[0])
	}
}

func TestLoadCustomRoots_RecordsFilePaths(t *testing.T) {
	t.Parallel()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Path Tracking Root CA"},
		IsCA:    true,
	}
	rootCert, _, err := testutil.GenerateSelfSignedCert(template)
	if err != nil {
		t.Fatalf("Failed to generate root certificate: %v", err)
	}

	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "custom-ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	if err := os.WriteFile(bundlePath, pemData, 0600); err != nil {
		t.Fatalf("Failed to write PEM file: %v", err)
	}

	ts := NewTrustStore()
	if err := ts.LoadCustomRoots(bundlePath); err != nil {
		t.Fatalf("LoadCustomRoots() error = %v", err)
	}

	cert := NewCertificate(rootCert, CertificateSource{Type: SourceTypeFile, Location: bundlePath})

	if !ts.IsTrusted(cert) {
		t.Fatal("Expected certificate to be trusted after LoadCustomRoots")
	}

	locations := ts.TrustedLocations(cert)
	if len(locations) != 1 {
		t.Fatalf("Expected 1 location, got %d: %v", len(locations), locations)
	}
	if locations[0] != bundlePath {
		t.Errorf("Expected location %q, got %q", bundlePath, locations[0])
	}
}

func TestLoadCustomRoots_MultipleBundlesTrackAllPaths(t *testing.T) {
	t.Parallel()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Multi-Bundle Root CA"},
		IsCA:    true,
	}
	rootCert, _, err := testutil.GenerateSelfSignedCert(template)
	if err != nil {
		t.Fatalf("Failed to generate root certificate: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})

	tmpDir := t.TempDir()
	bundle1 := filepath.Join(tmpDir, "bundle-a.pem")
	bundle2 := filepath.Join(tmpDir, "bundle-b.pem")
	for _, p := range []string{bundle1, bundle2} {
		if err := os.WriteFile(p, pemData, 0600); err != nil {
			t.Fatalf("Failed to write PEM file %s: %v", p, err)
		}
	}

	ts := NewTrustStore()
	if err := ts.LoadCustomRoots(bundle1); err != nil {
		t.Fatalf("LoadCustomRoots(%s) error = %v", bundle1, err)
	}
	if err := ts.LoadCustomRoots(bundle2); err != nil {
		t.Fatalf("LoadCustomRoots(%s) error = %v", bundle2, err)
	}

	cert := NewCertificate(rootCert, CertificateSource{Type: SourceTypeFile})

	locations := ts.TrustedLocations(cert)
	if len(locations) != 2 {
		t.Fatalf("Expected 2 locations, got %d: %v", len(locations), locations)
	}
	if locations[0] != bundle1 || locations[1] != bundle2 {
		t.Errorf("Expected locations [%s, %s], got %v", bundle1, bundle2, locations)
	}
}

func TestTrustedLocations_ReturnedSliceIsIndependent(t *testing.T) {
	t.Parallel()

	cert, ts := setupTrustStoreTest(t, "Slice Safety Root CA", true, false)

	// Get locations and mutate the returned slice.
	locations1 := ts.TrustedLocations(cert)
	if len(locations1) != 1 || locations1[0] != "system" {
		t.Fatalf("Expected [system], got %v", locations1)
	}
	locations1[0] = "corrupted"

	// Get locations again -- must not be affected by the mutation above.
	locations2 := ts.TrustedLocations(cert)
	if len(locations2) != 1 || locations2[0] != "system" {
		t.Errorf("TrustedLocations corrupted by caller mutation: got %v, want [system]", locations2)
	}
}

func TestTrustedLocations_EmptySliceIsIndependent(t *testing.T) {
	t.Parallel()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Untrusted Slice Safety"},
		IsCA:    true,
	}
	rootCert, _, err := testutil.GenerateSelfSignedCert(template)
	if err != nil {
		t.Fatalf("Failed to generate root certificate: %v", err)
	}
	cert := NewCertificate(rootCert, CertificateSource{Type: SourceTypeFile})
	ts := NewTrustStore()

	// Get empty locations and append to them.
	locations1 := ts.TrustedLocations(cert)
	if len(locations1) != 0 {
		t.Fatalf("Expected empty slice, got %v", locations1)
	}
	_ = append(locations1, "injected") //nolint:gocritic // intentional append for corruption test

	// Get again -- must still be empty.
	locations2 := ts.TrustedLocations(cert)
	if len(locations2) != 0 {
		t.Errorf("TrustedLocations empty slice corrupted by append: got %v, want []", locations2)
	}
}

func TestFindIssuers_StoreTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(dts *defaultTrustStore, root *Certificate)
	}{
		{
			name: "system root",
			setup: func(dts *defaultTrustStore, root *Certificate) {
				dts.systemRoots[root.FingerprintSHA256()] = root
				subject := string(root.Raw().RawSubject)
				dts.systemBySubject[subject] = append(dts.systemBySubject[subject], root)
				if len(root.Raw().SubjectKeyId) > 0 {
					ski := HexEncodeUpper(root.Raw().SubjectKeyId)
					dts.systemBySKI[ski] = append(dts.systemBySKI[ski], root)
				}
			},
		},
		{
			name: "custom root",
			setup: func(dts *defaultTrustStore, root *Certificate) {
				dts.customCerts[root.FingerprintSHA256()] = root
				subject := string(root.Raw().RawSubject)
				dts.customBySubject[subject] = append(dts.customBySubject[subject], root)
				if len(root.Raw().SubjectKeyId) > 0 {
					ski := HexEncodeUpper(root.Raw().SubjectKeyId)
					dts.customBySKI[ski] = append(dts.customBySKI[ski], root)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			x509Certs, _, err := testutil.GenerateSimpleChain()
			if err != nil {
				t.Fatalf("Failed to generate chain: %v", err)
			}

			src := CertificateSource{Type: SourceTypeFile, Location: "test"}
			intermediate := NewCertificate(x509Certs[1], src)
			root := NewCertificate(x509Certs[2], src)

			ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
			dts := ts.(*defaultTrustStore)
			tt.setup(dts, root)

			issuers := ts.FindIssuers(intermediate)
			if len(issuers) == 0 {
				t.Fatal("FindIssuers returned no issuers; expected root")
			}
			if issuers[0].FingerprintSHA256() != root.FingerprintSHA256() {
				t.Errorf("FindIssuers returned wrong cert: got %s, want %s",
					issuers[0].FingerprintSHA256(), root.FingerprintSHA256())
			}
		})
	}
}

func TestFindIssuers_NoMatch(t *testing.T) {
	t.Parallel()

	x509Certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("Failed to generate chain: %v", err)
	}

	src := CertificateSource{Type: SourceTypeFile, Location: "test"}
	endEntity := NewCertificate(x509Certs[0], src)

	// Create an empty trust store.
	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))

	issuers := ts.FindIssuers(endEntity)
	if len(issuers) != 0 {
		t.Errorf("FindIssuers returned %d issuers; expected 0", len(issuers))
	}
}

func TestFindIssuers_NilCert(t *testing.T) {
	t.Parallel()

	ts := NewTrustStore()
	issuers := ts.FindIssuers(nil)
	if issuers != nil {
		t.Errorf("FindIssuers(nil) returned %v; expected nil", issuers)
	}
}

func TestLoadSystemRoots(t *testing.T) {
	t.Parallel()

	certs, err := loadSystemRoots("", slog.Default())
	if errors.Is(err, ErrPlatformNotSupported) {
		t.Skip("platform not supported")
	}
	if err != nil {
		t.Fatalf("loadSystemRoots(\"\") unexpected error: %v", err)
	}

	t.Run("non-empty", func(t *testing.T) {
		if len(certs) == 0 {
			t.Error("loadSystemRoots(\"\") returned no certificates")
		}
	})

	t.Run("valid fingerprints and source", func(t *testing.T) {
		for i, cert := range certs {
			if cert == nil {
				t.Errorf("certs[%d] is nil", i)
				continue
			}
			if cert.FingerprintSHA256() == "" {
				t.Errorf("certs[%d] has empty fingerprint", i)
			}
			if cert.Source().Type != SourceTypeFile {
				t.Errorf("certs[%d].Source().Type = %v, want SourceTypeFile", i, cert.Source().Type)
			}
		}
	})

	t.Run("no duplicates", func(t *testing.T) {
		seen := make(map[string]bool, len(certs))
		for _, cert := range certs {
			fp := cert.FingerprintSHA256()
			if seen[fp] {
				t.Errorf("duplicate fingerprint %s in loadSystemRoots result", fp)
			}
			seen[fp] = true
		}
	})
}

func TestWithSystemRootsPath(t *testing.T) {
	t.Parallel()

	ts := NewTrustStore(WithSystemRootsPath("/custom/certs")).(*defaultTrustStore)
	if ts.opts.systemRootsPath != "/custom/certs" {
		t.Errorf("systemRootsPath = %q, want %q", ts.opts.systemRootsPath, "/custom/certs")
	}
}

func TestWithTrustStoreLogger_NilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil logger, got none")
		}
	}()
	WithTrustStoreLogger(nil)(&defaultTrustStore{})
}

func TestSecurityLoadCustomRootsRelativePath(t *testing.T) {
	t.Parallel()

	ts := NewTrustStore()
	err := ts.LoadCustomRoots("relative/path/ca.pem")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput,
		"relative paths must be rejected with ErrInvalidInput")
}

func TestSecurityLoadCustomRootsEmptyPath(t *testing.T) {
	t.Parallel()

	ts := NewTrustStore()
	err := ts.LoadCustomRoots("")
	require.Error(t, err)
	// filepath.Clean("") == "." which is relative, so ErrInvalidInput is expected.
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestSecurityLoadCustomRootsNonexistentFile(t *testing.T) {
	t.Parallel()

	// Use a path rooted in t.TempDir() so it is absolute on all platforms
	// (including Windows, where "/nonexistent/..." is not a valid absolute path).
	nonexistent := filepath.Join(t.TempDir(), "nonexistent-ca-bundle.pem")
	ts := NewTrustStore()
	err := ts.LoadCustomRoots(nonexistent)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

func TestSecurityLoadCustomRootsNonPEMFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	txtPath := filepath.Join(dir, "not-a-cert.pem")
	require.NoError(t, os.WriteFile(txtPath, []byte("this is not a PEM certificate file\n"), 0o600))

	ts := NewTrustStore()
	err := ts.LoadCustomRoots(txtPath)
	require.Error(t, err,
		"file with no certificate PEM blocks must be rejected")
}

// TestSecurityLoadCustomRootsPrivateKeyOnly verifies that a file containing only
// a private key PEM block produces an error, not silent success.
func TestSecurityLoadCustomRootsPrivateKeyOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key-only.pem")

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not a real key"),
	})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	ts := NewTrustStore()
	err := ts.LoadCustomRoots(keyPath)
	require.Error(t, err,
		"PEM file containing only private keys must produce an error (no certs found)")
}

func TestSecurityLoadCustomRootsOversizedFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bigPath := filepath.Join(dir, "big-bundle.pem")
	data := make([]byte, 10<<20+1)
	copy(data, []byte("-----BEGIN CERTIFICATE-----\n"))
	require.NoError(t, os.WriteFile(bigPath, data, 0o600))

	ts := NewTrustStore()
	err := ts.LoadCustomRoots(bigPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFileTooLarge)
}

func TestSecurityLoadCustomRootsDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ts := NewTrustStore()
	err := ts.LoadCustomRoots(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestSecurityTrustStore_ConcurrentLoadSystemRoots(t *testing.T) {
	t.Parallel()

	const goroutines = 16

	ts := NewTrustStore()
	var wg sync.WaitGroup

	for range goroutines {
		wg.Go(func() {
			// LoadSystemRoots may fail in CI environments without a system trust
			// store (e.g., minimal containers). Ignore errors; race is what matters.
			_ = ts.LoadSystemRoots()
		})
	}

	wg.Wait()
}

func TestSecurityTrustStore_ConcurrentReadsDuringWrite(t *testing.T) {
	t.Parallel()

	rawCerts, rawKeys, err := testutil.GenerateSimpleChain()
	require.NoError(t, err)
	require.Len(t, rawCerts, 3)

	bundlePath := filepath.Join(t.TempDir(), "roots.pem")
	require.NoError(t, os.WriteFile(bundlePath, testutil.EncodePEM(rawCerts[2]), 0600))
	_ = rawKeys

	source := CertificateSource{Type: SourceTypeBytes}
	leaf := NewCertificate(rawCerts[0], source)
	root := NewCertificate(rawCerts[2], source)

	ts := NewTrustStore()

	// Without the RW-mutex, this would trigger concurrent map read/write.
	const readers = 8
	const writers = 4

	var wg sync.WaitGroup

	for range readers {
		wg.Go(func() {
			for range 20 {
				_ = ts.IsTrusted(leaf)
				_ = ts.IsTrusted(root)
				_ = ts.FindIssuers(leaf)
				_ = ts.TrustedLocations(root)
			}
		})
	}

	for range writers {
		wg.Go(func() {
			// Errors are tolerable (idempotent loads); races are not.
			_ = ts.LoadCustomRoots(bundlePath)
		})
	}

	wg.Wait()
}

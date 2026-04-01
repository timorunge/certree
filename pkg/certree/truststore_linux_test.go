//go:build linux

package certree

import (
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// pemCertFile writes a single self-signed PEM certificate to dir/<filename>
// and returns its absolute path.
func pemCertFile(t *testing.T, dir, filename string) string {
	t.Helper()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: filename},
		IsCA:    true,
	}
	cert, _, err := testutil.GenerateSelfSignedCert(template)
	if err != nil {
		t.Fatalf("generating cert for %s: %v", filename, err)
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, testutil.EncodePEM(cert), 0o644); err != nil {
		t.Fatalf("writing cert to %s: %v", path, err)
	}
	return path
}

func TestLinuxCertDirs_DefaultList(t *testing.T) {
	t.Parallel()

	if len(linuxCertDirs) == 0 {
		t.Fatal("linuxCertDirs must not be empty")
	}

	wantDirs := map[string]bool{
		"/etc/ssl/certs":     false,
		"/etc/pki/tls/certs": false,
	}
	for _, d := range linuxCertDirs {
		wantDirs[d] = true
	}
	for name, found := range wantDirs {
		if !found {
			t.Errorf("linuxCertDirs missing expected directory %q", name)
		}
	}
}

func TestLoadCertsFromDir_ValidPEMFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemCertFile(t, dir, "root.pem")

	seen := make(map[string]struct{})
	certs, err := loadCertsFromDir(dir, seen, false, slog.Default())
	if err != nil {
		t.Fatalf("loadCertsFromDir unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certs))
	}
}

func TestLoadCertsFromDir_MultipleExtensions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemCertFile(t, dir, "a.pem")
	pemCertFile(t, dir, "b.crt")
	pemCertFile(t, dir, "c.cer")

	seen := make(map[string]struct{})
	certs, err := loadCertsFromDir(dir, seen, false, slog.Default())
	if err != nil {
		t.Fatalf("loadCertsFromDir unexpected error: %v", err)
	}
	if len(certs) != 3 {
		t.Errorf("expected 3 certs, got %d", len(certs))
	}
}

func TestLoadCertsFromDir_IgnoresUnknownExtensions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemCertFile(t, dir, "valid.pem")
	// Write a plain text file with a non-cert extension.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("writing readme.txt: %v", err)
	}

	seen := make(map[string]struct{})
	certs, err := loadCertsFromDir(dir, seen, false, slog.Default())
	if err != nil {
		t.Fatalf("loadCertsFromDir unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert (non-.pem file ignored), got %d", len(certs))
	}
}

func TestLoadCertsFromDir_EmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	seen := make(map[string]struct{})
	certs, err := loadCertsFromDir(dir, seen, false, slog.Default())
	if err != nil {
		t.Fatalf("loadCertsFromDir unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from empty dir, got %d", len(certs))
	}
}

func TestLoadCertsFromDir_NonExistentDir(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{})
	_, err := loadCertsFromDir("/nonexistent/certree/dir", seen, false, slog.Default())
	if err == nil {
		t.Fatal("expected error for non-existent dir, got nil")
	}
}

func TestLoadCertsFromDir_DeduplicationViaSeen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemCertFile(t, dir, "root.pem")

	// First load: populate seen.
	seen := make(map[string]struct{})
	certs, err := loadCertsFromDir(dir, seen, false, slog.Default())
	if err != nil {
		t.Fatalf("first loadCertsFromDir unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("first pass: expected 1 cert, got %d", len(certs))
	}

	// Second load with the same seen map: should return nothing.
	certs2, err := loadCertsFromDir(dir, seen, false, slog.Default())
	if err != nil {
		t.Fatalf("second loadCertsFromDir unexpected error: %v", err)
	}
	if len(certs2) != 0 {
		t.Errorf("second pass: expected 0 certs (dedup), got %d", len(certs2))
	}
}

func TestLoadCertsFromDir_SourceLocation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := pemCertFile(t, dir, "root.pem")

	seen := make(map[string]struct{})
	certs, err := loadCertsFromDir(dir, seen, false, slog.Default())
	if err != nil {
		t.Fatalf("loadCertsFromDir unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Source().Location != path {
		t.Errorf("Source().Location = %q, want %q", certs[0].Source().Location, path)
	}
}

func TestLoadSystemRoots_Linux_CustomPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemCertFile(t, dir, "ca.pem")

	certs, err := loadSystemRoots(dir, slog.Default())
	if err != nil {
		t.Fatalf("loadSystemRoots(%q) unexpected error: %v", dir, err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certs))
	}
}

func TestLoadSystemRoots_Linux_CustomPath_NonExistentDir(t *testing.T) {
	t.Parallel()

	_, err := loadSystemRoots("/nonexistent/certree/certs", slog.Default())
	if err == nil {
		t.Fatal("expected error for non-existent custom path, got nil")
	}
}

func TestLoadSystemRoots_Linux_CustomPath_FileInsteadOfDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := pemCertFile(t, dir, "ca.pem")

	_, err := loadSystemRoots(filePath, slog.Default())
	if err == nil {
		t.Fatal("expected error for file path as customPath, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

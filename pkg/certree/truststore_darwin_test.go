//go:build darwin

package certree

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinKeychains_DefaultList(t *testing.T) {
	t.Parallel()

	if len(darwinKeychains) == 0 {
		t.Fatal("darwinKeychains must not be empty")
	}

	wantKeychains := map[string]bool{
		"/System/Library/Keychains/SystemRootCertificates.keychain": false,
		"/Library/Keychains/System.keychain":                        false,
	}
	for _, k := range darwinKeychains {
		wantKeychains[k] = true
	}
	for name, found := range wantKeychains {
		if !found {
			t.Errorf("darwinKeychains missing expected entry %q", name)
		}
	}
}

func TestValidateKeychainPath_RelativePath(t *testing.T) {
	t.Parallel()

	err := validateKeychainPath("relative/path/store.keychain")
	if err == nil {
		t.Fatal("expected error for relative path, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

func TestValidateKeychainPath_NonExistentPath(t *testing.T) {
	t.Parallel()

	err := validateKeychainPath("/nonexistent/path/store.keychain")
	if err == nil {
		t.Fatal("expected error for non-existent path, got nil")
	}
}

func TestValidateKeychainPath_Directory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	err := validateKeychainPath(dir)
	if err == nil {
		t.Fatalf("expected error for directory path %q, got nil", dir)
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

func TestValidateKeychainPath_WrongExtension(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "store-*.pem")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	_ = f.Close()

	if err := validateKeychainPath(f.Name()); err == nil {
		t.Fatalf("expected error for .pem extension, got nil")
	} else if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got: %v", err)
	}
}

func TestValidateKeychainPath_ValidKeychainExtension(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.keychain")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("creating temp file: %v", err)
	}

	if err := validateKeychainPath(path); err != nil {
		t.Errorf("validateKeychainPath(%q) unexpected error: %v", path, err)
	}
}

func TestLoadSystemRoots_Darwin_InvalidCustomPath(t *testing.T) {
	t.Parallel()

	_, err := loadSystemRoots("/nonexistent/custom.keychain", slog.Default())
	if err == nil {
		t.Fatal("expected error for non-existent keychain path, got nil")
	}
}

func TestLoadSystemRoots_Darwin_InvalidExtension(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "certs.pem")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("creating temp file: %v", err)
	}

	_, err := loadSystemRoots(path, slog.Default())
	if err == nil {
		t.Fatal("expected error for .pem custom path, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected error wrapping ErrInvalidInput, got: %v", err)
	}
}

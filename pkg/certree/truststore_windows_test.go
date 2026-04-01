//go:build windows

package certree

import (
	"errors"
	"log/slog"
	"testing"
)

func TestWindowsCertStores_DefaultList(t *testing.T) {
	t.Parallel()

	if len(windowsCertStores) == 0 {
		t.Fatal("windowsCertStores must not be empty")
	}

	wantStores := map[string]bool{"ROOT": false, "AuthRoot": false}
	for _, s := range windowsCertStores {
		wantStores[s] = true
	}
	for name, found := range wantStores {
		if !found {
			t.Errorf("windowsCertStores missing expected store %q", name)
		}
	}
}

func TestLoadSystemRoots_Windows_CustomStore(t *testing.T) {
	t.Parallel()

	certs, err := loadSystemRoots("ROOT", slog.Default())
	if err != nil {
		t.Fatalf("loadSystemRoots(\"ROOT\") unexpected error: %v", err)
	}
	if len(certs) == 0 {
		t.Error("loadSystemRoots(\"ROOT\") returned no certificates")
	}
}

func TestLoadSystemRoots_Windows_InvalidStore(t *testing.T) {
	t.Parallel()

	_, err := loadSystemRoots("CERTREE_NONEXISTENT_STORE_XYZ", slog.Default())
	if err == nil {
		t.Fatal("loadSystemRoots with invalid store name: expected error, got nil")
	}
	if !errors.Is(err, ErrNoCertificatesFound) {
		t.Errorf("expected ErrNoCertificatesFound, got: %v", err)
	}
}

func TestLoadCertsFromWindowsStore_ROOT(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{})
	certs, err := loadCertsFromWindowsStore("ROOT", seen, slog.Default())
	if err != nil {
		t.Fatalf("loadCertsFromWindowsStore(\"ROOT\") unexpected error: %v", err)
	}
	if len(certs) == 0 {
		t.Error("loadCertsFromWindowsStore(\"ROOT\") returned no certificates")
	}
}

func TestLoadCertsFromWindowsStore_DeduplicationViaSeen(t *testing.T) {
	t.Parallel()

	// First pass: collect all fingerprints.
	seen := make(map[string]struct{})
	certs, err := loadCertsFromWindowsStore("ROOT", seen, slog.Default())
	if err != nil {
		t.Fatalf("first loadCertsFromWindowsStore(\"ROOT\") unexpected error: %v", err)
	}
	firstCount := len(certs)

	// Second pass: re-use the same seen map -- should return nothing new.
	certs2, err := loadCertsFromWindowsStore("ROOT", seen, slog.Default())
	if err != nil {
		t.Fatalf("second loadCertsFromWindowsStore(\"ROOT\") unexpected error: %v", err)
	}
	if len(certs2) != 0 {
		t.Errorf("expected 0 new certs on second load with same seen map, got %d (first pass loaded %d)", len(certs2), firstCount)
	}
}

func TestLoadCertsFromWindowsStore_SourceLocation(t *testing.T) {
	t.Parallel()

	const storeName = "ROOT"
	seen := make(map[string]struct{})
	certs, err := loadCertsFromWindowsStore(storeName, seen, slog.Default())
	if err != nil {
		t.Fatalf("loadCertsFromWindowsStore(%q) unexpected error: %v", storeName, err)
	}
	for i, cert := range certs {
		if cert.Source().Location != storeName {
			t.Errorf("certs[%d].Source().Location = %q, want %q", i, cert.Source().Location, storeName)
		}
	}
}

func TestLoadCertsFromWindowsStore_InvalidStore(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{})
	_, err := loadCertsFromWindowsStore("CERTREE_NONEXISTENT_STORE_XYZ", seen, slog.Default())
	if err == nil {
		t.Fatal("expected error for invalid store name, got nil")
	}
}

//go:build darwin

// macOS trust store: loads system root certificates from Keychains.

package certree

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// keychainCommandTimeout is the maximum time to wait for the macOS
// security command to export certificates from a keychain.
const keychainCommandTimeout = 30 * time.Second

// macOS keychains searched for trusted root certificates (in order):
//   - SystemRootCertificates.keychain: Apple-shipped root CAs
//   - System.keychain: Admin/MDM-deployed enterprise CAs
//
// When a custom path is provided via trustStoreOptions.SystemRootsPath, only
// that single keychain is loaded (useful for testing or non-standard setups).
var darwinKeychains = []string{
	"/System/Library/Keychains/SystemRootCertificates.keychain",
	"/Library/Keychains/System.keychain",
}

// loadSystemRoots loads trusted root certificates from macOS Keychains.
func loadSystemRoots(customPath string, logger *slog.Logger) ([]*Certificate, error) {
	if customPath != "" {
		if err := validateKeychainPath(customPath); err != nil {
			return nil, fmt.Errorf("invalid keychain path: %w", err)
		}
		return loadCertsFromKeychain(filepath.Clean(customPath))
	}

	// Load from all default keychains, deduplicating by fingerprint.
	var allCerts []*Certificate
	seen := make(map[string]struct{})

	for _, keychainPath := range darwinKeychains {
		certs, err := loadCertsFromKeychain(keychainPath)
		if err != nil {
			// Non-fatal: System.keychain may not exist on all macOS versions.
			logger.Warn("skipping keychain", "path", keychainPath, "error", err)
			continue
		}
		for _, cert := range certs {
			fp := cert.FingerprintSHA256()
			if _, ok := seen[fp]; ok {
				continue
			}
			seen[fp] = struct{}{}
			allCerts = append(allCerts, cert)
		}
	}

	if len(allCerts) == 0 {
		return nil, fmt.Errorf("no certificates found in keychains %v: %w", darwinKeychains, ErrNoCertificatesFound)
	}

	return allCerts, nil
}

// loadCertsFromKeychain exports and parses all certificates from a single macOS keychain.
func loadCertsFromKeychain(keychainPath string) ([]*Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keychainCommandTimeout)
	defer cancel()

	// #nosec G204 -- keychainPath is validated (filepath.Clean, os.Stat, extension check) by caller; otherwise hardcoded from darwinKeychains.
	cmd := exec.CommandContext(ctx, "security", "find-certificate", "-a", "-p", keychainPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("executing security command for %s: %w", keychainPath, err)
	}

	certs, err := ParsePEMCertificates(output, CertificateSource{
		Type:     SourceTypeFile,
		Location: keychainPath,
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing certificates from keychain %s: %w", keychainPath, err)
	}

	return certs, nil
}

// validateKeychainPath validates that a user-provided keychain path is safe to
// use as an argument to the security command. It cleans the path, verifies it
// exists on disk, and checks for a .keychain or .keychain-db extension.
func validateKeychainPath(path string) error {
	cleaned := filepath.Clean(path)

	// Reject relative paths -- they resolve unpredictably in library usage.
	if !filepath.IsAbs(cleaned) {
		return fmt.Errorf("path %q must be absolute: %w", cleaned, ErrInvalidInput)
	}

	info, err := os.Stat(cleaned)
	if err != nil {
		return fmt.Errorf("path %q does not exist: %w", cleaned, err)
	}
	if info.IsDir() {
		return fmt.Errorf("path %q is a directory, expected a keychain file: %w", cleaned, ErrInvalidInput)
	}

	ext := strings.ToLower(filepath.Ext(cleaned))
	if ext != ".keychain" && ext != ".keychain-db" {
		return fmt.Errorf("path %q has unexpected extension %q (expected .keychain or .keychain-db): %w", cleaned, ext, ErrInvalidInput)
	}

	return nil
}

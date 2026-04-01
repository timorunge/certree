//go:build linux

// Linux trust store: loads system root certificates from standard directories.

package certree

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

// Common Linux certificate directories searched for trusted root certificates.
// These directories follow standard Linux filesystem hierarchy conventions:
//   - /etc/ssl/certs: Debian/Ubuntu standard location
//   - /etc/pki/tls/certs: Red Hat/CentOS/Fedora standard location
//   - /etc/pki/ca-trust/extracted/pem: Red Hat/CentOS/Fedora CA trust bundle
//   - /usr/share/ca-certificates: Debian/Ubuntu CA certificates
//
// The loadSystemRoots function searches these directories in order and loads
// all valid certificates found, automatically deduplicating by fingerprint.
var linuxCertDirs = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
	"/etc/pki/ca-trust/extracted/pem",
	"/usr/share/ca-certificates",
}

// loadSystemRoots loads trusted root certificates from Linux certificate directories.
func loadSystemRoots(customPath string, logger *slog.Logger) ([]*Certificate, error) {
	var certs []*Certificate
	seen := make(map[string]struct{})

	searchDirs := linuxCertDirs
	if customPath != "" {
		cleaned := filepath.Clean(customPath)
		if !filepath.IsAbs(cleaned) {
			return nil, fmt.Errorf("custom certificate path %q must be absolute: %w", cleaned, ErrInvalidInput)
		}
		info, err := os.Stat(cleaned)
		if err != nil {
			return nil, fmt.Errorf("accessing custom certificate directory %q: %w", cleaned, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("custom certificate path %q is not a directory: %w", cleaned, ErrInvalidInput)
		}
		searchDirs = []string{cleaned}
	}

	isCustom := customPath != ""

	for _, dir := range searchDirs {
		dirCerts, err := loadCertsFromDir(dir, seen, isCustom, logger)
		if err != nil {
			continue
		}
		certs = append(certs, dirCerts...)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in system directories %v: %w", searchDirs, ErrNoCertificatesFound)
	}

	return certs, nil
}

// loadCertsFromDir loads all PEM certificates from a directory tree, deduplicating by fingerprint.
func loadCertsFromDir(dir string, seen map[string]struct{}, followSymlinks bool, logger *slog.Logger) ([]*Certificate, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("accessing directory %s: %w", dir, err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory: %w", dir, ErrInvalidInput)
	}

	var certs []*Certificate
	skippedSymlinks := 0

	// WalkDir is more efficient than Walk: it does not call os.Lstat on every
	// entry, and the DirEntry.Type() method lets us skip symlinks cheaply.
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Warn("skipping inaccessible path during trust store walk", "path", path, "error", err)
			return nil
		}

		if d.IsDir() {
			return nil
		}

		// Skip symlinks in system directories to avoid double-loading on
		// Debian-style systems where /etc/ssl/certs contains hash symlinks.
		// Follow symlinks in custom paths since the user may intentionally
		// symlink certificates from a central store.
		if d.Type()&fs.ModeSymlink != 0 && !followSymlinks {
			skippedSymlinks++
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".pem" && ext != ".crt" && ext != ".cer" {
			return nil
		}

		// #nosec G304,G122 -- Path constructed by filepath.WalkDir from a validated base directory.
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			logger.Debug("skipping unreadable file", "path", path, "error", readErr)
			return nil
		}

		source := CertificateSource{
			Type:     SourceTypeFile,
			Location: path,
		}

		parsedCerts, parseErr := ParsePEMCertificates(data, source, 0)
		if parseErr != nil {
			logger.Debug("skipping file with no valid certificates", "path", path, "error", parseErr)
			return nil
		}

		for _, certWrapper := range parsedCerts {
			fingerprint := certWrapper.FingerprintSHA256()
			if _, ok := seen[fingerprint]; ok {
				continue
			}
			seen[fingerprint] = struct{}{}
			certs = append(certs, certWrapper)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking directory %s: %w", dir, err)
	}

	if len(certs) == 0 && skippedSymlinks > 0 {
		logger.Warn("directory contains only symlinks, no certificates loaded",
			"directory", dir,
			"skipped_symlinks", skippedSymlinks,
		)
	}

	return certs, nil
}

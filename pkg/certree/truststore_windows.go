//go:build windows

// Windows trust store: loads system root certificates from the Windows Certificate Store.

package certree

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"syscall"
	"unsafe"
)

// windowsCertStores lists the Windows certificate stores searched for trusted root
// certificates (in order):
//   - ROOT: Trusted Root Certification Authorities (built-in + enterprise)
//   - AuthRoot: Third-Party Root Certification Authorities
//
// When a custom store name is provided via trustStoreOptions.SystemRootsPath, only
// that single named store is loaded.
var windowsCertStores = []string{"ROOT", "AuthRoot"}

// loadSystemRoots loads trusted root certificates from the Windows Certificate Store.
func loadSystemRoots(customPath string, logger *slog.Logger) ([]*Certificate, error) {
	stores := windowsCertStores
	if customPath != "" {
		stores = []string{customPath}
	}

	var allCerts []*Certificate
	seen := make(map[string]struct{})

	for _, storeName := range stores {
		storeCerts, err := loadCertsFromWindowsStore(storeName, seen, logger)
		if err != nil {
			// Non-fatal: a store may not exist on all Windows configurations.
			logger.Warn("skipping Windows certificate store", "store", storeName, "error", err)
			continue
		}
		allCerts = append(allCerts, storeCerts...)
	}

	if len(allCerts) == 0 {
		return nil, fmt.Errorf("no certificates found in Windows system stores %v: %w", stores, ErrNoCertificatesFound)
	}

	return allCerts, nil
}

// loadCertsFromWindowsStore enumerates and parses all certificates from a single named Windows certificate store.
func loadCertsFromWindowsStore(storeName string, seen map[string]struct{}, logger *slog.Logger) ([]*Certificate, error) {
	namePtr, err := syscall.UTF16PtrFromString(storeName)
	if err != nil {
		return nil, fmt.Errorf("encoding store name %q: %w", storeName, err)
	}

	store, err := syscall.CertOpenSystemStore(0, namePtr)
	if err != nil {
		return nil, fmt.Errorf("opening Windows certificate store %q: %w", storeName, err)
	}
	defer func() {
		if closeErr := syscall.CertCloseStore(store, 0); closeErr != nil {
			logger.Warn("error closing Windows certificate store", "store", storeName, "error", closeErr)
		}
	}()

	var certs []*Certificate

	// Enumerate certificates. Each call to CertEnumCertificatesInStore frees
	// the previously returned CertContext, so we must not access prev after the
	// next call. The last CertContext is freed when the call returns nil.
	var prev *syscall.CertContext
	storeHasCerts := false
	for {
		ctx, enumErr := syscall.CertEnumCertificatesInStore(store, prev)
		if enumErr != nil || ctx == nil {
			break
		}
		storeHasCerts = true

		// Extract DER-encoded certificate bytes from the CertContext.
		// unsafe.Slice gives a Go slice header over the Windows-owned buffer;
		// we copy immediately so the slice is safe to use after the next call.
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length) // #nosec G103 -- Audited: immediately copied to derCopy below.
		derCopy := make([]byte, len(der))
		copy(derCopy, der)

		parsed, parseErr := x509.ParseCertificate(derCopy)
		if parseErr != nil {
			logger.Debug("skipping unparseable certificate in Windows store",
				"store", storeName,
				"error", parseErr,
			)
			prev = ctx
			continue
		}

		// SourceTypeFile is used because Windows certificate stores are a
		// persistent, file-backed trust source (like PEM bundles on Linux).
		// There is no dedicated SourceType for platform trust stores.
		source := CertificateSource{
			Type:     SourceTypeFile,
			Location: storeName,
		}
		wrapped := NewCertificate(parsed, source)
		fp := wrapped.FingerprintSHA256()
		if _, ok := seen[fp]; !ok {
			seen[fp] = struct{}{}
			certs = append(certs, wrapped)
		}

		prev = ctx
	}

	// CertOpenSystemStore succeeds even for non-existent store names, producing
	// an empty store. Return an error so callers can distinguish a genuinely
	// invalid store from a valid-but-empty one.
	if !storeHasCerts {
		return nil, fmt.Errorf("certificate store %q is empty or does not exist: %w",
			storeName, ErrNoCertificatesFound)
	}

	return certs, nil
}

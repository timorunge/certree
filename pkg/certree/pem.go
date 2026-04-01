// PEM and DER certificate parsing utilities.

package certree

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
)

// pemParseConfig controls PEM parsing behavior for the shared parsePEMData function.
type pemParseConfig struct {
	// maxCerts limits the number of certificates parsed. Zero means unlimited.
	maxCerts    int
	skipInvalid bool
	// logger receives debug and warning messages during parsing. Nil means silent.
	logger *slog.Logger
}

// ParsePEMCertificates parses CERTIFICATE blocks from PEM-encoded data,
// skipping non-certificate blocks (private keys, CSRs, etc.).
// maxCerts limits the number of certificates parsed; zero means unlimited.
// Returns [*StructuredError] with [ErrCertificateLimitExceeded] when the
// limit is exceeded.
func ParsePEMCertificates(data []byte, source CertificateSource, maxCerts int) ([]*Certificate, error) {
	certs, err := parsePEMData(data, source, pemParseConfig{maxCerts: maxCerts})
	if err != nil {
		category := ErrParseFailed
		msg := "could not parse PEM certificates"
		if errors.Is(err, ErrNoCertificatesFound) {
			category = ErrNoCertificatesFound
		}
		if errors.Is(err, ErrCertificateLimitExceeded) {
			category = ErrCertificateLimitExceeded
			msg = "too many certificates in PEM data"
		}
		return nil, NewStructuredError(msg, category, err)
	}
	return certs, nil
}

// ParseDERCertificate parses a single DER-encoded certificate.
func ParseDERCertificate(data []byte, source CertificateSource) (*Certificate, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, NewStructuredError(
			"could not parse DER-encoded certificate",
			ErrParseFailed,
			err,
		)
	}
	return NewCertificate(cert, source), nil
}

// isPrivateKeyBlock reports whether a PEM block type is a private key.
// Covers the types defined by RFC 5958 (PKCS#8 OneAsymmetricKey / EncryptedPrivateKeyInfo),
// RFC 3447 (RSA), RFC 5915 (EC), PKCS#5/PKCS#8 encrypted form, and OpenSSH.
func isPrivateKeyBlock(blockType string) bool {
	switch blockType {
	case "PRIVATE KEY", // RFC 5958 / PKCS#8 unencrypted
		"ENCRYPTED PRIVATE KEY", // RFC 5958 / PKCS#8 encrypted
		"RSA PRIVATE KEY",       // PKCS#1 / RFC 3447
		"EC PRIVATE KEY",        // SEC1 / RFC 5915
		"DSA PRIVATE KEY",       // PKCS#9 legacy DSA
		"OPENSSH PRIVATE KEY":   // OpenSSH private key format
		return true
	}
	return false
}

// parsePEMBlock parses a single PEM certificate block and appends it to certs.
func parsePEMBlock(block *pem.Block, source CertificateSource, certs []*Certificate, cfg pemParseConfig) ([]*Certificate, error) {
	rawCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		if cfg.skipInvalid {
			if cfg.logger != nil {
				cfg.logger.Debug("skipping invalid certificate", "error", err)
			}
			return certs, nil
		}
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return append(certs, NewCertificate(rawCert, source)), nil
}

// parsePEMData extracts certificates from PEM data using the provided configuration.
func parsePEMData(data []byte, source CertificateSource, cfg pemParseConfig) ([]*Certificate, error) {
	estimate := bytes.Count(data, []byte("-----BEGIN CERTIFICATE-----"))
	if cfg.maxCerts > 0 && estimate > cfg.maxCerts {
		estimate = cfg.maxCerts
	}
	certs := make([]*Certificate, 0, estimate)
	rest := data

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			if cfg.logger != nil && isPrivateKeyBlock(block.Type) {
				cfg.logger.Debug("private key found and ignored for security")
			}
			continue
		}

		// Enforce certificate limit before parsing to avoid wasted work.
		if cfg.maxCerts > 0 && len(certs) >= cfg.maxCerts {
			return nil, certLimitExceededError(cfg.maxCerts)
		}

		var err error
		certs, err = parsePEMBlock(block, source, certs, cfg)
		if err != nil {
			return nil, err
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data: %w", ErrNoCertificatesFound)
	}

	return certs, nil
}

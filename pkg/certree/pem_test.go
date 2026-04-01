package certree

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

func pemTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "test.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
		return nil
	}
	return cert
}

// pemTestChain generates a simple 3-level certificate chain for PEM unit tests.
func pemTestChain(t *testing.T) []*x509.Certificate {
	t.Helper()
	certs, _, err := testutil.GenerateSimpleChain()
	if err != nil {
		t.Fatalf("Failed to generate chain: %v", err)
		return nil
	}
	return certs
}

func TestParsePEMCertificates_MixedBlocks(t *testing.T) {
	t.Parallel()

	x509Cert, key, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "test.example.com"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x509Cert.Raw,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	certPEM = append(certPEM, keyPEM...)
	pemData := certPEM

	source := CertificateSource{
		Type:     SourceTypeFile,
		Location: "mixed.pem",
	}

	certs, err := ParsePEMCertificates(pemData, source, 0)
	if err != nil {
		t.Fatalf("ParsePEMCertificates() error = %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("ParsePEMCertificates() returned %d certs, want 1 (should skip private key)", len(certs))
	}
}

func TestParsePEMCertificates_NoCertificates(t *testing.T) {
	t.Parallel()

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake key data"),
	})

	source := CertificateSource{
		Type:     SourceTypeFile,
		Location: "nocer.pem",
	}

	_, err := ParsePEMCertificates(pemData, source, 0)
	if err == nil {
		t.Error("ParsePEMCertificates() expected error for no certificates")
	}
}

func TestParsePEMCertificates_EmptyData(t *testing.T) {
	t.Parallel()

	source := CertificateSource{
		Type:     SourceTypeFile,
		Location: "empty.pem",
	}

	_, err := ParsePEMCertificates([]byte{}, source, 0)
	if err == nil {
		t.Error("ParsePEMCertificates() expected error for empty data")
	}
}

func TestParsePEMCertificates_InvalidPEMData(t *testing.T) {
	t.Parallel()

	pemData := []byte("-----BEGIN CERTIFICATE-----\nInvalid data\n-----END CERTIFICATE-----")

	source := CertificateSource{
		Type:     SourceTypeFile,
		Location: "invalid.pem",
	}

	_, err := ParsePEMCertificates(pemData, source, 0)
	if err == nil {
		t.Error("ParsePEMCertificates() expected error for invalid PEM data")
	}
}

func TestParseDERCertificate_InvalidData(t *testing.T) {
	t.Parallel()
	derData := []byte("invalid der data")

	source := CertificateSource{
		Type:     SourceTypeFile,
		Location: "invalid.der",
	}

	_, err := ParseDERCertificate(derData, source)
	if err == nil {
		t.Error("ParseDERCertificate() expected error for invalid DER data")
	}
}

func TestParseDERCertificate_TruncatedData(t *testing.T) {
	t.Parallel()

	x509Cert := pemTestCert(t)
	truncatedData := x509Cert.Raw[:len(x509Cert.Raw)/2]

	source := CertificateSource{
		Type:     SourceTypeFile,
		Location: "truncated.der",
	}

	_, err := ParseDERCertificate(truncatedData, source)
	if err == nil {
		t.Error("ParseDERCertificate() expected error for truncated DER data")
	}
}

func TestParsePEMCertificates_UnderLimit(t *testing.T) {
	t.Parallel()

	cert := pemTestCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	source := CertificateSource{Type: SourceTypeFile, Location: "test.pem"}
	certs, err := ParsePEMCertificates(pemData, source, 10)
	if err != nil {
		t.Fatalf("ParsePEMCertificates() error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certs))
	}
}

func TestParsePEMCertificates_ExceedsLimit(t *testing.T) {
	t.Parallel()

	chain := pemTestChain(t)
	pemData := make([]byte, 0, len(chain)*2048)
	for _, cert := range chain {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	source := CertificateSource{Type: SourceTypeFile, Location: "test.pem"}
	_, err := ParsePEMCertificates(pemData, source, 2)
	if err == nil {
		t.Fatal("expected error when exceeding limit, got nil")
	}
}

func TestSecurityParsePEMCertificates_EdgeCases(t *testing.T) {
	t.Parallel()

	src := CertificateSource{Type: SourceTypeFile, Location: "test.pem"}

	t.Run("thousands of comment lines between certs", func(t *testing.T) {
		t.Parallel()

		cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "comment-flood.example.com"},
		})
		require.NoError(t, err)

		var buf bytes.Buffer
		for range 5000 {
			buf.WriteString("# this is a comment\n")
		}
		buf.Write(testutil.EncodePEM(cert))

		certs, parseErr := ParsePEMCertificates(buf.Bytes(), src, 0)
		require.NoError(t, parseErr)
		assert.Len(t, certs, 1)
	})

	t.Run("extremely long single-line base64 no wrapping", func(t *testing.T) {
		t.Parallel()

		cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "nowrap.example.com"},
		})
		require.NoError(t, err)

		// RFC 7468 requires 64-char lines, but the Go PEM decoder is lenient.
		encoded := base64.StdEncoding.EncodeToString(cert.Raw)
		pemData := []byte("-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n")

		certs, parseErr := ParsePEMCertificates(pemData, src, 0)
		require.NoError(t, parseErr)
		assert.Len(t, certs, 1)
	})

	t.Run("mixed valid and invalid blocks", func(t *testing.T) {
		t.Parallel()

		cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "mixed.example.com"},
		})
		require.NoError(t, err)

		invalidBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "GARBAGE BLOCK",
			Bytes: []byte("not a certificate"),
		})
		validBlock := testutil.EncodePEM(cert)

		mixed := append(invalidBlock, validBlock...)
		certs, parseErr := ParsePEMCertificates(mixed, src, 0)
		require.NoError(t, parseErr)
		assert.Len(t, certs, 1, "non-CERTIFICATE PEM blocks must be silently skipped")
	})

	t.Run("empty certificate block", func(t *testing.T) {
		t.Parallel()

		// Syntactically valid PEM but zero bytes of DER; x509 must reject it.
		pemData := []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
		p := NewParser()
		_, err := p.ParseBytes(pemData)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrUnknownFormat),
			"empty DER in PEM block must surface as ErrUnknownFormat, got: %v", err)
	})
}

func TestSecurityParsePEMCertificates_MaxCerts(t *testing.T) {
	t.Parallel()

	certs, _, err := testutil.GenerateSimpleChain()
	require.NoError(t, err)
	chainPEM := testutil.EncodePEMChain(certs)
	src := CertificateSource{Type: SourceTypeFile, Location: "test.pem"}

	t.Run("limit of 0 means unlimited", func(t *testing.T) {
		t.Parallel()
		parsed, parseErr := ParsePEMCertificates(chainPEM, src, 0)
		require.NoError(t, parseErr)
		assert.Len(t, parsed, 3, "zero limit means unlimited - all 3 certs must be parsed")
	})
}

package render

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/timorunge/certree/pkg/certree"
	"github.com/timorunge/certree/pkg/certree/testutil"
)

func TestPublicKeyInfo(t *testing.T) {
	t.Parallel()

	t.Run("RSA", func(t *testing.T) {
		t.Parallel()
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "rsa"},
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{})
		if got := publicKeyInfo(cert); got != "RSA 2048-bit" {
			t.Errorf("publicKeyInfo() = %q, want %q", got, "RSA 2048-bit")
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		t.Parallel()
		raw, _, err := testutil.GenerateSelfSignedCertEd25519(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "ed25519"},
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{})
		if got := publicKeyInfo(cert); got != "Ed25519" {
			t.Errorf("publicKeyInfo() = %q, want %q", got, "Ed25519")
		}
	})

	t.Run("ECDSA P-256", func(t *testing.T) {
		t.Parallel()
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ECDSA key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "ecdsa"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		raw, err := testutil.CreateAndParseCert(tmpl, tmpl, &ecKey.PublicKey, ecKey)
		if err != nil {
			t.Fatalf("create cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{})
		if got := publicKeyInfo(cert); got != "ECDSA P-256" {
			t.Errorf("publicKeyInfo() = %q, want %q", got, "ECDSA P-256")
		}
	})
}

func TestFormatNotAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC)

	t.Run("not expired shows days", func(t *testing.T) {
		t.Parallel()
		notBefore := now.Add(-30 * 24 * time.Hour)
		notAfterTime := now.Add(100 * 24 * time.Hour)
		raw, _, err := testutil.GenerateCertificateWithExpiry("test", notBefore, notAfterTime)
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{}, certree.WithCertificateTime(now))
		got := formatNotAfter(cert, identityColorFunc)
		if !strings.Contains(got, "100 days") {
			t.Errorf("formatNotAfter() = %q, expected days remaining", got)
		}
	})

	t.Run("expired omits days", func(t *testing.T) {
		t.Parallel()
		notBefore := now.Add(-365 * 24 * time.Hour)
		notAfterTime := now.Add(-10 * 24 * time.Hour)
		raw, _, err := testutil.GenerateCertificateWithExpiry("expired", notBefore, notAfterTime)
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{}, certree.WithCertificateTime(now))
		got := formatNotAfter(cert, identityColorFunc)
		if strings.Contains(got, "days") {
			t.Errorf("formatNotAfter() = %q, expired cert should not show days", got)
		}
	})
}

func TestFormatNotBefore(t *testing.T) {
	t.Parallel()

	notBefore := time.Date(2025, 3, 15, 12, 0, 0, 0, time.UTC)
	notAfterTime := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	raw, _, err := testutil.GenerateCertificateWithExpiry("notbefore-test", notBefore, notAfterTime)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	cert := certree.NewCertificate(raw, certree.CertificateSource{})
	got := formatNotBefore(cert)
	if !strings.Contains(got, "2025-03-15") {
		t.Errorf("formatNotBefore() = %q, expected to contain date", got)
	}
}

func TestKeyUsageNames(t *testing.T) {
	t.Parallel()

	t.Run("multiple bits", func(t *testing.T) {
		t.Parallel()
		got := keyUsageNames(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign)
		want := []string{"Digital Signature", "Certificate Sign", "CRL Sign"}
		if len(got) != len(want) {
			t.Fatalf("keyUsageNames() returned %d items, want %d: %v", len(got), len(want), got)
		}
		for i, name := range got {
			if name != want[i] {
				t.Errorf("keyUsageNames()[%d] = %q, want %q", i, name, want[i])
			}
		}
	})

	t.Run("none", func(t *testing.T) {
		t.Parallel()
		if got := keyUsageNames(0); len(got) != 0 {
			t.Errorf("keyUsageNames(0) = %v, want empty", got)
		}
	})
}

func TestPolicyOIDName(t *testing.T) {
	t.Parallel()

	if got := policyOIDName("2.23.140.1.2.1"); got != "DV" {
		t.Errorf("policyOIDName(DV OID) = %q, want %q", got, "DV")
	}
	if got := policyOIDName("1.2.3.4.5"); got != "" {
		t.Errorf("policyOIDName(unknown) = %q, want empty", got)
	}
}

func TestTrustStoreValue(t *testing.T) {
	t.Parallel()

	t.Run("trusted cert shows locations", func(t *testing.T) {
		t.Parallel()
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "trusted"},
			IsCA:    true,
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{}).
			WithTrustedLocations([]string{"system", "custom"})
		got := trustStoreValue(cert)
		if got != "system, custom" {
			t.Errorf("trustStoreValue() = %q, want %q", got, "system, custom")
		}
	})

	t.Run("untrusted self-signed returns none", func(t *testing.T) {
		t.Parallel()
		raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "untrusted"},
			IsCA:    true,
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		cert := certree.NewCertificate(raw, certree.CertificateSource{})
		got := trustStoreValue(cert)
		if got != "none" {
			t.Errorf("trustStoreValue() = %q, want %q", got, "none")
		}
	})
}

func TestShortFingerprintPrefix(t *testing.T) {
	t.Parallel()

	if got := shortFingerprintPrefix("A887602F9BC1DE45"); got != "A8:87:60:2F:9B:C1" {
		t.Errorf("shortFingerprintPrefix(long) = %q, want %q", got, "A8:87:60:2F:9B:C1")
	}
	if got := shortFingerprintPrefix("A887"); got != "A8:87" {
		t.Errorf("shortFingerprintPrefix(short) = %q, want %q", got, "A8:87")
	}
}

func TestDisambiguateNames(t *testing.T) {
	t.Parallel()

	t.Run("nil for unique names", func(t *testing.T) {
		t.Parallel()
		raw1, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "cert-a"},
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		raw2, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
			Subject:      pkix.Name{CommonName: "cert-b"},
			SerialNumber: big.NewInt(2),
		})
		if err != nil {
			t.Fatalf("generate cert: %v", err)
		}
		certs := []*certree.Certificate{
			certree.NewCertificate(raw1, certree.CertificateSource{}),
			certree.NewCertificate(raw2, certree.CertificateSource{}),
		}
		if got := disambiguateNames(certs); got != nil {
			t.Errorf("disambiguateNames(unique names) = %v, want nil", got)
		}
	})

	t.Run("duplicate names get fingerprint prefixes", func(t *testing.T) {
		t.Parallel()
		raws, _, err := testutil.GenerateCertificateWithCN("same-name", 2)
		if err != nil {
			t.Fatalf("generate certs: %v", err)
		}
		certs := make([]*certree.Certificate, len(raws))
		for i, raw := range raws {
			certs[i] = certree.NewCertificate(raw, certree.CertificateSource{})
		}
		result := disambiguateNames(certs)
		if result == nil {
			t.Fatal("disambiguateNames returned nil, expected map")
		}
		seen := make(map[string]struct{})
		for _, cert := range certs {
			prefix, ok := result[cert.FingerprintSHA256()]
			if !ok {
				t.Errorf("fingerprint %s not in disambiguation map", cert.FingerprintSHA256())
				continue
			}
			if _, dup := seen[prefix]; dup {
				t.Errorf("duplicate prefix %q across different certs", prefix)
			}
			seen[prefix] = struct{}{}
		}
	})
}

func TestFormatDisambiguated(t *testing.T) {
	t.Parallel()

	// Two certs with same name get fingerprint suffixes.
	raws, _, err := testutil.GenerateCertificateWithCN("dup-name", 2)
	if err != nil {
		t.Fatalf("generate certs: %v", err)
	}
	certs := make([]*certree.Certificate, len(raws))
	for i, raw := range raws {
		certs[i] = certree.NewCertificate(raw, certree.CertificateSource{})
	}
	names := formatDisambiguated(certs)
	if len(names) != 2 {
		t.Fatalf("formatDisambiguated returned %d names, want 2", len(names))
	}
	for _, name := range names {
		if !strings.Contains(name, "dup-name") {
			t.Errorf("name %q does not contain base name", name)
		}
		if !strings.Contains(name, ":") {
			t.Errorf("name %q missing fingerprint disambiguation", name)
		}
	}

	// Two certs with different names get no suffix.
	raw1, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "unique-a"},
	})
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	raw2, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject:      pkix.Name{CommonName: "unique-b"},
		SerialNumber: big.NewInt(99),
	})
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	uniqueCerts := []*certree.Certificate{
		certree.NewCertificate(raw1, certree.CertificateSource{}),
		certree.NewCertificate(raw2, certree.CertificateSource{}),
	}
	uniqueNames := formatDisambiguated(uniqueCerts)
	for _, name := range uniqueNames {
		if strings.Contains(name, ":") {
			t.Errorf("unique name %q should not have fingerprint suffix", name)
		}
	}
}

func TestDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subject pkix.Name
		want    string
	}{
		{
			name:    "common name",
			subject: pkix.Name{CommonName: "example.com"},
			want:    "example.com",
		},
		{
			name:    "organization fallback",
			subject: pkix.Name{Organization: []string{"ACME Corp"}},
			want:    "ACME Corp",
		},
		{
			name:    "no CN",
			subject: pkix.Name{},
			want:    "(no CN)",
		},
		{
			name:    "CSI escape codes stripped",
			subject: pkix.Name{CommonName: "evil\x1b[31mcert\x1b[0m"},
			want:    "evilcert",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
				Subject: tt.subject,
			})
			if err != nil {
				t.Fatalf("generate cert: %v", err)
			}
			cert := certree.NewCertificate(raw, certree.CertificateSource{})
			if got := displayName(cert); got != tt.want {
				t.Errorf("displayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

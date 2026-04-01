package certree

import (
	"crypto/x509"
	"testing"
)

func TestEKUShortName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		eku  x509.ExtKeyUsage
		want string
	}{
		{x509.ExtKeyUsageAny, "anyExtendedKeyUsage"},
		{x509.ExtKeyUsageServerAuth, "serverAuth"},
		{x509.ExtKeyUsageClientAuth, "clientAuth"},
		{x509.ExtKeyUsageCodeSigning, "codeSigning"},
		{x509.ExtKeyUsageEmailProtection, "emailProtection"},
		{x509.ExtKeyUsageTimeStamping, "timeStamping"},
		{x509.ExtKeyUsageOCSPSigning, "ocspSigning"},
		{x509.ExtKeyUsage(999), "ExtKeyUsage(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := EKUShortName(tt.eku); got != tt.want {
				t.Errorf("EKUShortName(%d) = %q, want %q", tt.eku, got, tt.want)
			}
		})
	}
}

func TestEKUDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		eku  x509.ExtKeyUsage
		want string
	}{
		{x509.ExtKeyUsageAny, "Any"},
		{x509.ExtKeyUsageServerAuth, "Server Authentication"},
		{x509.ExtKeyUsageClientAuth, "Client Authentication"},
		{x509.ExtKeyUsageCodeSigning, "Code Signing"},
		{x509.ExtKeyUsageEmailProtection, "Email Protection"},
		{x509.ExtKeyUsageIPSECEndSystem, "IPsec End System"},
		{x509.ExtKeyUsageIPSECTunnel, "IPsec Tunnel"},
		{x509.ExtKeyUsageIPSECUser, "IPsec User"},
		{x509.ExtKeyUsageTimeStamping, "Time Stamping"},
		{x509.ExtKeyUsageOCSPSigning, "OCSP Signing"},
		{x509.ExtKeyUsageMicrosoftServerGatedCrypto, "Microsoft SGC"},
		{x509.ExtKeyUsageNetscapeServerGatedCrypto, "Netscape SGC"},
		{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, "Microsoft Commercial Code Signing"},
		{x509.ExtKeyUsageMicrosoftKernelCodeSigning, "Microsoft Kernel Code Signing"},
		{x509.ExtKeyUsage(999), "Unknown (999)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := EKUDisplayName(tt.eku); got != tt.want {
				t.Errorf("EKUDisplayName(%d) = %q, want %q", tt.eku, got, tt.want)
			}
		})
	}
}

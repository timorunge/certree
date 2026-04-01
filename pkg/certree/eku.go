// Extended Key Usage name lookups for certificate analysis and display.

package certree

import (
	"crypto/x509"
	"fmt"
)

// ekuEntry holds the RFC 5280 short name and a human-readable display label
// for a single x509.ExtKeyUsage value.
type ekuEntry struct {
	short   string // RFC 5280 style, e.g. "serverAuth".
	display string // Human-readable, e.g. "Server Authentication".
}

// ekuTable maps known x509.ExtKeyUsage values to their name entries.
var ekuTable = map[x509.ExtKeyUsage]ekuEntry{
	x509.ExtKeyUsageAny:                            {"anyExtendedKeyUsage", "Any"},
	x509.ExtKeyUsageServerAuth:                     {"serverAuth", "Server Authentication"},
	x509.ExtKeyUsageClientAuth:                     {"clientAuth", "Client Authentication"},
	x509.ExtKeyUsageCodeSigning:                    {"codeSigning", "Code Signing"},
	x509.ExtKeyUsageEmailProtection:                {"emailProtection", "Email Protection"},
	x509.ExtKeyUsageIPSECEndSystem:                 {"ipsecEndSystem", "IPsec End System"},
	x509.ExtKeyUsageIPSECTunnel:                    {"ipsecTunnel", "IPsec Tunnel"},
	x509.ExtKeyUsageIPSECUser:                      {"ipsecUser", "IPsec User"},
	x509.ExtKeyUsageTimeStamping:                   {"timeStamping", "Time Stamping"},
	x509.ExtKeyUsageOCSPSigning:                    {"ocspSigning", "OCSP Signing"},
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     {"msServerGatedCrypto", "Microsoft SGC"},
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      {"nsServerGatedCrypto", "Netscape SGC"},
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: {"msMicrosoftCommercialCodeSigning", "Microsoft Commercial Code Signing"},
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     {"msMicrosoftKernelCodeSigning", "Microsoft Kernel Code Signing"},
}

// EKUShortName returns the RFC 5280 short name for a known x509.ExtKeyUsage
// value (e.g. "serverAuth"). Unknown values return "ExtKeyUsage(N)".
func EKUShortName(eku x509.ExtKeyUsage) string {
	if e, ok := ekuTable[eku]; ok {
		return e.short
	}
	return fmt.Sprintf("ExtKeyUsage(%d)", eku)
}

// EKUDisplayName returns a human-readable name for a known x509.ExtKeyUsage
// value (e.g. "Server Authentication"). Unknown values return "Unknown (N)".
func EKUDisplayName(eku x509.ExtKeyUsage) string {
	if e, ok := ekuTable[eku]; ok {
		return e.display
	}
	return fmt.Sprintf("Unknown (%d)", eku)
}

package testutil

import (
	"bytes"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToX509Template_InvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		template    CertificateTemplate
		wantIPs     int
		wantURIs    int
		wantFirstIP net.IP
	}{
		{
			name: "invalid IP is silently dropped",
			template: CertificateTemplate{
				IPAddresses: []string{"not-an-ip"},
			},
			wantIPs:  0,
			wantURIs: 0,
		},
		{
			name: "invalid URL is silently dropped",
			template: CertificateTemplate{
				URIs: []string{"://missing-scheme"},
			},
			wantIPs:  0,
			wantURIs: 0,
		},
		{
			name: "valid IP is preserved",
			template: CertificateTemplate{
				IPAddresses: []string{"192.168.1.1"},
			},
			wantIPs:     1,
			wantURIs:    0,
			wantFirstIP: net.ParseIP("192.168.1.1"),
		},
		{
			name: "valid URL is preserved",
			template: CertificateTemplate{
				URIs: []string{"https://example.com"},
			},
			wantIPs:  0,
			wantURIs: 1,
		},
		{
			name: "mixed valid and invalid IPs",
			template: CertificateTemplate{
				IPAddresses: []string{"10.0.0.1", "not-valid", "::1"},
			},
			wantIPs:     2,
			wantURIs:    0,
			wantFirstIP: net.ParseIP("10.0.0.1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := ToX509Template(tt.template)

			assert.Len(t, result.IPAddresses, tt.wantIPs)
			assert.Len(t, result.URIs, tt.wantURIs)

			if tt.wantFirstIP != nil && tt.wantIPs > 0 {
				assert.True(t, tt.wantFirstIP.Equal(result.IPAddresses[0]),
					"expected first IP %v, got %v", tt.wantFirstIP, result.IPAddresses[0])
			}
		})
	}
}

func TestApplyTemplateDefaults_Interactions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		template        CertificateTemplate
		checkSerial     *big.Int
		preservesBefore bool
		preservesAfter  bool
	}{
		{
			name:        "zero NotBefore and NotAfter get filled",
			template:    CertificateTemplate{},
			checkSerial: big.NewInt(1),
		},
		{
			name: "non-zero SerialNumber is preserved",
			template: CertificateTemplate{
				SerialNumber: big.NewInt(42),
			},
			checkSerial: big.NewInt(42),
		},
		{
			name: "non-zero NotBefore is preserved",
			template: CertificateTemplate{
				NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			checkSerial:     big.NewInt(1),
			preservesBefore: true,
		},
		{
			name: "non-zero NotAfter is preserved",
			template: CertificateTemplate{
				NotAfter: time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC),
			},
			checkSerial:    big.NewInt(1),
			preservesAfter: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			original := tt.template
			ApplyTemplateDefaults(&tt.template)

			assert.Equal(t, tt.checkSerial, tt.template.SerialNumber)
			assert.False(t, tt.template.NotBefore.IsZero(), "NotBefore should not be zero after defaults")
			assert.False(t, tt.template.NotAfter.IsZero(), "NotAfter should not be zero after defaults")

			if tt.preservesBefore {
				assert.Equal(t, original.NotBefore, tt.template.NotBefore,
					"non-zero NotBefore should be preserved")
			}
			if tt.preservesAfter {
				assert.Equal(t, original.NotAfter, tt.template.NotAfter,
					"non-zero NotAfter should be preserved")
			}
		})
	}
}

func TestGenerateChainWithDepth_BoundaryCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		depth     int
		wantErr   bool
		wantLen   int
		checkRoot bool
		checkLeaf bool
	}{
		{
			name:    "depth 0 returns error",
			depth:   0,
			wantErr: true,
		},
		{
			name:      "depth 1 returns just a root",
			depth:     1,
			wantLen:   1,
			checkRoot: true,
		},
		{
			name:      "depth 2 returns leaf and root",
			depth:     2,
			wantLen:   2,
			checkLeaf: true,
			checkRoot: true,
		},
		{
			name:      "depth 5 returns correct chain length",
			depth:     5,
			wantLen:   5,
			checkLeaf: true,
			checkRoot: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certs, keys, err := GenerateChainWithDepth(tt.depth)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, certs)
				assert.Nil(t, keys)
				return
			}

			require.NoError(t, err)
			require.Len(t, certs, tt.wantLen)
			require.Len(t, keys, tt.wantLen)

			if tt.checkRoot {
				root := certs[len(certs)-1]
				assert.True(t, root.IsCA, "last certificate should be a CA")
			}

			if tt.checkLeaf && tt.wantLen >= 2 {
				leaf := certs[0]
				assert.False(t, leaf.IsCA, "first certificate should not be a CA")
			}
		})
	}
}

func TestGenerateCertificateWithCN_Invariants(t *testing.T) {
	t.Parallel()

	t.Run("count zero returns error", func(t *testing.T) {
		t.Parallel()
		_, _, err := GenerateCertificateWithCN("test", 0)
		assert.Error(t, err)
	})

	t.Run("all certs share CN", func(t *testing.T) {
		t.Parallel()
		certs, keys, err := GenerateCertificateWithCN("shared.example.com", 3)
		require.NoError(t, err)
		require.Len(t, certs, 3)
		require.Len(t, keys, 3)
		for i, cert := range certs {
			assert.Equal(t, "shared.example.com", cert.Subject.CommonName,
				"cert %d should have CN shared.example.com", i)
		}
	})
}

func TestEncodePEMChain_Structure(t *testing.T) {
	t.Parallel()

	t.Run("empty input returns empty output", func(t *testing.T) {
		t.Parallel()
		result := EncodePEMChain(nil)
		assert.Empty(t, result)
	})

	t.Run("two certs produce two PEM blocks", func(t *testing.T) {
		t.Parallel()
		certs, _, err := GenerateSimpleChain()
		require.NoError(t, err)

		twoChain := certs[:2]
		encoded := EncodePEMChain(twoChain)

		count := bytes.Count(encoded, []byte("-----BEGIN CERTIFICATE-----"))
		assert.Equal(t, 2, count, "should contain exactly 2 PEM blocks")

		rest := encoded
		for i := range 2 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			require.NotNil(t, block, "block %d should decode", i)
			assert.Equal(t, "CERTIFICATE", block.Type)
		}
	})
}

package certree

import (
	"fmt"
	"testing"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// cachedSimChains holds pre-generated certificate chains keyed by depth,
// avoiding expensive chain generation inside test iterations.
type cachedSimChains struct {
	chains map[int][]*Certificate
}

// setupSimChains generates chains for depths 3..7 for reuse in tests.
func setupSimChains(t *testing.T) *cachedSimChains {
	t.Helper()
	src := CertificateSource{Type: SourceTypeFile, Location: "test"}
	cached := &cachedSimChains{chains: make(map[int][]*Certificate)}
	for depth := 3; depth <= 7; depth++ {
		x509Certs, _, err := testutil.GenerateChainWithDepth(depth)
		if err != nil {
			t.Fatalf("generating chain with depth %d: %v", depth, err)
		}
		certs := make([]*Certificate, len(x509Certs))
		for i, raw := range x509Certs {
			certs[i] = NewCertificate(raw, src)
		}
		cached.chains[depth] = certs
	}
	return cached
}

// TestGhostMarking verifies simulation marking for every (depth, excludeIdx)
// combination: certs above the excluded index are ghosted, the excluded cert
// has IsExcluded only, and certs below have neither. Also checks structural
// alignment (simulated path has same cert count as original).
func TestGhostMarking(t *testing.T) {
	t.Parallel()

	cached := setupSimChains(t)

	// Build all meaningful (depth, excludeIdx) pairs: index 1..depth-1.
	type testCase struct {
		depth      int
		excludeIdx int
	}
	var cases []testCase
	for depth := 3; depth <= 7; depth++ {
		for idx := 1; idx < depth; idx++ {
			cases = append(cases, testCase{depth, idx})
		}
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("depth%d_exclude%d", tc.depth, tc.excludeIdx), func(t *testing.T) {
			t.Parallel()

			certs := make([]*Certificate, len(cached.chains[tc.depth]))
			copy(certs, cached.chains[tc.depth])

			excludedCert := certs[tc.excludeIdx]
			originalPath := &TrustPath{
				Certificates: certs,
				Status:       PathTrusted,
			}

			sim := &defaultSimulator{
				excludedCNs: []string{excludedCert.CommonName()},
				logger:      NewLogger(),
			}
			matchers := sim.compileExclusionMatchers()
			simPath := sim.simulatePath(originalPath, matchers)

			if simPath == nil {
				t.Fatal("simulatePath returned nil for non-leaf exclusion")
			}

			// Structural alignment: cert count must match.
			if len(simPath.Certificates) != len(originalPath.Certificates) {
				t.Fatalf("cert count: got %d, want %d", len(simPath.Certificates), len(originalPath.Certificates))
			}

			// Verify marking at each position.
			for i, cert := range simPath.Certificates {
				switch {
				case i > tc.excludeIdx:
					if !simPath.IsGhosted(cert) {
						t.Errorf("cert[%d]: expected IsGhosted=true (above excluded index %d)", i, tc.excludeIdx)
					}
				case i == tc.excludeIdx:
					if !simPath.IsExcluded(cert) {
						t.Errorf("cert[%d]: expected IsExcluded=true", i)
					}
					if simPath.IsGhosted(cert) {
						t.Errorf("cert[%d]: expected IsGhosted=false (excluded cert should not be ghosted)", i)
					}
				default:
					if simPath.IsGhosted(cert) {
						t.Errorf("cert[%d]: expected IsGhosted=false (below excluded index %d)", i, tc.excludeIdx)
					}
				}
			}
		})
	}
}

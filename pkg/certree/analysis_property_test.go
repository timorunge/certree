package certree

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// cachedJSONChains holds pre-generated certificate chains keyed by depth,
// avoiding expensive chain generation inside test iterations.
type cachedJSONChains struct {
	chains map[int][]*Certificate
}

func setupJSONChains(t *testing.T) *cachedJSONChains {
	t.Helper()
	cached := &cachedJSONChains{chains: make(map[int][]*Certificate)}
	for depth := 1; depth <= 5; depth++ {
		x509Certs, _, err := testutil.GenerateChainWithDepth(depth)
		if err != nil {
			t.Fatalf("generating chain with depth %d: %v", depth, err)
		}
		certs := make([]*Certificate, len(x509Certs))
		for i, raw := range x509Certs {
			src := CertificateSource{Type: SourceTypeRemote, Location: "test:443"}
			certs[i] = NewCertificate(raw, src)
		}
		cached.chains[depth] = certs
	}
	return cached
}

// TestJSON_ReferenceIntegrity_Property verifies JSON reference integrity across
// 320 combinations of chain depth, path count, pool subset, trust store
// presence, errors, warnings, and simulation metadata.
func TestJSON_ReferenceIntegrity_Property(t *testing.T) {
	t.Parallel()

	cached := setupJSONChains(t)

	type testCase struct {
		name         string
		depth        int
		pathCount    int
		poolSubset   bool // top-level pool has fewer certs than paths reference
		withTrust    bool // root cert has trusted_locations
		withErrors   bool
		withWarnings bool
		withSimMeta  bool
	}

	var cases []testCase
	for depth := 1; depth <= 5; depth++ {
		for _, pathCount := range []int{1, 2} {
			for _, poolSubset := range []bool{false, true} {
				for _, withTrust := range []bool{false, true} {
					for _, withErrors := range []bool{false, true} {
						for _, withWarnings := range []bool{false, true} {
							for _, withSimMeta := range []bool{false, true} {
								cases = append(cases, testCase{
									name: fmt.Sprintf("d%d_p%d_sub%t_trust%t_err%t_warn%t_sim%t",
										depth, pathCount, poolSubset, withTrust, withErrors, withWarnings, withSimMeta),
									depth:        depth,
									pathCount:    pathCount,
									poolSubset:   poolSubset,
									withTrust:    withTrust,
									withErrors:   withErrors,
									withWarnings: withWarnings,
									withSimMeta:  withSimMeta,
								})
							}
						}
					}
				}
			}
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain := cached.chains[tc.depth]

			// Optionally mark the root as trusted.
			root := chain[len(chain)-1]
			if tc.withTrust {
				root = root.WithTrustedLocations([]string{"system", "/etc/ssl/certs/root.pem"})
			}

			// Build trust path(s) using the potentially-updated root.
			pathChain := make([]*Certificate, len(chain))
			copy(pathChain, chain)
			pathChain[len(pathChain)-1] = root

			paths := make([]*TrustPath, 0, tc.pathCount)
			for range tc.pathCount {
				tp := NewTrustPath(pathChain, PathTrusted)

				if tc.withErrors {
					tp.Errors = []ValidationError{
						{Certificate: pathChain[0], Type: ErrorExpired, Message: "test error"},
					}
				}
				if tc.withWarnings {
					tp.Warnings = []ValidationWarning{
						{Certificate: pathChain[0], Type: WarningExpiringSoon, Message: "test warning"},
						{Message: "path-level warning (nil cert)"}, // nil cert reference
					}
				}
				if tc.withSimMeta {
					tp.SimulationMetadata = map[string]CertSimulationState{
						pathChain[0].FingerprintSHA256(): {IsExcluded: true},
					}
				}

				paths = append(paths, tp)
			}

			// Build top-level pool. When poolSubset is true, omit the root --
			// simulating how the chain builder adds trust store roots only to
			// paths, not the top-level pool.
			var pool []*Certificate
			if tc.poolSubset && len(chain) > 1 {
				pool = chain[:len(chain)-1] // omit root from pool
			} else {
				pool = chain
			}

			analysis := NewAnalysis(pool, paths, "test", WithSimulated(tc.withSimMeta))

			data, err := json.Marshal(analysis)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}

			var result map[string]any
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}

			certsMap, ok := result["certificates"].(map[string]any)
			if !ok {
				t.Fatal("certificates is not a map")
			}

			// Invariant 1: every map key matches the embedded fingerprint_sha256.
			for key, val := range certsMap {
				cert := val.(map[string]any)
				embedded := cert["fingerprint_sha256"].(string)
				if key != embedded {
					t.Errorf("map key %q != embedded fingerprint %q", key, embedded)
				}
			}

			// Invariant 2: every trust path fingerprint reference resolves.
			jsonPaths := result["trust_paths"].([]any)
			for i, p := range jsonPaths {
				path := p.(map[string]any)
				for j, ref := range path["certificates"].([]any) {
					fp := ref.(string)
					if _, found := certsMap[fp]; !found {
						t.Errorf("path %d cert %d: fingerprint %q not in certificates map", i, j, fp)
					}
				}

				// Invariant 3: error certificate references resolve.
				for j, e := range path["errors"].([]any) {
					errObj := e.(map[string]any)
					if fp, hasCert := errObj["certificate"].(string); hasCert {
						if _, found := certsMap[fp]; !found {
							t.Errorf("path %d error %d: fingerprint %q not in certificates map", i, j, fp)
						}
					}
				}

				// Invariant 4: warning certificate references resolve.
				for j, w := range path["warnings"].([]any) {
					warnObj := w.(map[string]any)
					if fp, hasCert := warnObj["certificate"].(string); hasCert {
						if _, found := certsMap[fp]; !found {
							t.Errorf("path %d warning %d: fingerprint %q not in certificates map", i, j, fp)
						}
					}
				}
			}

			// Invariant 5: trusted_locations preserved when withTrust is set.
			if tc.withTrust {
				rootFP := ColonHex(root.FingerprintSHA256())
				rootObj, found := certsMap[rootFP]
				if !found {
					t.Fatalf("trusted root %q missing from certificates map", rootFP)
				}
				meta := rootObj.(map[string]any)["metadata"].(map[string]any)
				locs, ok := meta["trusted_locations"].([]any)
				if !ok || len(locs) == 0 {
					t.Errorf("trusted root %q: trusted_locations should be non-empty, got %v", rootFP, meta["trusted_locations"])
				}
			}

			// Invariant 6: simulation_metadata fingerprints use colon-hex and resolve.
			if tc.withSimMeta {
				for i, p := range jsonPaths {
					path := p.(map[string]any)
					simMeta, hasSim := path["simulation_metadata"].(map[string]any)
					if !hasSim {
						continue
					}
					for fp := range simMeta {
						if _, found := certsMap[fp]; !found {
							t.Errorf("path %d simulation_metadata key %q not in certificates map", i, fp)
						}
					}
				}
			}
		})
	}
}

package certree

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// mockAIAFetcher is a mock implementation of AIAFetcher for testing.
type mockAIAFetcher struct {
	cert       *Certificate
	shouldFail bool
	err        error
}

func (m *mockAIAFetcher) FetchIssuers(_ context.Context, _ *Certificate) ([]*Certificate, error) {
	if m.shouldFail {
		return nil, m.err
	}
	return []*Certificate{m.cert}, nil
}

func (m *mockAIAFetcher) ResetCache() {}

// mockTrustStore is a mock trust store that trusts no certificates.
type mockTrustStore struct{}

func (m *mockTrustStore) IsTrusted(_ *Certificate) bool { return false }

func (m *mockTrustStore) TrustedLocations(_ *Certificate) []string { return nil }

func (m *mockTrustStore) LoadSystemRoots() error { return nil }

func (m *mockTrustStore) LoadCustomRoots(_ string) error { return nil }

func (m *mockTrustStore) FindIssuers(_ *Certificate) []*Certificate { return nil }

// mockTrustStoreWithRoot is a mock trust store that trusts a single root certificate.
type mockTrustStoreWithRoot struct {
	root *Certificate
}

func (m *mockTrustStoreWithRoot) IsTrusted(cert *Certificate) bool {
	if m.root == nil {
		return false
	}
	return cert.FingerprintSHA256() == m.root.FingerprintSHA256()
}

func (m *mockTrustStoreWithRoot) TrustedLocations(cert *Certificate) []string {
	if m.IsTrusted(cert) {
		return []string{"test"}
	}
	return nil
}

func (m *mockTrustStoreWithRoot) LoadSystemRoots() error { return nil }

func (m *mockTrustStoreWithRoot) LoadCustomRoots(_ string) error { return nil }

func (m *mockTrustStoreWithRoot) FindIssuers(cert *Certificate) []*Certificate {
	if m.root == nil || cert == nil {
		return nil
	}
	if bytes.Equal(cert.Raw().RawIssuer, m.root.Raw().RawSubject) {
		return []*Certificate{m.root}
	}
	return nil
}

// slowAIAFetcher is a mock AIA fetcher that simulates slow network.
type slowAIAFetcher struct {
	delay time.Duration
}

func (s *slowAIAFetcher) FetchIssuers(ctx context.Context, _ *Certificate) ([]*Certificate, error) {
	select {
	case <-time.After(s.delay):
		return nil, fmt.Errorf("fetch failed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *slowAIAFetcher) ResetCache() {}

// conditionalAIAFetcher is a mock AIA fetcher that succeeds for the first N fetches
// and fails for subsequent fetches.
type conditionalAIAFetcher struct {
	successCert *Certificate
	failAfter   int
	fetchCount  atomic.Int32
}

func (c *conditionalAIAFetcher) FetchIssuers(_ context.Context, _ *Certificate) ([]*Certificate, error) {
	c.fetchCount.Add(1)
	if int(c.fetchCount.Load()) <= c.failAfter {
		return []*Certificate{c.successCert}, nil
	}
	return nil, fmt.Errorf("fetch failed")
}

func (c *conditionalAIAFetcher) ResetCache() {}

// mockAIAFetcherFunc is a mock AIAFetcher backed by an arbitrary function.
// Use it when a test needs fine-grained control over which certs are returned
// for each input (e.g. cross-signing and AIAForce scenarios).
type mockAIAFetcherFunc struct {
	fn func(context.Context, *Certificate) ([]*Certificate, error)
}

func (m *mockAIAFetcherFunc) FetchIssuers(ctx context.Context, cert *Certificate) ([]*Certificate, error) {
	return m.fn(ctx, cert)
}

func (m *mockAIAFetcherFunc) ResetCache() {}

// mockLogHandler is a slog.Handler that captures log records for assertion.
// Unlike testLogHandler in aia_test.go (which uses per-level callback functions
// for flexible stub behavior), mockLogHandler records all entries in a slice so
// tests can inspect the full log history after execution.
type mockLogHandler struct {
	mu   sync.Mutex
	logs []logEntry
}

type logEntry struct {
	level string
	msg   string
	args  map[string]any
}

func (h *mockLogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *mockLogHandler) Handle(_ context.Context, r slog.Record) error {
	args := make(map[string]any, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		args[a.Key] = a.Value.Any()
		return true
	})
	entry := logEntry{level: r.Level.String(), msg: r.Message, args: args}
	h.mu.Lock()
	h.logs = append(h.logs, entry)
	h.mu.Unlock()
	return nil
}

func (h *mockLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

func (h *mockLogHandler) WithGroup(_ string) slog.Handler { return h }

// newMockLogger returns a *slog.Logger backed by a mockLogHandler.
// The handler is returned separately so tests can inspect captured logs.
func newMockLogger() (*slog.Logger, *mockLogHandler) {
	h := &mockLogHandler{}
	return slog.New(h), h
}

var (
	simpleChainOnce  sync.Once
	simpleChainCerts []*Certificate // 3-cert chain from GenerateSimpleChain

	depth3ChainOnce  sync.Once
	depth3ChainCerts []*Certificate // depth-3 chain from GenerateChainWithDepth(3)
)

// getSimpleChain returns a cached 3-cert chain [leaf, intermediate, root].
func getSimpleChain(t *testing.T) []*Certificate {
	t.Helper()
	simpleChainOnce.Do(func() {
		x509Certs, _, err := testutil.GenerateSimpleChain()
		if err != nil {
			panic(fmt.Sprintf("generating simple chain: %v", err))
		}
		src := CertificateSource{Type: SourceTypeFile, Location: "test"}
		simpleChainCerts = make([]*Certificate, len(x509Certs))
		for i, raw := range x509Certs {
			simpleChainCerts[i] = NewCertificate(raw, src)
		}
	})
	return simpleChainCerts
}

// getDepth3Chain returns a cached depth-3 chain.
func getDepth3Chain(t *testing.T) []*Certificate {
	t.Helper()
	depth3ChainOnce.Do(func() {
		x509Certs, _, err := testutil.GenerateChainWithDepth(3)
		if err != nil {
			panic(fmt.Sprintf("generating depth-3 chain: %v", err))
		}
		src := CertificateSource{Type: SourceTypeFile, Location: "test"}
		depth3ChainCerts = make([]*Certificate, len(x509Certs))
		for i, raw := range x509Certs {
			depth3ChainCerts[i] = NewCertificate(raw, src)
		}
	})
	return depth3ChainCerts
}

func TestChainBuilder_TrustStoreIntegration(t *testing.T) {
	t.Parallel()

	// Use cached 3-cert chain.
	certs := getDepth3Chain(t)
	if len(certs) != 3 {
		t.Fatalf("Expected 3 certs, got %d", len(certs))
	}

	// Add root to trust store
	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))
	root := certs[2] // Last cert is root

	t.Logf("Root cert: %s, IsSelfSigned: %v", root.CommonName(), root.IsSelfSigned())
	t.Logf("Root fingerprint: %s", root.FingerprintSHA256())

	// Write root cert to temp PEM file and load into trust store
	tmpFile := filepath.Join(t.TempDir(), "root.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw().Raw})
	if err := os.WriteFile(tmpFile, pemData, 0600); err != nil {
		t.Fatalf("Failed to write PEM file: %v", err)
	}
	if err := ts.LoadCustomRoots(tmpFile); err != nil {
		t.Fatalf("LoadCustomRoots() error = %v", err)
	}

	if !ts.IsTrusted(root) {
		t.Fatalf("Root should be trusted")
	}

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), certs, ts)
	if err != nil {
		t.Fatalf("BuildChains error: %v", err)
	}

	t.Logf("Found %d paths", len(paths))
	for i, path := range paths {
		t.Logf("Path %d: Status=%v, Depth=%d", i, path.Status, len(path.Certificates))
		for j, cert := range path.Certificates {
			t.Logf("  Cert %d: %s", j, cert.CommonName())
		}
	}

	// Should have at least one trusted path
	hasTrustedPath := false
	for _, path := range paths {
		if path.Status.IsTrusted() {
			hasTrustedPath = true
			break
		}
	}

	if !hasTrustedPath {
		t.Fatalf("No trusted path found")
	}
}

func TestChainBuilder_AIAFetchingIntegration(t *testing.T) {
	t.Parallel()

	// Use cached simple chain; re-wrap with the sources needed by this test.
	cached := getSimpleChain(t)

	// Create wrapped certificates
	endEntity := &Certificate{
		raw:    cached[0].Raw(),
		source: CertificateSource{Type: SourceTypeFile},
	}
	intermediate := &Certificate{
		raw:    cached[1].Raw(),
		source: CertificateSource{Type: SourceTypeAIA, Location: "http://test.example.com/intermediate.crt"},
	}

	// Create a mock AIA fetcher that returns the intermediate
	mockFetcher := &mockAIAFetcher{
		cert:       intermediate,
		shouldFail: false,
	}

	// Create chain builder with AIA fetcher
	builder := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAFetcher(mockFetcher),
	)

	// Build chains with only the end-entity (intermediate should be fetched)
	paths, err := builder.BuildChains(t.Context(), []*Certificate{endEntity}, &mockTrustStore{})

	if err != nil {
		t.Fatalf("BuildChains failed: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("Expected at least one path")
	}

	foundFetched := false
	for _, path := range paths {
		for _, cert := range path.Certificates {
			if cert.Source().Type == SourceTypeAIA {
				foundFetched = true
				if cert.Raw().Subject.CommonName != intermediate.Raw().Subject.CommonName {
					t.Errorf("Fetched certificate has wrong subject: got %s, want %s",
						cert.Raw().Subject.CommonName, intermediate.Raw().Subject.CommonName)
				}
				break
			}
		}
	}

	if !foundFetched {
		t.Error("Fetched certificate not found in path")
	}
}

func TestChainBuilder_AIAFetchErrors(t *testing.T) {
	t.Parallel()

	cached := getSimpleChain(t)

	tests := []struct {
		name string
		err  error
	}{
		{"timeout", context.DeadlineExceeded},
		{"network error", fmt.Errorf("network error: connection refused")},
		{"invalid certificate", fmt.Errorf("invalid certificate data")},
		{"connection timeout", fmt.Errorf("connection timeout")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			endEntity := &Certificate{
				raw:    cached[0].Raw(),
				source: CertificateSource{Type: SourceTypeFile},
			}

			mockFetcher := &mockAIAFetcher{
				cert:       nil,
				shouldFail: true,
				err:        tt.err,
			}

			builder := NewChainBuilder(
				WithAIAFetch(true),
				WithAIAFetcher(mockFetcher),
			)

			paths, err := builder.BuildChains(t.Context(), []*Certificate{endEntity}, &mockTrustStore{})
			if err != nil {
				t.Fatalf("BuildChains failed: %v", err)
			}

			if len(paths) == 0 {
				t.Fatal("Expected at least one path")
			}

			if paths[0].Status != PathIncomplete {
				t.Error("Path should be incomplete when AIA fetch fails")
			}
		})
	}
}

func TestChainBuilder_AIAFetcherNil(t *testing.T) {
	t.Parallel()

	cached := getSimpleChain(t)

	endEntity := &Certificate{
		raw:    cached[0].Raw(),
		source: CertificateSource{Type: SourceTypeFile},
	}

	builder := NewChainBuilder(
		WithAIAFetch(true),
	)

	paths, err := builder.BuildChains(t.Context(), []*Certificate{endEntity}, &mockTrustStore{})

	if err != nil {
		t.Fatalf("BuildChains failed: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("Expected at least one path")
	}

	if paths[0].Status != PathIncomplete {
		t.Error("Path should be incomplete when no fetcher available")
	}
}

func TestChainBuilder_AIAFetchWithProvidedCertificates(t *testing.T) {
	t.Parallel()

	cached := getSimpleChain(t)

	endEntity := &Certificate{
		raw:    cached[0].Raw(),
		source: CertificateSource{Type: SourceTypeFile},
	}
	intermediate := &Certificate{
		raw:    cached[1].Raw(),
		source: CertificateSource{Type: SourceTypeFile},
	}
	root := &Certificate{
		raw:    cached[2].Raw(),
		source: CertificateSource{Type: SourceTypeFile},
	}

	mockFetcher := &mockAIAFetcher{
		cert:       nil,
		shouldFail: true,
		err:        fmt.Errorf("fetcher should not be called when issuer is provided"),
	}

	builder := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAFetcher(mockFetcher),
	)

	trustStore := &mockTrustStoreWithRoot{root: root}

	paths, err := builder.BuildChains(t.Context(), []*Certificate{endEntity, intermediate, root}, trustStore)

	if err != nil {
		t.Fatalf("BuildChains failed: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("Expected at least one path")
	}

	if paths[0].Status == PathIncomplete {
		t.Error("Path should be complete when all certificates are provided")
	}

	for _, path := range paths {
		for _, cert := range path.Certificates {
			if cert.Source().Type == SourceTypeAIA {
				t.Error("Found AIA-fetched certificate when all certs were provided")
			}
		}
	}
}

func TestChainBuilder_AIAFetchContextCancellation(t *testing.T) {
	t.Parallel()

	cached := getSimpleChain(t)

	endEntity := &Certificate{
		raw:    cached[0].Raw(),
		source: CertificateSource{Type: SourceTypeFile},
	}

	mockFetcher := &slowAIAFetcher{
		delay: 100 * time.Millisecond,
	}

	builder := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAFetcher(mockFetcher),
	)

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	_, err := builder.BuildChains(ctx, []*Certificate{endEntity}, &mockTrustStore{})

	if err == nil {
		t.Error("Expected error due to context cancellation")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled error, got: %v", err)
	}
}

func TestChainBuilder_AIAErrorLogging(t *testing.T) {
	t.Parallel()

	cached := getSimpleChain(t)

	endEntity := &Certificate{raw: cached[0].Raw(), source: CertificateSource{Type: SourceTypeFile}}

	logger, handler := newMockLogger()

	mockFetcher := &mockAIAFetcher{
		cert:       nil,
		shouldFail: true,
		err:        fmt.Errorf("network error: DNS lookup failed for issuer.example.com"),
	}

	builder := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAFetcher(mockFetcher),
		WithChainLogger(logger),
	)

	_, err := builder.BuildChains(t.Context(), []*Certificate{endEntity}, &mockTrustStore{})
	if err != nil {
		t.Fatalf("BuildChains failed: %v", err)
	}

	foundErrorLog := false
	for _, log := range handler.logs {
		if log.level == "WARN" && log.msg == "failed to fetch issuers via AIA" {
			foundErrorLog = true
			if log.args["error"] == nil {
				t.Error("Expected error details in log")
			}
			if log.args["cert"] == nil {
				t.Error("Expected certificate context in log")
			}
		}
	}

	if !foundErrorLog {
		t.Error("Expected detailed error log for AIA failure")
	}
}

func TestChainBuilder_PartialAIASuccess(t *testing.T) {
	t.Parallel()

	cached := getSimpleChain(t)

	endEntity1 := &Certificate{raw: cached[0].Raw(), source: CertificateSource{Type: SourceTypeFile}}
	intermediate1 := &Certificate{
		raw:    cached[1].Raw(),
		source: CertificateSource{Type: SourceTypeAIA, Location: "http://issuer.example.com/cert"},
	}
	endEntity2 := &Certificate{raw: cached[0].Raw(), source: CertificateSource{Type: SourceTypeFile}}

	mockFetcher := &conditionalAIAFetcher{
		successCert: intermediate1,
		failAfter:   1,
	}

	builder := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAFetcher(mockFetcher),
	)

	paths, err := builder.BuildChains(t.Context(), []*Certificate{endEntity1, endEntity2}, &mockTrustStore{})

	if err != nil {
		t.Fatalf("BuildChains should not fail: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("Expected at least one path")
	}

	// The AIA-fetched intermediate must appear in at least one surviving path.
	// deduplicatePaths keeps the longer path (with the intermediate), so the
	// AIA-fetched cert must be present.
	foundAIAFetched := false
	for _, path := range paths {
		for _, cert := range path.Certificates {
			if cert.Source().Type == SourceTypeAIA {
				foundAIAFetched = true
				break
			}
		}
	}

	if !foundAIAFetched {
		t.Error("Expected AIA-fetched certificate in at least one path")
	}
}

func TestChainBuilder_DeduplicatePaths(t *testing.T) {
	t.Parallel()

	// Use cached certs for building paths.
	cached := getSimpleChain(t)

	src := CertificateSource{Type: SourceTypeFile}
	leaf := NewCertificate(cached[0].Raw(), src)
	intermediate := NewCertificate(cached[1].Raw(), src)
	root := NewCertificate(cached[2].Raw(), src)

	tests := []struct {
		name      string
		paths     []*TrustPath
		wantCount int
	}{
		{
			name:      "nil paths",
			paths:     nil,
			wantCount: 0,
		},
		{
			name: "single path",
			paths: []*TrustPath{
				{Certificates: []*Certificate{leaf, intermediate, root}, Status: PathTrusted},
			},
			wantCount: 1,
		},
		{
			name: "exact duplicates deduplicated",
			paths: []*TrustPath{
				{Certificates: []*Certificate{leaf, intermediate, root}, Status: PathTrusted},
				{Certificates: []*Certificate{leaf, intermediate, root}, Status: PathTrusted},
			},
			wantCount: 1,
		},
		{
			// Both paths end at genuine trust anchors. Each represents a distinct
			// trust anchor choice and must be preserved (the cloudflare case).
			name: "both trusted prefix paths kept",
			paths: []*TrustPath{
				{Certificates: []*Certificate{leaf, intermediate}, Status: PathTrusted},
				{Certificates: []*Certificate{leaf, intermediate, root}, Status: PathTrusted},
			},
			wantCount: 2,
		},
		{
			// Shorter path terminates at a trust anchor; longer extends past it to
			// an untrusted root. The longer path is AIAForce noise -- remove it.
			name: "shorter trusted, longer untrusted: remove longer",
			paths: []*TrustPath{
				{Certificates: []*Certificate{leaf, intermediate}, Status: PathTrusted},
				{Certificates: []*Certificate{leaf, intermediate, root}, Status: PathUntrusted},
			},
			wantCount: 1,
		},
		{
			// Shorter path is untrusted; longer terminates at a trust anchor.
			// Remove the shorter incomplete path.
			name: "shorter untrusted, longer trusted: remove shorter",
			paths: []*TrustPath{
				{Certificates: []*Certificate{leaf, intermediate}, Status: PathUntrusted},
				{Certificates: []*Certificate{leaf, intermediate, root}, Status: PathTrusted},
			},
			wantCount: 1,
		},
		{
			// Both paths are untrusted. Remove the shorter incomplete path.
			name: "both untrusted: remove shorter",
			paths: []*TrustPath{
				{Certificates: []*Certificate{leaf, intermediate}, Status: PathUntrusted},
				{Certificates: []*Certificate{leaf, intermediate, root}, Status: PathUntrusted},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := deduplicatePaths(tt.paths)
			if len(got) != tt.wantCount {
				t.Errorf("deduplicatePaths() returned %d paths, want %d", len(got), tt.wantCount)
			}
		})
	}
}

func TestChainBuilder_AIAForce_SPKIDedup(t *testing.T) {
	t.Parallel()

	// Build a 3-cert chain: leaf -> intermediate -> rootA (self-signed, trusted).
	rootAX509, rootAKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Root CA"},
		IsCA:    true,
	})
	require.NoError(t, err)

	intermediateX509, intermediateKey, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Intermediate CA"}, IsCA: true},
		rootAX509, rootAKey,
	)
	require.NoError(t, err)

	leafX509, _, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "leaf.example.com"}},
		intermediateX509, intermediateKey,
	)
	require.NoError(t, err)

	src := CertificateSource{Type: SourceTypeFile}
	wrappedLeaf := NewCertificate(leafX509, src)
	wrappedIntermediate := NewCertificate(intermediateX509, src)
	wrappedRootA := NewCertificate(rootAX509, src)

	// Create rootB: same subject and public key as rootA, but different DER
	// (different serial number). This simulates the trust-store cert vs.
	// AIA-served cert scenario where the same CA re-issued its own root with
	// a different serial but the same key pair.
	rootATemplate := *rootAX509
	rootATemplate.SerialNumber = new(big.Int).Add(rootAX509.SerialNumber, big.NewInt(1))
	rootBX509, err := testutil.CreateAndParseCert(&rootATemplate, &rootATemplate, rootAX509.PublicKey, rootAKey)
	require.NoError(t, err)
	wrappedRootB := NewCertificate(rootBX509, CertificateSource{Type: SourceTypeAIA})

	// Verify rootA and rootB have the same SPKI but different fingerprints.
	require.NotEqual(t, wrappedRootA.FingerprintSHA256(), wrappedRootB.FingerprintSHA256(),
		"rootA and rootB must have different fingerprints for this test to be meaningful")
	require.Equal(t, wrappedRootA.spkiSHA256, wrappedRootB.spkiSHA256,
		"rootA and rootB must have the same SPKI (same public key)")

	// Trust store trusts rootA (the pool version). rootB is not trusted.
	ts := &mockTrustStoreWithRoot{root: wrappedRootA}

	// AIA fetcher returns rootB (re-issued version) when asked for the issuer
	// of the intermediate. rootB has the same key but a different serial, so
	// it gets indexed as a separate certificate. The chain builder produces
	// paths through both rootA (trusted) and rootB (untrusted). Only the
	// trusted path through rootA matters; the untrusted rootB path is expected.
	mockFetcher := &mockAIAFetcherFunc{fn: func(_ context.Context, cert *Certificate) ([]*Certificate, error) {
		if cert.FingerprintSHA256() == wrappedIntermediate.FingerprintSHA256() {
			return []*Certificate{wrappedRootB}, nil
		}
		return nil, fmt.Errorf("no AIA for %s", cert.CommonName())
	}}

	// Pool: trust store lookup will find rootA; AIA fetch adds rootB.
	// Both get indexed. rootA produces a trusted path, rootB an untrusted one.
	inputCerts := []*Certificate{wrappedLeaf, wrappedIntermediate}

	cb := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAForce(true),
		WithAIAFetcher(mockFetcher),
	)
	paths, err := cb.BuildChains(t.Context(), inputCerts, ts)
	require.NoError(t, err)

	trustedPaths := 0
	for _, p := range paths {
		if p.Status.IsTrusted() {
			trustedPaths++
		}
	}
	if trustedPaths != 1 {
		t.Errorf("expected exactly 1 trusted path, got %d", trustedPaths)
		for i, p := range paths {
			cns := make([]string, len(p.Certificates))
			for j, c := range p.Certificates {
				cns[j] = c.CommonName()
			}
			t.Logf("Path %d (%v): %v", i+1, p.Status, cns)
		}
	}
}

func TestChainBuilder_AIAForce_UntrustedExtension(t *testing.T) {
	t.Parallel()

	// Chain: leaf -> intermediate -> trustedRoot (NOT self-signed, trusted).
	// AIAForce discovers: trustedRoot -> untrustedOldRoot (NOT in trust store).
	untrustedOldRootX509, untrustedOldRootKey, err := testutil.GenerateSelfSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Old Root CA (retired)"}, IsCA: true},
	)
	require.NoError(t, err)

	// trustedRoot is cross-signed: signed by untrustedOldRoot, but is itself in the
	// trust store. This models a cross-signed intermediate trust anchor.
	trustedRootX509, trustedRootKey, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Trusted Root CA"}, IsCA: true},
		untrustedOldRootX509, untrustedOldRootKey,
	)
	require.NoError(t, err)

	intermediateX509, intermediateKey, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Intermediate CA"}, IsCA: true},
		trustedRootX509, trustedRootKey,
	)
	require.NoError(t, err)

	leafX509, _, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "leaf.example.com"}},
		intermediateX509, intermediateKey,
	)
	require.NoError(t, err)

	src := CertificateSource{Type: SourceTypeFile}
	wrappedLeaf := NewCertificate(leafX509, src)
	wrappedIntermediate := NewCertificate(intermediateX509, src)
	wrappedTrustedRoot := NewCertificate(trustedRootX509, src)
	wrappedOldRoot := NewCertificate(untrustedOldRootX509, src)

	// Trust store: only trustedRoot is trusted (NOT oldRoot).
	ts := &mockTrustStoreWithRoot{root: wrappedTrustedRoot}

	// AIA fetcher returns oldRoot when asked for trustedRoot's issuer.
	mockFetcher := &mockAIAFetcherFunc{fn: func(_ context.Context, cert *Certificate) ([]*Certificate, error) {
		if cert.FingerprintSHA256() == wrappedTrustedRoot.FingerprintSHA256() {
			return []*Certificate{wrappedOldRoot}, nil
		}
		return nil, fmt.Errorf("no AIA for %s", cert.CommonName())
	}}

	// Pool: leaf + intermediate (trustedRoot not in pool; found via trust store).
	inputCerts := []*Certificate{wrappedLeaf, wrappedIntermediate}

	cb := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAForce(true),
		WithAIAFetcher(mockFetcher),
	)
	paths, err := cb.BuildChains(t.Context(), inputCerts, ts)
	require.NoError(t, err)

	// Expect exactly 1 trusted path: {leaf, intermediate, trustedRoot}.
	// The longer untrusted extension {leaf, intermediate, trustedRoot, oldRoot}
	// must be removed.
	trustedPaths := 0
	totalPaths := len(paths)
	for _, p := range paths {
		if p.Status.IsTrusted() {
			trustedPaths++
		}
	}

	if trustedPaths != 1 {
		t.Errorf("expected 1 trusted path, got %d (total paths: %d)", trustedPaths, totalPaths)
	}
	if totalPaths != 1 {
		t.Errorf("expected 1 total path (untrusted extension should be removed), got %d", totalPaths)
		for i, p := range paths {
			cns := make([]string, len(p.Certificates))
			for j, c := range p.Certificates {
				cns[j] = c.CommonName()
			}
			t.Logf("Path %d (%v): %v", i+1, p.Status, cns)
		}
	}
}

func TestChainBuilder_AIAForce_BothTrustedKept(t *testing.T) {
	t.Parallel()

	// Chain: leaf -> intermediate -> crossRoot (NOT self-signed, trusted).
	// AIAForce discovers: crossRoot -> anchorRoot (self-signed, ALSO trusted).
	// Both crossRoot and anchorRoot are in the trust store.
	anchorRootX509, anchorRootKey, err := testutil.GenerateSelfSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Anchor Root CA"}, IsCA: true},
	)
	require.NoError(t, err)

	crossRootX509, crossRootKey, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Cross Root CA"}, IsCA: true},
		anchorRootX509, anchorRootKey,
	)
	require.NoError(t, err)

	intermediateX509, intermediateKey, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "Intermediate CA"}, IsCA: true},
		crossRootX509, crossRootKey,
	)
	require.NoError(t, err)

	leafX509, _, err := testutil.GenerateSignedCertUniqueKey(
		testutil.CertificateTemplate{Subject: pkix.Name{CommonName: "leaf.example.com"}},
		intermediateX509, intermediateKey,
	)
	require.NoError(t, err)

	src := CertificateSource{Type: SourceTypeFile}
	wrappedLeaf := NewCertificate(leafX509, src)
	wrappedIntermediate := NewCertificate(intermediateX509, src)
	wrappedCrossRoot := NewCertificate(crossRootX509, src)
	wrappedAnchorRoot := NewCertificate(anchorRootX509, src)

	// Both crossRoot and anchorRoot are trusted.
	ts := &integrationMockTrustStoreMultipleRoots{
		roots: []*Certificate{wrappedCrossRoot, wrappedAnchorRoot},
	}

	// AIA fetcher returns anchorRoot when asked for crossRoot's issuer.
	mockFetcher := &mockAIAFetcherFunc{fn: func(_ context.Context, cert *Certificate) ([]*Certificate, error) {
		if cert.FingerprintSHA256() == wrappedCrossRoot.FingerprintSHA256() {
			return []*Certificate{wrappedAnchorRoot}, nil
		}
		return nil, fmt.Errorf("no AIA for %s", cert.CommonName())
	}}

	// Pool: leaf + intermediate (crossRoot found via trust store lookup).
	inputCerts := []*Certificate{wrappedLeaf, wrappedIntermediate}

	cb := NewChainBuilder(
		WithAIAFetch(true),
		WithAIAForce(true),
		WithAIAFetcher(mockFetcher),
	)
	paths, err := cb.BuildChains(t.Context(), inputCerts, ts)
	require.NoError(t, err)

	// Expect exactly 2 trusted paths:
	//   Path A: {leaf, intermediate, crossRoot}       -- crossRoot as trust anchor
	//   Path B: {leaf, intermediate, crossRoot, anchorRoot} -- anchorRoot as trust anchor
	// Both represent distinct trust anchor choices and must be preserved.
	trustedPaths := 0
	for _, p := range paths {
		if p.Status.IsTrusted() {
			trustedPaths++
		}
	}
	if trustedPaths != 2 {
		t.Errorf("expected 2 trusted paths (distinct trust anchors must be kept), got %d", trustedPaths)
		for i, p := range paths {
			cns := make([]string, len(p.Certificates))
			for j, c := range p.Certificates {
				cns[j] = c.CommonName()
			}
			t.Logf("Path %d (%v): %v", i+1, p.Status, cns)
		}
	}
}

func TestChainBuilder_TrustStoreIssuerLookup(t *testing.T) {
	t.Parallel()

	// Use cached depth-3 chain: end-entity -> intermediate -> root.
	cachedDepth3 := getDepth3Chain(t)

	src := CertificateSource{Type: SourceTypeRemote, Location: "example.com:443"}
	endEntity := NewCertificate(cachedDepth3[0].Raw(), src)
	intermediate := NewCertificate(cachedDepth3[1].Raw(), src)
	root := NewCertificate(cachedDepth3[2].Raw(), src)

	// Only give the chain builder the leaf and intermediate (simulating what
	// a TLS server sends). The root is NOT in the certificate pool.
	serverCerts := []*Certificate{endEntity, intermediate}

	// Put the root in the trust store (simulating the OS trust store).
	trustStore := &mockTrustStoreWithRoot{root: root}

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), serverCerts, trustStore)
	if err != nil {
		t.Fatalf("BuildChains error: %v", err)
	}

	// Should find a trusted path despite the root not being in the server certs.
	hasTrustedPath := false
	for _, path := range paths {
		if path.Status.IsTrusted() {
			hasTrustedPath = true
			// The trusted path should have 3 certs: end-entity, intermediate, root.
			if len(path.Certificates) != 3 {
				t.Errorf("Expected 3 certs in trusted path, got %d", len(path.Certificates))
			}
			break
		}
	}

	if !hasTrustedPath {
		t.Fatalf("Expected a trusted path when root is in trust store but not in server certs; got %d paths", len(paths))
	}
}

func TestChainBuilder_TrustStoreIssuerLookupNoMatch(t *testing.T) {
	t.Parallel()

	// Use cached depth-3 chain.
	cachedDepth3 := getDepth3Chain(t)

	src := CertificateSource{Type: SourceTypeRemote, Location: "example.com:443"}
	endEntity := NewCertificate(cachedDepth3[0].Raw(), src)
	intermediate := NewCertificate(cachedDepth3[1].Raw(), src)

	// Only give the chain builder the leaf and intermediate.
	serverCerts := []*Certificate{endEntity, intermediate}

	// Empty trust store -- no root available anywhere.
	trustStore := &mockTrustStore{}

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), serverCerts, trustStore)
	if err != nil {
		t.Fatalf("BuildChains error: %v", err)
	}

	// All paths should be incomplete since the root is nowhere to be found.
	for _, path := range paths {
		if path.Status.IsTrusted() {
			t.Fatalf("Expected no trusted paths, but found one with %d certs", len(path.Certificates))
		}
	}
}

func TestChainBuilder_SelfSignedRootIdentification(t *testing.T) {
	t.Parallel()

	// Generate a self-signed CA certificate.
	selfSignedCert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName: "Self-Signed Root",
		},
		IsCA: true,
	})
	require.NoError(t, err)

	selfSigned := NewCertificate(selfSignedCert, CertificateSource{
		Type:     SourceTypeFile,
		Location: "test",
	})

	// Create empty trust store (no trusted roots).
	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))

	// Build chains.
	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), []*Certificate{selfSigned}, ts)
	require.NoError(t, err)
	require.NotEmpty(t, paths, "expected at least one path for self-signed certificate")

	// Path should be complete and root should be the self-signed cert.
	path := paths[0]
	assert.NotEqual(t, PathIncomplete, path.Status)
	require.NotNil(t, path.Root(), "path should have a root")
	assert.True(t, path.Root().IsSelfSigned(), "root should be self-signed")
}

func TestChainBuilder_CircularReferenceDetection(t *testing.T) {
	t.Parallel()

	// Generate two CAs that form a circular reference via cross-signing.
	//
	// Step 1: Generate self-signed Root A.
	rootACert, rootAKey, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Root A"},
		IsCA:    true,
	})
	require.NoError(t, err)

	// Step 2: Generate Cert B signed by Root A (Subject=B, Issuer=A).
	certBCert, certBKey, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Cert B"},
		IsCA:    true,
	}, rootACert, rootAKey)
	require.NoError(t, err)

	// Step 3: Cross-sign Root A with Cert B's key, producing a certificate
	// with Subject=A and Issuer=B. This creates a cycle:
	//   crossSignedA (Issuer=B) -> certB (Issuer=A) -> crossSignedA ...
	crossSignedACert, err := testutil.GenerateCrossSigned(rootACert, certBCert, certBKey)
	require.NoError(t, err)

	certA := NewCertificate(crossSignedACert, CertificateSource{
		Type:     SourceTypeFile,
		Location: "test",
	})
	certB := NewCertificate(certBCert, CertificateSource{
		Type:     SourceTypeFile,
		Location: "test",
	})

	// Create empty trust store.
	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))

	// Build chains with circular detection enabled.
	cb := NewChainBuilder(WithCircularDetection(true))
	paths, err := cb.BuildChains(t.Context(), []*Certificate{certA, certB}, ts)
	require.NoError(t, err)
	require.NotEmpty(t, paths, "expected at least one path")

	// At least one path should report a circular reference error.
	hasCircularError := false
	for _, path := range paths {
		for _, pathErr := range path.Errors {
			if pathErr.Type == ErrorCircularReference {
				hasCircularError = true
				break
			}
		}
	}

	assert.True(t, hasCircularError, "expected circular reference error in paths")
}

func TestChainBuilder_IncompleteChainMarking(t *testing.T) {
	t.Parallel()

	// Use the cached 3-cert chain and keep only the end-entity (non-self-signed).
	cached := getSimpleChain(t)
	cert := NewCertificate(cached[0].Raw(), CertificateSource{
		Type:     SourceTypeFile,
		Location: "test",
	})

	require.False(t, cert.IsSelfSigned(), "end-entity should not be self-signed")

	// Create empty trust store (issuer is intentionally missing).
	ts := NewTrustStore(WithTrustStoreLogger(NewLogger()))

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), []*Certificate{cert}, ts)
	require.NoError(t, err)
	require.NotEmpty(t, paths, "expected at least one path")

	// Path should be marked as incomplete since the issuer is missing.
	assert.Equal(t, PathIncomplete, paths[0].Status, "path should be marked as incomplete")
}

func TestBuildChains_ConcurrentSafe(t *testing.T) {
	t.Parallel()

	cached := getSimpleChain(t)
	src := CertificateSource{Type: SourceTypeFile}
	leaf := NewCertificate(cached[0].Raw(), src)
	intermediate := NewCertificate(cached[1].Raw(), src)
	root := NewCertificate(cached[2].Raw(), src)

	ts := &mockTrustStoreWithRoot{root: root}
	cb := NewChainBuilder()

	const goroutines = 8
	errs := make([]error, goroutines)
	var wg sync.WaitGroup

	for i := range goroutines {
		idx := i
		wg.Go(func() {
			_, errs[idx] = cb.BuildChains(t.Context(), []*Certificate{leaf, intermediate, root}, ts)
		})
	}

	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d BuildChains returned error", i)
	}
}

func TestNewChainBuilder_AIAForceWithoutFetchWarns(t *testing.T) {
	t.Parallel()

	logger, handler := newMockLogger()
	_ = NewChainBuilder(WithAIAForce(true), WithChainLogger(logger))

	found := false
	for _, entry := range handler.logs {
		if entry.level == "WARN" && strings.Contains(entry.msg, "WithAIAForce") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected WARN log mentioning WithAIAForce when aiaFetch is disabled")
}

func TestBuildChains_ContextCancelReturnsError(t *testing.T) {
	t.Parallel()

	cached := getSimpleChain(t)
	src := CertificateSource{Type: SourceTypeFile}
	leaf := NewCertificate(cached[0].Raw(), src)
	intermediate := NewCertificate(cached[1].Raw(), src)
	root := NewCertificate(cached[2].Raw(), src)

	ts := &mockTrustStoreWithRoot{root: root}
	cb := NewChainBuilder()

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel immediately before calling BuildChains

	_, err := cb.BuildChains(ctx, []*Certificate{leaf, intermediate, root}, ts)
	assert.Error(t, err, "expected error from canceled context")
	assert.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got: %v", err)
}

func TestDeduplicatePaths_RunsWithoutAIAForce(t *testing.T) {
	t.Parallel()

	cached := getSimpleChain(t)
	src := CertificateSource{Type: SourceTypeFile}
	leaf := NewCertificate(cached[0].Raw(), src)
	intermediate := NewCertificate(cached[1].Raw(), src)
	root := NewCertificate(cached[2].Raw(), src)

	// Two identical trusted paths -- deduplicatePaths must collapse them to one.
	dup := []*TrustPath{
		{Certificates: []*Certificate{leaf, intermediate, root}, Status: PathTrusted},
		{Certificates: []*Certificate{leaf, intermediate, root}, Status: PathTrusted},
	}

	result := deduplicatePaths(dup)
	assert.Len(t, result, 1, "deduplicatePaths should collapse identical paths regardless of AIAForce")

	// Also verify via BuildChains on a ChainBuilder without AIAForce.
	// Provide the same root in both the pool and the trust store; this can
	// produce a pool-based path and a trust-store-based path with identical
	// certificate sequences, which must be deduplicated.
	ts := &mockTrustStoreWithRoot{root: root}
	cb := NewChainBuilder() // no WithAIAForce

	paths, err := cb.BuildChains(t.Context(), []*Certificate{leaf, intermediate, root}, ts)
	assert.NoError(t, err)

	// Regardless of how many raw paths were produced internally, deduplicated
	// output should not contain exact duplicate certificate sequences.
	seen := make(map[string]bool)
	for _, p := range paths {
		key := p.PathKey()
		assert.False(t, seen[key], "duplicate path found after BuildChains without AIAForce")
		seen[key] = true
	}
}

func TestWithChainLogger_NilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil logger, got none")
		}
	}()
	WithChainLogger(nil)(&defaultChainBuilder{})
}

func TestChainBuilder_CrossSignPathMultiplication(t *testing.T) {
	t.Parallel()

	// N cross-signed issuers for a leaf should produce N trust paths.
	tests := []struct {
		name    string
		issuers int
	}{
		{"1 issuer", 1},
		{"2 issuers", 2},
		{"3 issuers", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Generate a root and leaf signed by that root.
			// Unique keys prevent SKI collisions that cause false issuer matches.
			rootRaw, rootKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
				Subject:  pkix.Name{CommonName: "Root CA"},
				IsCA:     true,
				KeyUsage: x509.KeyUsageCertSign,
			})
			require.NoError(t, err)

			leafRaw, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
				Subject: pkix.Name{CommonName: "leaf.example.com"},
			}, rootRaw, rootKey)
			require.NoError(t, err)

			src := CertificateSource{Type: SourceTypeFile}
			allCerts := []*Certificate{NewCertificate(leafRaw, src), NewCertificate(rootRaw, src)}

			// Generate cross-signed versions of the root (N-1 additional issuers).
			for i := 1; i < tt.issuers; i++ {
				crossSignerRaw, crossSignerKey, genErr := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
					Subject:  pkix.Name{CommonName: fmt.Sprintf("Cross Signer %d", i)},
					IsCA:     true,
					KeyUsage: x509.KeyUsageCertSign,
				})
				require.NoError(t, genErr)

				crossSignedRoot, csErr := testutil.GenerateCrossSigned(rootRaw, crossSignerRaw, crossSignerKey)
				require.NoError(t, csErr)

				allCerts = append(allCerts, NewCertificate(crossSignedRoot, src), NewCertificate(crossSignerRaw, src))
			}

			cb := NewChainBuilder()
			paths, err := cb.BuildChains(t.Context(), allCerts, &mockTrustStore{})
			require.NoError(t, err)

			assert.Len(t, paths, tt.issuers,
				"leaf with %d issuer(s) should produce %d path(s)", tt.issuers, tt.issuers)
		})
	}
}

func TestChainBuilder_DepthLimitEnforcement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		maxDepth  int
		chainLen  int
		wantError bool
	}{
		{"depth 2 chain within limit 3", 3, 2, false},
		{"depth 3 chain at limit 3", 3, 3, false},
		{"depth 5 chain exceeds limit 3", 3, 5, true},
		{"depth 4 chain exceeds limit 2", 2, 4, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rawChain, _, err := testutil.GenerateChainWithDepth(tt.chainLen)
			require.NoError(t, err)

			src := CertificateSource{Type: SourceTypeFile}
			certs := make([]*Certificate, len(rawChain))
			for i, raw := range rawChain {
				certs[i] = NewCertificate(raw, src)
			}

			cb := NewChainBuilder(WithMaxDepth(tt.maxDepth))
			paths, err := cb.BuildChains(t.Context(), certs, &mockTrustStore{})
			require.NoError(t, err)

			if tt.wantError {
				// At least one path should have ErrorDepthExceeded.
				hasDepthError := false
				for _, p := range paths {
					for _, e := range p.Errors {
						if e.Type == ErrorDepthExceeded {
							hasDepthError = true
							break
						}
					}
				}
				assert.True(t, hasDepthError,
					"chain of length %d with maxDepth %d should have ErrorDepthExceeded", tt.chainLen, tt.maxDepth)
			}
		})
	}
}

// newSecCertFromX509 wraps an x509.Certificate in a certree Certificate with a bytes source.
func newSecCertFromX509(raw *x509.Certificate) *Certificate {
	return NewCertificate(raw, CertificateSource{Type: SourceTypeBytes})
}

func TestSecurityDeepChainExhaustion(t *testing.T) {
	t.Parallel()

	t.Run("chain exceeds default max depth", func(t *testing.T) {
		t.Parallel()

		// Depth 15 exceeds DefaultMaxDepth=10.
		rawCerts, _, err := testutil.GenerateChainWithDepth(15)
		require.NoError(t, err)

		certs := make([]*Certificate, len(rawCerts))
		for i, rc := range rawCerts {
			certs[i] = newSecCertFromX509(rc)
		}

		cb := NewChainBuilder()
		ts := &mockTrustStore{}
		paths, err := cb.BuildChains(t.Context(), certs, ts)
		require.NoError(t, err)
		require.NotEmpty(t, paths, "builder must return at least one path")

		hasDepthError := false
		for _, p := range paths {
			for _, ve := range p.Errors {
				if ve.Type == ErrorDepthExceeded {
					hasDepthError = true
				}
			}
		}
		assert.True(t, hasDepthError, "at least one path should report ErrorDepthExceeded for a chain of depth 15")
	})

	t.Run("max depth zero means unlimited", func(t *testing.T) {
		t.Parallel()

		// WithMaxDepth(0) disables the depth limit. A depth-12 chain should
		// complete without ErrorDepthExceeded.
		rawCerts, _, err := testutil.GenerateChainWithDepth(12)
		require.NoError(t, err)

		certs := make([]*Certificate, len(rawCerts))
		for i, rc := range rawCerts {
			certs[i] = newSecCertFromX509(rc)
		}

		cb := NewChainBuilder(WithMaxDepth(0))
		ts := &mockTrustStore{}
		paths, err := cb.BuildChains(t.Context(), certs, ts)
		require.NoError(t, err)
		require.NotEmpty(t, paths)

		for _, p := range paths {
			for _, ve := range p.Errors {
				assert.NotEqual(t, ErrorDepthExceeded, ve.Type,
					"unlimited depth must not produce ErrorDepthExceeded")
			}
		}
	})
}

func TestSecurityCircularCertificateReferences(t *testing.T) {
	t.Parallel()

	t.Run("circular detection disabled still terminates via depth limit", func(t *testing.T) {
		t.Parallel()

		// When circular detection is off, the depth limit is the backstop.
		// A simple 3-cert chain must still build without hanging.
		rawCerts, _, err := testutil.GenerateChainWithDepth(3)
		require.NoError(t, err)

		certs := make([]*Certificate, len(rawCerts))
		for i, rc := range rawCerts {
			certs[i] = newSecCertFromX509(rc)
		}

		cb := NewChainBuilder(WithCircularDetection(false), WithMaxDepth(5))
		ts := &mockTrustStore{}
		paths, err := cb.BuildChains(t.Context(), certs, ts)
		require.NoError(t, err)
		assert.NotEmpty(t, paths, "disabled circular detection with depth limit must still build paths")
	})
}

func TestSecurityCertificatePoolExplosion(t *testing.T) {
	t.Parallel()

	const issuerCount = 20

	rootTmpl := testutil.CertificateTemplate{
		Subject:  pkix.Name{CommonName: "Explosion Root"},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rawRoot, rootKey, err := testutil.GenerateSelfSignedCertUniqueKey(rootTmpl)
	require.NoError(t, err)

	rootCert := newSecCertFromX509(rawRoot)
	ts := &mockTrustStoreWithRoot{root: rootCert}

	certs := make([]*Certificate, 0, issuerCount+2)
	certs = append(certs, rootCert)

	// Each intermediate shares the same CN so the subject-based index treats
	// them as interchangeable issuers. All are signed by the real root.
	for i := range issuerCount {
		intermTmpl := testutil.CertificateTemplate{
			Subject:      pkix.Name{CommonName: "Shared Intermediate"},
			SerialNumber: big.NewInt(int64(100 + i)),
			IsCA:         true,
			KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		var rawInterm *x509.Certificate
		rawInterm, _, err = testutil.GenerateSignedCertUniqueKey(intermTmpl, rawRoot, rootKey)
		require.NoError(t, err)
		certs = append(certs, newSecCertFromX509(rawInterm))
	}

	// Sign the leaf directly from the root so the builder has an end-entity.
	leafTmpl := testutil.CertificateTemplate{
		Subject:     pkix.Name{CommonName: "leaf.explosion.test"},
		DNSNames:    []string{"leaf.explosion.test"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	rawLeaf, _, err := testutil.GenerateSignedCertUniqueKey(leafTmpl, rawRoot, rootKey)
	require.NoError(t, err)
	certs = append(certs, newSecCertFromX509(rawLeaf))

	cb := NewChainBuilder()
	paths, err := cb.BuildChains(t.Context(), certs, ts)
	require.NoError(t, err)

	assert.LessOrEqual(t, len(paths), maxTrustPaths,
		"path count must not exceed the maxTrustPaths safety limit")
}

func TestSecuritySelfSignedCertificateHandling(t *testing.T) {
	t.Parallel()

	t.Run("self-signed intermediate breaks chain", func(t *testing.T) {
		t.Parallel()

		rawIntermediate, intKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:  pkix.Name{CommonName: "Self-Signed Intermediate"},
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign,
		})
		require.NoError(t, err)

		rawLeaf, _, err := testutil.GenerateSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:  pkix.Name{CommonName: "leaf.selfint.test"},
			DNSNames: []string{"leaf.selfint.test"},
			KeyUsage: x509.KeyUsageDigitalSignature,
		}, rawIntermediate, intKey)
		require.NoError(t, err)

		certs := []*Certificate{
			newSecCertFromX509(rawLeaf),
			newSecCertFromX509(rawIntermediate),
		}
		cb := NewChainBuilder()
		ts := &mockTrustStore{}
		paths, err := cb.BuildChains(t.Context(), certs, ts)
		require.NoError(t, err)
		require.NotEmpty(t, paths)

		hasNonTrustedPath := false
		for _, p := range paths {
			if p.Status != PathTrusted {
				hasNonTrustedPath = true
			}
		}
		assert.True(t, hasNonTrustedPath, "chain terminating at untrusted self-signed cert must not be PathTrusted")
	})

	t.Run("two self-signed certs with same subject but different keys are distinct paths", func(t *testing.T) {
		t.Parallel()

		// Same subject name, genuinely different RSA keys. The trust store trusts
		// only one of them. The builder must produce separate paths rather than
		// conflating the two certificates via their shared subject.
		sharedSubject := pkix.Name{CommonName: "Shared Subject CA"}

		rawCA1, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:  sharedSubject,
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign,
		})
		require.NoError(t, err)

		rawCA2, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:  sharedSubject,
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign,
		})
		require.NoError(t, err)

		ca1 := newSecCertFromX509(rawCA1)
		ca2 := newSecCertFromX509(rawCA2)

		require.NotEqual(t, ca1.FingerprintSHA256(), ca2.FingerprintSHA256())

		// Trust only the first.
		ts := &mockTrustStoreWithRoot{root: ca1}
		certs := []*Certificate{ca1, ca2}
		cb := NewChainBuilder()
		paths, err := cb.BuildChains(t.Context(), certs, ts)
		require.NoError(t, err)
		require.NotEmpty(t, paths)

		trustedCount := 0
		for _, p := range paths {
			if p.Status == PathTrusted {
				trustedCount++
			}
		}
		assert.GreaterOrEqual(t, trustedCount, 1, "at least one trusted path for the trusted root")

		untrustedCount := 0
		for _, p := range paths {
			if p.Status == PathUntrusted {
				untrustedCount++
			}
		}
		assert.GreaterOrEqual(t, untrustedCount, 1, "untrusted path for the non-trusted root")
	})
}

func TestSecurityMalformedCertificateFields(t *testing.T) {
	t.Parallel()

	t.Run("certificate with empty subject is accepted by the builder", func(t *testing.T) {
		t.Parallel()

		// RFC 5280 section 4.1.2.6 allows an empty subject when a subjectAltName
		// is present. An empty subject must not cause a nil-dereference or panic.
		rawCert, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:  pkix.Name{},
			DNSNames: []string{"empty-subject.test"},
		})
		require.NoError(t, err)

		cert := newSecCertFromX509(rawCert)
		assert.Equal(t, "", cert.CommonName(), "empty subject CN must return empty string, not panic")

		cb := NewChainBuilder()
		ts := &mockTrustStore{}
		paths, err := cb.BuildChains(t.Context(), []*Certificate{cert}, ts)
		require.NoError(t, err, "empty subject cert must not cause BuildChains to error")
		assert.NotEmpty(t, paths)
	})

	t.Run("certificate with extremely long CommonName does not panic", func(t *testing.T) {
		t.Parallel()

		// An attacker could embed a 1000-character CN to probe string handling,
		// logging, or display code. certree must handle it without allocation
		// failures or format-string exploits.
		longCN := strings.Repeat("X", 1000)

		rawCert, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:  pkix.Name{CommonName: longCN},
			DNSNames: []string{"long-cn.test"},
		})
		require.NoError(t, err)

		cert := newSecCertFromX509(rawCert)
		assert.Equal(t, longCN, cert.CommonName(), "1000-char CN must survive round-trip without truncation")

		cb := NewChainBuilder()
		ts := &mockTrustStore{}
		paths, err := cb.BuildChains(t.Context(), []*Certificate{cert}, ts)
		require.NoError(t, err, "1000-char CN must not cause BuildChains to error")
		assert.NotEmpty(t, paths)
	})

	t.Run("certificate with special characters in CommonName is handled safely", func(t *testing.T) {
		t.Parallel()

		// Tab, newline, and null-like sequences in CN fields probe log injection
		// and potential format-string issues in the rendering and logging layers.
		specialCN := "CN with\ttab and\nnewline"

		rawCert, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject:  pkix.Name{CommonName: specialCN},
			DNSNames: []string{"special-cn.test"},
		})
		require.NoError(t, err)

		cert := newSecCertFromX509(rawCert)
		assert.Equal(t, specialCN, cert.CommonName())

		cb := NewChainBuilder()
		ts := &mockTrustStore{}
		paths, err := cb.BuildChains(t.Context(), []*Certificate{cert}, ts)
		require.NoError(t, err)
		assert.NotEmpty(t, paths)
	})

	t.Run("certificate with null byte in CommonName is handled safely", func(t *testing.T) {
		t.Parallel()

		// Null bytes in CN fields are a classic attack vector for certificate
		// spoofing (CVE-2009-2408 class). Go's x509 parser may strip or reject
		// these; the test documents the actual behavior rather than asserting
		// a specific outcome, as long as no panic occurs.
		//
		// testutil generators cannot be used here: they propagate errors from
		// x509.CreateCertificate directly to the caller, but this test must
		// gracefully handle the case where Go's x509 library rejects the null
		// byte and continue (log + return) rather than fail the test.
		nullCN := "evil\x00.example.com"

		keyNullCN, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(42),
			Subject:      pkix.Name{CommonName: nullCN},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			DNSNames:     []string{"safe.example.com"},
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &keyNullCN.PublicKey, keyNullCN)

		if err != nil {
			// Go's x509 library may reject null bytes in Subject fields.
			t.Logf("x509.CreateCertificate rejected null byte in CN (expected): %v", err)
			return
		}

		parsed, err := x509.ParseCertificate(derBytes)
		if err != nil {
			t.Logf("x509.ParseCertificate rejected null byte in CN (expected): %v", err)
			return
		}

		cert := newSecCertFromX509(parsed)
		cb := NewChainBuilder()
		ts2 := &mockTrustStore{}
		paths, buildErr := cb.BuildChains(t.Context(), []*Certificate{cert}, ts2)
		require.NoError(t, buildErr, "null-byte CN must not cause BuildChains to panic or error")
		assert.NotEmpty(t, paths)
	})
}

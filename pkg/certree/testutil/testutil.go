// Package testutil provides certificate generators and helpers for testing.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// serialCounter provides unique serial numbers across all test certificate
// generators, avoiding RFC 5280 §4.1.2.2 collisions when multiple certs
// are generated within the same second.
var serialCounter atomic.Int64

const (
	keyPoolSize                = 16
	defaultRSAKeySize          = 2048
	rsa1024KeySize             = 1024
	rsa4096KeySize             = 4096
	defaultTestValidity        = 365 * 24 * time.Hour
	defaultTestNotBeforeOffset = -1 * time.Hour
	estimatedPEMCertSize       = 2048
)

// cachedKeyPool provides pre-generated RSA keys to avoid per-test key generation cost.
var cachedKeyPool = &keyPool{
	keys2048: make([]*rsa.PrivateKey, 0, keyPoolSize),
}

// cachedRSA1024 provides a shared RSA-1024 key, generating it once on first call.
var cachedRSA1024 struct {
	key  *rsa.PrivateKey
	once sync.Once
}

// getCachedRSA1024Key returns the shared RSA-1024 key, generating it once on first call.
func getCachedRSA1024Key() *rsa.PrivateKey {
	cachedRSA1024.once.Do(func() {
		// #nosec G403 -- Intentionally weak key for testing weak-key detection.
		key, err := rsa.GenerateKey(rand.Reader, rsa1024KeySize)
		if err != nil {
			panic("testutil: failed to generate RSA-1024 key: " + err.Error())
		}
		cachedRSA1024.key = key
	})
	return cachedRSA1024.key
}

var cachedRSA4096 struct {
	key  *rsa.PrivateKey
	once sync.Once
}

// getCachedRSA4096Key returns the shared RSA-4096 key, generating it once on first call.
func getCachedRSA4096Key() *rsa.PrivateKey {
	cachedRSA4096.once.Do(func() {
		// #nosec G403 -- Test-only key generation for performance caching.
		key, err := rsa.GenerateKey(rand.Reader, rsa4096KeySize)
		if err != nil {
			panic("testutil: failed to generate RSA-4096 key: " + err.Error())
		}
		cachedRSA4096.key = key
	})
	return cachedRSA4096.key
}

// CertificateTemplate contains parameters for generating a test certificate.
type CertificateTemplate struct {
	Subject             pkix.Name
	SerialNumber        *big.Int
	NotBefore           time.Time
	NotAfter            time.Time
	KeyUsage            x509.KeyUsage
	ExtKeyUsage         []x509.ExtKeyUsage
	IsCA                bool
	MaxPathLen          int
	MaxPathLenZero      bool
	DNSNames            []string
	EmailAddresses      []string
	IPAddresses         []string
	URIs                []string
	SubjectKeyID        []byte
	AuthorityKeyID      []byte
	OCSPServer          []string
	IssuingCertURL      []string
	CRLDistributionPts  []string
	PermittedDNSDomains []string
	ExcludedDNSDomains  []string
}

// keyPool provides a pool of RSA-2048 keys for use in tests.
type keyPool struct {
	keys2048 []*rsa.PrivateKey
	idx      int
	mu       sync.Mutex
	once     sync.Once
}

// Get returns a cached RSA-2048 key from the pool, cycling round-robin.
func (p *keyPool) Get() *rsa.PrivateKey {
	p.initPool()
	p.mu.Lock()
	defer p.mu.Unlock()
	key := p.keys2048[p.idx%keyPoolSize]
	p.idx++
	return key
}

// initPool pre-generates a pool of RSA-2048 keys in parallel.
func (p *keyPool) initPool() {
	p.once.Do(func() {
		keys := make([]*rsa.PrivateKey, keyPoolSize)
		var wg sync.WaitGroup
		for i := range keyPoolSize {
			idx := i
			wg.Go(func() {
				// #nosec G403 -- Test-only key generation for performance caching.
				key, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
				if err != nil {
					panic("testutil: failed to pre-generate RSA key: " + err.Error())
				}
				keys[idx] = key
			})
		}
		wg.Wait()
		p.keys2048 = keys
	})
}

// GetCachedKey returns a pre-generated RSA-2048 private key from the pool.
func GetCachedKey() *rsa.PrivateKey {
	return cachedKeyPool.Get()
}

// ApplyTemplateDefaults fills in zero-value fields with sensible defaults.
func ApplyTemplateDefaults(tmpl *CertificateTemplate) {
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(1)
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(defaultTestNotBeforeOffset)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(defaultTestValidity)
	}
}

// ToX509Template converts a CertificateTemplate to an x509.Certificate template.
func ToX509Template(tmpl CertificateTemplate) *x509.Certificate {
	ips := make([]net.IP, 0, len(tmpl.IPAddresses))
	for _, s := range tmpl.IPAddresses {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}

	uris := make([]*url.URL, 0, len(tmpl.URIs))
	for _, s := range tmpl.URIs {
		if u, err := url.Parse(s); err == nil {
			uris = append(uris, u)
		}
	}

	return &x509.Certificate{
		SerialNumber:          tmpl.SerialNumber,
		Subject:               tmpl.Subject,
		NotBefore:             tmpl.NotBefore,
		NotAfter:              tmpl.NotAfter,
		KeyUsage:              tmpl.KeyUsage,
		ExtKeyUsage:           tmpl.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  tmpl.IsCA,
		MaxPathLen:            tmpl.MaxPathLen,
		MaxPathLenZero:        tmpl.MaxPathLenZero,
		DNSNames:              tmpl.DNSNames,
		EmailAddresses:        tmpl.EmailAddresses,
		IPAddresses:           ips,
		URIs:                  uris,
		SubjectKeyId:          tmpl.SubjectKeyID,
		AuthorityKeyId:        tmpl.AuthorityKeyID,
		OCSPServer:            tmpl.OCSPServer,
		IssuingCertificateURL: tmpl.IssuingCertURL,
		CRLDistributionPoints: tmpl.CRLDistributionPts,
		PermittedDNSDomains:   tmpl.PermittedDNSDomains,
		ExcludedDNSDomains:    tmpl.ExcludedDNSDomains,
	}
}

// CreateAndParseCert signs a certificate template and parses the result.
func CreateAndParseCert(template, parent *x509.Certificate, publicKey, signingKey any) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signingKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

// GenerateSelfSignedCertUniqueKey generates a self-signed certificate with a fresh RSA key.
func GenerateSelfSignedCertUniqueKey(template CertificateTemplate) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	if err != nil {
		return nil, nil, err
	}

	ApplyTemplateDefaults(&template)
	certTemplate := ToX509Template(template)

	cert, err := CreateAndParseCert(certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, privateKey, nil
}

// GenerateSelfSignedCert generates a self-signed certificate using a cached RSA key.
func GenerateSelfSignedCert(template CertificateTemplate) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey := cachedKeyPool.Get()
	ApplyTemplateDefaults(&template)
	certTemplate := ToX509Template(template)

	cert, err := CreateAndParseCert(certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, privateKey, nil
}

// GenerateSignedCertUniqueKey generates a certificate signed by the provided issuer with a fresh RSA key.
func GenerateSignedCertUniqueKey(template CertificateTemplate, issuerCert *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	if err != nil {
		return nil, nil, err
	}

	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(serialCounter.Add(1))
	}
	ApplyTemplateDefaults(&template)
	certTemplate := ToX509Template(template)

	cert, err := CreateAndParseCert(certTemplate, issuerCert, &privateKey.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, privateKey, nil
}

// GenerateSignedCert generates a certificate signed by the provided issuer using a cached RSA key.
func GenerateSignedCert(template CertificateTemplate, issuerCert *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey := cachedKeyPool.Get()
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(serialCounter.Add(1))
	}
	ApplyTemplateDefaults(&template)
	certTemplate := ToX509Template(template)

	cert, err := CreateAndParseCert(certTemplate, issuerCert, &privateKey.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, privateKey, nil
}

// GenerateSelfSignedCertEd25519 generates a self-signed certificate using an Ed25519 key.
func GenerateSelfSignedCertEd25519(template CertificateTemplate) (*x509.Certificate, ed25519.PrivateKey, error) {
	pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}

	ApplyTemplateDefaults(&template)
	certTemplate := ToX509Template(template)

	cert, err := CreateAndParseCert(certTemplate, certTemplate, pubKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, privateKey, nil
}

// GenerateSelfSignedCertRSA4096 generates a self-signed certificate using a cached RSA-4096 key.
func GenerateSelfSignedCertRSA4096(template CertificateTemplate) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey := getCachedRSA4096Key()
	ApplyTemplateDefaults(&template)
	certTemplate := ToX509Template(template)

	cert, err := CreateAndParseCert(certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, privateKey, nil
}

// GenerateSelfSignedCertRSA1024 generates a self-signed certificate using a cached RSA-1024 key.
func GenerateSelfSignedCertRSA1024(template CertificateTemplate) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey := getCachedRSA1024Key()
	ApplyTemplateDefaults(&template)
	certTemplate := ToX509Template(template)

	cert, err := CreateAndParseCert(certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, privateKey, nil
}

// GenerateSimpleChain generates a simple 3-level certificate chain using cached RSA keys.
// Returns: [end-entity, intermediate, root].
func GenerateSimpleChain() ([]*x509.Certificate, []*rsa.PrivateKey, error) {
	rootTemplate := CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: 2,
	}
	rootCert, rootKey, err := GenerateSelfSignedCert(rootTemplate)
	if err != nil {
		return nil, nil, err
	}

	intermediateTemplate := CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Org"},
		},
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: 1,
	}
	intermediateCert, intermediateKey, err := GenerateSignedCert(intermediateTemplate, rootCert, rootKey)
	if err != nil {
		return nil, nil, err
	}

	endEntityTemplate := CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames:    []string{"test.example.com", "www.test.example.com"},
		IsCA:        false,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	endEntityCert, endEntityKey, err := GenerateSignedCert(endEntityTemplate, intermediateCert, intermediateKey)
	if err != nil {
		return nil, nil, err
	}

	certs := []*x509.Certificate{endEntityCert, intermediateCert, rootCert}
	keys := []*rsa.PrivateKey{endEntityKey, intermediateKey, rootKey}

	return certs, keys, nil
}

// GenerateChainWithDepth generates a certificate chain with a specific depth using cached RSA keys.
// Returns: [end-entity, intermediate(s), root].
func GenerateChainWithDepth(depth int) ([]*x509.Certificate, []*rsa.PrivateKey, error) {
	if depth <= 0 {
		return nil, nil, fmt.Errorf("chain depth must be at least 1, got %d", depth)
	}

	certs := make([]*x509.Certificate, 0, depth)
	keys := make([]*rsa.PrivateKey, 0, depth)

	rootTemplate := CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("Test Root CA (depth %d)", depth),
			Organization: []string{"Test Org"},
		},
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: depth - 1,
	}
	rootCert, rootKey, err := GenerateSelfSignedCert(rootTemplate)
	if err != nil {
		return nil, nil, fmt.Errorf("generating root certificate: %w", err)
	}

	if depth == 1 {
		return []*x509.Certificate{rootCert}, []*rsa.PrivateKey{rootKey}, nil
	}

	currentIssuer := rootCert
	currentIssuerKey := rootKey
	intermediates := make([]*x509.Certificate, 0, depth-2)
	intermediateKeys := make([]*rsa.PrivateKey, 0, depth-2)

	for i := depth - 2; i > 0; i-- {
		intermediateTemplate := CertificateTemplate{
			Subject: pkix.Name{
				CommonName:   fmt.Sprintf("Test Intermediate CA %d", i),
				Organization: []string{"Test Org"},
			},
			IsCA:       true,
			KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			MaxPathLen: i - 1,
		}
		var intermediateCert *x509.Certificate
		var intermediateKey *rsa.PrivateKey
		intermediateCert, intermediateKey, err = GenerateSignedCert(intermediateTemplate, currentIssuer, currentIssuerKey)
		if err != nil {
			return nil, nil, fmt.Errorf("generating intermediate certificate %d: %w", i, err)
		}

		intermediates = append(intermediates, intermediateCert)
		intermediateKeys = append(intermediateKeys, intermediateKey)

		currentIssuer = intermediateCert
		currentIssuerKey = intermediateKey
	}

	endEntityTemplate := CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames:    []string{"test.example.com", "www.test.example.com"},
		IsCA:        false,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	endEntityCert, endEntityKey, err := GenerateSignedCert(endEntityTemplate, currentIssuer, currentIssuerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generating end-entity certificate: %w", err)
	}

	certs = append(certs, endEntityCert)
	keys = append(keys, endEntityKey)

	for i, cert := range slices.Backward(intermediates) {
		certs = append(certs, cert)
		keys = append(keys, intermediateKeys[i])
	}

	certs = append(certs, rootCert)
	keys = append(keys, rootKey)

	return certs, keys, nil
}

// GenerateCertificateWithCN generates count certificates sharing the same CN.
func GenerateCertificateWithCN(cn string, count int) ([]*x509.Certificate, []*rsa.PrivateKey, error) {
	if count <= 0 {
		return nil, nil, fmt.Errorf("count must be greater than 0, got %d", count)
	}

	certs := make([]*x509.Certificate, 0, count)
	keys := make([]*rsa.PrivateKey, 0, count)

	for i := range count {
		template := CertificateTemplate{
			Subject: pkix.Name{
				CommonName: cn,
			},
			SerialNumber: big.NewInt(int64(i + 1)),
		}

		cert, key, err := GenerateSelfSignedCert(template)
		if err != nil {
			return nil, nil, fmt.Errorf("generating certificate %d: %w", i+1, err)
		}

		certs = append(certs, cert)
		keys = append(keys, key)
	}

	return certs, keys, nil
}

// GenerateCertificateWithExpiry generates a certificate with the given validity window.
func GenerateCertificateWithExpiry(cn string, notBefore, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey, error) {
	if !notBefore.Before(notAfter) {
		return nil, nil, fmt.Errorf("notBefore must be before notAfter: notBefore=%v, notAfter=%v", notBefore, notAfter)
	}

	template := CertificateTemplate{
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	cert, key, err := GenerateSelfSignedCert(template)
	if err != nil {
		return nil, nil, fmt.Errorf("generating certificate with expiry: %w", err)
	}

	return cert, key, nil
}

// GenerateCertificateWithAIA generates a certificate with a CA Issuers AIA URL.
func GenerateCertificateWithAIA(cn string, aiaURL string) (*x509.Certificate, *rsa.PrivateKey, error) {
	template := CertificateTemplate{
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	if aiaURL != "" {
		template.IssuingCertURL = []string{aiaURL}
	}

	cert, key, err := GenerateSelfSignedCert(template)
	if err != nil {
		return nil, nil, fmt.Errorf("generating certificate with AIA: %w", err)
	}

	return cert, key, nil
}

// GenerateCrossSigned creates a cross-signed version of targetCert: same subject and
// public key, but signed by crossSigner.
func GenerateCrossSigned(
	targetCert *x509.Certificate,
	crossSigner *x509.Certificate,
	crossSignerKey *rsa.PrivateKey,
) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               targetCert.Subject,
		NotBefore:             targetCert.NotBefore,
		NotAfter:              targetCert.NotAfter,
		KeyUsage:              targetCert.KeyUsage,
		ExtKeyUsage:           targetCert.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  targetCert.IsCA,
		MaxPathLen:            targetCert.MaxPathLen,
		MaxPathLenZero:        targetCert.MaxPathLenZero,
		SubjectKeyId:          targetCert.SubjectKeyId,
	}

	return CreateAndParseCert(template, crossSigner, targetCert.PublicKey, crossSignerKey)
}

// EncodePEM returns the PEM-encoded representation of a certificate.
func EncodePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// EncodePEMChain returns the PEM-encoded representation of a certificate chain.
func EncodePEMChain(certs []*x509.Certificate) []byte {
	result := make([]byte, 0, len(certs)*estimatedPEMCertSize)
	for _, cert := range certs {
		result = append(result, EncodePEM(cert)...)
	}
	return result
}

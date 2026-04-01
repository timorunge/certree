package certree

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pkcs12"

	"github.com/timorunge/certree/pkg/certree/testutil"
)

// PKCS#12 test encoder -- builds a valid PFX (PKCS#12) container from a
// certificate and private key using encoding/asn1 and the PKCS#12 KDF
// (RFC 7292 Appendix B). Only used in tests; not production quality.

// PKCS#12 ASN.1 OIDs.
var (
	oidPKCS7Data        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidCertBag          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidPKCS8ShroudedKey = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidX509Certificate  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidSHA1             = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidPBES1SHA1And3DES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
)

// pkcs12BMPString encodes a password as BMPString (UTF-16BE) with trailing null pair,
// per PKCS#12 section B.1.
func pkcs12BMPString(password string) []byte {
	bmp := make([]byte, (len(password)+1)*2)
	for i, r := range password {
		bmp[i*2] = byte(r >> 8)
		bmp[i*2+1] = byte(r)
	}
	return bmp
}

// pkcs12KDF implements PKCS#12 key derivation (RFC 7292 Appendix B.2).
func pkcs12KDF(newHash func() hash.Hash, id byte, password, salt []byte, iterations, size int) []byte {
	h := newHash()
	u := h.Size()      // hash output length
	v := h.BlockSize() // hash block size

	// Step 1: diversifier D.
	D := bytes.Repeat([]byte{id}, v)

	// Step 2: I = S || P padded to multiples of v.
	pad := func(src []byte) []byte {
		if len(src) == 0 {
			return nil
		}
		n := ((len(src) + v - 1) / v) * v
		out := make([]byte, n)
		for i := range out {
			out[i] = src[i%len(src)]
		}
		return out
	}
	S := pad(salt)
	P := pad(password)
	I := append(S, P...)

	var result []byte
	for len(result) < size {
		// A_i = H^iterations(D || I)
		h.Reset()
		h.Write(D)
		h.Write(I)
		A := h.Sum(nil)
		for range iterations - 1 {
			h.Reset()
			h.Write(A)
			A = h.Sum(nil)
		}
		result = append(result, A...)

		if len(result) >= size {
			break
		}

		// Compute B = A padded to v bytes, then I_j = (I_j + B + 1) mod 2^v.
		B := make([]byte, v)
		for i := range B {
			B[i] = A[i%u]
		}
		for j := 0; j < len(I)/v; j++ {
			carry := uint32(1)
			for k := v - 1; k >= 0; k-- {
				carry += uint32(I[j*v+k]) + uint32(B[k])
				I[j*v+k] = byte(carry)
				carry >>= 8
			}
		}
	}
	return result[:size]
}

// generateTestPKCS12 creates a PKCS#12 (PFX) container holding cert and key,
// protected by a password-based MAC. The AuthenticatedSafe contains two
// ContentInfo items (certs + keys) as required by golang.org/x/crypto/pkcs12.
func generateTestPKCS12(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey, password string) []byte {
	t.Helper()

	// Encode private key as PKCS#8.
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling PKCS#8 key: %v", err)
	}

	// --- Build cert SafeContents (ContentInfo #1, unencrypted data) ---
	// CertBag value: SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
	certBagContent := mustMarshalSequence(t,
		oidX509Certificate,
		wrapExplicit(t, mustMarshal(t, cert.Raw)),
	)
	// SafeBag: SEQUENCE { bagId OID, bagValue [0] EXPLICIT CertBag }
	certSafeBag := mustMarshalSequence(t,
		oidCertBag,
		wrapExplicit(t, certBagContent),
	)
	// SafeContents: SEQUENCE OF SafeBag
	certSafeContents := wrapSequenceOf(t, certSafeBag)
	// ContentInfo: SEQUENCE { contentType OID, content [0] EXPLICIT OCTET STRING(SafeContents) }
	certContentInfo := mustMarshalSequence(t,
		oidPKCS7Data,
		wrapExplicit(t, mustMarshal(t, certSafeContents)),
	)

	// --- Build key SafeContents (ContentInfo #2, unencrypted data) ---
	// KeyBag: raw PKCS#8 key
	// Encrypt PKCS#8 key with PBE-SHA1-3DES (the format x/crypto/pkcs12 expects).
	encryptedKey := pkcs12EncryptPBE(t, pkcs8Key, password)
	keySafeBag := mustMarshalSequence(t,
		oidPKCS8ShroudedKey,
		wrapExplicit(t, encryptedKey),
	)
	keySafeContents := wrapSequenceOf(t, keySafeBag)
	keyContentInfo := mustMarshalSequence(t,
		oidPKCS7Data,
		wrapExplicit(t, mustMarshal(t, keySafeContents)),
	)

	// --- AuthenticatedSafe: SEQUENCE OF ContentInfo (exactly 2) ---
	authSafeBytes := wrapSequenceOf(t, certContentInfo, keyContentInfo)

	// --- Outer ContentInfo wrapping the AuthenticatedSafe ---
	outerContentInfo := mustMarshalSequence(t,
		oidPKCS7Data,
		wrapExplicit(t, mustMarshal(t, authSafeBytes)),
	)

	// --- Compute MAC over authSafeBytes ---
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generating salt: %v", err)
	}
	const macIterations = 2048
	bmpPassword := pkcs12BMPString(password)
	macKey := pkcs12KDF(sha1.New, 3, bmpPassword, salt, macIterations, 20)
	h := hmac.New(sha1.New, macKey)
	h.Write(authSafeBytes)
	macDigest := h.Sum(nil)

	// MacData: SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER }
	digestAlg := mustMarshalSequence(t, oidSHA1, asn1.RawValue{Tag: asn1.TagNull})
	digestInfo := mustMarshalSequence(t,
		asn1.RawValue{FullBytes: digestAlg},
		asn1.RawValue{FullBytes: mustMarshal(t, macDigest)},
	)
	macData := mustMarshalSequence(t,
		asn1.RawValue{FullBytes: digestInfo},
		salt,
		macIterations,
	)

	// PFX: SEQUENCE { version INTEGER(3), authSafe ContentInfo, macData MacData }
	return mustMarshalSequence(t,
		3,
		asn1.RawValue{FullBytes: outerContentInfo},
		asn1.RawValue{FullBytes: macData},
	)
}

// pkcs12EncryptPBE encrypts data using PBE-SHA1-3DES (OID 1.2.840.113549.1.12.1.3)
// and returns an EncryptedPrivateKeyInfo DER structure.
func pkcs12EncryptPBE(t *testing.T, data []byte, password string) []byte {
	t.Helper()

	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generating PBE salt: %v", err)
	}
	const iterations = 2048
	bmpPassword := pkcs12BMPString(password)

	// Derive 24-byte 3DES key (purpose ID 1) and 8-byte IV (purpose ID 2).
	desKey := pkcs12KDF(sha1.New, 1, bmpPassword, salt, iterations, 24)
	iv := pkcs12KDF(sha1.New, 2, bmpPassword, salt, iterations, 8)

	// PKCS#7 pad to 3DES block size (8 bytes).
	padLen := 8 - len(data)%8
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	// Encrypt with 3DES-CBC.
	block, err := des.NewTripleDESCipher(desKey) //nolint:gosec // test-only, intentional weak crypto for PKCS#12 compat
	if err != nil {
		t.Fatalf("creating 3DES cipher: %v", err)
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(padded))
	cbc.CryptBlocks(encrypted, padded)

	// AlgorithmIdentifier: SEQUENCE { OID, SEQUENCE { salt OCTET STRING, iterations INTEGER } }
	pbeParams := mustMarshalSequence(t, salt, iterations)
	algID := mustMarshalSequence(t, oidPBES1SHA1And3DES, asn1.RawValue{FullBytes: pbeParams})

	// EncryptedPrivateKeyInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
	return mustMarshalSequence(t, asn1.RawValue{FullBytes: algID}, asn1.RawValue{FullBytes: mustMarshal(t, encrypted)})
}

// wrapExplicit wraps DER bytes in an ASN.1 context-specific EXPLICIT tag.
func wrapExplicit(t *testing.T, content []byte) asn1.RawValue {
	t.Helper()
	return asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: content,
	}
}

// wrapSequenceOf wraps one or more DER-encoded items in a SEQUENCE.
func wrapSequenceOf(t *testing.T, items ...[]byte) []byte {
	t.Helper()
	var content []byte
	for _, item := range items {
		content = append(content, item...)
	}
	result, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: content,
	})
	if err != nil {
		t.Fatalf("asn1.Marshal SEQUENCE OF: %v", err)
	}
	return result
}

// mustMarshal marshals val to ASN.1 DER, failing the test on error.
func mustMarshal(t *testing.T, val any) []byte {
	t.Helper()
	data, err := asn1.Marshal(val)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return data
}

// mustMarshalSequence marshals multiple values into a single ASN.1 SEQUENCE.
func mustMarshalSequence(t *testing.T, vals ...any) []byte {
	t.Helper()
	var content []byte
	for _, v := range vals {
		switch vv := v.(type) {
		case asn1.RawValue:
			if vv.FullBytes != nil {
				content = append(content, vv.FullBytes...)
			} else {
				b, err := asn1.Marshal(vv)
				if err != nil {
					t.Fatalf("asn1.Marshal RawValue: %v", err)
				}
				content = append(content, b...)
			}
		default:
			b, err := asn1.Marshal(v)
			if err != nil {
				t.Fatalf("asn1.Marshal: %v", err)
			}
			content = append(content, b...)
		}
	}
	result, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: content,
	})
	if err != nil {
		t.Fatalf("asn1.Marshal SEQUENCE: %v", err)
	}
	return result
}

// goErrorInternals contains substrings characteristic of raw Go error internals
// that must not appear in user-facing messages.
var goErrorInternals = []string{
	"dial tcp",
	"lookup",
	"read tcp",
	"tls:",
	"x509:",
	"asn1:",
}

// buildPKCS7SignedData constructs a minimal PKCS#7 SignedData ASN.1 structure
// containing the given certificates. Used for testing parsePKCS7.
//
// Encoding follows RFC 5652 section 5.1 / RFC 2315 section 9.1:
//
//	certificates [0] IMPLICIT SET OF CertificateChoices
//
// With IMPLICIT tagging the SET tag (0x31) is replaced by context [0] (0xa0),
// so the content inside [0] is the raw concatenation of certificate DER bytes
// with NO inner SEQUENCE or SET wrapper.
func buildPKCS7SignedData(t *testing.T, certs []*x509.Certificate) []byte {
	t.Helper()

	// Concatenate raw certificate DER bytes directly -- no SEQUENCE wrapper.
	// This matches the RFC 5652 [0] IMPLICIT SET OF CertificateChoices encoding.
	var certsBuf bytes.Buffer
	for _, cert := range certs {
		certsBuf.Write(cert.Raw)
	}

	// Build SignedData SEQUENCE manually.
	versionBytes, _ := asn1.Marshal(1)
	emptySet := []byte{0x31, 0x00} // SET {}
	dataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	dataOIDBytes, _ := asn1.Marshal(dataOID)
	contentInfoBytes := marshalASN1Seq(t, dataOIDBytes)      // SEQUENCE { OID }
	certsTagged := marshalASN1Tag(t, 0xa0, certsBuf.Bytes()) // [0] IMPLICIT SET content
	signedDataInner := concatBytes(versionBytes, emptySet, contentInfoBytes, certsTagged, emptySet)
	signedDataSeq := marshalASN1Seq(t, signedDataInner)

	// Outer PKCS#7: SEQUENCE { signedData OID, [0] EXPLICIT { SignedData } }.
	signedDataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidBytes, _ := asn1.Marshal(signedDataOID)
	explicitContent := marshalASN1Tag(t, 0xa0, signedDataSeq)
	return marshalASN1Seq(t, concatBytes(oidBytes, explicitContent))
}

// buildPKCS7WithOID constructs a minimal PKCS#7 structure with the given content type OID.
func buildPKCS7WithOID(t *testing.T, oid []int) []byte {
	t.Helper()

	oidBytes, _ := asn1.Marshal(asn1.ObjectIdentifier(oid))
	emptySeq := marshalASN1Seq(t, nil)
	explicitContent := marshalASN1Tag(t, 0xa0, emptySeq)
	return marshalASN1Seq(t, concatBytes(oidBytes, explicitContent))
}

// buildPKCS7SignedDataWithInvalid constructs a PKCS#7 SignedData with valid certs
// plus one invalid certificate entry (garbage bytes).
//
// Encoding follows RFC 5652 section 5.1: certificates [0] IMPLICIT SET OF CertificateChoices.
// The content inside [0] is the raw concatenation of certificate DER bytes with NO
// inner SEQUENCE or SET wrapper. Valid cert DER bytes are concatenated directly,
// followed by a minimal SEQUENCE with garbage content to trigger parse errors.
func buildPKCS7SignedDataWithInvalid(t *testing.T, validCerts []*x509.Certificate) []byte {
	t.Helper()

	// Concatenate raw certificate DER bytes directly -- no SEQUENCE wrapper.
	var certsBuf bytes.Buffer
	for _, cert := range validCerts {
		certsBuf.Write(cert.Raw)
	}
	// Append an invalid certificate entry (a minimal SEQUENCE with garbage content).
	invalidCert := marshalASN1Seq(t, []byte{0x01, 0x02, 0x03})
	certsBuf.Write(invalidCert)

	versionBytes, _ := asn1.Marshal(1)
	emptySet := []byte{0x31, 0x00}
	dataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	dataOIDBytes, _ := asn1.Marshal(dataOID)
	contentInfoBytes := marshalASN1Seq(t, dataOIDBytes)
	certsTagged := marshalASN1Tag(t, 0xa0, certsBuf.Bytes())
	signedDataInner := concatBytes(versionBytes, emptySet, contentInfoBytes, certsTagged, emptySet)
	signedDataSeq := marshalASN1Seq(t, signedDataInner)

	signedDataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidBytes, _ := asn1.Marshal(signedDataOID)
	explicitContent := marshalASN1Tag(t, 0xa0, signedDataSeq)
	return marshalASN1Seq(t, concatBytes(oidBytes, explicitContent))
}

// marshalASN1Seq wraps content in an ASN.1 SEQUENCE (tag 0x30).
func marshalASN1Seq(t *testing.T, content []byte) []byte {
	t.Helper()
	return marshalASN1Tag(t, 0x30, content)
}

// marshalASN1Tag wraps content in an ASN.1 TLV with the given tag.
func marshalASN1Tag(t *testing.T, tag byte, content []byte) []byte {
	t.Helper()
	length := len(content)
	if length < 128 {
		result := make([]byte, 0, 2+length)
		result = append(result, tag, byte(length))
		result = append(result, content...)
		return result
	}
	var lenBytes []byte
	l := length
	for l > 0 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
		l >>= 8
	}
	result := make([]byte, 0, 2+len(lenBytes)+length)
	// #nosec G115 -- length is bounded by certificate size, no overflow risk in tests.
	result = append(result, tag, byte(0x80|len(lenBytes)))
	result = append(result, lenBytes...)
	result = append(result, content...)
	return result
}

// concatBytes joins multiple byte slices.
func concatBytes(slices ...[]byte) []byte {
	total := 0
	for _, s := range slices {
		total += len(s)
	}
	result := make([]byte, 0, total)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}

func TestParser_FailFast(t *testing.T) {
	t.Parallel()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cert, _, err := testutil.GenerateSelfSignedCertUniqueKey(template)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	// Create PEM with valid and invalid certificates.
	validPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid data"),
	})

	validPEM = append(validPEM, invalidPEM...)
	pemData := validPEM

	// Create parser with SkipInvalid disabled (fail-fast).
	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))

	// Parse - should fail on invalid certificate.
	_, err = p.ParseBytes(pemData)
	if err == nil {
		t.Fatal("expected error for invalid certificate, got nil")
	}
}

func TestParser_CertificateLimit(t *testing.T) {
	t.Parallel()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cert, _, err := testutil.GenerateSelfSignedCertUniqueKey(template)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	// Create PEM with 3 certificates.
	certBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	pemData := make([]byte, 0, 3*len(certBlock))
	for range 3 {
		pemData = append(pemData, certBlock...)
	}

	// Create parser with limit of 2.
	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(2))

	// Parse - should fail due to limit.
	_, err = p.ParseBytes(pemData)
	if err == nil {
		t.Fatal("expected error for certificate limit exceeded, got nil")
	}
}

func TestParser_MultiCertificateOrderPreservation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		numCerts int
	}{
		{"two certificates", 2},
		{"three certificates", 3},
		{"four certificates", 4},
		{"five certificates", 5},
	}

	// Pre-generate certificates with distinct CNs and serials.
	certs := make([]*x509.Certificate, 5)
	for i := range 5 {
		template := testutil.CertificateTemplate{
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("order-test-%d.example.com", i),
			},
		}
		cert, _, err := testutil.GenerateSelfSignedCert(template)
		if err != nil {
			t.Fatalf("generating cert %d: %v", i, err)
		}
		certs[i] = cert
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var pemData bytes.Buffer
			for i := range tt.numCerts {
				if err := pem.Encode(&pemData, &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: certs[i].Raw,
				}); err != nil {
					t.Fatalf("encoding PEM: %v", err)
				}
			}

			p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))
			parsed, err := p.ParseBytes(pemData.Bytes())
			if err != nil {
				t.Fatalf("ParseBytes: %v", err)
			}

			if len(parsed) != tt.numCerts {
				t.Fatalf("got %d certificates, want %d", len(parsed), tt.numCerts)
			}

			for i, parsedCert := range parsed {
				if parsedCert.Raw().Subject.CommonName != certs[i].Subject.CommonName {
					t.Errorf("position %d: got CN %q, want %q",
						i, parsedCert.Raw().Subject.CommonName, certs[i].Subject.CommonName)
				}
			}
		})
	}
}

func TestParser_FileContext(t *testing.T) {
	t.Parallel()

	template := testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cert, _, err := testutil.GenerateSelfSignedCertUniqueKey(template)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Create temporary file.
	tmpFile := t.TempDir() + "/test.pem"
	// #nosec G306 -- Test file with intentionally permissive permissions
	err = os.WriteFile(tmpFile, pemData, 0644)
	if err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	// Create parser.
	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))

	// Test with canceled context.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = p.ParseFile(ctx, tmpFile)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got %v", err)
	}

	// Test with valid context.
	certs, err := p.ParseFile(t.Context(), tmpFile)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}
}

func TestParseRemote_DefaultTimeout(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	// Create parser.
	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))

	opts := RemoteOptions{
		Timeout:        0,             // No timeout specified - should use default 5s
		SNI:            "example.com", // Provide SNI for IP address
		VerifyHostname: false,
	}

	// Use a non-routable IP that will timeout.
	_, err := p.ParseRemote(t.Context(), "192.0.2.1:443", opts)
	if err == nil {
		t.Error("expected timeout error, got nil")
	}

	isExpected := errors.Is(err, ErrConnectionFailed)
	if !isExpected {
		// Also accept a raw timeout / deadline exceeded error.
		isExpected = os.IsTimeout(err) || errors.Is(err, context.DeadlineExceeded)
	}
	if !isExpected {
		t.Errorf("expected ErrConnectionFailed or timeout error, got %v", err)
	}
}

func TestParseRemote_ReturnsStructuredError(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))

	ctx := t.Context()
	opts := RemoteOptions{
		Timeout:        2 * time.Second,
		SNI:            "example.com",
		VerifyHostname: false,
	}

	// Get a port that is guaranteed to not be listening.
	ln, listenErr := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("failed to allocate port: %v", listenErr)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, err := p.ParseRemote(ctx, addr, opts)
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}

	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("errors.Is(err, ErrConnectionFailed) = false, want true; err = %v", err)
	}

	se, ok := errors.AsType[*StructuredError](err)
	if !ok {
		t.Fatalf("errors.As(err, *StructuredError) = false, want true; err = %v", err)
	}

	msg := se.UserMessage()
	if !strings.Contains(msg, addr) {
		t.Errorf("UserMessage() should contain host:port, got %q", msg)
	}
	for _, internal := range goErrorInternals {
		if strings.Contains(msg, internal) {
			t.Errorf("UserMessage() contains Go internal %q: %s", internal, msg)
		}
	}

	if se.Detail() == nil {
		t.Error("Detail() should be non-nil for a connection failure")
	}

	if se.Category() != ErrConnectionFailed {
		t.Errorf("Category() = %v, want ErrConnectionFailed", se.Category())
	}
}

func TestParseFile_ReturnsStructuredError(t *testing.T) {
	t.Parallel()

	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))

	// Use a nonexistent path rooted in t.TempDir() so it is absolute on all
	// platforms, including Windows where "/nonexistent/..." is not absolute.
	certPath := filepath.Join(t.TempDir(), "nonexistent", "cert.pem")
	_, err := p.ParseFile(t.Context(), certPath)
	if err == nil {
		t.Fatal("expected file read error, got nil")
	}

	if !errors.Is(err, ErrFileReadFailed) {
		t.Errorf("errors.Is(err, ErrFileReadFailed) = false, want true; err = %v", err)
	}

	se, ok := errors.AsType[*StructuredError](err)
	if !ok {
		t.Fatalf("errors.As(err, *StructuredError) = false, want true; err = %v", err)
	}

	msg := se.UserMessage()
	if !strings.Contains(msg, certPath) {
		t.Errorf("UserMessage() should contain file path, got %q", msg)
	}
	for _, internal := range goErrorInternals {
		if strings.Contains(msg, internal) {
			t.Errorf("UserMessage() contains Go internal %q: %s", internal, msg)
		}
	}

	if se.Detail() == nil {
		t.Error("Detail() should be non-nil for a stat failure")
	}

	if se.Category() != ErrFileReadFailed {
		t.Errorf("Category() = %v, want ErrFileReadFailed", se.Category())
	}
}

func TestParseBytes_ReturnsStructuredError(t *testing.T) {
	t.Parallel()

	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))

	tests := []struct {
		name    string
		data    []byte
		wantCat error
	}{
		{
			name:    "empty input",
			data:    nil,
			wantCat: ErrEmptyInput,
		},
		{
			name:    "unknown format",
			data:    []byte("not a certificate"),
			wantCat: ErrUnknownFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := p.ParseBytes(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, tt.wantCat) {
				t.Errorf("errors.Is(err, %v) = false, want true; err = %v", tt.wantCat, err)
			}

			se, ok := errors.AsType[*StructuredError](err)
			if !ok {
				t.Fatalf("errors.As(err, *StructuredError) = false, want true; err = %v", err)
			}

			msg := se.UserMessage()
			for _, internal := range goErrorInternals {
				if strings.Contains(msg, internal) {
					t.Errorf("UserMessage() contains Go internal %q: %s", internal, msg)
				}
			}

			if se.Category() != tt.wantCat {
				t.Errorf("Category() = %v, want %v", se.Category(), tt.wantCat)
			}
		})
	}
}

func TestParsePKCS7_ValidBundle(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertUniqueKey() error = %v", err)
	}
	source := CertificateSource{Type: SourceTypeFile, Location: "test.p7b"}

	// Build a minimal PKCS#7 SignedData ASN.1 structure containing the certificate.
	pkcs7Data := buildPKCS7SignedData(t, []*x509.Certificate{cert})

	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))

	certs, err := p.(*defaultParser).parsePKCS7(pkcs7Data, source)
	if err != nil {
		t.Fatalf("parsePKCS7() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].CommonName() != cert.Subject.CommonName {
		t.Errorf("expected CN %q, got %q", cert.Subject.CommonName, certs[0].CommonName())
	}
}

func TestParsePKCS7_InvalidData(t *testing.T) {
	t.Parallel()

	source := CertificateSource{Type: SourceTypeFile, Location: "test.p7b"}
	p := NewParser(WithMaxCertificates(100))

	_, err := p.(*defaultParser).parsePKCS7([]byte("not-asn1"), source)
	if err == nil {
		t.Fatal("expected error for invalid data, got nil")
	}
}

func TestParsePKCS7_NotSignedData(t *testing.T) {
	t.Parallel()

	// Build a PKCS#7 structure with a non-SignedData OID.
	source := CertificateSource{Type: SourceTypeFile, Location: "test.p7b"}
	p := NewParser(WithMaxCertificates(100))

	// Construct a minimal ASN.1 structure with wrong OID (1.2.840.113549.1.7.1 = data, not signedData).
	notSignedData := buildPKCS7WithOID(t, []int{1, 2, 840, 113549, 1, 7, 1})

	_, err := p.(*defaultParser).parsePKCS7(notSignedData, source)
	if err == nil {
		t.Fatal("expected error for non-SignedData OID, got nil")
	}
	// parsePKCS7 wraps ErrParseFailed for both "not SignedData" and "extra data" cases.
	if !errors.Is(err, ErrParseFailed) {
		t.Errorf("expected error wrapping ErrParseFailed, got: %v", err)
	}
}

func TestParsePKCS7_ExtraData(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertUniqueKey() error = %v", err)
	}
	source := CertificateSource{Type: SourceTypeFile, Location: "test.p7b"}
	p := NewParser(WithMaxCertificates(100))

	pkcs7Data := buildPKCS7SignedData(t, []*x509.Certificate{cert})
	// Append extra data.
	pkcs7Data = append(pkcs7Data, 0x00, 0x00)

	_, err = p.(*defaultParser).parsePKCS7(pkcs7Data, source)
	if err == nil {
		t.Fatal("expected error for extra data, got nil")
	}
	// parsePKCS7 wraps ErrParseFailed for both "extra data" and "not SignedData" cases.
	if !errors.Is(err, ErrParseFailed) {
		t.Errorf("expected error wrapping ErrParseFailed, got: %v", err)
	}
}

func TestParsePKCS7_SkipInvalid(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertUniqueKey() error = %v", err)
	}
	source := CertificateSource{Type: SourceTypeFile, Location: "test.p7b"}

	// Build PKCS#7 with one valid cert and one invalid cert.
	pkcs7Data := buildPKCS7SignedDataWithInvalid(t, []*x509.Certificate{cert})

	p := NewParser(WithSkipInvalid(true), WithMaxCertificates(100))

	certs, err := p.(*defaultParser).parsePKCS7(pkcs7Data, source)
	if err != nil {
		t.Fatalf("parsePKCS7() with SkipInvalid error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 valid cert (skipping invalid), got %d", len(certs))
	}
}

func TestParsePKCS7_CertificateLimit(t *testing.T) {
	t.Parallel()

	cert1, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertUniqueKey() error = %v", err)
	}
	cert2, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertUniqueKey() error = %v", err)
	}
	source := CertificateSource{Type: SourceTypeFile, Location: "test.p7b"}

	pkcs7Data := buildPKCS7SignedData(t, []*x509.Certificate{cert1, cert2})

	p := NewParser(WithMaxCertificates(1))

	_, err = p.(*defaultParser).parsePKCS7(pkcs7Data, source)
	if err == nil {
		t.Fatal("expected error for certificate limit exceeded, got nil")
	}
	if !errors.Is(err, ErrCertificateLimitExceeded) {
		t.Errorf("expected error wrapping ErrCertificateLimitExceeded, got: %v", err)
	}
}

func TestParser_HostPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"hostname with port", "example.com:443", "example.com", "443", false},
		{"hostname only", "example.com", "example.com", "", false},
		{"ipv6 with port", "[::1]:443", "::1", "443", false},
		{"ipv6 without brackets", "::1:443", "", "", true},
		{"ipv4 with port", "192.168.1.1:443", "192.168.1.1", "443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			host, port, err := parseHostPort(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseHostPort(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr {
				if host != tt.wantHost {
					t.Errorf("parseHostPort(%q) host = %q, want %q", tt.input, host, tt.wantHost)
				}
				if port != tt.wantPort {
					t.Errorf("parseHostPort(%q) port = %q, want %q", tt.input, port, tt.wantPort)
				}
			}
		})
	}
}

func TestParseRemote_IPAddressRequiresSNI(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	tests := []struct {
		name string
		host string
	}{
		{"ipv4 standard port", "192.0.2.1:443"},
		{"ipv4 custom port", "10.0.0.1:8443"},
		{"ipv4 loopback", "127.0.0.1:443"},
		{"ipv6 loopback", "[::1]:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))

			ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
			defer cancel()

			opts := RemoteOptions{
				SNI:            "", // No SNI provided
				Timeout:        1 * time.Second,
				VerifyHostname: false,
			}

			_, err := p.ParseRemote(ctx, tt.host, opts)
			if err == nil {
				t.Fatal("expected error for IP address without SNI, got nil")
			}

			errMsg := err.Error()
			if !strings.Contains(errMsg, "SNI") && !strings.Contains(errMsg, "sni") {
				t.Errorf("error message should mention SNI requirement, got: %s", errMsg)
			}
		})
	}
}

func TestParseRemote_CustomTimeout(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))

	timeout := 500 * time.Millisecond

	opts := RemoteOptions{
		Timeout:        timeout,
		SNI:            "example.com",
		VerifyHostname: false,
	}

	start := time.Now()
	// Use non-routable IP address (192.0.2.0/24 is reserved for documentation).
	_, err := p.ParseRemote(t.Context(), "192.0.2.1:443", opts)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	// The operation should complete within a reasonable multiple of the timeout.
	maxExpected := timeout * 3
	if elapsed > maxExpected {
		t.Errorf("operation took %v, expected at most %v", elapsed, maxExpected)
	}

	// The operation should not complete instantly (should attempt connection).
	minExpected := 1 * time.Millisecond
	if elapsed < minExpected {
		t.Errorf("operation completed in %v, expected at least %v", elapsed, minExpected)
	}
}

func TestParser_ParseBytesPKCS12(t *testing.T) {
	t.Parallel()

	cert, key, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "PKCS12 Test Cert"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}
	expectedFingerprint := NewCertificate(cert, CertificateSource{Type: SourceTypeBytes}).FingerprintSHA256()

	p12Data := generateTestPKCS12(t, cert, key, "")

	// Verify our generated data is valid via pkcs12.ToPEM.
	blocks, err := pkcs12.ToPEM(p12Data, "")
	if err != nil {
		t.Fatalf("pkcs12.ToPEM validation failed: %v", err)
	}
	foundCert := false
	for _, block := range blocks {
		if block.Type == "CERTIFICATE" {
			foundCert = true
		}
	}
	if !foundCert {
		t.Fatal("pkcs12.ToPEM did not find certificate in generated data")
	}

	// Parse using the certree parser with auto-detect enabled.
	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))
	certs, err := p.ParseBytes(p12Data)
	if err != nil {
		t.Fatalf("ParseBytes() error = %v", err)
	}

	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}

	if certs[0].FingerprintSHA256() != expectedFingerprint {
		t.Errorf("fingerprint mismatch: got %s, want %s", certs[0].FingerprintSHA256(), expectedFingerprint)
	}
}

func TestParsePKCS12_PasswordProtected(t *testing.T) {
	t.Parallel()

	cert, key, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "Password Protected Cert"},
	})
	if err != nil {
		t.Fatalf("generating cert: %v", err)
	}

	p12Data := generateTestPKCS12(t, cert, key, "secret")

	// Verify the password-protected data is valid with the correct password.
	if _, verifyErr := pkcs12.ToPEM(p12Data, "secret"); verifyErr != nil {
		t.Fatalf("pkcs12.ToPEM with correct password failed: %v", verifyErr)
	}

	// Parse with the certree parser (which uses empty password) -- must fail.
	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))
	_, err = p.ParseBytes(p12Data)
	if err == nil {
		t.Fatal("expected error for password-protected PKCS#12, got nil")
	}
	if !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("expected ErrPasswordRequired, got: %v", err)
	}
}

func TestParser_ParseFileDER(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{
			CommonName:   "DER Test Certificate",
			Organization: []string{"Test Org"},
		},
	})
	if err != nil {
		t.Fatalf("generating certificate: %v", err)
	}

	// Write raw DER bytes to a temp file.
	tmpFile := t.TempDir() + "/test.der"
	// #nosec G306 -- Test file with intentionally permissive permissions.
	err = os.WriteFile(tmpFile, cert.Raw, 0644)
	if err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	expectedFingerprint := NewCertificate(cert, CertificateSource{Type: SourceTypeFile}).FingerprintSHA256()

	p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(100))
	certs, err := p.ParseFile(t.Context(), tmpFile)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}

	if certs[0].FingerprintSHA256() != expectedFingerprint {
		t.Errorf("fingerprint mismatch: got %s, want %s", certs[0].FingerprintSHA256(), expectedFingerprint)
	}
}

func TestParser_KeyTypeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cn       string
		keyUsage x509.KeyUsage
		// generate returns the cert; key type varies so we use a closure.
		generate func(testutil.CertificateTemplate) (*x509.Certificate, error)
	}{
		{
			name:     "Ed25519",
			cn:       "Ed25519 Test",
			keyUsage: x509.KeyUsageDigitalSignature,
			generate: func(tmpl testutil.CertificateTemplate) (*x509.Certificate, error) {
				c, _, err := testutil.GenerateSelfSignedCertEd25519(tmpl)
				return c, err
			},
		},
		{
			name:     "RSA-4096",
			cn:       "RSA-4096 Test",
			keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			generate: func(tmpl testutil.CertificateTemplate) (*x509.Certificate, error) {
				c, _, err := testutil.GenerateSelfSignedCertRSA4096(tmpl)
				return c, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert, err := tt.generate(testutil.CertificateTemplate{
				Subject: pkix.Name{
					CommonName:   tt.cn,
					Organization: []string{"Test Org"},
				},
				KeyUsage: tt.keyUsage,
			})
			if err != nil {
				t.Fatalf("generate() error = %v", err)
			}

			pemData := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})

			p := NewParser(WithAutoDetectFormat(true), WithMaxCertificates(10))
			certs, parseErr := p.ParseBytes(pemData)
			if parseErr != nil {
				t.Fatalf("ParseBytes() error = %v", parseErr)
			}

			if len(certs) != 1 {
				t.Fatalf("expected 1 certificate, got %d", len(certs))
			}

			if certs[0].CommonName() != tt.cn {
				t.Errorf("CommonName() = %q, want %q", certs[0].CommonName(), tt.cn)
			}
		})
	}
}

func TestWithParserLogger_NilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil logger, got none")
		}
	}()
	WithParserLogger(nil)(&defaultParser{})
}

func TestParseURL_PEM(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "URL Test CA"}, IsCA: true,
	})
	require.NoError(t, err)

	pemData := testutil.EncodePEM(cert)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pemData)
	}))
	defer server.Close()

	p := NewParser(WithAutoDetectFormat(true), WithParserAllowPrivateNetworks(true), WithHTTPUpgrade(false))
	certs, err := p.ParseURL(t.Context(), server.URL+"/ca.pem")
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "URL Test CA", certs[0].CommonName())
	assert.Equal(t, SourceTypeURL, certs[0].Source().Type)
}

func TestParseURL_DER(t *testing.T) {
	t.Parallel()

	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "DER URL Test"}, IsCA: true,
	})
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(cert.Raw)
	}))
	defer server.Close()

	p := NewParser(WithAutoDetectFormat(true), WithParserAllowPrivateNetworks(true), WithHTTPUpgrade(false))
	certs, err := p.ParseURL(t.Context(), server.URL+"/ca.der")
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "DER URL Test", certs[0].CommonName())
}

func TestParseURL_HTTPError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	p := NewParser(WithAutoDetectFormat(true), WithParserAllowPrivateNetworks(true), WithHTTPUpgrade(false))
	_, err := p.ParseURL(t.Context(), server.URL+"/missing.pem")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrURLFetchFailed)

	var se *StructuredError
	require.ErrorAs(t, err, &se)
	assert.Contains(t, se.UserMessage(), "HTTP 404")
}

func TestParseURL_EmptyResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := NewParser(WithAutoDetectFormat(true), WithParserAllowPrivateNetworks(true), WithHTTPUpgrade(false))
	_, err := p.ParseURL(t.Context(), server.URL+"/empty.pem")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyInput)
}

func TestParseURL_CanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	p := NewParser(WithAutoDetectFormat(true), WithParserAllowPrivateNetworks(true))
	_, err := p.ParseURL(ctx, "http://example.com/cert.pem")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestParseURL_SSRFBlocked(t *testing.T) {
	t.Parallel()

	p := NewParser(WithAutoDetectFormat(true))
	_, err := p.ParseURL(t.Context(), "http://127.0.0.1/cert.pem")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrURLFetchFailed)
}

func TestParser_RoundTrip(t *testing.T) {
	t.Parallel()

	raw, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "roundtrip.example.com"},
		IsCA:    true,
	})
	require.NoError(t, err)

	tests := []struct {
		name string
		data []byte
	}{
		{"PEM", testutil.EncodePEM(raw)},
		{"DER", raw.Raw},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := NewParser(WithAutoDetectFormat(true))
			parsed, err := p.ParseBytes(tt.data)
			require.NoError(t, err)
			require.Len(t, parsed, 1)

			assert.Equal(t, raw.Raw, parsed[0].Raw().Raw, "DER bytes must survive %s round-trip", tt.name)
			assert.Equal(t, raw.Subject.String(), parsed[0].Raw().Subject.String())
			assert.Equal(t, raw.NotBefore, parsed[0].Raw().NotBefore, "NotBefore must be preserved")
			assert.Equal(t, raw.NotAfter, parsed[0].Raw().NotAfter, "NotAfter must be preserved")
		})
	}
}

// writeCertFile writes PEM-encoded certificate data to path.
func writeCertFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

// generatePEMCert returns the PEM bytes of a fresh self-signed certificate.
func generatePEMCert(t *testing.T) []byte {
	t.Helper()
	cert, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "security-test"},
		IsCA:    true,
	})
	require.NoError(t, err)
	return testutil.EncodePEM(cert)
}

func TestSecurityParseBytes_MalformedData(t *testing.T) {
	t.Parallel()

	p := NewParser()

	cases := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{
			name:    "random garbage bytes",
			data:    []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0x00, 0x01},
			wantErr: ErrUnknownFormat,
		},
		{
			name:    "truncated PEM header only",
			data:    []byte("-----BEGIN CERTIFICATE-----"),
			wantErr: ErrUnknownFormat,
		},
		{
			name:    "partial base64 with no end marker",
			data:    []byte("-----BEGIN CERTIFICATE-----\nMIIB"),
			wantErr: ErrUnknownFormat,
		},
		{
			name: "wrong block type: PRIVATE KEY",
			// A syntactically valid PEM block, but not a certificate - the parser
			// must skip it and then report no certificates found (wrapped as unknown format).
			data:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("fake key")}),
			wantErr: ErrUnknownFormat,
		},
		{
			name: "corrupted base64 inside PEM block",
			// Invalid base64 characters between the markers trip the PEM decoder.
			data:    []byte("-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n"),
			wantErr: ErrUnknownFormat,
		},
		{
			name:    "empty byte slice",
			data:    []byte{},
			wantErr: ErrEmptyInput,
		},
		{
			name:    "single byte",
			data:    []byte{0x42},
			wantErr: ErrUnknownFormat,
		},
		{
			name: "PEM with embedded null bytes in data section",
			// Null bytes in the base64 payload corrupt the decoded DER, which must
			// not be silently ignored.
			data: func() []byte {
				raw := []byte("some\x00cert\x00data")
				encoded := base64.StdEncoding.EncodeToString(raw)
				return []byte("-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n")
			}(),
			wantErr: ErrUnknownFormat,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := p.ParseBytes(tc.data)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.wantErr),
				"want errors.Is(err, %v), got: %v", tc.wantErr, err)
		})
	}
}

func TestSecurityParseBytes_SizeLimits(t *testing.T) {
	t.Parallel()

	p := NewParser()

	t.Run("just under 10MB limit", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte("A"), maxParserInputSize-1)
		_, err := p.ParseBytes(data)
		// Input is accepted by the size gate; it fails later because it is not a cert.
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrInputTooLarge),
			"input under limit must not return ErrInputTooLarge")
	})

	t.Run("exactly at 10MB limit", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte("B"), maxParserInputSize)
		_, err := p.ParseBytes(data)
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrInputTooLarge),
			"input at exact limit must not return ErrInputTooLarge")
	})

	t.Run("one byte over 10MB limit", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte("C"), maxParserInputSize+1)
		_, err := p.ParseBytes(data)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInputTooLarge),
			"input over limit must return ErrInputTooLarge, got: %v", err)
	})
}

func TestSecurityParseBytes_FormatConfusion(t *testing.T) {
	t.Parallel()

	p := NewParser()

	cases := []struct {
		name string
		data []byte
	}{
		{
			name: "HTML content",
			data: []byte("<!DOCTYPE html><html><body><h1>Not a cert</h1></body></html>"),
		},
		{
			name: "JSON content",
			data: []byte(`{"type":"certificate","data":"dGVzdA=="}`),
		},
		{
			name: "JPEG header followed by PEM marker",
			// A JPEG magic number (\xFF\xD8\xFF) before a PEM marker tests
			// that the binary-data sniff path does not accidentally accept
			// content that merely contains the string "-----BEGIN CERTIFICATE-----".
			data: []byte("\xFF\xD8\xFF\xE0-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
		},
		{
			name: "ASN.1 valid structure but not a certificate",
			// A well-formed ASN.1 SEQUENCE wrapping a UTF8String. The DER parser
			// will accept the outer structure but x509.ParseCertificate must reject
			// it because it lacks the mandatory Certificate fields.
			data: func() []byte {
				type fakeASN struct {
					Value string `asn1:"utf8"`
				}
				der, _ := asn1.Marshal(fakeASN{Value: "not a certificate"})
				return der
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := p.ParseBytes(tc.data)
			require.Error(t, err, "format-confused input must be rejected")
		})
	}
}

func TestSecurityCertificateLimitEnforcement(t *testing.T) {
	t.Parallel()

	cert1, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "limit-test-1.example.com"},
	})
	require.NoError(t, err)

	cert2, _, err := testutil.GenerateSelfSignedCert(testutil.CertificateTemplate{
		Subject: pkix.Name{CommonName: "limit-test-2.example.com"},
	})
	require.NoError(t, err)

	twoCertPEM := append(testutil.EncodePEM(cert1), testutil.EncodePEM(cert2)...)

	t.Run("limit of 0 clamps to default 100", func(t *testing.T) {
		t.Parallel()
		// Zero is not a meaningful limit (it would reject everything) so it must
		// be clamped to DefaultMaxCertificates. A 2-cert bundle should succeed.
		p := NewParser(WithMaxCertificates(0))
		certs, parseErr := p.ParseBytes(twoCertPEM)
		require.NoError(t, parseErr)
		assert.Len(t, certs, 2, "zero limit clamped to default should accept 2 certs")
	})

	t.Run("negative limit clamps to default 100", func(t *testing.T) {
		t.Parallel()
		p := NewParser(WithMaxCertificates(-1))
		certs, parseErr := p.ParseBytes(twoCertPEM)
		require.NoError(t, parseErr)
		assert.Len(t, certs, 2, "negative limit clamped to default should accept 2 certs")
	})
}

func TestSecurityParseFilePathTraversal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemData := generatePEMCert(t)

	// Write a real cert at a known location so we can construct a traversal path
	// that still resolves to it after cleaning.
	target := filepath.Join(dir, "cert.pem")
	writeCertFile(t, target, pemData)

	p := NewParser()

	// filepath.Clean normalises traversal components before any stat or open call.
	subdir := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(subdir, 0o755))
	traversalPath := filepath.Join(subdir, "..", "cert.pem")

	certs, err := p.ParseFile(t.Context(), traversalPath)
	require.NoError(t, err, "traversal path resolving to real cert should succeed")
	assert.Len(t, certs, 1)
}

func TestSecurityParseFileDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := NewParser()

	_, err := p.ParseFile(t.Context(), dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestSecurityParseFileDevNull(t *testing.T) {
	t.Parallel()

	p := NewParser()
	_, err := p.ParseFile(t.Context(), "/dev/null")
	// /dev/null is a character device, not a regular file - expect ErrInvalidInput.
	require.Error(t, err)
}

func TestSecurityParseFileNullByte(t *testing.T) {
	t.Parallel()

	p := NewParser()
	// An embedded null byte would allow an attacker to craft a path that looks
	// like "/safe/path\x00evil" and hope the C layer stops at the null.
	_, err := p.ParseFile(t.Context(), "/tmp/cert\x00evil.pem")
	require.Error(t, err, "null byte in path must be rejected")
}

func TestSecurityParseFileSymlinkToCert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemData := generatePEMCert(t)

	real := filepath.Join(dir, "real.pem")
	writeCertFile(t, real, pemData)

	link := filepath.Join(dir, "link.pem")
	require.NoError(t, os.Symlink(real, link))

	p := NewParser()
	certs, err := p.ParseFile(t.Context(), link)
	require.NoError(t, err, "symlink to valid cert file should succeed")
	assert.Len(t, certs, 1)
}

func TestSecurityParseFileSymlinkToDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(target, 0o755))

	link := filepath.Join(dir, "dirlink")
	require.NoError(t, os.Symlink(target, link))

	p := NewParser()
	_, err := p.ParseFile(t.Context(), link)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestSecurityParseFileUnicodePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemData := generatePEMCert(t)

	// Unicode filenames are legitimate on all platforms certree targets.
	unicodePath := filepath.Join(dir, "Ünïcödé-cërt.pem")
	writeCertFile(t, unicodePath, pemData)

	p := NewParser()
	certs, err := p.ParseFile(t.Context(), unicodePath)
	require.NoError(t, err, "unicode filename should succeed")
	assert.Len(t, certs, 1)
}

func TestSecurityParseFileVeryLongPath(t *testing.T) {
	t.Parallel()

	// Build a path longer than PATH_MAX (4096 on Linux).
	longSegment := strings.Repeat("a", 300)
	veryLongPath := "/" + strings.Join([]string{
		longSegment, longSegment, longSegment,
		longSegment, longSegment, longSegment,
		longSegment, longSegment, longSegment,
		longSegment, longSegment, longSegment,
		longSegment, longSegment, "cert.pem",
	}, "/")

	p := NewParser()
	_, err := p.ParseFile(t.Context(), veryLongPath)
	// Exact error category depends on OS, but it must not panic.
	require.Error(t, err)
}

func TestSecurityParseFileEmptyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.pem")
	writeCertFile(t, emptyPath, []byte{})

	p := NewParser()
	_, err := p.ParseFile(t.Context(), emptyPath)
	require.Error(t, err, "empty file must not silently produce zero certificates")
}

func TestSecurityParseFileSizeLimit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemData := generatePEMCert(t)

	t.Run("small file succeeds", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "small.pem")
		writeCertFile(t, path, pemData)

		p := NewParser()
		certs, err := p.ParseFile(t.Context(), path)
		require.NoError(t, err)
		assert.NotEmpty(t, certs)
	})

	t.Run("oversized file returns ErrFileTooLarge", func(t *testing.T) {
		t.Parallel()
		// Write a file just over the 10 MB limit; contents don't need to be valid PEM.
		oversizedPath := filepath.Join(dir, "oversized.pem")
		data := make([]byte, maxParserInputSize+1)
		// Prefix with "-----BEGIN" so the file looks like PEM and passes sniff checks
		// if any caller runs ValidateSource first - the size gate fires before parsing.
		copy(data, []byte("-----BEGIN CERTIFICATE-----\n"))
		require.NoError(t, os.WriteFile(oversizedPath, data, 0o600))

		p := NewParser()
		_, err := p.ParseFile(t.Context(), oversizedPath)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrFileTooLarge,
			"files exceeding the 10 MB limit must return ErrFileTooLarge")
	})
}

func TestSecurityParseFileExtensions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemData := generatePEMCert(t)

	// Extensions that the parser recognizes.
	validExts := []string{".pem", ".crt", ".cer"}
	for _, ext := range validExts {
		t.Run("valid PEM with extension "+ext, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, "cert"+ext)
			writeCertFile(t, path, pemData)
			p := NewParser()
			certs, err := p.ParseFile(t.Context(), path)
			require.NoError(t, err)
			assert.NotEmpty(t, certs)
		})
	}

	// Text content written with a cert extension must produce a parse error, not a crash.
	badExts := []string{".pem", ".crt", ".txt"}
	for _, ext := range badExts {
		t.Run("garbage content with extension "+ext, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, "garbage"+ext)
			writeCertFile(t, path, []byte("not certificate data\n"))
			p := NewParser()
			_, err := p.ParseFile(t.Context(), path)
			// Must return an error, not silently succeed or panic.
			require.Error(t, err)
			// Verify the error is typed (StructuredError), not a raw panic value.
			se, ok := errors.AsType[*StructuredError](err)
			assert.True(t, ok,
				"parse error for non-cert content must be a StructuredError, got %T: %v", err, err)
			_ = se
		})
	}
}

func TestSecurityParseFileShellInjectionLikePaths(t *testing.T) {
	t.Parallel()

	// These look like shell injection patterns. They should fail with a file-not-found
	// style error (ErrFileReadFailed) because the OS tries to open the literal path.
	injectionPaths := []string{
		"/tmp/$(whoami).pem",
		"/tmp/`id`.pem",
		"/tmp/cert|cat /etc/passwd",
		"/tmp/cert;touch /tmp/pwned",
	}

	p := NewParser()
	for _, path := range injectionPaths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			_, err := p.ParseFile(t.Context(), path)
			// The path is treated as a literal; the file doesn't exist.
			require.Error(t, err,
				"shell-injection-like path must fail, not execute a command")
			assert.ErrorIs(t, err, ErrFileReadFailed,
				"literal non-existent path must return ErrFileReadFailed")
		})
	}
}

func TestSecurityParseFileConcurrent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pemData := generatePEMCert(t)
	path := filepath.Join(dir, "concurrent.pem")
	writeCertFile(t, path, pemData)

	p := NewParser()
	const goroutines = 20

	var wg sync.WaitGroup

	errs := make([]error, goroutines)
	counts := make([]int, goroutines)

	for i := range goroutines {
		idx := i
		wg.Go(func() {
			certs, err := p.ParseFile(t.Context(), path)
			errs[idx] = err
			counts[idx] = len(certs)
		})
	}

	wg.Wait()

	for i := range goroutines {
		assert.NoError(t, errs[i], "goroutine %d must not error", i)
		assert.Equal(t, 1, counts[i], "goroutine %d must parse exactly 1 cert", i)
	}
}

func TestSecurityHTTPUpgrade_Behavior(t *testing.T) {
	t.Parallel()

	t.Run("http is upgraded to https", func(t *testing.T) {
		t.Parallel()
		got := upgradeHTTPToHTTPS("http://example.com/cert.pem")
		assert.Equal(t, "https://example.com/cert.pem", got)
	})

	t.Run("https is not double-upgraded", func(t *testing.T) {
		t.Parallel()
		got := upgradeHTTPToHTTPS("https://example.com/cert.pem")
		assert.Equal(t, "https://example.com/cert.pem", got)
	})

	t.Run("non-http schemes are unchanged", func(t *testing.T) {
		t.Parallel()
		// ftp:// must not be silently upgraded to ftps:// or https://.
		got := upgradeHTTPToHTTPS("ftp://example.com/cert.pem")
		assert.Equal(t, "ftp://example.com/cert.pem", got)
	})

	t.Run("ParseURL with default settings upgrades http to https causing TLS error on plain server", func(t *testing.T) {
		t.Parallel()

		// A plain-HTTP server is deliberately used here.  With the default upgrade
		// setting the parser rewrites http:// to https:// before sending, so the
		// connection attempt hits the plain-HTTP server with a TLS handshake and
		// fails.  The fetch error proves the URL was upgraded; a successful
		// connection would mean the upgrade did not fire.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		// Default parser: httpUpgrade=true, SSRF guard on.  Allow private
		// networks so httptest's loopback address is reachable, but keep upgrade
		// enabled to exercise the rewrite path.
		parser := NewParser(
			WithParserAllowPrivateNetworks(true),
			// WithHTTPUpgrade intentionally omitted so the default (true) applies.
			WithURLFetchTimeout(3*time.Second),
		)

		// Convert the https:// URL that the TLS server would have back to http://
		// so we can feed it to ParseURL and watch the upgrade kick in.
		httpURL := "http://" + srv.Listener.Addr().String() + "/"
		_, err := parser.ParseURL(t.Context(), httpURL)
		// The parser upgrades http:// to https://, then tries a TLS handshake
		// against the plain-HTTP server, which causes a connection error.
		require.Error(t, err, "expected TLS failure proving the http→https upgrade fired")
		assert.True(t, errors.Is(err, ErrURLFetchFailed),
			"expected ErrURLFetchFailed after failed TLS handshake on upgraded URL, got: %v", err)
	})

	t.Run("WithHTTPUpgrade false leaves http as-is", func(t *testing.T) {
		t.Parallel()

		// Serve a PEM cert over plain HTTP so we can verify the parser reaches it.
		ca, caKey, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{
			Subject: pkix.Name{CommonName: "NoUpgrade CA"},
			IsCA:    true,
		})
		require.NoError(t, err)

		leaf, _, err := testutil.GenerateSignedCert(testutil.CertificateTemplate{
			Subject:  pkix.Name{CommonName: "noupgrade.example.com"},
			DNSNames: []string{"noupgrade.example.com"},
		}, ca, caKey)
		require.NoError(t, err)

		pemData := testutil.EncodePEM(leaf)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-pem-file")
			_, _ = w.Write(pemData)
		}))
		defer srv.Close()

		// Private networks must be allowed because httptest binds to 127.0.0.1.
		parser := NewParser(
			WithParserAllowPrivateNetworks(true),
			WithHTTPUpgrade(false),
			WithURLFetchTimeout(3*time.Second),
		)
		certs, err := parser.ParseURL(t.Context(), srv.URL)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
	})
}

func TestSecurityParseURL_HostileServerBehavior(t *testing.T) {
	t.Parallel()

	t.Run("server sending oversized body without Content-Length", func(t *testing.T) {
		t.Parallel()

		oversizeBody := strings.Repeat("X", maxParserInputSize+1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			// Deliberately omit Content-Length so the client streams the body.
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, oversizeBody)
		}))
		defer srv.Close()

		parser := NewParser(
			WithParserAllowPrivateNetworks(true),
			WithHTTPUpgrade(false),
			WithURLFetchTimeout(30*time.Second),
		)
		_, err := parser.ParseURL(t.Context(), srv.URL)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInputTooLarge),
			"expected ErrInputTooLarge for oversized response, got: %v", err)
	})

	t.Run("server returning non-certificate content with 200 OK", func(t *testing.T) {
		t.Parallel()

		// A misconfigured or attacker-controlled endpoint might return HTML or
		// JSON.  The parser must reject content that is not a valid certificate.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "<html><body>not a certificate</body></html>")
		}))
		defer srv.Close()

		parser := NewParser(
			WithParserAllowPrivateNetworks(true),
			WithHTTPUpgrade(false),
			WithURLFetchTimeout(5*time.Second),
		)
		_, err := parser.ParseURL(t.Context(), srv.URL)
		require.Error(t, err, "expected parse error for non-certificate content")
	})
}

func TestSecurityParser_ConcurrentParseBytes(t *testing.T) {
	t.Parallel()

	const goroutines = 16

	// Prepare distinct PEM payloads so goroutines cannot share a result by
	// accident; state leakage between calls would produce cross-cert results.
	rawPEMs := make([][]byte, goroutines)
	fingerprints := make([]string, goroutines)
	for i := range goroutines {
		rawCert, _, err := testutil.GenerateSelfSignedCertUniqueKey(testutil.CertificateTemplate{})
		require.NoError(t, err)
		rawPEMs[i] = testutil.EncodePEM(rawCert)
		// Compute expected fingerprint via NewCertificate so we can assert
		// that each goroutine parsed its own certificate, not another's.
		parsed := NewCertificate(rawCert, CertificateSource{Type: SourceTypeBytes})
		fingerprints[i] = parsed.FingerprintSHA256()
	}

	parser := NewParser()

	var wg sync.WaitGroup

	for i := range goroutines {
		idx := i
		wg.Go(func() {
			certs, err := parser.ParseBytes(rawPEMs[idx])
			assert.NoError(t, err, "goroutine %d: ParseBytes error", idx)
			if assert.Len(t, certs, 1, "goroutine %d: expected 1 certificate", idx) {
				assert.Equal(t, fingerprints[idx], certs[0].FingerprintSHA256(),
					"goroutine %d: fingerprint mismatch (state leakage?)", idx)
			}
		})
	}

	wg.Wait()
}

func TestSecurityOptionsDoNotLeakState(t *testing.T) {
	t.Parallel()

	p1 := NewParser(
		WithMaxCertificates(10),
		WithSkipInvalid(true),
		WithAutoDetectFormat(false),
	).(*defaultParser)

	p2 := NewParser(
		WithMaxCertificates(99),
		WithSkipInvalid(false),
		WithAutoDetectFormat(true),
	).(*defaultParser)

	// Options from p2 must not bleed into p1.
	assert.Equal(t, 10, p1.opts.maxCertificates)
	assert.True(t, p1.opts.skipInvalid)
	assert.False(t, p1.opts.autoDetectFormat)

	assert.Equal(t, 99, p2.opts.maxCertificates)
	assert.False(t, p2.opts.skipInvalid)
	assert.True(t, p2.opts.autoDetectFormat)
}

func TestSecurityDoubleOptionApplication_WithMaxCertificates(t *testing.T) {
	t.Parallel()

	// Two conflicting limits on the same parser - the second must win.
	p := NewParser(
		WithMaxCertificates(1),
		WithMaxCertificates(1000),
	).(*defaultParser)

	assert.Equal(t, 1000, p.opts.maxCertificates)
}

# Certificate Trust Paths, Cross-Signing, and AIA Discovery

A guide to how TLS certificate chains work, why multiple trust paths exist,
and how to reason about them.

## Contents

- [What Happens When You Connect to a Website](#what-happens-when-you-connect-to-a-website)
- [The Chain of Trust](#the-chain-of-trust)
- [Trust Stores: Who Do We Trust and Why?](#trust-stores-who-do-we-trust-and-why)
- [Cross-Signing: Why One Certificate Can Have Multiple Trust Paths](#cross-signing-why-one-certificate-can-have-multiple-trust-paths)
- [AIA: How Missing Certificates Are Found](#aia-how-missing-certificates-are-found)
- [Matching Certificates to Trust Stores](#matching-certificates-to-trust-stores)
- [Detecting Self-Signed Certificates](#detecting-self-signed-certificates)
- [Validation: What Makes a Path Trusted?](#validation-what-makes-a-path-trusted)
- [Simulation: Planning CA Migrations](#simulation-planning-ca-migrations)
- [What Happens When You Exclude a Certificate](#what-happens-when-you-exclude-a-certificate)
- [Practical Examples](#practical-examples)
- [Key Takeaways](#key-takeaways)
- [Further Reading](#further-reading)

## What Happens When You Connect to a Website

When your browser connects to `https://example.com`, a TLS handshake happens
before any HTTP traffic flows. During this handshake, the server sends its
certificate chain. Your client then needs to answer one question: **do I
trust this server?**

The answer depends on whether the server's certificate chain leads to a root
Certificate Authority (CA) that your operating system or browser trusts.

Here is a simplified TLS 1.2 handshake (TLS 1.3 merges several of these
steps, but the certificate exchange works the same way):

```
Client                          Server
  |                               |
  |  --- ClientHello ---------->  |
  |  <-- ServerHello -----------  |
  |  <-- Certificate Chain -----  |   <-- This is what we're examining
  |  <-- ServerHelloDone ------   |
  |  --- ClientKeyExchange ---->  |
  |  --- Finished ------------->  |
  |  <-- Finished --------------  |
  |                               |
  |  === Encrypted traffic ====   |
```

The certificate chain the server sends typically looks like this:

```
[Leaf Certificate]          "*.example.com" -- the server's identity
       |
       | signed by
       v
[Intermediate CA]           "Example CA G2" -- issued by a root CA
       |
       | signed by
       v
[Root CA]                   "Example Root CA" -- self-signed, in your trust store
```

## The Chain of Trust

Each certificate in the chain contains key fields:

| Field | Purpose | Example |
|-------|---------|---------|
| Subject | Who this certificate identifies | `CN=*.example.com` |
| Issuer | Who signed this certificate | `CN=Example CA G2` |
| SubjectKeyId (SKI) | Hash of this certificate's public key | `AB:CD:12:34:...` |
| AuthorityKeyId (AKI) | SKI of the certificate that signed this one | `EF:56:78:90:...` |
| NotBefore / NotAfter | Validity period | `2024-01-01` to `2025-12-31` |
| AIA URLs | Where to download the issuer certificate | `http://ca.example.com/intermediate.crt` |

Verification works bottom-up:

1. Take the leaf certificate's signature
2. Verify it using the intermediate CA's public key
3. Take the intermediate's signature
4. Verify it using the root CA's public key
5. Check if the root CA is in the system trust store
6. If yes: the chain is trusted. If no: connection fails.

The AKI in each certificate points to the SKI of its issuer. This is how
the chain is linked together -- not by names, but by key identifiers.

## Trust Stores: Who Do We Trust and Why?

A trust store is a curated collection of root CA certificates that the
operating system vendor has vetted and approved. These are the "trust
anchors" -- the starting points for all certificate verification.

| Platform | Trust Store Location | Managed By |
|----------|---------------------|------------|
| macOS | System Keychain | Apple |
| Windows | Certificate Store | Microsoft |
| Linux | `/etc/ssl/certs/` | Distribution maintainers |
| Firefox | NSS database | Mozilla |
| Java | `cacerts` keystore | Oracle/OpenJDK |

Each vendor has their own inclusion criteria. Apple, Microsoft, and Mozilla
all maintain independent root programs with auditing requirements. A root CA
must pass regular audits (WebTrust, ETSI) to stay in these stores.

When you see "certificate not trusted," it means the chain's root CA is not
in your trust store. Common reasons:

- The root CA was removed (revoked, failed audit, sunset)
- The server didn't send the full chain (missing intermediate)
- The certificate is self-signed (no CA involved)
- The root CA is new and not yet in your OS version's trust store

## Cross-Signing: Why One Certificate Can Have Multiple Trust Paths

Cross-signing is the mechanism that makes CA transitions possible without
breaking the internet.

### The Problem

When a new CA (say, "New Root CA") is created, it takes years before every
device in the world has it in their trust store. Old phones, IoT devices,
enterprise systems -- they all have outdated trust stores.

### The Solution

An established CA ("Old Root CA") signs the new CA's certificate. Now the
new CA has two valid trust paths:

```
Path 1 (modern devices):
  Leaf --> Intermediate --> New Root CA (self-signed, in trust store)

Path 2 (older devices):
  Leaf --> Intermediate --> New Root CA (cross-signed by Old Root CA) --> Old Root CA (in trust store)
```

Both paths are valid. Modern devices use Path 1 (shorter, faster). Older
devices that don't have "New Root CA" in their trust store fall back to
Path 2 through the cross-sign.

### Real-World Example: Cloudflare's Certificate Chain

Cloudflare uses Google Trust Services (GTS) for its TLS certificates. GTS
Root R4 is a relatively new root CA, so to maintain backward compatibility
with older devices, it was cross-signed by GlobalSign Root CA -- an
established root that has been in trust stores for years.

When you connect to `cloudflare.com`, the server sends a chain through its
intermediate (WE1) up to GTS Root R4. But there are actually four valid
trust paths:

```
Path 1: cloudflare.com --> WE1 --> GTS Root R4 (self-signed, in trust store)
Path 2: cloudflare.com --> WE1 --> GTS Root R4 (cross-signed) --> GlobalSign Root CA
Path 3: cloudflare.com --> WE1 --> GTS Root R4 (cross-signed, in trust store)
Path 4: cloudflare.com --> WE1 (cross-signed) --> GlobalSign (in trust store)
```

Paths 1 and 3 terminate at different variants of the same GTS Root R4 key
(self-signed and cross-signed). Path 2 extends through GTS Root R4 to
GlobalSign Root CA for backward compatibility with older devices. Path 4 is
the most interesting -- it reaches GlobalSign through a different WE1
variant, providing an entirely independent trust path. If GTS Root R4 is
distrusted, path 4 survives.

Most TLS clients only show you one path -- the one they used. The other
paths are invisible unless you go looking for them. The
[Hands-On Guide](./hands-on-guide.md#cross-signing-and-multiple-trust-paths)
walks through this with certree.

### The Cross-Signing Identity Problem

The cross-signed version of GTS Root R4 and the self-signed version are
**different certificates**. They have:

- Same Subject name ("GTS Root R4")
- Same public key (same SubjectKeyId)
- Different Issuer (self vs. GlobalSign)
- Different serial number
- Different signature
- Different SHA-256 fingerprint

This matters because trust store lookups traditionally use fingerprints. A
cross-signed certificate won't match by fingerprint even though it
represents the same trust anchor. The correct approach is to match by
**public key**: same key = same trust anchor, regardless of who signed the
certificate.
[Matching Certificates to Trust Stores](#matching-certificates-to-trust-stores)
explains how certree implements this.

## AIA: How Missing Certificates Are Found

Authority Information Access (AIA) is an X.509 extension that tells clients
where to download the issuer certificate. It's the mechanism that makes
incomplete chains work.

### When AIA Is Used

The server is supposed to send the full chain, but often doesn't. Common
scenarios:

- Server misconfiguration (only sends the leaf)
- Intermediate CA was re-issued and the server has the old one
- Cross-signed intermediates aren't included

When a client can't find the issuer in the certificates it already has, it
checks the AIA extension:

```
Certificate: *.example.com
  ...
  Authority Information Access:
    CA Issuers: http://certs.example.com/intermediate.crt
    OCSP: http://ocsp.example.com
  ...
```

The "CA Issuers" URL points to the issuer certificate. The client downloads
it, adds it to the chain, and continues verification.

### How AIA Discovery Works Step by Step

```
1. Parse leaf certificate
2. No issuer found locally
3. Check AIA extension --> found URL: http://ca.example.com/intermediate.crt
4. HTTP GET the URL
5. Parse the downloaded certificate (DER or PEM format)
6. Validate: does the downloaded cert's SKI match the leaf's AKI?
7. If yes: add to chain, continue building
8. If no: discard, try next AIA URL
9. Repeat for the downloaded certificate (it may also have AIA URLs)
```

### AIA Limitations

- **HTTP and HTTPS only.** The AIA extension (RFC 5280 §4.2.2.1) allows the
  CA Issuers `accessLocation` to be any URI. In practice, CAs have used
  `http://`, `ldap://`, and occasionally `ftp://` schemes. certree only
  fetches from HTTP and HTTPS URLs. AIA URLs with other schemes (LDAP, FTP,
  etc.) are silently skipped. LDAP-based AIA URLs are most commonly found in
  older enterprise and Windows Server PKI environments; virtually all public
  CAs use HTTP.
- Requires network access (won't work in air-gapped environments)
- Adds latency (HTTP round-trip per missing certificate)
- AIA URLs can be unreachable (server down, firewall, DNS issues)
- Not all certificates have AIA extensions (especially older roots)
- Not all TLS clients support AIA fetching
- AIA fetches to RFC 1918 private IP addresses are blocked by default as an
  SSRF safeguard. Internal PKI environments where AIA endpoints live on
  private networks must enable `--allow-private-networks` (or the equivalent
  library option) to permit these requests.

### Default vs. Force AIA

Most TLS clients only fetch via AIA when the chain is incomplete -- when no
local issuer is found. This is the "fallback" behavior.

Force AIA means fetching via AIA **even when local issuers exist**. This
discovers alternate trust paths that the server didn't send. It's useful
for:

- Discovering cross-signed chains during CA migrations
- Auditing which trust paths exist for a certificate
- Understanding what happens when a certificate is excluded from a chain

## Matching Certificates to Trust Stores

When verifying a chain, the client needs to check if the root certificate
is in the trust store. This sounds simple -- just compare certificates --
but cross-signing makes it harder than it looks.

### The Cross-Signing Problem

As described in
[The Cross-Signing Identity Problem](#the-cross-signing-identity-problem),
cross-signed variants of the same CA share the same public key but differ
in every other field. A fingerprint-only lookup would miss the match and
report the chain as untrusted. certree solves this with two levels of
matching.

### Level 1: Fingerprint Match (Exact)

SHA-256 hash of the entire DER-encoded certificate. Two certificates with
the same fingerprint are byte-for-byte identical. This is the primary
lookup and covers the common case where the chain ends at a root that is in
the trust store verbatim.

### Level 2: Public Key Match (Cross-Sign Aware)

When fingerprint matching fails, certree falls back to comparing the
SHA-256 hash of the certificate's SubjectPublicKeyInfo (SPKI) -- the ASN.1
structure that encodes the public key algorithm and key bytes. Cross-signed
variants of the same CA share the same SPKI because they carry the same
public key, even though everything else about the certificate differs.

This is more reliable than comparing the SubjectKeyIdentifier (SKI)
extension, which RFC 5280 defines as an opaque value that CAs can set
freely. SKI is designed for path building (finding which certificate issued
which), not for trust store matching. SPKI comparison is a cryptographic
guarantee of key equivalence -- the actual invariant that cross-signing
preserves.

### Why Not Just Use Names?

Certificate subject names are not unique. Multiple CAs can have the same
Common Name. Cross-signed certificates have the same Subject AND Issuer
names but different keys. Name-only matching would produce false positives.

| Strategy | Handles Cross-Signing | False Positives | Standard |
|----------|----------------------|-----------------|----------|
| Fingerprint only | No | None | Common |
| SPKI match | Yes | None | certree |
| SKI match | Yes | Extremely rare | RFC 5280 |
| Name only | No | Yes | Avoid |

## Detecting Self-Signed Certificates

A self-signed certificate is one where the subject signed it with their own
key. Simple name comparison (`Subject == Issuer`) is not sufficient because
a CA can re-issue its certificate with a new key while keeping the same
name. In that case Subject and Issuer names match, but the certificate was
signed by a different key -- it is not self-signed.

The correct check:

1. Subject name matches Issuer name
2. AND the AuthorityKeyId matches the SubjectKeyId (same key signed it)

If AKI is absent (some legacy roots), fall back to name-only comparison.

## Validation: What Makes a Path Trusted?

Each certificate in a path is validated independently. The checks happen in
order, and the first failure determines the certificate's status:

| Check | Description |
|-------|-------------|
| **Trusted?** | Is the certificate in the system trust store? If yes, it's a trust anchor -- the chain terminates here. This is the most important check. |
| **Signature valid?** | Does the issuer's public key verify this certificate's signature? A failed signature means the certificate was tampered with or chained to the wrong issuer. |
| **Within validity period?** | Is the current date between the certificate's NotBefore and NotAfter dates? Expired certificates are invalid. Certificates expiring within 30 days produce a warning. |
| **Self-signed?** | A self-signed certificate that's in the trust store is a root CA -- that's normal. A self-signed certificate that's not in the trust store is an unknown trust anchor -- the chain can't be verified. |

A **path** is trusted when its root certificate is in the trust store.
Individual certificates can be valid even in an untrusted path -- they're
individually fine, they just chain to a root that nobody vouches for.

## Simulation: Planning CA Migrations

The most practical application of multi-path analysis is planning for
certificate changes. When any certificate in a chain is being sunset,
revoked, or replaced, you need to know:

- Which of my services chain through this certificate?
- Do they have alternate trust paths?
- What breaks if this certificate is removed?

By simulating the exclusion of a certificate -- whether it's a root,
intermediate, or leaf -- you can see the before/after impact without
actually changing anything.

For comprehensive migration planning, combine `--validation-time` with
`--exclude-*` flags. The `--validation-time` flag shifts the clock forward
so that expiry checks run against a future date, while `--exclude-*` removes
specific certificates from the chain. Together they answer questions like
"if we revoke Old CA **and** it's November 2037, which paths still work?"
Use `--compare` or `--diff` to see the combined effect side by side.

## What Happens When You Exclude a Certificate

Simulation gets interesting when cross-signing is involved. The outcome
depends on one thing: **is there another trust anchor below the excluded
certificate?**

Per RFC 5280, certificate path validation terminates at a trust anchor --
any certificate in the system trust store. Once the path builder hits a
trust anchor, it stops. Everything above that anchor in the chain is
irrelevant for validation. It's only there for backward compatibility with
older clients.

Consider a cross-signed chain:

```
Leaf --> Intermediate --> New Root CA --> Old Root CA
```

If New Root CA is independently in the trust store, the chain has two valid
trust paths:

```
Path 1: Leaf --> Intermediate --> New Root CA (in trust store) --> Old Root CA
Path 2: Leaf --> Intermediate --> New Root CA (in trust store)
```

Now simulate excluding Old Root CA. Path 1 still has New Root CA as a
trust anchor below the excluded cert. The chain survives -- Old Root CA is
ghosted (dimmed) but the path stays trusted. Path 2 doesn't involve Old
Root CA at all, so it's unaffected.

```
[+ ] (no source) -- 1 trusted path
`- [+ ] Leaf
   `- [+ ] Intermediate
      `- [+ ] New Root CA
         `- [+ ] Old Root CA (ghosted)             <-- dimmed, path still trusted
```

Now simulate excluding New Root CA instead. No certificate below it is a
trust anchor. The chain breaks for both paths:

```
[x ] (no source) -- 1 untrusted path
`- [! ] Leaf (broken)
   `- [! ] Intermediate (broken)
      `- [! ] New Root CA (excluded)
         `- [+ ] Old Root CA (ghosted)             <-- dimmed, path untrusted
```

The rule is simple: **if a trust anchor exists below the excluded cert, the
path survives. If not, everything below breaks.** Simulation lets you check
which case you're in before making changes.

## Practical Examples

The concepts above -- cross-signing, AIA discovery, trust store matching,
and simulation -- are all things you can explore with certree. The
[Hands-On Guide](./hands-on-guide.md) walks through each one step by step
with runnable commands and example certificates.

## Key Takeaways

1. **A single leaf certificate can have multiple valid trust paths.**
   Cross-signing creates alternate routes to different root CAs.

2. **The chain the server sends is not the only valid chain.** AIA
   extensions enable discovery of intermediates and cross-signed roots
   that aren't in the server's chain.

3. **Trust store matching must handle cross-signed variants.** Same public
   key (same SPKI hash) = same trust anchor, even if the fingerprint
   differs.

4. **AIA fetching is a fallback, not a guarantee.** It requires network
   access and the AIA URLs must be reachable. Always configure servers to
   send the full chain.

5. **CA migrations are visible through multi-path analysis.** By building
   all possible trust paths, you can see which roots a certificate depends
   on and plan for their removal.

6. **Self-signed does not mean untrusted.** Self-signed root CAs in the
   system trust store are the foundation of all TLS trust. "Self-signed"
   just means the certificate signed itself -- it's the normal state for
   root CAs.

## Further Reading

- [RFC 5280: Internet X.509 PKI Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280) -- certificate structure, path building, and validation
- [RFC 6960: OCSP](https://datatracker.ietf.org/doc/html/rfc6960) -- Online Certificate Status Protocol for revocation checking
- [Mozilla Root Program](https://wiki.mozilla.org/CA) -- how Mozilla decides which CAs to trust
- [Apple Root Program](https://www.apple.com/certificateauthority/ca_program.html) -- Apple's trust store requirements
- [Let's Encrypt Chain of Trust](https://letsencrypt.org/certificates/) -- a well-documented example of cross-signing in practice

See also: [Hands-On Guide](./hands-on-guide.md), [Configuration Reference](./configuration.md), [CLI Reference](./cli.md).

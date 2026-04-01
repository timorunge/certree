# Hands-On Guide

A practical, step-by-step guide to analyzing certificate chains, validating
trust paths, simulating CA migrations, and injecting replacement
certificates. Every command in this guide can be run against the included
example certificates or real public domains.

## Prerequisites

- certree installed (`go install github.com/timorunge/certree/cmd/certree@latest`
  or download from [releases](https://github.com/timorunge/certree/releases))
- Internet access (for remote host examples)
- The example certificates in `docs/examples/` (included in this repository)

## Contents

- [Reading Certificate Chains](#reading-certificate-chains)
- [Trust Stores and Why Chains Break](#trust-stores-and-why-chains-break)
- [Validation -- Expiry, Hostnames, and Error States](#validation----expiry-hostnames-and-error-states)
- [Cross-Signing and Multiple Trust Paths](#cross-signing-and-multiple-trust-paths)
- [Simulating Certificate Exclusion](#simulating-certificate-exclusion)
- [Injecting Certificates -- Rotation Simulation](#injecting-certificates----rotation-simulation)
- [Time Travel -- Future Expiry Planning](#time-travel----future-expiry-planning)
- [Scripting and Automation](#scripting-and-automation)

## Reading Certificate Chains

### Analyzing a remote host

Connect to a live server and see its certificate chain:

```bash
certree github.com
```

```
[+ ] github.com -- 1 trusted path
`- [+ ] github.com
   `- [+ ] Sectigo Public Server Authentication CA DV E36
      `- [+ ] Sectigo Public Server Authentication Root E46
```

> **Note:** Certificate authorities change over time. The exact chain you
> see may differ from what is shown here.

The tree reads bottom-up:
- **github.com** is the leaf certificate (the server's identity)
- **Sectigo ... CA DV E36** is the intermediate CA that signed the leaf
- **Sectigo ... Root E46** is the root CA, found in your system trust store

The `[+ ]` icon means the certificate is valid. The root label shows
`1 trusted` -- one trust path, fully verified.

### Showing certificate details

Add `--fields` to see more about each certificate:

```bash
certree --fields subject,validity,fingerprint github.com
```

Common field combinations:
- `--fields all` -- everything certree knows about each certificate
- `--fields subject,validity` -- who the cert identifies and when it expires
- `--fields fingerprint,serial` -- unique identifiers for exact matching
- `--fields san` -- Subject Alternative Names (which hostnames are covered)
- `--fields extensions` -- Basic Constraints, Key Usage, Extended Key Usage
- `--fields diagnostics` -- validation errors and warnings for each certificate

### Analyzing a local file

certree reads PEM, DER, PKCS#7, and PKCS#12 files:

```bash
certree --annotations docs/examples/chain.pem
```

```
[x ] docs/examples/chain.pem -- 1 incomplete path
`- [+ ] app.example.com
   `- [! ] Example Intermediate CA (incomplete chain)
```

> Without `--annotations`, the output shows only the status icons (`[+ ]`,
> `[! ]`) without the parenthesized explanation. For full diagnostic detail,
> use `--fields diagnostics` to see all errors and warnings per certificate.

The chain is incomplete because the root CA isn't in the system trust store.
The leaf itself is valid `[+ ]`, but the intermediate shows `[! ]` (warning)
because its issuer can't be found. The root label shows `1 incomplete path`.

## Trust Stores and Why Chains Break

### The problem: untrusted chains

Without a matching root CA in the trust store, a chain can't be verified:

```bash
certree --annotations docs/examples/self-signed.pem
```

```
[x ] docs/examples/self-signed.pem -- 1 untrusted path
`- [x ] self-signed.example.com (self-signed)
```

Exit code is `1` (validation error). The certificate is self-signed and not
in any trust store, so it's untrusted.

### Providing a custom trust bundle

Use `--trust-bundle` to tell certree about your own root CAs:

```bash
certree --trust-bundle docs/examples/root-ca.pem docs/examples/chain.pem
```

```
[+ ] docs/examples/chain.pem -- 1 trusted path
`- [+ ] app.example.com
   `- [+ ] Example Intermediate CA
      `- [+ ] Example Root CA
```

Now the chain is complete. Use `-f trust-store` to confirm which store
anchors the chain:

```bash
certree --trust-bundle docs/examples/root-ca.pem --fields trust-store docs/examples/chain.pem
```

```
[+ ] docs/examples/chain.pem -- 1 trusted path
`- [+ ] app.example.com
   `- [+ ] Example Intermediate CA
      `- [+ ] Example Root CA
                Trust Store:  docs/examples/root-ca.pem
```

The root was found in the custom bundle, not the system store.

### What trust store membership means

When a certificate is in the trust store, it's treated as a trust anchor
regardless of other status. An expired certificate that's still in the trust
store is still trusted -- the trust store operator has decided to keep it.

## Validation -- Expiry, Hostnames, and Error States

### Expired certificates

The example includes a certificate that expired in June 2025:

```bash
certree --annotations --fields subject,validity docs/examples/expired.pem
```

```
[x ] docs/examples/expired.pem -- 1 untrusted path
`- [x ] expired.example.com (expired)
          Subject:
            Common Name:  expired.example.com
          Validity:
            Not Before:  2025-01-01 00:00:00 UTC
            Not After:   2025-06-01 00:00:00 UTC (expired)
          Errors:
            - self-signed certificate not in trust store
            - certificate expired on 2025-06-01T00:00:00Z
```

Two errors: the certificate is self-signed and not in any trust store, and
it has expired. The annotation `(expired)` highlights the most critical
issue; the `Errors` section under `--fields` lists all reasons.

### Expiry warnings

Certificates expiring soon trigger warnings. Adjust the threshold with
`--expiry-warning-days`:

```bash
certree --annotations --expiry-warning-days 365 github.com
```

```
[! ] github.com -- 1 trusted path
`- [! ] github.com (expires in NN days)
   `- [+ ] Sectigo Public Server Authentication CA DV E36
      `- [+ ] Sectigo Public Server Authentication Root E46
```

With a 365-day window, github.com's leaf triggers a warning `[! ]` because
it expires within the threshold (the exact day count depends on when you run
it). The intermediates and root are fine because they have years left.

### Hostname verification

Verify that a certificate covers a specific hostname:

```bash
certree --annotations --hostname wrong.example.com github.com
```

```
[x ] github.com -- 1 untrusted path
`- [x ] github.com (hostname mismatch)
   `- [+ ] Sectigo Public Server Authentication CA DV E36
      `- [+ ] Sectigo Public Server Authentication Root E46
```

The leaf is `[x ]` because its SAN list (`github.com`, `www.github.com`)
does not include `wrong.example.com`. Exit code is `1`.

### Status icon reference

| Icon | Meaning |
|------|---------|
| `[+ ]` | Valid -- certificate passed all checks |
| `[! ]` | Warning -- expiring soon, excluded, broken chain, or has a non-fatal issue |
| `[x ]` | Error -- expired, untrusted, hostname mismatch, or other validation failure |

## Cross-Signing and Multiple Trust Paths

### Discovering alternate trust paths

Most TLS clients only show you one chain. certree can discover all possible
trust paths using AIA (Authority Information Access) fetching:

```bash
certree --annotations --aia-force cloudflare.com
```

```
[+ ] cloudflare.com -- 4 trusted paths
`- [+ ] cloudflare.com
   +- [+ ] WE1 1D:FC:16:05:FB:AD
   |  +- [+ ] GTS Root R4 76:B2:7B:80:A5:80
   |  |  `- [+ ] GlobalSign Root CA
   |  `- [+ ] GTS Root R4 34:9D:FA:40:58:C5
   `- [+ ] WE1 A2:87:FF:AB:76:2C
      `- [+ ] GlobalSign
```

Four trust paths exist, collapsed into a merged tree that branches where
paths diverge. When paths diverge through certificates with the same CN,
short fingerprint prefixes automatically disambiguate them -- shown as
dimmed hex after the name:
- The first **WE1** (1D:FC:16:05:FB:AD) intermediate leads to two variants
  of **GTS Root R4** -- one extending to **GlobalSign Root CA** for backward
  compatibility with older devices, the other terminating directly as a
  trust anchor
- The second **WE1** (A2:87:FF:AB:76:2C) variant reaches **GlobalSign**
  through an entirely independent trust path

Use `--fields trust-store` to see which certificates are in the system trust
store and why each path terminates where it does.

### Identifying paths with `--path-index`

When many trust paths exist, use `--path-index` to see which path each
branch belongs to:

```bash
certree --path-index --aia-force cloudflare.com
```

```
[+ ] cloudflare.com -- 4 trusted paths
`- [+ ] cloudflare.com
   +- [+ ] WE1 1D:FC:16:05:FB:AD
   |  +- [+ ] GTS Root R4 76:B2:7B:80:A5:80  #1
   |  |  `- [+ ] GlobalSign Root CA          #2
   |  `- [+ ] GTS Root R4 34:9D:FA:40:58:C5  #3
   `- [+ ] WE1 A2:87:FF:AB:76:2C
      `- [+ ] GlobalSign                     #4
```

Each `#N` marks the terminal certificate of a trust path, right-aligned for
a clean column. Path #1 ends at GTS Root R4 (cross-signed), #2 continues
to GlobalSign Root CA, #3 is the directly-trusted GTS Root R4, and #4
reaches GlobalSign via the second WE1 variant.

### Why this matters

If GTS Root R4 is distrusted, the paths through the first WE1 break -- but
the path through the second WE1 to GlobalSign survives. Understanding which
paths exist lets you plan for CA migrations without downtime.

## Simulating Certificate Exclusion

### Side-by-side comparison

Simulate removing a certificate and see the before/after impact:

```bash
certree --annotations --trust-bundle docs/examples/root-ca.pem \
        --exclude-cn "Example Intermediate CA" \
        --compare docs/examples/chain.pem
```

```
Before                                            | After
--------------------------------------------------+--------------------------------------------------
[+ ] docs/examples/chain.pem -- 1 trusted path    | [x ] docs/examples/chain.pem -- 1 incomplete path
`- [+ ] app.example.com                           | `- [! ] app.example.com (broken)
   `- [+ ] Example Intermediate CA                |    `- [! ] Example Intermediate CA (excluded)
      `- [+ ] Example Root CA                     |       `- [+ ] Example Root CA (ghosted)
```

The excluded intermediate breaks the chain. Before: fully trusted. After:
path is `[x ]` with the intermediate marked as excluded. The root is
ghosted -- still present but dimmed, since nothing chains to it anymore.

### Unified diff output

For a more compact view:

```bash
certree --annotations --aia-force --exclude-cn "GTS Root R4" --diff cloudflare.com
```

```
--- Before (cloudflare.com)
+++ After (cloudflare.com)
-[+ ] cloudflare.com -- 4 trusted paths
+[+ ] cloudflare.com -- 1 trusted, 3 incomplete paths
 `- [+ ] cloudflare.com
-   +- [+ ] WE1 1D:FC:16:05:FB:AD
+   +- [! ] WE1 1D:FC:16:05:FB:AD (broken)
-   |  +- [+ ] GTS Root R4 76:B2:7B:80:A5:80
+   |  +- [! ] GTS Root R4 76:B2:7B:80:A5:80 (excluded)
-   |  |  `- [+ ] GlobalSign Root CA
+   |  |  `- [+ ] GlobalSign Root CA (ghosted)
-   |  `- [+ ] GTS Root R4 34:9D:FA:40:58:C5
+   |  `- [! ] GTS Root R4 34:9D:FA:40:58:C5 (excluded)
    `- [+ ] WE1 A2:87:FF:AB:76:2C
       `- [+ ] GlobalSign
```

> This is actual `certree --diff` output. Lines prefixed with `-` were
> removed, `+` were added, and unprefixed lines are unchanged context.

The first WE1 branch depends entirely on GTS Root R4, so excluding it
breaks those paths. The second WE1 branch reaches GlobalSign independently
-- it survives the exclusion unchanged.

### When exclusion doesn't break the chain

Excluding a certificate above a trust anchor has no effect on chain
validity:

```bash
certree --annotations --aia-force --exclude-cn "GlobalSign Root CA" --compare cloudflare.com
```

GlobalSign Root CA sits above GTS Root R4 in the merged tree. Since GTS
Root R4 is independently a trust anchor, the path survives -- GlobalSign
Root CA is marked excluded but the chain stays trusted.

### Excluding by fingerprint

When the same CN appears in multiple variants (cross-signed certificates),
`--exclude-fingerprint` lets you target a specific one:

```bash
certree --aia-force --fields fingerprint cloudflare.com
```

Find the fingerprint of the intermediate you want to exclude, then:

```bash
certree --annotations --aia-force --exclude-fingerprint "1D:FC:16:05:*" cloudflare.com
```

```
[+ ] cloudflare.com -- 1 trusted, 3 incomplete paths
`- [+ ] cloudflare.com
   +- [! ] WE1 1D:FC:16:05:FB:AD (excluded)
   |  +- [+ ] GTS Root R4 76:B2:7B:80:A5:80 (ghosted)
   |  |  `- [+ ] GlobalSign Root CA (ghosted)
   |  `- [+ ] GTS Root R4 34:9D:FA:40:58:C5 (ghosted)
   `- [+ ] WE1 A2:87:FF:AB:76:2C
      `- [+ ] GlobalSign
```

The first WE1 node was excluded (matching fingerprint). The second WE1
variant has a different fingerprint (cross-signed by GlobalSign), so it
survives. This is the value of cross-signing: independent trust paths
provide resilience when any single certificate is compromised or distrusted.

### Impact summary

Add `--impact` to get a quantitative breakdown:

```bash
certree --annotations --aia-force --exclude-cn "GTS Root R4" --impact cloudflare.com
```

```
[+ ] cloudflare.com -- 1 trusted, 3 incomplete paths
`- [+ ] cloudflare.com
   +- [! ] WE1 1D:FC:16:05:FB:AD (broken)
   |  +- [! ] GTS Root R4 76:B2:7B:80:A5:80 (excluded)
   |  |  `- [+ ] GlobalSign Root CA (ghosted)
   |  `- [! ] GTS Root R4 34:9D:FA:40:58:C5 (excluded)
   `- [+ ] WE1 A2:87:FF:AB:76:2C
      `- [+ ] GlobalSign

Impact:
  Excluded:
    - GTS Root R4 76:B2:7B:80:A5:80
    - GTS Root R4 34:9D:FA:40:58:C5
  Ghosted:          GlobalSign Root CA
  Broken paths:     3
  Remaining paths:  1
```

Three paths broke, but one survived. GTS Root R4 appears twice in the
excluded list -- one cross-signed by GlobalSign and one self-signed --
because the CN match targeted both variants. The leaf `cloudflare.com` is
not listed as broken because it still has a healthy path through the second
WE1 -> GlobalSign branch. The broken WE1 is a different certificate
(different fingerprint) from the healthy WE1 and has no surviving path.

For the full set of exclusion flags and wildcard syntax, see
[CLI Reference -- Simulation](./cli.md#simulation).

## Injecting Certificates -- Rotation Simulation

Certificate rotation means replacing an old certificate with a new one.
The `--inject` flag lets you add certificate files into the chain analysis
and rebuild all trust paths to see what changes.

### Seeing what injection adds

Inject a new intermediate and its leaf to see what new trust paths appear:

```bash
certree --annotations --trust-bundle docs/examples/root-ca.pem \
        --inject docs/examples/new-intermediate-ca.pem \
        --inject docs/examples/leaf-new.pem \
        --compare docs/examples/chain.pem
```

```
Before                                               | After
-----------------------------------------------------+-----------------------------------------------------
[+ ] docs/examples/chain.pem -- 1 trusted path       | [+ ] docs/examples/chain.pem -- 2 trusted paths
`- [+ ] app.example.com                              | +- [+ ] app.example.com 56:BA:21:71:CF:D3
   `- [+ ] Example Intermediate CA                   | |  `- [+ ] Example Intermediate CA
      `- [+ ] Example Root CA                        | |     `- [+ ] Example Root CA
                                                     | `- [+ ] app.example.com D5:A9:30:85:22:09 (injected)
                                                     |    `- [+ ] Example Intermediate CA v2 (injected)
                                                     |       `- [+ ] Example Root CA
```

Before: one trust path through the original intermediate. After: a second
path appears through the new intermediate CA v2. The fingerprint
disambiguators on the two `app.example.com` nodes distinguish the original
from the injected leaf.

### Full rotation: inject new, exclude old

Combine `--inject` and `--exclude-cn` to simulate replacing one
intermediate with another:

```bash
certree --annotations --trust-bundle docs/examples/root-ca.pem \
        --inject docs/examples/new-intermediate-ca.pem \
        --inject docs/examples/leaf-new.pem \
        --exclude-cn "Example Intermediate CA" \
        --compare --impact docs/examples/chain.pem
```

```
Before                                         | After
-----------------------------------------------+--------------------------------------------------------------
[+ ] docs/examples/chain.pem -- 1 trusted path | [+ ] docs/examples/chain.pem -- 1 trusted, 1 incomplete paths
`- [+ ] app.example.com                        | +- [! ] app.example.com 56:BA:21:71:CF:D3 (broken)
   `- [+ ] Example Intermediate CA             | |  `- [! ] Example Intermediate CA (excluded)
      `- [+ ] Example Root CA                  | |     `- [+ ] Example Root CA (ghosted)
                                               | `- [+ ] app.example.com D5:A9:30:85:22:09 (injected)
                                               |    `- [+ ] Example Intermediate CA v2 (injected)
                                               |       `- [+ ] Example Root CA

Impact:
  Injected:
    - app.example.com
    - Example Intermediate CA v2
  Excluded:           Example Intermediate CA
  Ghosted:            Example Root CA
  Broken paths:       1
  New trusted paths:  1
  Remaining paths:    1
```

The old path through "Example Intermediate CA" breaks. The new path
through "Example Intermediate CA v2" takes over. One path broke, one new
path appeared, one path remains trusted. The rotation is safe.

## Time Travel -- Future Expiry Planning

### Testing future expiry

Use `--validation-time` to shift the clock forward and check which
certificates will have expired by a given date:

```bash
certree --annotations --trust-bundle docs/examples/root-ca.pem \
        --validation-time "2042-04-01T00:00:00Z" \
        --compare docs/examples/chain.pem
```

```
Before                                           | After
-------------------------------------------------+-------------------------------------------------
[+ ] docs/examples/chain.pem -- 1 trusted path   | [x ] docs/examples/chain.pem -- 1 untrusted path
`- [+ ] app.example.com                          | `- [x ] app.example.com (expired)
   `- [+ ] Example Intermediate CA               |    `- [x ] Example Intermediate CA (expired)
      `- [+ ] Example Root CA                    |       `- [! ] Example Root CA (expired, trusted)
```

By April 2042, every certificate in the chain has expired. The leaf expires
first (2027), then the intermediate (2031), and finally the root (2036).
The root still shows `[! ]` (warning, not error) because it's in the trust
store, but the path is counted as untrusted because the leaf and
intermediate have expired.

### Combining time travel with exclusion

Answer questions like "if we revoke Old CA **and** it's November 2037,
which paths still work?":

```bash
certree --aia-force \
        --exclude-cn "GTS Root R4" \
        --validation-time "2037-11-01T00:00:00Z" \
        cloudflare.com
```

This shifts the validation clock to November 2037 and simultaneously
excludes GTS Root R4, showing the combined effect.

## Scripting and Automation

### JSON output

Use `--format json` for machine-readable output:

```bash
certree --format json github.com | jq '.[0].metadata'
```

```
{
  "source": "github.com",
  "timestamp": "2026-04-01T12:00:00.000000+02:00",
  "is_simulated": false,
  "total_certs": 3,
  "total_paths": 1,
  "trusted_paths": 1
}
```

JSON output is always an array, even for a single source, so scripts can
rely on a consistent type.

### Quiet mode and exit codes

Use `--quiet` to suppress all output and communicate via exit codes only:

```bash
certree --quiet github.com; echo "exit: $?"
```

```
exit: 0
```

```bash
certree --quiet --hostname wrong.example.com github.com; echo "exit: $?"
```

```
exit: 1
```

| Exit Code | Meaning |
|-----------|---------|
| 0 | All certificates valid |
| 1 | Validation error |

See [CLI Reference -- Exit Codes](./cli.md#exit-codes) for the full list.

### Batch processing

Analyze multiple hosts from a file:

```bash
cat hosts.txt
```

```
github.com
letsencrypt.org
cloudflare.com
```

```bash
certree --batch hosts.txt
```

### Monitoring script example

Check certificates across your infrastructure and alert on expiry:

```bash
#!/bin/bash
HOSTS="api.example.com web.example.com auth.example.com"
WARN_DAYS=30

for host in $HOSTS; do
    if ! certree --quiet --expiry-warning-days "$WARN_DAYS" "$host"; then
        echo "WARN: $host has certificate issues (exit: $?)"
    fi
done
```

### Reverse order

Use `--reverse` to show chains root-first (top-down) instead of
leaf-first:

```bash
certree --reverse github.com
```

```
[+ ] github.com -- 1 trusted path
`- [+ ] Sectigo Public Server Authentication Root E46
   `- [+ ] Sectigo Public Server Authentication CA DV E36
      `- [+ ] github.com
```

> **Note:** The certificate authorities serving github.com may change over time.

## Example Certificates

The `docs/examples/` directory contains pre-built certificates for local
experimentation:

| File | Description |
|------|-------------|
| `root-ca.pem` | Self-signed root CA ("Example Root CA") |
| `intermediate-ca.pem` | Intermediate CA signed by root |
| `leaf.pem` | End-entity cert for `app.example.com` |
| `chain.pem` | Leaf + intermediate bundled together |
| `new-intermediate-ca.pem` | Replacement intermediate ("Example Intermediate CA v2") |
| `leaf-new.pem` | Leaf re-signed by new intermediate |
| `chain-new.pem` | New leaf + new intermediate bundled |
| `self-signed.pem` | Self-signed cert not in any trust store |
| `expired.pem` | Certificate that expired in June 2025 |

All local file examples in this guide use
`--trust-bundle docs/examples/root-ca.pem` because the example root CA is
not in your system trust store.

See also: [CLI Reference](./cli.md),
[Certificate Trust Paths](./certificate-trust-paths.md),
[Configuration](./configuration.md), [Library Guide](./library.md).

# CLI Reference

A practical guide to using certree from the command line.

## Contents

- [Usage](#usage)
- [Sources](#sources)
- [Examples](#examples)
  - [Analyzing local files](#analyzing-local-files)
  - [Connecting to remote servers](#connecting-to-remote-servers)
  - [Reading from stdin](#reading-from-stdin)
  - [Multiple sources](#multiple-sources)
  - [Output formats](#output-formats)
  - [Display options](#display-options)
  - [Themes](#themes)
  - [Filtering](#filtering)
  - [Validation](#validation)
  - [SNI vs Hostname](#sni-vs-hostname)
  - [Discovering alternate trust paths](#discovering-alternate-trust-paths)
  - [Simulation](#simulation)
  - [Batch processing](#batch-processing)
  - [Configuration](#configuration)
- [Options](#options)
- [Exit Codes](#exit-codes)
- [stdin and stdout](#stdin-and-stdout)

## Usage

```
certree [OPTIONS] [SOURCE ...]
```

certree takes one or more sources -- files, remote hosts, or stdin --
and produces a structured view of the certificate trust paths it finds.
No subcommands. Sources are positional arguments.

## Sources

certree accepts five types of input:

| Source | Example | Description |
|--------|---------|--------------|
| File | `certree cert.pem` | Reads PEM, DER, PKCS#7, or PKCS#12 certificates from disk |
| Remote host | `certree example.com` | Connects via TLS and retrieves the server's certificate chain |
| URL | `certree https://pki.example.com/ca.pem` | Fetches certificates from an HTTP(S) URL. HTTP URLs are automatically upgraded to HTTPS. SSRF protection blocks private IPs unless `--allow-private-networks` is set. |
| Stdin | `cat cert.pem \| certree -` | Reads PEM-encoded certificates from standard input |
| Batch file | `certree --batch hosts.txt` | Processes multiple sources listed one per line |

Bare hostnames like `example.com` default to port 443. To connect on a
different port, include it explicitly: `example.com:8443`. Multiple
sources can be passed as positional arguments, freely mixing types.

## Examples

### Analyzing local files

The simplest use case. Point certree at a certificate file:

```bash
# PEM file (most common)
certree cert.pem

# DER-encoded certificate
certree cert.der

# PKCS#12 bundle (empty password only -- password-protected bundles are not supported)
certree bundle.p12

# Multiple certificates in one PEM file -- certree handles this naturally
certree chain.pem
```

### Connecting to remote servers

certree connects via TLS and retrieves whatever the server sends:

```bash
# Explicit port for non-standard TLS
certree example.com:8443

# Custom SNI (useful when the hostname doesn't match the connection target)
certree --sni example.com 10.0.0.1:443

# Longer timeout for slow connections
certree --connect-timeout 30s example.com

# Mutual TLS with client certificate
certree --client-cert client.pem --client-key client-key.pem internal.corp:443

# Internal service with private AIA/OCSP endpoints
certree --aia-fetch --allow-private-networks internal.corp:443
```

### Reading from stdin

The `-` source reads from stdin, which makes certree composable with
other tools:

```bash
# Pipe from OpenSSL
echo q | openssl s_client -connect example.com:443 -showcerts 2>/dev/null | certree -

# Pipe from another process
cat /etc/ssl/certs/ca-certificates.crt | certree -

# Combine stdin with other sources
echo q | openssl s_client -connect example.com:443 -showcerts 2>/dev/null | certree - github.com
```

### Multiple sources

Pass multiple sources as positional arguments to analyze them in a
single invocation. Sources can be any mix of remote hosts, local files,
and stdin:

```bash
# Multiple remote hosts
certree github.com cloudflare.com example.com

# Mix remote hosts and local files
certree github.com cert.pem

# Positional sources combined with a batch file
certree github.com --batch hosts.txt
```

When multiple sources are provided, certree processes them concurrently
and displays results in the order they were specified, with a header per
analysis.

### Output formats

certree writes to stdout by default. The default format is a tree view;
JSON is available for scripting:

```bash
# Default tree output
certree example.com

# JSON for scripting
certree --format json example.com

# Pipe JSON into jq
certree --format json example.com | jq '.[0].metadata'

# Write output to a file (use shell redirection)
certree example.com > result.txt

# Wrap long detail lines to fit the terminal width (tree mode only)
certree --fields all --wrap example.com
```

### Display options

Control how much detail certree shows:

```bash
# Default output: flat chain view (one line per cert with status + CN)
certree example.com

# Show specific fields (comma-separated)
certree --fields fingerprint example.com
certree -f serial,validity example.com

# Show which trust store anchors each certificate
certree -f trust-store example.com

# Show all detail fields at once
certree --fields all example.com

# Show status annotations (e.g. expired, self-signed) -- off by default
certree --annotations example.com

# Show path index markers (#1, #2, ...) to identify trust paths
certree --path-index --aia-force cloudflare.com

# Reverse order -- root CA first, leaf last (like browser certificate viewers)
certree --reverse example.com

# Error-level logging to stderr
certree -v example.com

# Warning-level logging
certree -vv example.com

# Info-level logging
certree -vvv example.com

# Debug-level logging (most verbose)
certree -vvvv example.com
```

### Themes

certree ships with three built-in themes that control status icons and
tree characters. Select one with `--theme`:

```bash
certree --theme terse example.com
certree --theme minimal example.com
```

The examples below use `--annotations` to show status annotations
alongside each theme's icons:

The `classic` theme uses spaced bracketed icons and full tree characters:

```
[x ] example.com -- 1 untrusted path
`- [+ ] example.com
   `- [! ] Intermediate CA (expires in 12 days)
      `- [x ] Root CA (self-signed)
```

The `terse` theme uses compact bracketed icons with no inner spacing:

```
[x] example.com -- 1 untrusted path
`- [+] example.com
   `- [!] Intermediate CA (expires in 12 days)
      `- [x] Root CA (self-signed)
```

The `minimal` theme drops brackets entirely and uses single characters
with no tree decorations:

```
x example.com -- 1 untrusted path
  + example.com
    ! Intermediate CA (expires in 12 days)
      x Root CA (self-signed)
```

All three themes support ANSI color output when `--color` is enabled.
The status icons map to: green for valid, yellow for warnings, red for
errors, and blue for informational.

### Filtering

Narrow the output to certificates matching specific criteria. All
`--filter-*` flags are repeatable -- when specified multiple times,
certificates matching any of the given patterns are shown. Patterns
support wildcards (`*`, `?`, `[abc]`) and pipe-separated alternatives
(`"Root CA|Intermediate*"`). Multiple filter types are combined with OR
logic: a certificate is shown if it matches any filter:

```bash
# Filter by Common Name pattern
certree --filter-cn "*.example.com" example.com

# Filter by SHA-256 fingerprint (colon-separated or plain hex)
certree --filter-fingerprint "A8:87:60:2F*" example.com

# Filter by serial number (colon-separated or plain hex)
certree --filter-serial "04:00:00:*" example.com

# Multiple patterns -- show certificates matching either pattern
certree --filter-cn "*.example.com" --filter-cn "Root CA" example.com

# Combine filter types -- show certificates matching any filter
certree --filter-cn "Root*" --filter-fingerprint "A8:87:*" example.com
```

### Validation

certree validates certificates by default (signatures, expiry). You can
enable additional checks:

```bash
# Warn if certificates expire within 60 days from now (default is 30) -- renewal monitoring
certree --expiry-warning-days 60 example.com

# Verify hostname matches the certificate
certree --verify-hostname --hostname example.com example.com

# Enable revocation checking (OCSP and CRL)
# Revocation results are cached within a batch run to avoid redundant
# network requests. Use -vvv to see OCSP/CRL check details.
certree --verify-revocation example.com

# Verify EKU chaining: each cert's EKU must be a subset of its issuer's EKU
certree --verify-eku cert.pem

# Verify name constraints imposed by CA certificates (RFC 5280 §4.2.1.10)
certree --verify-name-constraints cert.pem

# Warn if a certificate's total issued lifetime exceeds 398 days (CA/B Forum TLS limit)
# Checks NotAfter-NotBefore, not remaining time -- catches over-long certs regardless of age
certree --max-validity-days 398 cert.pem

# Skip invalid certificates instead of failing
certree --skip-invalid cert.pem
```

### SNI vs Hostname

These two flags serve different purposes in the TLS lifecycle:

```
                          TLS Handshake              Validation
                         +--------------+            +------------+
  certree --sni X \      |  ClientHello |            |            |
  --hostname Y \         |  SNI: X      |----------->| Check cert |
  192.168.1.1:443        |              |   Server   | covers Y?  |
                         |              |   sends    |            |
                         |              |   cert     |            |
                         +--------------+   for X    +------------+
```

`--sni` controls which certificate the server returns. It's the Server
Name Indication value sent during the TLS handshake -- the server uses
it to pick the right certificate when multiple domains share the same
IP.

`--hostname` controls what certree validates the certificate against.
After the handshake, certree checks whether the certificate's SANs
(Subject Alternative Names) cover this hostname.

```bash
# Connect to an IP, use SNI to get the right cert
certree --sni example.com 10.0.0.1:443

# Get the cert from github.com, verify it covers www.github.com
certree --hostname www.github.com github.com

# Both: connect to IP, request example.com's cert, verify it covers api.example.com
certree --sni example.com --hostname api.example.com 10.0.0.1:443
```

When neither flag is set, certree automatically derives the hostname
from the source or SNI for verification. Use `--verify-hostname=false`
to disable this.

### Discovering alternate trust paths

Certificate chains can have multiple valid trust paths, especially when
cross-signing is involved. certree can discover these through AIA
(Authority Information Access) fetching:

```bash
# Fetch missing intermediates via AIA when the chain is incomplete
certree --aia-fetch example.com

# Force AIA fetching to discover alternate trust paths
# (fetches even when local issuers exist)
certree --aia-force cloudflare.com

# Force AIA for batch operations -- cache prevents redundant fetches
certree --aia-force --batch hosts.txt
```

The AIA fetcher caches certificates by URL, so repeated references to
the same issuer URL across batch items return the cached certificate
without a network request. Total AIA fetches per analysis are bounded
by `--max-depth` (default 10): each chain-building recursion level
performs at most one AIA fetch.

AIA fetching supports HTTP and HTTPS URLs only. Certificates with LDAP
or FTP-based AIA URLs (sometimes found in older enterprise PKI
environments) will have those URLs silently skipped. See
[Certificate Trust Paths](./certificate-trust-paths.md) for background
on why multiple trust paths exist and when this matters.

### Simulation

Simulate what happens when a certificate is removed -- useful for
planning CA migrations, testing revocation scenarios, or understanding
chain dependencies. Any certificate in the chain can be excluded: leaf,
intermediate, or root. All `--exclude-*` flags are repeatable and can
be combined to exclude multiple certificates in a single invocation.
All exclusion flags support wildcard patterns (`*` matches any sequence
of characters, `?` matches a single character, `[abc]` matches a
character class) and pipe-separated alternatives (`"Old CA|Legacy*"`
matches either value):

```bash
# Exclude by Common Name
certree --exclude-cn "Intermediate CA" cert.pem

# Exclude multiple certificates by Common Name
certree --exclude-cn "Intermediate CA" --exclude-cn "Legacy Root" cert.pem

# Wildcard patterns
certree --exclude-cn "Intermediate*" cert.pem
certree --exclude-cn "*example.com" cert.pem

# Exclude by SHA-256 fingerprint (colon-separated or plain hex)
certree --exclude-fingerprint "A1:B2:C3:D4:*" cert.pem
certree --exclude-fingerprint "A1B2*" cert.pem

# Exclude by serial number (colon-separated or plain hex)
certree --exclude-serial "04:00:00:*" cert.pem

# Combine different exclusion types
certree --exclude-cn "Intermediate CA" --exclude-serial "04:00:*" cert.pem

# Show before/after comparison side by side
certree --exclude-cn "Intermediate CA" --compare cert.pem

# Show unified diff of before/after simulation
certree --exclude-cn "Intermediate CA" --diff cert.pem

# Diff with impact summary
certree --exclude-cn "Intermediate CA" --diff --impact cert.pem

# Simulate certificate rotation: inject new intermediate, exclude old
certree --inject new-intermediate.pem --exclude-cn "Old CA" --compare cert.pem

# Inject a certificate and see what new paths it creates
certree --inject missing-intermediate.pem --compare example.com
```

The `--diff` flag produces unified diff output following standard
`diff -u` conventions. Removed lines are prefixed with `-` (red when
color is enabled), added lines with `+` (green), and unchanged context
lines with a space. Example output:

```
--- Before (example.com)
+++ After (example.com)
-[+ ] example.com -- 1 trusted path
+[x ] example.com -- 1 untrusted path
-`- [+ ] example.com
+`- [! ] example.com (broken)
-   `- [+ ] Intermediate CA
+   `- [! ] Intermediate CA (excluded)
-      `- [+ ] Root CA
+      `- [+ ] Root CA (ghosted)
```

`--diff` and `--compare` are mutually exclusive -- use `--compare` for
side-by-side, `--diff` for a compact vertical view. `--diff` requires
at least one simulation flag (`--exclude-*`, `--inject`, or
`--validation-time`) and is not supported with `--format json`. It
respects `--fields`, `--theme`, `--reverse`, and the `--filter-*`
flags. With `--quiet`, output is suppressed and only the exit code is
returned.

Simulation is also triggered by `--validation-time`, which shifts the
clock for re-validation without requiring any `--exclude-*` flags:

```bash
# What expires by June 2038?
certree --validation-time 2038-06-15T00:00:00Z example.com

# Side-by-side: now vs. June 2038
certree --validation-time 2038-06-15T00:00:00Z --compare example.com

# Combined: time shift + certificate exclusion
certree --validation-time 2038-06-15T00:00:00Z --exclude-cn "Old CA" --diff example.com

# Combine with expiry warning window for maintenance planning
certree --validation-time 2038-06-15T00:00:00Z --expiry-warning-days 90 example.com
```

### Batch processing

Process multiple sources from a file:

```bash
# hosts.txt contains one source per line:
#   example.com:443
#   test.com:443
#   /path/to/cert.pem
certree --batch hosts.txt

# Combine positional arguments with a batch file
# Positional sources are processed before batch file sources
certree github.com --batch hosts.txt

# Combine with JSON output for aggregation
certree --batch hosts.txt --format json > results.json
```

In batch mode, each analysis result includes the source in its header:

```
[+ ] example.com -- 1 trusted path
`- [+ ] example.com
   `- [+ ] Root CA

[+ ] test.com -- 1 trusted path
`- [+ ] test.com
   `- [+ ] Root CA
```

### Configuration

Pass `--config path/to/config.toml` for persistent settings; see
[Configuration Reference](./configuration.md) for the full file format
and how settings combine with flags.

## Options

### Source

| Flag | Description | Default |
|------|-------------|---------|
| `-b`, `--batch` | Batch process sources from file (one per line) | |

### Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `-c`, `--config` | Configuration file path | |

### Trust Store

| Flag | Description | Default |
|------|-------------|---------|
| `--prefer-custom-roots` | Prefer custom trust bundle over system roots when both match | `false` |
| `--system-roots` | Path to system root certificates directory or file | |
| `--trust-bundle` | Path to custom CA bundle PEM file | |

### Connection

| Flag | Description | Default |
|------|-------------|---------|
| `--connect-timeout` | TLS connection timeout for remote hosts | `5s` |
| `--fetch-timeout` | HTTP timeout for URL certificate fetches | `5s` |
| `--sni` | Override SNI hostname sent in TLS handshake | |
| `--client-cert` | Client certificate PEM file for mutual TLS | |
| `--client-key` | Client private key PEM file for mutual TLS | |
| `--aia-fetch` | Fetch missing intermediates via AIA | `false` |
| `--aia-force` | Always fetch via AIA, even when local issuers exist (implies `--aia-fetch`) | `false` |
| `--aia-timeout` | Per-request HTTP timeout for AIA fetches | `5s` |
| `--allow-private-networks` | Allow AIA/OCSP/CRL fetches to private IPs (RFC 1918). Disabled by default as SSRF safeguard. | `false` |

### Validation

| Flag | Description | Default |
|------|-------------|---------|
| `--verify-signatures` | Verify certificate signatures in the chain (RFC 5280 §6.1) | `true` |
| `--verify-expiry` | Verify certificate expiry dates (RFC 5280 §4.1.2.5) | `true` |
| `--expiry-warning-days` | Warn if a certificate expires within N days **from now** -- operational renewal monitoring | `30` |
| `--max-validity-days` | Warn if a non-CA certificate's **total issued lifetime** exceeds N days -- compliance/policy enforcement (0 = disabled, 398 = CA/B Forum TLS limit) | `0` |
| `--verify-hostname` | Verify hostname against certificate SANs and CN (RFC 6125). Auto-derives hostname from source or `--sni` when no explicit `--hostname` is set. | `true` |
| `--hostname` | Override hostname for verification (implies `--verify-hostname`) | |
| `--verify-revocation` | Check revocation status via OCSP (RFC 6960) and CRL (RFC 5280 §5) | `false` |
| `--revocation-fail-open` | Treat OCSP/CRL network failures as warnings, not errors. Disable (`--no-revocation-fail-open`) to fail hard when revocation status cannot be determined. | `true` |
| `--verify-eku` | Verify EKU chaining: each certificate's EKU must be a subset of its issuer's EKU (RFC 5280 §4.2.1.12). Certs without an EKU extension are exempt (legacy compatibility). | `false` |
| `--verify-name-constraints` | Verify name constraints imposed by CA certificates (RFC 5280 §4.2.1.10). When a CA restricts permitted DNS names, IP ranges, emails, or URIs, subordinate certificates must fall within those bounds. | `false` |
| `--max-certificates` | Maximum certificates to process per source | `100` |
| `--max-depth` | Maximum chain depth to build | `10` |
| `--skip-invalid` | Skip unparseable certificates instead of failing | `false` |

### Flag Implications

Some flags automatically enable related flags:

| Flag | Implies |
|------|---------|
| `--aia-force` | `--aia-fetch` (force is meaningless without fetch) |
| `--hostname <name>` | `--verify-hostname` (specifying a name without verification is contradictory) |

Implications apply regardless of whether the value comes from the CLI
or a config file. They cannot be overridden in the same invocation --
`--aia-force --no-aia-fetch` still enables AIA fetching.

### Boolean Flag Negation

Every boolean flag has a hidden `--no-<flag>` counterpart that sets the
flag to `false`. This is useful for disabling a setting that a config
file enables:

```bash
# Disable expiry checking for this run only
certree --no-verify-expiry example.com

# Override a config file that enables revocation checking
certree --config ~/.certree.toml --no-verify-revocation example.com
```

When both the positive and negative forms are set
(`--verify-expiry --no-verify-expiry`), the negative form wins.

### Display

| Flag | Description | Default |
|------|-------------|---------|
| `-f`, `--fields` | Certificate fields to display: `aia`, `algorithm`, `all`, `crl`, `diagnostics`, `extensions`, `fingerprint`, `issuer`, `san`, `serial`, `source`, `subject`, `trust-store`, `validity` | |
| `--filter-cn` | Filter by Common Name pattern, supports wildcards (repeatable) | |
| `--filter-fingerprint` | Filter by SHA-256 fingerprint pattern, supports wildcards (repeatable) | |
| `--filter-serial` | Filter by serial number pattern, supports wildcards (repeatable) | |
| `--annotations` | Show parenthesized status annotations on certificate and path nodes (e.g. `(expired)`, `(self-signed, trusted)`). Off by default for minimal output; enable with `--annotations` when you need contextual detail. | `false` |
| `--path-index` | Show a right-aligned path index (`#1`, `#2`, ...) on path terminal certificates to identify which trust path each branch represents. Most useful with multiple trust paths. | `false` |
| `--expand` | Show each trust path separately instead of the default merged tree view | `false` |
| `--reverse` | Render certificates in root-to-leaf order | `false` |
| `--theme` | Render theme: `classic`, `terse`, `minimal` | `classic` |
| `--wrap` | Wrap long detail lines to fit terminal width (tree mode only; ignored with `--format json`) | `false` |

### Output

| Flag | Description | Default |
|------|-------------|---------|
| `--color` | Color mode: `auto`, `always`, `never` | `auto` |
| `--format` | Output format: `tree`, `json` | `tree` |
| `-q`, `--quiet` | Suppress stdout and stderr, exit code only. Use `-v` flags to re-enable stderr logging | `false` |
| `-v`, `--verbose` | Log verbosity: `-v` (error), `-vv` (warn), `-vvv` (info), `-vvvv` (debug) | `off` |

### Simulation

| Flag | Description | Default |
|------|-------------|---------|
| `--compare` | Show side-by-side before/after comparison. Requires at least one simulation flag (`--exclude-*`, `--inject`, or `--validation-time`). With `--format json`, outputs `[{"before":..., "after":...}]`. | `false` |
| `--diff` | Show unified diff of before/after changes. Not supported with `--format json`. | `false` |
| `--exclude-cn` | Exclude certificates by Common Name, supports wildcards (repeatable) | |
| `--exclude-fingerprint` | Exclude certificates by SHA-256 fingerprint, supports wildcards (repeatable) | |
| `--exclude-serial` | Exclude certificates by serial number, supports wildcards (repeatable) | |
| `--inject` | Add certificates from file (PEM/DER) into the chain analysis and rebuild all trust paths (repeatable) | |
| `--validation-time` | Override current time for simulation re-validation (RFC 3339 format) | |
| `--impact` | Show impact summary after simulation. Requires at least one simulation flag (`--exclude-*`, `--inject`, or `--validation-time`). Not supported with `--format json`. | `false` |

### Info

| Flag | Description | Default |
|------|-------------|---------|
| `-h`, `--help` | Show help message | |
| `--version` | Show version information | |

## Exit Codes

certree uses exit codes to communicate results to scripts and CI
pipelines:

| Code | Description |
|------|-------------|
| 0 | All certificates valid |
| 1 | Certificate validation failed (expired, untrusted, etc.) |
| 2 | Invalid arguments or missing sources |
| 3 | Invalid config file or conflicting options |
| 4 | Remote host unreachable or TLS handshake failed |
| 5 | Certificate file could not be parsed |
| 6 | Output rendering failure |

Use exit codes in scripts:

```bash
if certree example.com --quiet; then
    echo "Certificates valid"
else
    echo "Certificate issue detected (exit code: $?)"
fi
```

## stdin and stdout

certree follows Unix conventions for standard streams:

- **stdout**: Analysis output (tree or JSON)
- **stderr**: Errors, warnings, and log output
- **stdin**: Certificate data when the source is `-`

Color output is automatically disabled when stdout is not a terminal
(i.e., when piping), unless forced with `--color always`. The
`NO_COLOR` environment variable is also respected.

See also: [Certificate Trust Paths](./certificate-trust-paths.md),
[Configuration Reference](./configuration.md),
[Design Philosophy](./design-philosophy.md).

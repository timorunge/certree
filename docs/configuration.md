# Configuration Reference

How to configure certree with a TOML file, and what every setting does.

## How Configuration Works

certree does not search for configuration files. Unless you pass `--config`,
it uses built-in defaults with no file system lookups.

```bash
certree --config ~/.certree.toml example.com
```

For persistent config without typing the flag every time, use a shell alias:

```bash
alias certree='certree --config ~/.certree.toml'
```

CLI flags always override config file settings. A config file sets your
baseline; flags adjust it per invocation. Only flags you explicitly pass
on the command line take effect -- flags you omit leave the config file
values (or defaults) intact.

For boolean flags, use `--flag=false` or the `--no-<flag>` shorthand to
explicitly disable a setting that your config file enables:

```bash
# Config file has verify_revocation = true, disable it for this run
certree --config ~/.certree.toml --no-verify-revocation example.com
```

For string flags, pass the flag explicitly to override the config file value:

```bash
# Config file has fields = "subject", switch to fingerprint for this run
certree --config ~/.certree.toml --fields fingerprint example.com
```

Some flags are runtime-only and not backed by configuration: `--batch`,
`--config`, `--quiet`, `--verbose`, `--compare`, `--diff`, `--impact`,
the `--filter-*` flags, `--inject`, `--validation-time`, and the
`--exclude-*` simulation flags. These are inherently per-invocation and
never persisted. The `--filter-*` and `--exclude-*` flags are repeatable
-- specify them multiple times to match or exclude multiple values.

You don't need to specify every field -- only set what you want to change.
Fields you omit keep their defaults. For boolean fields, there is a
distinction between omitting a field and explicitly setting it to `false`:
if you write `verify_revocation = false`, that value is recorded even when
it matches the current default. This matters if defaults change in a future
version.

## Minimal Example

Most users only need a few settings. Here's a config that enables validity
dates and uses the terse theme:

```toml
[render]
fields = "validity"
theme = "terse"

[validation]
expiry_warning_days = 14
```

## Complete Reference

All available fields with their default values:

```toml
# certree configuration file
# Only set the fields you want to change. Everything else uses defaults.

[connection]
connect_timeout = "5s"          # TLS connection timeout for remote hosts
fetch_timeout = "5s"            # HTTP timeout for URL certificate fetches
sni = ""                        # Override SNI hostname sent in TLS handshake
client_cert = ""                # Client certificate PEM file for mutual TLS
client_key = ""                 # Client private key PEM file for mutual TLS
aia_fetch = false               # Fetch missing intermediates via AIA
aia_force = false               # Always fetch via AIA (implies aia_fetch)
aia_timeout = "5s"              # Per-request HTTP timeout for AIA fetches
allow_private_networks = false  # Allow AIA/OCSP/CRL to private IPs (SSRF safeguard)

[validation]
verify_signatures = true         # Verify certificate signatures in the chain (RFC 5280 §6.1)
verify_expiry = true             # Verify certificate expiry dates (RFC 5280 §4.1.2.5)
expiry_warning_days = 30         # Warn if certificate expires within N days from now (renewal monitoring)
max_validity_days = 0            # Warn if total issued lifetime > N days (0 = off, 398 = CA/B Forum limit)
verify_hostname = true           # Verify hostname against certificate SANs and CN (RFC 6125)
hostname = ""                    # Override hostname for verification (implies verify_hostname)
verify_revocation = false        # Check revocation via OCSP (RFC 6960) and CRL (RFC 5280 §5)
revocation_fail_open = true      # Treat OCSP/CRL failures as warnings, not errors
verify_eku = false               # Verify EKU chaining per RFC 5280 §4.2.1.12
verify_name_constraints = false  # Verify name constraints per RFC 5280 §4.2.1.10
skip_invalid = false             # Skip unparseable certificates instead of failing
max_certificates = 100           # Maximum certificates to process per source
max_depth = 10                   # Maximum chain depth to build

[render]
fields = ""                  # Comma-separated display fields: aia, algorithm, all,
                             # crl, diagnostics, extensions, fingerprint, issuer,
                             # san, serial, source, subject, trust-store, validity
annotations = false          # Show status annotations on certs/paths (expired, self-signed, etc.)
path_index = false           # Show right-aligned path index (#1, #2, ...) on path terminals
expand = false               # Show each trust path separately instead of merged tree view
reverse = false              # Display certificates in root-to-leaf order
theme = "classic"            # classic, terse, or minimal
wrap = false                 # Wrap long detail lines to fit terminal width

[output]
color = "auto"               # auto, always, or never
format = "tree"              # tree or json
log_level = "off"            # off, error, warn, info, or debug

[trust_store]
trust_bundle = ""            # Path to custom CA bundle PEM file
system_roots = ""            # Path to system root certificates directory or file
prefer_custom_roots = false  # Prefer custom bundle over system roots when both match
```

## Field Reference

### connection

Network behavior when connecting to remote TLS servers.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `connect_timeout` | string | `"5s"` | TLS connection timeout (`"5s"`, `"30s"`, `"1m"`). Must be positive and at most `5m`. |
| `fetch_timeout` | string | `"5s"` | HTTP client timeout for URL certificate fetches (`"5s"`, `"30s"`, `"1m"`). Must be positive and at most `5m`. |
| `sni` | string | `""` | Override the SNI hostname sent in the TLS ClientHello. Empty means use the target hostname. Useful when connecting through a proxy or when the DNS name differs from the certificate's hostname. |
| `client_cert` | string | `""` | Path to client certificate PEM file for mutual TLS authentication. Must be paired with `client_key`. |
| `client_key` | string | `""` | Path to client private key PEM file for mutual TLS authentication. Must be paired with `client_cert`. |
| `aia_fetch` | bool | `false` | Fetch missing intermediate certificates from AIA URLs embedded in certificates |
| `aia_force` | bool | `false` | Always fetch via AIA, even when local issuers exist. Discovers alternate trust paths. Implies `aia_fetch = true`. |
| `aia_timeout` | string | `"5s"` | Per-request HTTP timeout for AIA fetches. Controls how long each individual AIA fetch waits before timing out. Must be positive and at most `5m`. |
| `allow_private_networks` | bool | `false` | Allow AIA and OCSP/CRL fetches to RFC 1918 private IP addresses. Required for internal PKI with private AIA/OCSP endpoints. Disabled by default as an SSRF safeguard. |

### validation

Controls certificate validation behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `verify_signatures` | bool | `true` | Verify cryptographic signatures in the chain (RFC 5280 §6.1). |
| `verify_expiry` | bool | `true` | Verify certificate expiry dates (RFC 5280 §4.1.2.5). |
| `expiry_warning_days` | int | `30` | Warn if a certificate expires within this many days **from now**. Measures remaining time -- use this for operational renewal monitoring. Range: 1--3650. |
| `max_validity_days` | int | `0` | Warn if a non-CA certificate's **total issued lifetime** exceeds N days. Measures the validity window the cert was issued with -- use this for compliance enforcement (e.g. CA/B Forum caps TLS server certs at 398 days). Set to `0` to disable. |
| `verify_hostname` | bool | `true` | Verify the hostname against the certificate's SANs and CN (RFC 6125). When enabled and no explicit `hostname` is set, the hostname is auto-derived from the source domain or SNI. |
| `hostname` | string | `""` | Override hostname for verification. Implies `verify_hostname = true` when set. |
| `verify_revocation` | bool | `false` | Check revocation status via OCSP (RFC 6960) and CRL (RFC 5280 §5). |
| `revocation_fail_open` | bool | `true` | Treat OCSP/CRL network failures (timeouts, unreachable responders) as warnings instead of errors. Set to `false` to fail hard when revocation status cannot be determined. |
| `verify_eku` | bool | `false` | Verify EKU chaining: each certificate's extended key usages must be a subset of its issuer's. Certs without an EKU extension are exempt (legacy compatibility). |
| `verify_name_constraints` | bool | `false` | Verify name constraints imposed by CA certificates. When a CA restricts permitted DNS names, IP ranges, email addresses, or URIs, subordinate certificates must fall within those bounds. |
| `skip_invalid` | bool | `false` | Skip unparseable certificates instead of failing. Useful for bundles with known-bad certs. |
| `max_certificates` | int | `100` | Maximum number of certificates to process from a single source. Range: 1--10000. |
| `max_depth` | int | `10` | Maximum chain depth. Prevents runaway chain building in pathological cases. Range: 1--100. |

### render

Controls how certificate chains are visualized in the terminal.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fields` | string | `""` | Comma-separated list of display fields. Valid values: `aia`, `algorithm`, `all`, `crl`, `diagnostics`, `extensions`, `fingerprint`, `issuer`, `san`, `serial`, `source`, `subject`, `trust-store`, `validity`. Use `all` to enable every field. |
| `annotations` | bool | `false` | Show parenthesized status annotations on certificate and path nodes (e.g. `(expired)`, `(self-signed, trusted)`). Off by default for minimal output; enable with `annotations = true` or `--annotations` when you need contextual detail. |
| `path_index` | bool | `false` | Show a right-aligned path index (`#1`, `#2`, ...) on path terminal certificates to identify which trust path each branch represents. Most useful with multiple trust paths. |
| `expand` | bool | `false` | Show each trust path as a separate tree instead of the default merged view. Useful when you need to see exactly which certificates belong to which path. |
| `reverse` | bool | `false` | Display certificates in root-to-leaf order. Useful when you prefer reading chains from the trust anchor down, similar to how browsers display certificate hierarchies. |
| `theme` | string | `"classic"` | Display theme: `classic`, `terse`, or `minimal`. |
| `wrap` | bool | `false` | Wrap long detail field values onto continuation lines aligned under the value column. Applies to tree mode only; ignored with `--format json`. |

### output

Controls the output format and color behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `color` | string | `"auto"` | Color mode: `auto` (detect TTY), `always`, or `never`. Respects `NO_COLOR` env var. |
| `format` | string | `"tree"` | Output format: `tree` for human-readable, `json` for machine-readable. |
| `log_level` | string | `"off"` | Log verbosity: `"off"`, `"error"`, `"warn"`, `"info"`, `"debug"`, or `""` (treated as `"off"`). CLI `-v`/`-vv`/`-vvv`/`-vvvv` overrides this setting. |

### trust_store

Controls which trust anchors are used for chain validation.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trust_bundle` | string | `""` | Path to a PEM file containing custom trust anchors. |
| `system_roots` | string | `""` | Override the system root certificate path. Empty means use the OS default. |
| `prefer_custom_roots` | bool | `false` | When true, custom trust bundles take precedence over system roots when both contain the same certificate. |

See also: [Design Philosophy](./design-philosophy.md), [Certificate Trust Paths](./certificate-trust-paths.md), [CLI Reference](./cli.md).

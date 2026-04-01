# certree

[![CI](https://github.com/timorunge/certree/actions/workflows/ci.yml/badge.svg)](https://github.com/timorunge/certree/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/timorunge/certree)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/timorunge/certree)](https://goreportcard.com/report/github.com/timorunge/certree)
[![License](https://img.shields.io/github/license/timorunge/certree)](LICENSE)
[![Release](https://img.shields.io/github/v/release/timorunge/certree)](https://github.com/timorunge/certree/releases)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/timorunge/certree.svg)](https://pkg.go.dev/github.com/timorunge/certree)

A Go library and CLI tool for analyzing X.509 certificate chains.
certree shows you every trust path a certificate has -- including
cross-signed paths that most tools hide -- and lets you simulate what
happens when any certificate in the chain is removed.

Think `tree` for certificate chains, or `dig` for TLS trust paths.

## Why certree

When your browser connects to a server, it builds a certificate chain
and checks whether it leads to a trusted root. Most tools show you one
chain. But certificates can have multiple valid trust paths through
cross-signing, and understanding those paths matters when CAs are sunset
or trust stores change.

certree builds all possible trust paths, fetches missing intermediates
via AIA, and lets you simulate certificate exclusions to see what breaks
before you change anything.

## Installation

### Go install

```bash
go install github.com/timorunge/certree/cmd/certree@latest
```

### Binary download

Download pre-built binaries for your platform from the
[releases page](https://github.com/timorunge/certree/releases).

### Build from source

```bash
git clone https://github.com/timorunge/certree.git
cd certree
make build
```

## Quick Start

Analyze a remote server:

```bash
certree github.com
```

```
[+ ] github.com -- 1 trusted path
`- [+ ] github.com
   `- [+ ] Sectigo Public Server Authentication CA DV E36
      `- [+ ] Sectigo Public Server Authentication Root E46
```

Discover all trust paths, including cross-signed chains:

```bash
certree --aia-force cloudflare.com
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

Four trust paths through different root CAs, collapsed into a merged
tree. When certificates share the same CN (like the two WE1
intermediates), fingerprint prefixes automatically disambiguate them.
The first WE1 (`1D:FC...`) branches to two variants of GTS Root R4
(one extending to GlobalSign Root CA for backward compatibility). The
second WE1 (`A2:87...`) reaches GlobalSign directly -- an independent
trust path. If any one root is distrusted, other paths survive.

Simulate removing a certificate and see the impact. All `--exclude-*`
flags are repeatable and support wildcard patterns:

```bash
# Exclude by CN -- see which paths break
certree --exclude-cn "GTS Root R4" --aia-force cloudflare.com

# Exclude by fingerprint -- target a specific certificate variant
certree --exclude-fingerprint "1D:FC:16:*" --aia-force cloudflare.com

# Side-by-side before/after comparison
certree --exclude-cn "GTS Root R4" --compare --aia-force cloudflare.com

# Unified diff view
certree --exclude-cn "GTS Root R4" --diff --aia-force cloudflare.com

# Wildcard patterns
certree --exclude-cn "GTS Root*" --diff --aia-force cloudflare.com
```

Analyze a local certificate file:

```bash
certree cert.pem
```

## Common Usage

```bash
# Show certificate details
certree --fields all example.com

# JSON output for scripting
certree --format json cert.pem | jq '.[].trust_paths[] | select(.status == "trusted")'

# Pipe from another tool
echo q | openssl s_client -connect example.com:443 -showcerts 2>/dev/null | certree -

# Batch process a list of hosts
certree --batch hosts.txt
```

See the [CLI Reference](docs/cli.md) for the full list of options,
output formats, and exit codes.

## Configuration

certree uses sensible defaults for all settings. Pass `--config path`
for persistent configuration. See
[docs/configuration.md](docs/configuration.md) for every setting and
its default value.

## Library Usage

certree can be used as a Go library:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/timorunge/certree/pkg/certree"
)

func main() {
    p := certree.NewParser()
    analyzer, err := certree.NewAnalyzer(certree.WithParser(p))
    if err != nil {
        log.Fatal(err)
    }

    analysis, err := analyzer.Analyze(context.Background(), "cert.pem")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d certificates in %d trust paths\n",
        len(analysis.Certificates), len(analysis.TrustPaths))

    for _, cert := range analysis.Certificates {
        fmt.Printf("  %s (expired: %v)\n", cert.CommonName(), cert.Metadata().IsExpired)
    }
}
```

## Documentation

The [docs/](docs/) folder has the full documentation:

- [CLI Reference](docs/cli.md) -- usage, sources, options, output
  formats, exit codes
- [Library Guide](docs/library.md) -- using certree as a Go library
- [Configuration Reference](docs/configuration.md) -- TOML config file
  format and every setting
- [Architecture](docs/architecture.md) -- package structure, interfaces,
  and component interactions
- [Certificate Trust Paths](docs/certificate-trust-paths.md) -- how TLS
  chains work, cross-signing, and AIA discovery
- [Design Philosophy](docs/design-philosophy.md) -- why certree is
  built the way it is
- [Motivation](docs/motivation.md) -- why certree exists, the problem
  it solves, and building software with AI
- [Testing](docs/testing.md) -- testing philosophy and property-based
  testing approach
- [Security](docs/security.md) -- threat model, SSRF protection, and
  vulnerability reporting
- [Hands-on Guide](docs/hands-on-guide.md) -- step-by-step walkthrough
  of all certree features
- [Contributing](docs/contributing.md) -- development setup, quality
  gates, and how to submit changes

## Development

```bash
make help     # Show all available targets
make check    # Run all quality gates (fmt, tidy, vet, lint, test)
make lint     # Run golangci-lint
make test     # Run tests with race detector
make build    # Build static binary
```

See [docs/contributing.md](docs/contributing.md) for development setup,
quality gates, commit conventions, and the release process.

## License

MIT -- see [LICENSE](LICENSE).

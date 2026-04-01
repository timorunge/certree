# Documentation: Finding What You Need

An index of certree's documentation, organized so you can get to the right
page fast.

## What certree Does

certree is a Go library and CLI tool that analyzes X.509 certificate chains.
It builds all possible trust paths -- including cross-signed paths that most
tools hide -- and lets you simulate what happens when any certificate in the
chain is removed.

The [project README](../README.md) covers installation and quick-start usage.

## Where to Start

Different starting points for different goals:

**Using certree from the command line?**
Start with the [CLI Reference](./cli.md). It covers sources, flags, output
formats, and exit codes with practical examples.

**Integrating certree into a Go project?**
The [Library Guide](./library.md) walks through the API with working code
examples. Parsing, chain building, validation, simulation -- it is all there.

**Want a guided walkthrough with real certificates?**
The [Hands-On Guide](./hands-on-guide.md) walks through chain analysis, trust
stores, validation, exclusion, and injection step by step with runnable
examples.

**Debugging a "certificate not trusted" error?**
Read [Certificate Trust Paths](./certificate-trust-paths.md). It explains how
chains work, why multiple trust paths exist, and how cross-signing complicates
things.

**Contributing to certree?**
Start with [Contributing](./contributing.md) for development setup and
workflow, then read [Design Philosophy](./design-philosophy.md) to understand
the project's principles.

## Documentation Map

### Getting Started

| Document | What It Covers |
|----------|---------------|
| [CLI Reference](./cli.md) | Usage, sources, options, output formats, exit codes. The practical "how do I use this" guide. |
| [Hands-On Guide](./hands-on-guide.md) | Step-by-step walkthrough: chain analysis, trust stores, validation, exclusion, injection, and scripting. Includes example certificates you can run yourself. |
| [Configuration](./configuration.md) | TOML config file format, every setting with its default value, and how settings combine with flags. |

### Reference

| Document | What It Covers |
|----------|---------------|
| [Library Guide](./library.md) | Using certree as a Go library. Working code examples for parsing, chain building, validation, and simulation. |
| [Certificate Trust Paths](./certificate-trust-paths.md) | How TLS certificate chains work, cross-signing, AIA discovery, and trust store matching. Background knowledge for understanding certree's output. |

### Deep Dives

| Document | What It Covers |
|----------|---------------|
| [Architecture](./architecture.md) | Internal package structure, interfaces, data flow, CLI wiring, and key types. The structural map of the codebase. |
| [Contributing](./contributing.md) | Development setup, quality gates, commit conventions, release process. The practical "how do I contribute" guide. |
| [Design Philosophy](./design-philosophy.md) | Why certree is built the way it is. Unix philosophy, composability, and AI-assisted development. |
| [Motivation](./motivation.md) | Why certree exists, what problem it solves, and what it takes to build real software with AI. |
| [Testing](./testing.md) | Testing philosophy, property-based testing with gopter, test organization, and why every test earns its keep. |
| [Security](./security.md) | Threat model, SSRF protection, input limits, vulnerability reporting, and release verification. |

## Further Reading

- [Project README](../README.md) -- installation, quick-start, feature overview
- [Go Package Documentation](https://pkg.go.dev/github.com/timorunge/certree) -- generated API docs
- [Releases](https://github.com/timorunge/certree/releases) -- pre-built binaries and changelogs

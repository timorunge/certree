# Design Philosophy

Why certree is built the way it is.

## The Core Idea

certree exists because of a simple observation: there is no good, focused
command-line tool for inspecting TLS certificate chains the way `tree`
inspects directory structures or `dig` inspects DNS records.

The tools that exist are either too broad (OpenSSL's sprawling interface),
too narrow (browser certificate viewers), or too opaque (libraries that hide
the chain-building logic). None of them compose well with other tools. None
of them treat certificate chains as structured data you can pipe, filter, and
transform.

certree is an attempt to fill that gap -- and to do it following principles
that have proven themselves over fifty years of Unix development.

## Unix Philosophy: Do One Thing Well

The design of certree follows the program design guidelines described by Rob
Pike and Brian Kernighan, and practiced throughout the Unix tradition. The
core tenets:

**1. Make each program do one thing well.**

certree does one thing: it takes certificate sources (files, URLs, stdin) and
produces a structured view of the trust paths those certificates form. It does
not generate certificates, manage trust stores, or configure TLS servers.
Those are different problems for different tools.

**2. Expect the output of every program to become the input to another.**

certree writes to stdout. Errors go to stderr. Output formats include plain
text for humans and JSON for machines. This means certree slots into pipelines
naturally:

```bash
# Feed certree output into jq for filtering
certree --format json example.com | jq '.[].trust_paths[] | select(.status == "trusted")'

# Pipe a PEM file from another tool
echo q | openssl s_client -connect example.com:443 -showcerts 2>/dev/null | certree -

# Batch process a list of hosts
cat hosts.txt | xargs -I{} certree {}
```

**3. Design programs to handle text streams, because that is a universal interface.**

Certificates are text. PEM is text. The output is text. certree reads from
files, URLs, and stdin. It writes to stdout. No proprietary formats, no
databases, no state files. Everything flows through the standard streams that
every Unix tool understands.

**4. Build small, sharp tools rather than sprawling frameworks.**

The certree CLI is a thin layer over the `pkg/certree` library. The library
itself is composed of focused components -- a parser, a chain builder, a
validator, a simulator -- each doing one job. They compose through
well-defined interfaces, not through a monolithic "do everything" function.

## Explicit Configuration

certree uses sensible defaults for all settings. Pass `--config path` for
persistent configuration -- see [Configuration Reference](./configuration.md)
for every available setting and its default value.

## Why Go

The language choice was deliberate. certree needed to be:

- **Fast**: Certificate chain building involves cryptographic signature
  verification, ASN.1 parsing, and potentially network I/O for AIA fetching.
  Python and Node.js add overhead that matters when processing thousands of
  certificates or running in CI pipelines. certree takes this further with a
  benchmark suite that tracks allocation counts and memory usage across every
  hot path, ensuring performance does not regress as the codebase evolves.

- **Portable**: A single static binary that runs on Linux, macOS, and Windows
  without runtime dependencies. No `pip install`, no `node_modules`, no
  version conflicts. Download the binary, run it.

- **Close to the system**: Go's `crypto/x509` and `crypto/tls` packages
  provide direct access to certificate primitives, TLS connections, trust
  store access, and ASN.1 parsing. The `golang.org/x/` extensions add
  PKCS#12/OCSP support and terminal detection. Beyond the Go ecosystem, the
  runtime binary has three external dependencies: `fatih/color`,
  `spf13/pflag`, and `BurntSushi/toml`. This matters for a security tool --
  fewer dependencies means a smaller attack surface.

- **Concurrent by design**: AIA fetching, batch processing, and revocation
  checking are inherently parallel operations. Go's goroutines and channels
  make this natural without the complexity of thread pools or async/await
  chains.

Go sits in a practical sweet spot: lower-level than Python or TypeScript
(compiled, statically typed, negligible garbage collection pauses at this
scale), but higher-level than C or Rust (memory safety without manual
management, rich standard library). For a CLI tool that needs to be fast,
portable, and correct, it is the right choice.

There is also a practical reason: the human steering this project knows Go.
When AI agents generate code, having a human who can read it, reason about
it, and catch when something looks off matters. Familiarity with the language
means the review process is genuine, not ceremonial.

## AI-Assisted Development

certree is AI-generated software, built by AI agents under human direction.
The goal is to meet the same bar you would set for human-written production
software -- but getting there takes the same discipline any serious project
requires. The Unix principles that guide the design -- small components,
clear interfaces, data flowing in one direction -- also help keep
AI-generated code manageable. See [Motivation](./motivation.md) for more on
the experience of building software this way, and
[Architecture](./architecture.md) for how the pieces fit together.

## Further Reading

- [Rob Pike, Brian Kernighan - Program Design in the UNIX Environment](https://harmful.cat-v.org/cat-v/unix_prog_design.pdf)
  -- the paper that articulates these design principles
- [Doug McIlroy - Unix Philosophy](https://en.wikipedia.org/wiki/Unix_philosophy#Doug_McIlroy_on_Unix_programming)
  -- "Write programs that do one thing and do it well"
- [Eric S. Raymond - The Art of Unix Programming](https://en.wikipedia.org/wiki/The_Art_of_Unix_Programming)
  -- comprehensive treatment of Unix design philosophy
- [Go at Google: Language Design in the Service of Software Engineering](https://go.dev/talks/2012/splash.article)
  -- why Go's design aligns with these principles

See also: [Motivation](./motivation.md),
[Certificate Trust Paths](./certificate-trust-paths.md),
[Configuration Reference](./configuration.md), [Testing](./testing.md).

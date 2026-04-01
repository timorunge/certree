# Contributing

How to set up a development environment, run the quality gates, and submit
changes.

## Prerequisites

You need:

- **Go** (version in `go.mod` -- currently 1.26+)
- **golangci-lint** v2
  (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6`;
  version must match `.github/workflows/lint-and-test.yml`)
- **Git** with [Conventional Commits](https://www.conventionalcommits.org/)
  for commit messages

Optional but useful:

- **goreleaser** for building release binaries locally
  (`go install github.com/goreleaser/goreleaser@latest`)
- **cosign** for verifying release signatures
  (`go install github.com/sigstore/cosign/v2/cmd/cosign@latest`)
- **syft** for generating SBOMs locally
  (`go install github.com/anchore/syft/cmd/syft@latest`)
- **benchstat** for comparing benchmark results
  (`go install golang.org/x/perf/cmd/benchstat@latest`)

## Getting Started

```bash
git clone https://github.com/timorunge/certree.git
cd certree
make build
./certree --version
```

That's it. No Docker, no external services, no configuration files to create.
The binary is self-contained.

## Development Workflow

### 1. Make your changes

See [Architecture](./architecture.md) for the full package structure. The
short version: the library (`pkg/certree`) does the work, the CLI
(`internal/cli`) parses flags and calls it, and `internal/render` handles
terminal output.

### 2. Run the quality gates

Before committing, run all checks:

```bash
make check
```

This runs formatting, module tidying, vet, linting, and tests in one command.
All five must pass. Zero tolerance for lint warnings.

Or run them individually:

```bash
make fmt          # Check formatting (non-destructive)
make fmt-fix      # Fix formatting (destructive)
make lint         # Run golangci-lint
make test         # Run tests (short mode, race detector, 2m timeout)
```

### 3. Run benchmarks if you touched hot paths

If your change affects parsing, chain building, validation, rendering, or the
CLI pipeline, run the relevant benchmarks before and after:

```bash
# Before your change
go test -bench=. -benchmem -run='NOMATCH' ./pkg/certree/ > bench-before.txt

# After your change
go test -bench=. -benchmem -run='NOMATCH' ./pkg/certree/ > bench-after.txt

# Compare
benchstat bench-before.txt bench-after.txt
```

Performance regressions in hot paths should be justified. If your change adds
allocations to `NewCertificate` or `BuildChains`, there should be a good
reason.

### 4. Commit with conventional commits

Follow the conventions in [AGENTS.md](../AGENTS.md) under Git Conventions.

### 5. Open a pull request

Push your branch and open a PR against `main`. CI runs automatically:

- **Lint**: formatting, module tidiness, vet, and `golangci-lint` on Linux,
  macOS, and Windows
- **Test**: Full test suite with race detector on Linux, macOS, and Windows
- **Coverage**: Uploaded to Codecov

All checks must pass before merge.

## Testing

See [Testing](./testing.md) for the full philosophy, test organization, and
conventions. The key rules:

- Check `pkg/certree/testutil` before writing helpers -- it probably has what
  you need
- Cache certificates in benchmarks and property tests (RSA key generation is
  slow)
- Add benchmarks to the existing `bench_test.go`, not to individual test files

## Code Style

The short version:

- `golangci-lint run ./...` must pass with zero issues
- All exported symbols need godoc comments
- Errors are wrapped with `%w` and include context
- Accept `context.Context` for cancellable operations
- Use `bytes.Equal` on raw ASN.1 fields, not `pkix.Name.String()`, for
  comparisons
- Pre-allocate slices when capacity is known

The full conventions (declaration ordering, naming, import grouping, etc.) are
in `AGENTS.md` at the repository root.

## Error Handling

certree uses a two-tier error pattern: `*certree.StructuredError` at
user-facing boundaries (Parser, Analyzer, AIAFetcher), plain `fmt.Errorf`
everywhere else.

The quick decision: if you're in an unexported function, use `fmt.Errorf`.
The exported caller wraps the result in a `StructuredError` when appropriate.
All sentinel errors live in `pkg/certree/errors.go` -- check existing
sentinels before creating a new one.

See [Architecture](./architecture.md#key-types) for the full error model,
field accessors, and sentinel catalog.

## Releases

Releases are automated. When a version tag is pushed:

```bash
git tag v1.2.3
git push origin v1.2.3
```

GitHub Actions runs [GoReleaser](https://goreleaser.com/), which:

1. Builds binaries for Linux, macOS, and Windows (amd64 + arm64)
2. Signs the checksum file with
   [cosign](https://github.com/sigstore/cosign) (keyless, OIDC-based)
3. Generates an SPDX SBOM for each archive via
   [syft](https://github.com/anchore/syft)
4. Generates a changelog from conventional commits
5. Creates a GitHub release with binaries, checksums, signatures, and SBOMs
6. Groups changes into Features, Bug Fixes, Performance Improvements, etc.

All GitHub Actions are pinned to major version tags (e.g., `@v4`) and kept
up to date by Dependabot.

No manual release process. Tag it, push it, done.

## API Stability

`pkg/certree` is the public API. The following stability rules apply:

- **Stable types**: `Certificate`, `TrustPath`, `Analysis`,
  `StructuredError`, all constructor options (`With*`), all error sentinels
  (`Err*`), all enum types (`PathStatus`, `SourceType`, `ErrorType`,
  `WarningType`).
- **Experimental**: `pkg/certree/testutil` is not part of the public API and
  may change without notice.
- **Semver policy**: Breaking changes (removing exported symbols, changing
  signatures, altering JSON output schema) require a major version bump.
- **Iota enums**: New `SourceType`, `ErrorType`, or `WarningType` values must
  be appended at the end. Never insert before existing constants -- persisted
  data or `MarshalJSON`/`UnmarshalJSON` may depend on the ordering.
- **Struct fields**: Adding a field to `Analysis`, `TrustPath`, or
  `Certificate` is a minor change (JSON gains a key). Removing or renaming a
  field is breaking.
- **`internal/` packages**: Not covered by semver. These may change freely
  between releases.

See also: [CLI Reference](./cli.md), [Library Guide](./library.md),
[Testing](./testing.md), [Design Philosophy](./design-philosophy.md).

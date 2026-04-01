# Architecture Reference

How certree is structured internally, and how the pieces connect. For design
principles, see [Design Philosophy](./design-philosophy.md). For the public
API, see [Library Guide](./library.md).

## Package Structure

```
cmd/certree/                  CLI entry point (main.go only)
internal/
  cli/                        Flag parsing, config wiring, output orchestration
  config/                     TOML configuration types, loading, validation
  render/                     Tree visualization, themes, comparison, diff
pkg/certree/                  Public library (all core logic)
  testutil/                   Shared test infrastructure and generators
```

Three rules govern this layout:

1. `pkg/certree` is the public API. It must never import `internal/` packages.
2. `pkg/certree` must never contain rendering or formatting logic. Visual
   output belongs in `internal/render`.
3. `internal/config` is independent of flag parsing. It defines types,
   defaults, TOML loading, and validation -- nothing else.

## Data Flow

A single certree invocation follows this pipeline:

```
                       CLI Layer                              Library Layer
              +---------------------------+    +---------------------------------------+
              |                           |    |                                       |
  args -----> | flags -> config -> wiring | -> | Parser -> ChainBuilder -> Validator   |
              |                           |    |                            |          |
              +---------------------------+    |                         Simulator     |
                                               |                            |          |
              +---------------------------+    +---------------------------------------+
              |                           |                                 |
  stdout <--- |    render.Trees / Diffs   | <-------------------------------+
              |    render.Comparisons     |          []*Analysis
              +---------------------------+
```

Data flows in one direction. Each component is independent: the parser does
not know about validation, the chain builder does not know about rendering.
Components communicate through well-defined types, not through shared state.

**Example: `certree example.com`**

```
1. CLI parses "example.com" -> detects hostname -> appends ":443"
2. Parser.ParseRemote("example.com:443") -> [leaf, intermediate] (2 certs)
3. ChainBuilder.BuildChains([leaf, intermediate], trustStore)
   -> finds root in system store -> [TrustPath{leaf->intermediate->root, Trusted}]
4. Validator.Validate(paths) -> annotates: no errors, no warnings
5. render.Trees(analyses) -> ASCII tree to stdout
```

## Interfaces

The library is built around seven interfaces. Each has an unexported default
implementation created through a constructor function. This pattern keeps the
API surface small while allowing every component to be replaced in tests or
custom integrations.

### Core Pipeline

| Interface | Method | Constructor |
|-----------|--------|-------------|
| `Parser` | `ParseFile`, `ParseRemote`, `ParseURL`, `ParseBytes` | `NewParser(opts...)` |
| `ChainBuilder` | `BuildChains(ctx, certs, trustStore)` | `NewChainBuilder(opts...)` |
| `Validator` | `Validate(ctx, paths, opts)` | `NewValidator(opts...)` |
| `Simulator` | `ExcludeBy*`, `InjectCertificates`, `Simulate(ctx, analysis)` | `NewSimulator(opts...)` |
| `TrustStore` | `IsTrusted`, `TrustedLocations`, `LoadSystemRoots`, `LoadCustomRoots`, `FindIssuers` | `NewTrustStore(opts...)` |

### Support Components

| Interface | Method | Constructor |
|-----------|--------|-------------|
| `AIAFetcher` | `FetchIssuers(ctx, cert)`, `ResetCache()` | `NewAIAFetcher(opts...)` |
| `RevocationChecker` | `CheckRevocation(ctx, cert, issuer)`, `ResetCache()` | `NewRevocationChecker(opts...)` |

Logging uses `*slog.Logger` (stdlib `log/slog`) directly -- not a custom
interface. `certree.NewLogger()` returns a discard logger; pass any
`*slog.Logger` to `With*Logger` options to route output (e.g.,
`slog.New(slog.NewTextHandler(os.Stderr, nil))`).

All default implementations are unexported (`defaultParser`,
`defaultChainBuilder`, `defaultValidator`, `defaultSimulator`,
`defaultTrustStore`, `defaultAIAFetcher`, `defaultRevocationChecker`).

Compile-time interface checks enforce correctness:

```go
var _ Parser              = (*defaultParser)(nil)
var _ ChainBuilder        = (*defaultChainBuilder)(nil)
var _ Simulator           = (*defaultSimulator)(nil)
var _ TrustStore          = (*defaultTrustStore)(nil)
var _ Validator           = (*defaultValidator)(nil)
var _ AIAFetcher          = (*defaultAIAFetcher)(nil)
var _ RevocationChecker   = (*defaultRevocationChecker)(nil)
var _ slog.Handler        = (*cliHandler)(nil)    // internal/cli
```

## The Analyzer

`Analyzer` is a struct, not an interface. It is the top-level orchestrator
that wires the pipeline together. The CLI creates exactly one analyzer per
invocation.

```go
analyzer, err := certree.NewAnalyzer(
    certree.WithParser(parser),           // required
    certree.WithTrustStore(trustStore),
    certree.WithChainBuilder(chainBuilder),
    certree.WithValidator(validator),
    certree.WithValidationOptions(opts),
    certree.WithRemoteOptions(remoteOpts),
    certree.WithSNI(sni),
)
```

The parser is the only required option. Everything else has sensible defaults.
`WithRemoteOptions(opts RemoteOptions)` controls TLS timeout, hostname
verification, and intermediate fetching for remote connections.
`NewAnalyzer` eagerly calls `trustStore.LoadSystemRoots()` and logs a warning
if the trust store fails to load (non-fatal; analysis proceeds without system
roots).

The analyzer exposes five methods:

- `Analyze(ctx, source)` -- detects source type, parses, builds chains,
  validates
- `AnalyzeFile(ctx, path)` -- parses a local certificate file
- `AnalyzeHost(ctx, host)` -- connects to a remote TLS server
- `AnalyzeURL(ctx, rawURL)` -- fetches certificates from an HTTP(S) URL
- `AnalyzeBytes(ctx, data, source)` -- same pipeline but accepts raw bytes

All return `*Analysis`, which contains the certificates, trust paths, and
metadata.

**Example: `certree --exclude-cn "Intermediate CA" example.com`**

```
1-4. Same as above (initial analysis)
5.   Simulator.ExcludeByCommonName("Intermediate CA")
6.   Simulator.Simulate(analysis) -> removes intermediate from paths
     --> rebuilds: [TrustPath{leaf, Incomplete}]
     --> re-validates: ErrorUntrustedRoot on leaf
7.   render.Trees(simulated) -> tree with "[x] excluded by simulation" annotation
```

## Key Types

`Certificate` wraps `*x509.Certificate` with precomputed metadata (expiry,
self-signed detection, trust store locations). `TrustPath` is a single chain
from end-entity to root with status, validation errors/warnings, and
simulation metadata. `Analysis` is the complete result containing all
certificates, trust paths, and metadata. `ValidationError` and
`ValidationWarning` live on trust paths, not on the analysis; soft failures
are appended during validation rather than returned as errors.

See [Library Guide](./library.md) for the full API reference.
Error/warning type sentinels are defined in `pkg/certree/errors.go`.

### Structured Errors

Hard errors (connection failures, file I/O, parse failures) returned from
exported user-facing boundaries (`Parser`, `Analyzer`, `AIAFetcher`,
`Simulator`, `RevocationChecker`, `TrustStore`, `BatchAnalyzer`, and
standalone functions like `ValidateSource`) use `StructuredError` -- a type
that carries a short user-facing message, a sentinel error category, and the
raw cause. This separates user presentation from diagnostic detail:

- `UserMessage()` -- short, actionable message (e.g., "could not connect to
  example.com:443"). No raw Go internals.
- `Category()` -- sentinel error for programmatic matching via `errors.Is`
  (e.g., `ErrConnectionFailed`, `ErrFileReadFailed`).
- `Detail()` -- underlying cause with full diagnostic chain.

`StructuredError` implements `Unwrap() error` (cause chain) and
`Is(target) bool` (sentinel matching), so standard `errors.Is` and
`errors.As` work through any depth of `fmt.Errorf` wrapping. The CLI uses
`errors.As` to extract the structured error and renders output in two tiers:
at verbosity 0 (default) only the user message is shown; at verbosity 3+
(`-vvv` or `-vvvv`) the message, detail, and category are all displayed.
`-vvv` and `-vvvv` show the same error fields -- they differ only in
logging output (info vs debug). Internal helpers use plain `fmt.Errorf`; their errors
become the `cause` of a `StructuredError` at the user-facing call site.

## CLI Wiring

The CLI entry point is `cli.Run()` in `internal/cli/run.go`. It sets up a
signal context (`signal.NotifyContext` for `SIGINT`/`SIGTERM`) that threads
through the entire pipeline for graceful cancellation on Ctrl+C. It
orchestrates a multi-step pipeline:

1. **Register and parse flags** -- `registerFlags()` creates a
   `pflag.FlagSet` with defaults from `config.DefaultConfig()`
2. **Handle early exits** -- `--help`, `--version`
3. **Load configuration** -- `config.LoadConfig(path)` loads TOML (or
   returns defaults), then `applyFlagOverrides(cfg, fs)` overlays
   explicitly-set CLI flags
4. **Validate inputs** -- `cfg.Validate()` checks values;
   `validateFlagValues()` checks theme, color, format, and fields against
   known values
5. **Resolve sources** -- merges positional arguments with `--batch` file
6. **Build analyzer** -- `buildAnalyzer()` constructs the full dependency
   tree
7. **Parse timeout** -- converts the validated duration string
8. **Analyze sources** -- dispatches to single or batch analysis
9. **Simulate** -- if `--exclude-*`, `--inject`, or `--validation-time`
   flags are present, runs simulation. The simulator receives the CLI logger
   so that `-vvv`/`-vvvv` produces diagnostic output during exclusion and
   path rebuilding.
10. **Quiet mode exit** -- if `--quiet` is set, exits early with a status
    code and no output
11. **Render output** -- tree, comparison, diff, or JSON

### buildAnalyzer()

This function is the dependency injection point. It constructs every
component in order:

```
Logger --> Parser --> TrustStore --> ChainBuilder [--> AIAFetcher] --> [RevocationChecker] --> Validator --> Analyzer
```

The trust bundle (`--trust-bundle`) is loaded via
`TrustStore.LoadCustomRoots(path)` after the trust store is created. AIA
fetching is wired into the chain builder only when `--aia-fetch` or
`--aia-force` is enabled. The revocation checker is constructed with full options
(logger, network settings) only when `--verify-revocation` is enabled.
Both AIA and revocation caches are enabled by default.

The AIA fetcher maintains a URL-keyed certificate cache so that repeated
requests for the same AIA URL return the cached certificate without a
network round-trip. Total AIA fetches per analysis are bounded by the chain
builder's `MaxDepth` setting (default 10): each recursion level performs at
most one AIA fetch, so the depth limit prevents runaway network activity
without requiring a separate fetch counter.

The initial analysis (step 8) always uses the current time for expiry and
revocation checks. `--validation-time` is applied during simulation (step
9), where the simulator re-validates rebuilt paths at the shifted time via
`WithSimulatorValidationOptions`.

See [Configuration Guide](./configuration.md) for the full configuration
flow.

## Render Package

`internal/render` converts `*certree.Analysis` into terminal output. It has
four public entry points:

- `Trees(analyses, opts, w)` -- renders one or more analyses as ASCII trees
- `Comparisons(pairs, opts, w)` -- renders side-by-side before/after
  comparisons
- `Diffs(pairs, sources, opts, w)` -- renders unified diffs of simulations
- `ImpactSummary(before, after, indent, sep, expiryWarningDays)` -- computes
  a textual summary of simulation impact

The first three resolve the rendering environment first (terminal width,
color support, theme selection), then delegate to internal visualizers:

- `treeVisualizer` -- builds a tree of nodes from an analysis, renders with
  status icons and tree-drawing characters
- `comparisonVisualizer` -- wraps two tree visualizers, aligns output side
  by side
- `diffVisualizer` -- renders both trees, strips ANSI, computes LCS-based
  unified diff, re-colorizes

Three built-in themes (`classic`, `terse`, `minimal`) control status icon
format and tree character style. Status computation follows a priority
cascade: errors, simulation state, trust store membership, expiry warnings,
self-signed status.

## Batch Processing

`BatchAnalyzer` processes multiple sources concurrently using a worker pool:

```go
batchAnalyzer, err := certree.NewBatchAnalyzer(analyzer, maxWorkers)
analyses, err := batchAnalyzer.AnalyzeMultiple(ctx, sources)
```

All sources are processed regardless of individual failures. Successful
analyses are returned alongside an aggregated error (via `errors.Join`).
Each inner error may wrap a `*StructuredError` from the failed source,
extractable via `errors.As` on individual elements of the joined error. Only
context cancellation interrupts in-progress work.

The CLI dispatches to batch mode automatically when multiple sources are
provided. The `--batch` flag loads additional sources from a file (one per
line, `#` comments supported).

**Example: `certree github.com cloudflare.com cert.pem`**

```
1. CLI detects 3 sources -> dispatches to BatchAnalyzer
2. Worker pool (capped at maxBatchWorkers = 8) analyzes each source concurrently
3. Results collected, sorted by source order, rendered sequentially
```

## Testing Infrastructure

`pkg/certree/testutil` provides shared certificate generators, PEM encoding
helpers, and template defaults for testing. Tests live next to the code they
test; benchmarks live in `bench_test.go`, one per package.

See [Testing](./testing.md) for the full testing philosophy, testutil API,
and conventions.

See also: [Library Guide](./library.md),
[Design Philosophy](./design-philosophy.md),
[Configuration Reference](./configuration.md),
[Contributing](./contributing.md), [Testing](./testing.md).

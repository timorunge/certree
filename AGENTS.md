# AGENTS.md - certree

Guidelines for AI coding agents operating in this repository.

## Build / Lint / Test Commands

```bash
make build                    # Static binary: CGO_ENABLED=0, -trimpath
make check                    # All quality gates: fmt + tidy + vet + lint + test
make test                     # go test -race -short -timeout 2m ./...
make test-ci                  # go test -race -timeout 5m ./...
make test-coverage            # Coverage report to coverage.out
make bench                    # All benchmarks across all packages
make lint                     # golangci-lint run ./...
gofmt -l .                    # Check formatting (non-destructive)
gofmt -s -w .                 # Fix formatting

# Single test (use -run with package path)
go test -v -run TestNewCertificate ./pkg/certree/
go test -v -run TestReverseAnalysisCopy ./internal/cli/

# Property tests only
go test -v -run 'Property' ./pkg/certree/

# Tests in a specific package
go test -v -short ./internal/render/

# Single benchmark
go test -bench=BenchmarkParsePEM -benchmem -run='NOMATCH' ./pkg/certree/
```

## Code Style

### Imports

Three groups separated by blank lines: (1) standard library, (2) external
dependencies, (3) internal packages (`github.com/timorunge/certree/...`).

### File Headers

Every `.go` file starts with a comment describing its purpose, then a
blank line, then the `package` line. Exception: `doc.go` and `main.go` have no
blank line.

```go
// Certificate parsing and PEM/DER format detection.

package certree
```

### Declaration Ordering

Production files follow a consistent top-to-bottom order:

1. File header comment + `package` declaration
2. `import` block
3. Constants (`const`) -- defaults first, then sentinels, grouped by purpose;
   consolidate into single `const` blocks where possible
4. Variables (`var`) -- sentinel errors, standalone compile-time
   interface checks, package-level vars
5. Per logical type group (repeat for each type in the file):
   - Interface definition
   - Option type (`type FooOption func(...)`)
   - `With*` option constructor functions
   - Implementation struct
   - Constructor (`New*` / `new*`)
   - Compile-time interface check (`var _ Interface = (*implStruct)(nil)`) --
     always directly after the constructor
   - Exported methods
   - Unexported methods
6. Helper types (small types used only by the main type, with their own
   constructors and methods)
7. Standalone helper/utility functions at the bottom

Compile-time interface checks go directly after the constructor of the type they
verify. This is the standardized placement across the entire codebase.

### Naming

- **Packages**: short, lowercase, single-word
  (`certree`, `testutil`, `render`, `cli`)
- **Exported types**: MixedCaps (`Certificate`, `TrustPath`, `Analysis`)
- **Unexported types**: camelCase with `default` prefix for impls
  (`defaultParser`)
- **Interfaces**: nouns (`Parser`, `ChainBuilder`, `Validator`, `Simulator`)
- **Options structs**: unexported, plural (`parserOptions`, `validationOptions`)
- **Option functions**: `With<Thing>` pattern (`WithParser`, `WithAIAFetch`)
- **Constants**: MixedCaps exported, camelCase unexported; enums use `iota`
- **Variables**: short for short scope (`err`, `cert`, `ctx`),
  descriptive for long

### Parameter Ordering and Naming

Function parameters follow a consistent ordering convention across
the codebase:

1. `context.Context` -- always first when present
2. Primary data -- the main subject(s) being operated on
   (`cert`, `path`, `analyses`)
3. Dependencies -- concrete components needed for the operation
   (`analyzer`, `ac`)
4. Configuration -- options, flags, timeouts, boolean switches
   (`opts`, `cfg`, `timeout`)
5. Infrastructure -- logging (`logger *slog.Logger`)
6. Output destination -- `io.Writer` (`w`) near the end
7. Error reporter -- `*errReporter` last (internal/cli only)

For filter/search functions, data (the subject being filtered) comes
before filter criteria (the pattern/matcher), matching Go stdlib
conventions like
`strings.Contains(s, substr)`.

Naming preferences (use the preferred name unless it would shadow a
stdlib import or conflict with another identifier in scope -- in that
case pick the clearest unambiguous alternative):
- **`*slog.Logger`**: prefer `logger` (not `l`, `log`, `lg`)
- **`*TrustPath`**: prefer `path` (use `tp` when `"path"` is imported)
- **`io.Writer`**: prefer `w` (not `stdout` except in top-level
  entry points like `Run`)
- **`[]byte` certificate data**: prefer `data` (not `derBytes`, `pemBytes`)
- **`*CertificateTemplate`**: prefer `tmpl`
  (not `t` -- reserved for `*testing.T`)
- **`*Certificate`**: prefer `cert`
- **`*Analysis`**: prefer `analysis` (or `a` in methods on `*Analysis`)
- Sibling functions must use identical names for identical concepts
- When a preferred name shadows a stdlib package, use a short domain
  abbreviation (e.g. `tp` for `*TrustPath`) rather than inventing a
  novel name

`With*` option functions:
- Nil guards go **inside** the returned closure (panic at apply time, not at
  construction time)
- `With*Logger` functions panic on nil -- never silently ignore

### Error Handling

Two tiers of errors in `pkg/certree`:

- **Structured errors** at exported user-facing boundaries --
  functions and methods whose errors are returned directly to callers
  without further wrapping. This includes exported methods on `Parser`,
  `Analyzer`, `AIAFetcher`, `Simulator`, `RevocationChecker`,
  `TrustStore`, `BatchAnalyzer`, and standalone exported functions like
  `ValidateSource`, `ParsePEMCertificates`, `ParseDERCertificate`,
  `ParsePEMCertificatesWithLimit`.
  Use `NewStructuredError(userMessage, category, cause)`. The user
  message is short and actionable (no Go internals like "dial tcp" or
  "x509:"). The category is a sentinel for `errors.Is` matching. The
  cause is the raw Go error chain.
- **Plain `fmt.Errorf`** for internal plumbing and unexported helpers
  whose errors are wrapped by a structured error at the call site. When
  an internal component's errors are always wrapped by a structured
  error upstream (e.g., `ChainBuilder.BuildChains` errors wrapped by
  `Analyzer.analyzeChains`), it should use plain `fmt.Errorf`.

General rules:
- Always wrap: `fmt.Errorf("context: %w", err)` -- never lose the chain
- Lowercase error messages (they get wrapped into larger messages)
- Guard clause pattern (return early, avoid nesting)
- Sentinel errors for expected conditions -- see `pkg/certree/errors.go` for the
  complete catalog. Use `errors.Is` for matching, `errors.As` to extract
  `*StructuredError` through any wrapping depth.
- Never ignore errors: `data, _ := os.ReadFile(path)` is forbidden
- `errors.Is` matches the category sentinel via `StructuredError.Is()`
  and traverses the cause chain via `Unwrap()`
- `errors.As` extracts `*StructuredError` through any depth of
  `fmt.Errorf` wrapping
- User-facing messages must not contain raw Go error internals
  ("dial tcp", "lookup", "read tcp", "tls:", "x509:", "asn1:", DNS
  resolver addresses)

### Types and Patterns

- Unexported struct fields with getter methods to prevent invalid states
- Compile-time interface check: `var _ Parser = (*defaultParser)(nil)`
- Functional options: `a, err := NewAnalyzer(WithParser(p), WithTrustStore(ts))`
- Accept `context.Context` as first param for cancellable ops with early check
  (see Parameter Ordering and Naming)

### JSON / TOML

- `snake_case` for JSON tags, `omitempty` for optional fields
- Initialize slice fields to `[]string{}` (not nil) so JSON outputs
  `[]` not `null`
- Custom `MarshalJSON()` with named helper structs for performance

### Documentation

- All exported types/funcs/consts need godoc starting with the item name
- Comments end with a period (enforced by `godot` linter)
- ASCII only -- no emojis or special Unicode anywhere (docs, comments,
  CLI output)

### Comment Discipline

Comments explain **why**, not **what**. If the code is clear, no
comment is needed.

**Godoc rules:**
- Exported symbols: one sentence starting with the symbol name, ending
  with period. Multi-sentence godoc only when behavior is genuinely
  non-obvious.
- No `// Parameters:`, `// Returns:`, `// Error conditions:`, or
  `// Example usage:` sections -- the signature and tests convey this.
  Exception: complex functions where parameter semantics are ambiguous
  from the type alone.
- Unexported functions: one-line summary starting with the function
  name, ending with period. Skip only if the name is truly
  self-describing (e.g., a single-line helper whose purpose is obvious
  from the name and signature alone).
- Unexported types: one-line summary starting with the type name,
  ending with period. Skip only if the type is a trivial alias or
  single-field wrapper whose purpose is obvious from the name alone.

**Inline comment rules:**
- Never narrate the next line of code (`// Check context` before
  `select { case <-ctx.Done():`).
- Never restate a condition (`// If the host is an IP` before
  `if ip := net.ParseIP(host); ip != nil`).
- Do comment: non-obvious algorithms, performance trade-offs, security
  rationale, workarounds with ticket/RFC references, "why not the
  obvious approach" explanations.

**Struct field rules:**
- Skip comments on self-describing fields (`IsExpired bool`, `Source string`).
- Comment fields where the name does not convey valid values, units,
  nil semantics, or invariants.

**Test file rules:**
- Test function godoc is almost never needed -- the test name is the
  documentation. Only add godoc when the test name cannot convey a
  non-obvious setup or constraint.
- Test helper godoc: one line at most. Skip if the helper name is
  self-describing.
- No section divider banners (`// ----`) in any file. Use blank lines
  between groups.

**File header rules (production):**
- One-line file header comment describing the file's purpose (required
  by convention).
- Must not restate the package name or be generic
  ("Utility functions for X").

**File header rules (test):**
- Test file headers are optional. Only include if explaining non-obvious test
  infrastructure (e.g., TestMain compilation, integration test constraints).
- `// Unit tests for X.` headers that just name the file's subject add
  no value -- omit.

### Logging

All components accept `*slog.Logger` (stdlib `log/slog`) via their
`With*Logger` option. Call sites use
`logger.Info("message", "key1", val1, "key2", val2)`.
`certree.NewLogger()` returns a discard logger (default, silent).
Never log private keys, passwords, or PII.

## Testing

Three test layers: unit (`*_test.go`), property
(`*_property_test.go`), integration.

- `t.Parallel()` for independent tests and subtests
- Table-driven:
  `for _, tt := range tests { t.Run(tt.name, func(t *testing.T) {...}) }`
- Property tests use gopter; 100 iterations full, 10 in `-short` mode
- Use `pkg/certree/testutil` for cert generation -- never duplicate
  generators
- Cache certificates in tests that generate many (RSA key gen is
  expensive)
- Mark helpers with `t.Helper()`

**Test file ordering**: test files follow a consistent top-to-bottom
order:

1. Package declaration + imports
2. Constants and variables used across tests
3. Mock types, test helpers, and fixture-generating functions --
   before the tests that use them
4. Test functions, ordered to match the source file's declaration
   order

**Property vs unit decision**: if replacing the random generator with
one hardcoded example would be equally effective, it should be a unit
test.

## Linting

golangci-lint v2 with 21 linters (see `.golangci.yml`). Key settings:
- `gocyclo` min-complexity / `cyclop` max-complexity threshold: 20
- `dupl` threshold: 100
- `godot`: declaration comments must end with period
- `misspell`: US English
- `modernize`: enforces `slices.Sort`, `any`, `for range N`,
  `strings.ReplaceAll`

**Zero tolerance**: all code must pass with zero issues. The AI agent
runs `make check` (fmt, tidy, vet, lint, test) after every code change
to verify correctness. No `//nolint` except for `gocyclo`/`cyclop` on
high-complexity functions (with a justification comment).
`//nolint:revive` is never acceptable -- fix the code instead.

## Git Conventions

[Conventional Commits](https://www.conventionalcommits.org/):
```
<type>(<scope>): <subject>
```
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
`build`, `ci`, `chore`

Scopes: `parser`, `chain`, `validator`, `simulator`, `cli`, `config`,
`truststore`, `render`, `batch`, `aia`, `revocation`, `docs`

Rules: imperative present tense, no capital, no period, max 72 chars.
Breaking changes: add `!` after type/scope.

## Markdown Documentation

### Code Block Formatting

Separate commands from their output into distinct fenced code blocks.
This enables syntax highlighting on the command and makes it easy to
copy-paste without stripping a `$` prefix.

Command block (with `bash` language tag, no `$` prefix):

````markdown
```bash
certree --aia-force cloudflare.com
```
````

Output block (plain fenced block, no language tag):

````markdown
```
[+ ] cloudflare.com -- 4 trusted paths
`- [+ ] cloudflare.com
   ...
```
````

Never combine a command and its output in a single fenced block.
Never prefix commands with `$` -- the `bash` language tag already
signals that the block is a shell command.

Multi-line commands use backslash continuation with consistent
indentation:

````markdown
```bash
certree --annotations --trust-bundle docs/examples/root-ca.pem \
        --exclude-cn "Example Intermediate CA" \
        --compare docs/examples/chain.pem
```
````

### Terminal Output Captures

When capturing certree output for documentation:

- Use `COLUMNS=120` (or wider) when piping output to avoid truncated
  compare views. certree respects the `COLUMNS` environment variable
  when stdout is not a terminal.
- Ensure output is current -- re-capture after any rendering changes
  (fingerprint format, status icons, annotation text, field layout).
- ASCII only -- no ANSI escape codes in documentation output blocks.
  Use `--color never` if capturing from a terminal.

### General Markdown Rules

- ASCII only in all documentation -- no emojis or special Unicode
  characters.
- Use `--` (double dash) for em-dashes, not Unicode em-dash
  characters.
- Line length: wrap prose at ~80 characters for readable diffs. Code
  blocks and tables are exempt.
- Links to other docs use relative paths: `[CLI Reference](./cli.md)`.

## CI Pipeline

GitHub Actions: lint + test on 3 OS (linux, darwin, windows) +
coverage on Linux. Release via GoReleaser on `v*` tags (lint + test
must pass before release).

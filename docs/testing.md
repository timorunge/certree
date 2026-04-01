# Testing

Every test earns its keep. How certree thinks about testing, and why the
test suite is shaped the way it is.

## The Problem With "More Tests"

Most projects treat test count as a proxy for quality. More tests, more
confidence, right? Not exactly.

certree learned this the hard way. The test suite grew to roughly three
lines of test code for every line of source. That sounds thorough. In
practice, it meant:

- Property tests that used gopter but tested deterministic functions with
  two possible inputs. Random generation over a boolean is not
  property-based testing -- it is a coin flip with extra steps.
- Unit tests that verified the same behavior as a property test sitting in
  the next file over. Two tests, one truth, double the maintenance.
- Structural checks dressed up as properties. "Every flag has metadata" is
  a fact you can assert once, not a property you need to verify across
  random inputs.

The test suite was not wrong. It was wasteful. A systematic optimization
cut the test suite by roughly a third while maintaining the same coverage
-- in some areas, coverage actually improved because the remaining tests
were better targeted. Every surviving test earns its place. Tests that do
not catch bugs you would not otherwise catch are not earning their keep.
They are overhead: slower CI, harder refactors, more noise when something
actually breaks.

## The Testing Pyramid

certree organizes tests into three layers. Each layer has a job, and tests
belong in the layer where they do the most good.

```
        /\
       /  \        Integration tests (handful)
      /    \       (component workflows, E2E)
     /------\
    /        \     Property tests (modest layer)
   /          \    (invariants across generated inputs)
  /------------\
 /              \  Unit tests (vast majority)
/________________\ (specific examples, edge cases, error paths)
```

The bulk of the suite is unit tests. Property tests form a smaller but
critical middle layer. Integration tests are intentionally few -- each one
exercises a cross-component boundary that neither unit nor property tests
can reach. A separate benchmark suite tracks performance regressions across
all three packages.

### Unit Tests: The Foundation

Unit tests verify that specific inputs produce expected outputs. They are
fast, focused, and easy to debug when they fail. A failing unit test tells
you exactly what broke.

Use unit tests for:

- Known input/output pairs ("this PEM produces this certificate")
- Edge cases (empty input, nil values, boundary conditions)
- Error paths ("malformed PEM returns an error, not a panic")
- Structural facts ("every flag belongs to exactly one group")

Unit tests are the right choice when the input space is small or when you
need to verify a specific scenario. If there are only three valid inputs,
write three test cases. Do not spin up a random generator to pick among
them.

### Property Tests: The Middle Layer

Property tests define invariants that must hold across all valid inputs,
then verify those invariants against randomly generated examples. They are
certree's primary tool for catching bugs that handwritten examples miss.

A good property test earns its keep by exploring a combinatorial space
that no reasonable number of unit tests could cover. The chain builder,
for example, must correctly identify trust paths regardless of certificate
order, chain depth, or cross-signing topology. Writing unit tests for
every combination is impractical. Writing a property that says "every
certificate in the input appears in at least one output path" and letting
gopter generate thousands of certificate sets -- that scales.

Use property tests for:

- Invariants across large input spaces ("parsed certificates preserve all
  fields")
- Roundtrip properties ("parse then serialize produces the original")
- Relational properties ("adding a cross-signed intermediate multiplies
  paths")
- Boundary exploration ("chain depth limits are enforced for any depth
  value")

Do not use property tests for:

- Deterministic functions with trivially small input spaces
- Behavior that depends on a single known configuration
- Third-party library behavior (stdlib, pflag, etc.)
- Structural facts that can be asserted once in a unit test

The litmus test: if you replaced the random generator with a single
hardcoded example and the test would be equally effective, it should be a
unit test.

certree uses [gopter](https://github.com/leanovate/gopter) for
property-based testing. gopter provides generators for building random
inputs and a shrinking mechanism for minimizing failing cases. When a
property test fails, it gives you a minimal counterexample -- the simplest
input that violates the invariant. This is often more valuable than a
passing test, because it reveals assumptions you did not know you were
making. The project maintains custom generators in `pkg/certree/testutil`
for domain-specific types like certificates, trust paths, and analysis
results.

Property tests run with reduced iterations in `-short` mode (10 instead
of 100) so development feedback stays fast. They are never skipped
entirely -- even a few iterations catch regressions that unit tests miss.

### Integration Tests: The Top

Integration tests exercise multiple components together in realistic
workflows. They are the slowest and most expensive layer, so certree uses
them sparingly -- but they catch problems that no amount of unit or
property testing reveals.

Integration tests verify that the parser, chain builder, validator, and
render components work together correctly. They use real certificate data
and exercise the full pipeline from input to output.

These tests are never deleted during optimization. They represent
end-to-end confidence that the system works as a whole.

## Test Organization

### File Naming

Tests live next to the code they test, following Go convention:

- `parser.go` -> `parser_test.go` (unit tests)
- `parser.go` -> `parser_property_test.go` (property tests)
- `integration_test.go` (integration tests, one per package)

Each source file has at most one property test file, no exceptions. During
the optimization, several split-out property test files were merged back
into their parent property test files to enforce this rule. Bugfix
regression tests live alongside the other property tests for the same
source file, organized into logical sections within the file.

### The testutil Package

`pkg/certree/testutil` provides shared certificate generators, PEM
encoding helpers, and gopter generators. Before writing a local test
helper, check testutil -- if it does not have what you need, add it there
rather than duplicating in your test file. See the package godoc or
`pkg/certree/testutil/testutil.go` for the full API.

Mocks and helpers that reference package-internal types (like
`*Certificate`, `TrustStore`, `AIAFetcher`) cannot live in testutil due to
Go's circular import restriction. These stay as local helpers in the test
files that define them, and are shared across test files within the same
package via Go's standard `_test.go` compilation model.

### Certificate Caching

Generating certificates is expensive (RSA key generation, signing). Tests
that need many certificates -- especially property tests running hundreds
of iterations -- should cache generated certificates rather than creating
fresh ones each time.

The project uses patterns like `sync.Once` templates and count-keyed
caches to avoid redundant key generation. This keeps property tests fast
enough to run on every commit without sacrificing the breadth of random
exploration.

## Benchmarks

Benchmarks follow the same "earn their keep" philosophy. They exist to
catch performance regressions and guide optimization decisions -- not as
vanity metrics.

Each package that has performance-sensitive code has a single
`bench_test.go` file. The library benchmarks cover the core hot paths:
certificate wrapping, fingerprinting, PEM encoding, JSON serialization,
parsing at multiple scales, chain building, cross-sign detection, trust
store queries, validation, simulation, analysis creation, single-source
pipeline, and batch processing. The render benchmarks cover tree rendering
(default and detailed modes), comparison, diff, impact summary, and
ANSI-aware string utilities. The CLI benchmarks cover flag registration,
config construction, analyzer building, the full E2E pipeline, tree and
JSON render dispatch, field parsing, and CN filtering with compiled
pattern matching. Sub-benchmarks (like `BenchmarkParsePEM/1cert` and
`BenchmarkParsePEM/10certs`) test scaling without duplicating setup.

```bash
# Run benchmarks for a specific package
go test -bench=. -benchmem -run='NOMATCH' ./pkg/certree/
```

If you have not read Go benchmark output before: `ns/op` is how long the
function takes, `B/op` is how much memory it allocates, and `allocs/op`
is how many heap allocations it makes. Fewer allocations means less
garbage collector pressure.

## What Good Looks Like

A well-tested certree component has:

1. **Unit tests** for specific scenarios, edge cases, and error paths
2. **Property tests** for invariants across the input space -- but only
   where random generation provides value beyond what handwritten examples
   would
3. **No redundancy** between the two -- if a property test covers a space,
   unit tests focus on edge cases the property might miss, not on
   re-verifying the same invariant
4. **Shared infrastructure** from testutil, not local helpers that
   duplicate it
5. **Benchmarks** for hot-path functions, living in `bench_test.go`,
   catching regressions that correctness tests cannot

The test suite should be something you trust. When tests pass, you should
believe the code works. When a test fails, you should believe there is a
real bug. Tests that cry wolf -- that fail for irrelevant reasons or pass
despite real problems -- undermine that trust.

See also: [Design Philosophy](./design-philosophy.md),
[Certificate Trust Paths](./certificate-trust-paths.md),
[gopter](https://github.com/leanovate/gopter),
[Go Testing](https://pkg.go.dev/testing).

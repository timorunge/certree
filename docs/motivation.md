# Motivation

Why certree exists, what problem it solves, and what it set out to prove.

## The Problem

Certificate chains are critical infrastructure. Every TLS connection your
services make -- to APIs, databases, third-party providers, internal
microservices -- depends on a chain of trust that terminates at a root CA.
When that chain breaks, everything breaks. And chains break more often than
people think.

Root CAs get distrusted. Intermediates expire or get revoked. Organizations
migrate between certificate providers. Trust stores change with OS and
browser updates. Cross-signed certificates create multiple trust paths, and
removing one CA can silently break a path you did not know existed.

For critical workloads -- financial services, healthcare, government,
infrastructure -- understanding your certificate trust paths is not
optional. Every path terminates at a root CA operated by some
organization, under some jurisdiction. If all your paths depend on a
single CA, a distrust event you have no influence over can take down
your services. You need to know which CAs you depend on, whether
alternative paths exist, and what breaks if one is removed.

Nobody had a good way to answer these questions quickly.

## The Tooling Gap

The existing tools are not built for trust path analysis:

- **OpenSSL** shows one chain. It does not show alternative trust paths
  through cross-signed intermediates. Its interface is a sprawling
  collection of subcommands designed for certificate generation and TLS
  debugging, not chain analysis.

- **Browser certificate viewers** show the chain the browser negotiated,
  which is one path chosen by one implementation at one point in time.
  They do not show what other paths exist or what would break if a CA
  were removed.

- **Certificate transparency logs** tell you what certificates exist.
  They do not tell you how those certificates chain together or which
  paths lead to trusted roots.

- **No tool** lets you ask: "What happens to the trust paths if I remove
  this CA?" -- the question that matters most during CA migrations, trust
  store changes, and compliance audits.

certree was built to fill this gap. It shows all trust paths -- not just
the one your client negotiated -- fetches missing intermediates via AIA,
and lets you simulate certificate exclusions to see what breaks before
anything changes. It treats certificate chains as structured data you can
pipe, filter, and transform, following the Unix tradition.

## Building It Properly with AI

certree is AI-generated software. Every line of code, every test, every
configuration file, and every document -- including this one -- was
produced by AI agents working under human direction.

This was a deliberate choice, not a shortcut. The goal was to find out
whether AI-assisted development can produce software that meets the
standards you would demand from a skilled human engineer -- not just
software that runs, but software that lints, that has property-based
tests defining correctness invariants, that tracks allocations on hot
paths, that passes the race detector on every commit, that builds and
tests on three operating systems.

The process is specification-driven: define requirements, design, and
correctness properties up front. AI agents generate code, tests, and
documentation from the spec. Humans review for correctness, direction,
and whether the spec was followed. Quality gates run automatically after
every change. Iterate until everything passes with zero issues.

This takes time. You get to 80% fast -- that part is real. Some people
genuinely ship the whole thing in days. They have years of experience,
strong instincts for what to check, and the taste to know when something
is off. But most people are not those people, and AI makes it easy to
believe you are.

The remaining 20% is where software is actually made, and that part does
not compress the way people expect. You still lose hours on something
that should have taken minutes. The agent drifts from the spec you wrote
and you do not notice until three files later. You enforce a convention
in one package and violate it in another. You fix a bug and introduce a
subtle regression that only shows up under the race detector. These are
the same problems software development has always had. AI does not
eliminate them. It accelerates the cycle -- you hit them faster, you
recover faster -- but the problems themselves are structural, not
speed-limited.

Learning how to steer AI agents effectively is a skill that develops
over weeks and months, not hours.

The time distribution surprised us. The core library -- parsing, chain
building, validation, simulation -- came together fast. So did the
configuration layer and the CLI flag wiring. Backend code with clear
inputs, outputs, and testable contracts is exactly the kind of work
where AI agents excel. The rendering package was a different story. It
consumed the majority of the project's time -- easily more than the
library, CLI, and configuration combined. Getting a tree visualizer to
produce clean, aligned output across merged paths, side-by-side
comparisons, unified diffs, and ANSI-aware column alignment is the
kind of pixel-level visual work where "almost right" is the same as
wrong. Every edge case is visible. You cannot hide behind a passing
test when the output looks broken in a terminal. The hard part of
certree was not the certificate logic. It was the presentation.

## The Quality Problem

AI makes it easy to produce code that looks right. Clean syntax,
reasonable structure, even documentation. The hard part is not
generating output -- it is knowing whether the output is correct. That
gap is easy to underestimate, and we have underestimated it ourselves
more than once while building certree.

Good software follows design principles. It has architecture -- separation
of concerns, clear interfaces, components that compose without knowing
about each other. It has a testing philosophy, not just a test suite.

It handles errors deliberately, not by logging and hoping. These are not
things you bolt on after the code runs. They are the decisions that
determine whether the code keeps running six months from now, when
someone else has to change it.

The Unix tradition understood this fifty+ years ago. Small, focused tools.
Text streams as universal interfaces. Programs that do one thing well and
compose with other programs.

These principles survived because they produce software that endures.
They are not relics -- they are the reason `grep`, `awk`, and `curl` still
work exactly the way you expect them to. certree is built on these
principles because they are the right principles, not because they are
fashionable. The command line was here before AI agents, and it will be
here after.

certree takes the quality question seriously. The bar is the same bar
you would set for production software written by humans. The AI follows
conventions because the conventions are specified. The code is consistent
because the quality gates are automated and non-negotiable.

AI-assisted development works. But it works the way any serious software
development works: with specifications, quality gates, iteration, and
time. The AI changes the economics of writing code. It does not change
the economics of writing good software. That still requires standards,
and someone willing to enforce them. Someday that someone might be an
agent too.

See also: [Design Philosophy](./design-philosophy.md),
[Architecture](./architecture.md), [Testing](./testing.md).

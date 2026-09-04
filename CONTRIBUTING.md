# Contributing to dig-cert

Thanks for your interest in improving dig-cert. This crate implements a per-machine,
name-constrained local TLS CA + leaf issuance + automatic renewal — please read this before
opening a PR.

## Prerequisites

- [Rust](https://rustup.rs), version **1.75 or later** (as specified in `Cargo.toml`).

No additional prerequisites; the crate depends on well-established TLS/crypto libraries
(rustls, rcgen, ring) and no custom build steps.

## Build & test

```sh
# build the crate
cargo build

# run the full test suite
cargo test

# run tests with flaky-test detection (mirrors CI)
cargo nextest run --retries 2 --test-threads 1
```

## The gate (must pass before a PR is merged)

CI runs these on every PR (`.github/workflows/ci.yml`); run them locally first:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features --retries 2 --test-threads 1
cargo doc --no-deps --all-features
cargo llvm-cov nextest --all-features --fail-under-lines 80 --retries 2 --test-threads 1
```

Coverage is **gated at ≥80% line coverage** (`--fail-under-lines 80`); runs that drop
below this threshold fail. Install `cargo-llvm-cov` + `cargo-nextest` if you don't have them:

```sh
cargo install cargo-llvm-cov cargo-nextest
```

## Commit conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/) — `type(scope): summary`
  where `type` ∈ `feat|fix|docs|style|refactor|perf|test|build|ci|chore`, e.g.
  `feat(ca): add support for …`, `fix(renewal): …`, `docs: …`.
- A breaking change appends `!` and/or a `BREAKING CHANGE:` footer.
- Add a `Co-Authored-By: Claude <noreply@anthropic.com>` trailer if Claude helped author the commit.
- Keep one logical change per commit where practical.

## Where things live

| Module | Responsibility |
|---|---|
| `ca` | CA generation with critical name constraints |
| `leaf` | Leaf certificate issuance (90-day SAN) |
| `renewal` | Automatic renewal manager + backoff logic |
| `rustls_integration` | Hot-reloadable `rustls` ServerConfig + CertResolver |
| `paths` | Canonical on-disk layout and file modes |

## Security

This crate is a security-sensitive, name-constrained CA implementation. For anything
security-relevant, open a private issue or contact the maintainer — do not disclose
security findings publicly until they are patched and released. See `SPEC.md` for the
normative contract and `runbooks/` for deployment detail.

## Pull requests

1. Branch from `main`.
2. Make the gate green locally (format, clippy, tests ≥80% coverage).
3. Bump the patch version in `Cargo.toml` (docs-only changes use `docs:` scope and a patch bump).
4. Commit with a Conventional Commit message + optional `Co-Authored-By:` trailer.
5. Open a PR with a clear description of the change and its rationale; reference any
   related issue. Keep the diff focused.
6. All required checks must pass before merge (enforced by branch protection).


# Runbook — dig-cert (local build & test)

`dig-cert` is a library crate consumed as a git dependency; it has no deploy target of its own. Its
"release" is the `vX.Y.Z` tag cut on merge (per-merge model), which downstream consumers pin.

## Prerequisites

- A stable Rust toolchain (`rustup toolchain install stable`) with `rustfmt`, `clippy`, and
  `llvm-tools-preview`.
- `cargo-llvm-cov` and `cargo-nextest` for the coverage gate:
  `cargo install cargo-llvm-cov cargo-nextest` (CI installs both via `taiki-e/install-action`).

No system libraries are needed — the crypto is pure-Rust `ring`; there is no OpenSSL/aws-lc toolchain
dependency.

## Build & verify (the full release-gate set)

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps --all-features
cargo llvm-cov nextest --all-features --workspace --fail-under-lines 80 --retries 2 --test-threads 1
```

All of these run in CI (`.github/workflows/ci.yml`) and gate every PR, plus commitlint and the
version-increment check.

## Releasing

Bump `version` in `Cargo.toml` (SemVer) as the last commit on the PR branch. On merge to `main`,
`.github/workflows/release.yml` regenerates `CHANGELOG.md`, commits it, and pushes the matching
`vX.Y.Z` tag (using `RELEASE_TOKEN`). Consumers then bump their git-dependency pin to that tag.

## Nothing to deploy

There is no site, service, or binary. The only artifact is the tagged source consumed by
dig-installer, dig-node, and dig-dns.

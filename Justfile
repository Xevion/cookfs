default:
    @just --list

# One-stop gate mirroring CI: a clean run here means CI will very likely pass.
check: fmt-check clippy doc zizmor test

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Builds the API docs, which is what fires the workspace's rustdoc lints: broken intra-doc links,
# bad code blocks, bare URLs, unescaped backticks.
doc:
    cargo doc --workspace --all-features --no-deps

# nextest runs the suite; doctests run separately, since nextest doesn't cover them. Tests that
# need the sample corpus skip when it is absent and fail when it is present but broken.
test:
    cargo nextest run --workspace --all-features
    cargo test --workspace --all-features --doc

# Line coverage over the workspace, written to coverage/ (gitignored); needs cargo-llvm-cov.
# Doctests are left out, since --doctests is still incomplete. Advisory, not part of `check`.
coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p coverage
    cargo llvm-cov nextest --workspace --all-features --no-fail-fast \
      --html --output-dir coverage
    cargo llvm-cov report --lcov --output-path coverage/lcov.info

# Audits the workflows. Needs a token: the pin audits resolve `uses:` SHAs against GitHub and are
# silently skipped without one. CI supplies GH_TOKEN itself.
zizmor:
    GH_TOKEN="${GH_TOKEN:-$(gh auth token)}" zizmor .

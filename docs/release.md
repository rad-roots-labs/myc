# release acceptance

`myc` keeps one final production acceptance lane for release candidates:

```bash
./scripts/release-acceptance.sh
```

This lane is the final release gate after feature work is complete. It composes the already-established proof surfaces instead of introducing a separate synthetic test harness.

## included checks

Repo-local validation from the `myc` root:

- `cargo metadata --format-version 1 --no-deps`
- `cargo check --locked`
- `cargo test --locked`
- `cargo fmt --all --check`

Consumer-side live compatibility from the integrated workspace when available:

- `cargo check --manifest-path testing/rs/platform-integration/Cargo.toml`
- `cargo run --manifest-path testing/rs/platform-integration/Cargo.toml -- suite myc-nip46`
- `cargo run --manifest-path testing/rs/platform-integration/Cargo.toml -- suite myc-app-remote-signer`

## what this gate proves

- SQLite-backed signer state, runtime audit, and delivery outbox stay green under the full repo-local test matrix
- durable delivery startup recovery remains green
- backup, restore, and `verify-restore` stay green through the CLI proof lane
- backend-aware custody stays green through the full repo-local test matrix, including `managed_account` and `external_command`
- the repo-local upstream `nostr` interop lane stays green
- the consumer-side live compatibility lanes stay green when the integrated workspace is present

## workspace behavior

When `myc` is checked out inside the integrated Radroots workspace, the acceptance lane automatically runs the consumer-side `platform-integration` suites.

When `myc` is checked out standalone and `testing/rs/platform-integration/Cargo.toml` is not present, the script prints a skip notice and runs the repo-local release gate only.

You can also skip the consumer-side live lanes explicitly:

```bash
MYC_RELEASE_ACCEPTANCE_SKIP_PLATFORM_INTEGRATION=1 ./scripts/release-acceptance.sh
```

Use that override only when the live consumer-side environment is intentionally unavailable. It is not the canonical production release gate inside the integrated workspace.

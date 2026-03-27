# persistence

`myc` supports explicit persistence backends for signer state and runtime operation audit.

Current backends:

- signer state: `json_file`, `sqlite`
- runtime audit: `jsonl_file`, `sqlite`

The durable delivery outbox is currently always SQLite-backed.

`json_file` and `jsonl_file` remain supported for lightweight local use and backward compatibility.

For production deployment, the recommended path is:

- `MYC_PERSISTENCE_SIGNER_STATE_BACKEND=sqlite`
- `MYC_PERSISTENCE_RUNTIME_AUDIT_BACKEND=sqlite`

## paths

Persistence paths are derived from `MYC_PATHS_STATE_DIR`.

Signer state:

- `json_file` -> `<state_dir>/signer-state.json`
- `sqlite` -> `<state_dir>/signer-state.sqlite`

Runtime audit:

- `jsonl_file` -> `<state_dir>/audit/operations.jsonl`
- `sqlite` -> `<state_dir>/audit/operations.sqlite`

Delivery outbox:

- `sqlite` -> `<state_dir>/delivery-outbox.sqlite`

`myc status --view full` reports the active persistence backends, resolved paths, and SQLite schema state when SQLite is enabled. Delivery outbox path and health are reported separately in the `delivery_outbox` section. See [delivery.md](./delivery.md).

## migration

`myc` does not auto-migrate persistence on boot.

Use the explicit import command after switching the destination backend configuration to SQLite:

```bash
cargo run -- persistence import-json-to-sqlite
```

Import only signer state:

```bash
cargo run -- persistence import-json-to-sqlite --signer-state
```

Import only runtime audit:

```bash
cargo run -- persistence import-json-to-sqlite --runtime-audit
```

Import semantics:

- source state stays unchanged
- destination SQLite files are created automatically
- import refuses to write into a non-empty SQLite destination
- signer-state import refuses to proceed if the imported signer identity does not match the configured signer identity

The safest migration flow is:

1. keep the existing JSON and JSONL files in place
2. update the target config to `sqlite` backends
3. run `myc persistence import-json-to-sqlite`
4. run `myc persistence verify-restore`
5. run `myc status --view full` and verify the `persistence` section is ready
6. start `myc run` against the SQLite-backed config

## sqlite contract

The SQLite-backed stores are the production path because they add:

- schema versioning and migrations
- indexed reads for audit/status surfaces
- stronger durability than whole-file JSON rewrites

`myc` currently uses SQLite in local embedded mode. It is not a shared network database deployment.

## backup and restore

`myc` now provides first-class offline backup and restore commands around the configured persistence contract.

Create a backup:

```bash
cargo run -- persistence backup --out /path/to/backup-dir
```

Restore a backup into a fresh destination config:

```bash
cargo run -- persistence restore --from /path/to/backup-dir
```

Then run the strict preflight before `myc run`:

```bash
cargo run -- persistence verify-restore
```

Backup and restore rules:

- stop `myc` before running backup or restore
- `backup --out` requires an empty or nonexistent destination directory
- `restore --from` requires an empty or nonexistent destination state directory
- restore will not overwrite existing identity-reference files
- do not mix signer-state from one signer identity with a different configured signer identity
- restore persistence files and identity sources together
- keep the delivery outbox with signer state and runtime audit so unfinished publish work can still be recovered correctly

What `backup` copies:

- the full configured `state_dir`, including signer state, runtime audit, delivery outbox, SQLite sidecars, and future persistence files
- `filesystem` identity files
- `managed_account` account-store files
- `os_keyring` optional profile files when configured

What `backup` does not embed:

- OS keyring secrets
- `external_command` helper executables
- other out-of-band custody dependencies

For `os_keyring`, `managed_account`, and `external_command`, the backup manifest records the expected backend contract. `restore` requires the current config to match that contract and copies only the reference files that belong in the backup.

`verify-restore` is a strict preflight for migrated or restored deployments. It verifies:

- the configured signer-state, runtime-audit, and delivery-outbox files exist
- signer and user identities resolve from the current custody configuration
- persisted signer identity matches the configured signer identity
- unfinished delivery outbox jobs and persisted signer publish workflows are internally coherent before startup recovery runs

The recommended backup/restore flow is:

1. stop `myc`
2. run `myc persistence backup --out ...`
3. move the backup directory to the target machine or restore location
4. configure the target environment with matching persistence backends and custody contracts
5. run `myc persistence restore --from ...`
6. run `myc persistence verify-restore`
7. run `myc status --view full` and confirm the persistence and delivery sections are ready
8. start `myc run`

## recommended rollout

- local development: `json_file` + `jsonl_file` is acceptable
- production single-instance signer: `sqlite` + `sqlite`
- do not rely on implicit upgrade behavior; treat migration as an operator action

For identity custody guidance, see [custody.md](./custody.md). For status and health semantics, see [operability.md](./operability.md).

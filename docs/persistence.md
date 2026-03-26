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
4. run `myc status --view full` and verify the `persistence` section is ready
5. start `myc run` against the SQLite-backed config

## sqlite contract

The SQLite-backed stores are the production path because they add:

- schema versioning and migrations
- indexed reads for audit/status surfaces
- stronger durability than whole-file JSON rewrites

`myc` currently uses SQLite in local embedded mode. It is not a shared network database deployment.

## backup and restore

For the safest file-level backup:

1. stop `myc`
2. copy the configured state directory
3. copy any file-backed identity material still in use

If SQLite backends are active and you cannot stop the service, use SQLite-aware backup tooling or ensure the main `.sqlite` file and any `-wal` and `-shm` sidecars are kept consistent.

Restore rules:

- restore persistence files and identity sources together
- do not mix signer-state from one signer identity with a different configured signer identity
- if file-based identities are used, restore those identity files together with the state directory
- if keyring-backed identities are used, restore the database files and separately ensure the expected keyring entries exist
- if durable delivery is enabled, restore the delivery outbox together with signer state and runtime audit so unfinished publish work can still be recovered correctly

## recommended rollout

- local development: `json_file` + `jsonl_file` is acceptable
- production single-instance signer: `sqlite` + `sqlite`
- do not rely on implicit upgrade behavior; treat migration as an operator action

For identity custody guidance, see [custody.md](./custody.md). For status and health semantics, see [operability.md](./operability.md).

# discovery

`myc` can render discovery artifacts for NIP-46 and can explicitly publish a NIP-89 handler event. Discovery is operator-driven. It is not published automatically at startup.

Use [`config.example.toml`](../config.example.toml) as the checked starting point for a discovery-enabled configuration.

## commands

Render the NIP-05 `nostr.json` artifact to stdout:

```bash
cargo run -- discovery render-nip05 --stdout
```

Render the NIP-05 artifact to a specific path:

```bash
cargo run -- discovery render-nip05 --out ./.well-known/nostr.json
```

If `discovery.nip05_output_path` is configured, `cargo run -- discovery render-nip05` writes to that configured path.

Render the signed NIP-89 handler event for inspection:

```bash
cargo run -- discovery render-nip89
```

Publish the signed NIP-89 handler event to the configured discovery relays:

```bash
cargo run -- discovery publish-nip89
```

Fetch the grouped live NIP-89 handler state for the configured discovery identity:

```bash
cargo run -- discovery inspect-live-nip89
```

Diff the local discovery handler state against the grouped live NIP-89 handler state:

```bash
cargo run -- discovery diff-live-nip89
```

Refresh the live NIP-89 handler event only when local discovery state has changed:

```bash
cargo run -- discovery refresh-nip89
```

Force a refresh publish even when the latest live handler already matches local state:

```bash
cargo run -- discovery refresh-nip89 --force
```

Export a deterministic discovery bundle for deployment tooling:

```bash
cargo run -- discovery export-bundle --out ./dist/discovery
```

Verify an exported discovery bundle:

```bash
cargo run -- discovery verify-bundle --dir ./dist/discovery
```

## boundary

`myc` renders NIP-05 artifacts and may publish NIP-89 metadata, but it does not own HTTPS serving for `/.well-known/nostr.json`.

Serve the rendered `nostr.json` artifact from an external web surface:

- at `https://<domain>/.well-known/nostr.json`
- without redirects
- with CORS headers when browser-based clients need to fetch it

The NIP-05 artifact maps `names._` to the configured discovery app pubkey and includes the `nip46` relay and `nostrconnect_url` metadata described in NIP-46.

The bundle export writes:

- `bundle.json` with stable discovery metadata and artifact paths
- `.well-known/nostr.json` as the NIP-05 artifact
- `nip89-handler.json` as the unsigned handler specification for deployment tooling

## lifecycle

`inspect-live-nip89` fetches matching published handler events from each configured discovery relay separately, preserves relay provenance on grouped live events, and also returns per-relay live state.

Discovery relay fetch runs concurrently, but `relay_states` and grouped output are still returned in deterministic normalized relay order.

Each entry in `relay_states` now separates availability from semantic live state:

- `fetch_status` is `available` or `unavailable`
- `fetch_error` is present when a relay could not be queried
- `live_status` is only present for available relays and is one of `missing`, `matched`, `drifted`, or `conflicted`

`diff-live-nip89` compares the local rendered handler against the grouped live handler state and reports one of:

- `missing`
- `matched`
- `drifted`
- `conflicted`

`diff-live-nip89` and `refresh-nip89` also return:

- `relay_states` with per-relay fetch availability plus semantic live status when a relay was reachable
- `relay_summary` with compact relay lists for `unavailable`, `missing`, `matched`, `drifted`, and `conflicted`

`refresh-nip89` uses that same compare step:

- when any configured discovery relay is unavailable, `myc` refuses to refresh unless `--force` is set
- `myc` builds a relay-targeted refresh plan from per-relay `live_status`, instead of republishing to every configured relay
- relays that are `missing` or `drifted` are refreshed selectively without touching already matched relays
- relays that are themselves `conflicted` still require `--force`
- when every available relay is already `matched`, `myc` skips publication unless `--force` is set
- a mixed publish result is surfaced explicitly: `repair_results` shows per-relay `repaired`, `failed`, `unchanged`, or `skipped`, and `remaining_repair_relays` lists the relays that still need a follow-up repair run
- `repair_summary` provides a compact operator view of those per-relay outcomes without having to scan the full relay list
- every `refresh-nip89` run returns an `attempt_id` so operators can correlate later audit and repair follow-up against one logical refresh attempt
- when `refresh-nip89` fails after allocating an attempt, stderr includes that `attempt_id` directly so the failed run can be inspected without guessing which attempt was latest
- failed and blocked refresh attempts now keep structured relay actionability in audit output: `planned_repair_relays`, `blocked_relays`, and `blocked_reason`

This makes two different conflict shapes visible to operators:

- cross-relay divergence: different relays disagree, but each relay can still be individually `matched` or `drifted`
- stale relay history: a single relay reports multiple incompatible grouped live states and is itself `conflicted`

Cross-relay divergence does not require `--force` by itself. If the divergence is only `matched` versus `drifted`, `refresh-nip89` repairs the drifted relays and leaves matched relays alone.

`missing` and `unavailable` are intentionally different:

- `missing` means a relay was queried successfully and did not return a matching live handler
- `unavailable` means the relay could not be queried successfully at all

If at least one relay is available, `inspect-live-nip89` and `diff-live-nip89` still return partial healthy state plus unavailable-relay details.

If every configured discovery relay is unavailable, discovery sync fails as a hard error instead of pretending the live state is `missing`.

`audit summary --scope operation` distinguishes aggregate publish failures from per-relay repair failures. A mixed targeted refresh can therefore report a successful aggregate publish together with non-zero repair rejection counts when only some selected relays accepted the repair.

Discovery repair attempts can be queried directly:

- `cargo run -- audit latest-discovery-repair` returns the newest refresh attempt summary, including the repair summary, planned repair relays, blocked relays, remaining repair relays, and aggregate publish result
- `cargo run -- audit discovery-repair-attempt --attempt-id <attempt-id>` returns the summary for one specific attempt
- `cargo run -- audit discovery-repair-attempt --attempt-id <attempt-id> --view records` returns the raw runtime operation audit records for that attempt

Blocked refresh attempts are summarized explicitly:

- `planned_repair_relays` lists the relays `myc` intended to repair or would repair if the operator reruns with `--force`
- `blocked_relays` lists the relays that prevented the current refresh run from proceeding
- `blocked_reason` distinguishes cases such as `all_relays_unavailable`, `unavailable_relays`, and `conflicted_relays`
- `remaining_repair_relays` continues to track relays that still need follow-up after a partial publish, but blocked runs no longer rely on rejected repair records alone

If a refresh fails, `myc` prints the attempt id and an exact follow-up command:

- `myc: discovery repair attempt id: <attempt-id>`
- `myc: inspect with \`myc audit discovery-repair-attempt --attempt-id <attempt-id>\``
- `myc: discovery repair attempt json: {"attempt_id":"<attempt-id>","inspect_args":["audit","discovery-repair-attempt","--attempt-id","<attempt-id>"]}`

This keeps rolling-window audit totals and attempt-scoped repair history separate:

- `audit summary --scope operation` answers "what has happened recently across retained audit records?"
- `audit latest-discovery-repair` answers "what happened on the most recent discovery repair attempt?"
- `audit discovery-repair-attempt --attempt-id ...` answers "what happened on this exact refresh run?"

Because relay fetch is concurrent, partial outages are bounded by the configured discovery connect timeout rather than scaling linearly with relay count.

Discovery compare, conflict, skip, and publish decisions are recorded in the runtime audit log.

# operability

`myc` exposes machine-readable status and metrics from both the CLI and an optional local-only admin server.

Use [`.env.example`](../.env.example) as the checked starting point for the observability configuration.

## commands

Get a compact service snapshot:

```bash
cargo run -- status --view summary
```

Get the full service snapshot, including relay probe details:

```bash
cargo run -- status --view full
```

Render runtime counters as JSON:

```bash
cargo run -- metrics --format json
```

Render runtime counters as Prometheus-style text:

```bash
cargo run -- metrics --format prometheus
```

## config

The local admin surface is disabled by default.

- `MYC_OBSERVABILITY_ENABLED=true` enables the server
- `MYC_OBSERVABILITY_BIND_ADDR=127.0.0.1:9460` sets the listen address

`MYC_OBSERVABILITY_BIND_ADDR` must stay on a loopback address. `myc` rejects non-loopback bind addresses such as `0.0.0.0`.

## endpoints

When observability is enabled, `myc run` also serves:

- `GET /healthz`
- `GET /readyz`
- `GET /status`
- `GET /metrics`

The server is read-only. It does not expose connection approval, auth, or discovery mutation commands.

`/status` returns the same full JSON shape as `myc status --view full`.

`/metrics` returns the same Prometheus-style text as `myc metrics --format prometheus`.

Status output includes custody state for the signer, managed user, and discovery app identities, including the configured backend and whether each identity resolved successfully.

## semantics

Top-level runtime status is one of:

- `healthy`
- `degraded`
- `unready`

`ready` is reported separately because degraded service can still be ready.

Current readiness is driven by transport relay availability and the configured delivery policy:

- `any` is ready when at least one configured transport relay is available
- `quorum` is ready when the configured quorum can still be satisfied
- `all` is ready only when every configured transport relay is available

Examples:

- transport disabled: `unready`
- one relay down under `any`: `degraded` and `ready=true`
- one relay down under `all`: `unready`

Discovery availability affects health but not transport readiness:

- if discovery is disabled, it does not affect status
- if discovery is enabled and some discovery relays are unavailable, the service is `degraded`

## endpoint codes

- `/healthz` returns `200` for `healthy` and `degraded`, `503` for `unready`
- `/readyz` returns `200` when `ready=true`, otherwise `503`
- `/status` returns `200` with JSON unless status collection itself fails
- `/metrics` returns `200` with text unless metrics collection itself fails

## counters

The metrics surface is derived from retained signer-request audit and retained runtime operation audit.

It includes:

- signer request totals and decision counts
- runtime operation totals and per-outcome counts
- per-operation-kind outcome counts
- aggregate publish rejection totals
- discovery repair success and rejection totals
- unavailable-operation totals
- auth replay restore totals

Because the metrics are built from retained audit state, they reflect the retained audit window rather than a separate in-memory counter stream.

# durable delivery

`myc` persists publish work before it sends critical NIP-46 and discovery events to relays.

This durable-delivery layer exists to make restart behavior explicit and to keep publish-dependent signer state transitions safe across process crashes.

## covered publish flows

The delivery outbox currently covers:

- live listener response publishes
- `connect accept`
- auth replay publishes
- NIP-89 discovery handler publication, including refresh-driven repair publishes

## outbox path

The delivery outbox is currently always SQLite-backed.

Its file lives at:

- `<state_dir>/delivery-outbox.sqlite`

`myc status --view full` reports the resolved outbox path and the current outbox health in the `delivery_outbox` section.

## job lifecycle

Outbox jobs move through these states:

- `queued`: publish intent is durable, but no relay publish has been confirmed yet
- `published_pending_finalize`: relay publish met the configured delivery policy, but the local finalization step is not complete yet
- `finalized`: relay publish and local finalization both completed
- `failed`: the publish attempt failed and the job is now a terminal audit record

`myc` only auto-recovers unfinished jobs:

- `queued`
- `published_pending_finalize`

`failed` jobs are not retried automatically on startup. They remain as audit and operator evidence, and the higher-level operation must be reissued explicitly if it should be attempted again.

## startup recovery

`myc run` performs startup delivery recovery before the service is considered ready.

Recovery behavior is:

- `queued` jobs are republished
- `published_pending_finalize` jobs are finalized without an extra publish
- signer-side publish workflows are checked for consistency with the outbox record
- orphaned signer workflows with no matching outbox job are treated as startup errors

This keeps two sensitive transitions restart-safe:

- connect-secret consumption only becomes final after publish confirmation and workflow finalization
- auth replay only becomes final after publish confirmation and workflow finalization

For discovery publishes, recovery uses the signer identity or the configured discovery app identity based on the persisted event author.

## readiness and health

Delivery recovery feeds directly into service status.

Critical delivery jobs are:

- listener response publishes
- `connect accept`
- auth replay publishes

Non-critical delivery jobs are:

- discovery handler publishes

Status behavior is:

- missing outbox file: `unready`
- blocked critical unfinished jobs: `unready`
- blocked discovery-only jobs: `degraded` with `ready=true`
- no blocked unfinished jobs: `healthy`

The `delivery_outbox` status payload includes:

- `total_job_count`
- `queued_job_count`
- `published_pending_finalize_job_count`
- `finalized_job_count`
- `failed_job_count`
- `unfinished_job_count`
- `critical_unfinished_job_count`
- `blocked_job_count`
- `critical_blocked_job_count`
- `stuck_after_secs`
- `oldest_unfinished_age_secs`
- `oldest_blocked_age_secs`
- `last_recovery`

`last_recovery` is derived from the most recent `DeliveryRecovery` operation-audit record and summarizes whether the last startup recovery succeeded or failed.

## metrics

`myc metrics --format json|prometheus` exposes durable-delivery counters, including:

- delivery recovery success and rejection totals
- total outbox jobs
- queued outbox jobs
- `published_pending_finalize` jobs
- failed jobs
- finalized jobs
- unfinished jobs
- critical unfinished jobs
- blocked jobs
- critical blocked jobs

These counters are currently derived from retained runtime audit plus current outbox state.

## operator expectations

- use `myc status --view full` when the service is not ready and inspect the `delivery_outbox` section first
- a blocked critical outbox job is a production issue because signer-facing request completion may be incomplete
- a blocked discovery job does not stop the signer from serving NIP-46 requests, but it does mean discovery publication needs attention
- if startup recovery fails, fix the reported workflow or persistence inconsistency before treating the service as healthy
- after file-level restore or JSON-to-SQLite migration, run `myc persistence verify-restore` before `myc run`

For persistence layout and backup guidance, see [persistence.md](./persistence.md). For status and endpoint semantics, see [operability.md](./operability.md).

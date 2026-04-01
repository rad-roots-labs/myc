# release acceptance stability

This note captures the `rpv1-i7w` stabilization work for the `myc`
`release-acceptance` flake.

## current composition

`release-acceptance` currently composes:

- repo-local `cargo metadata --format-version 1 --no-deps`
- repo-local `cargo check --locked`
- repo-local `cargo test --locked`
- repo-local `cargo fmt --all --check`
- consumer-side `platform-integration` suites when the integrated workspace is present:
  - `myc-nip46`
  - `myc-app-remote-signer`

That composition is defined in [`scripts/release-acceptance.sh`](../scripts/release-acceptance.sh).

## current status

As of `rpv1-i7w.3`, the full gate is green again.

- two consecutive full `nix run .#release-acceptance` passes succeeded on
  `2026-03-31`
- the first proof pass completed with:
  - `myc-nip46` run `1774982802364755000`
  - `myc-app-remote-signer` run `1774982951820916000`
- the second proof pass completed with:
  - `myc-nip46` run `1774983130096599000`
  - `myc-app-remote-signer` run `1774983279477624000`

## pressure-test result

The instability is not currently isolated to a deterministic logic regression in
`myc` core behavior. The strongest reproduction signal is instead an async timing
class in the relay-backed acceptance lanes.

Observed signal:

- the previously seen failure in `tests/nip46_e2e.rs` was
  `live_listener_retries_until_all_delivery_policy_is_met` timing out with
  `Elapsed(())`
- the previously seen `operability_e2e` failure did not reproduce in focused repeat
  runs and remains a lower-confidence suspect
- focused repeat runs of the two previously suspected tests stayed green
- repeated repo-local acceptance runs with
  `MYC_RELEASE_ACCEPTANCE_SKIP_PLATFORM_INTEGRATION=1` stayed green through the
  same relay-backed `nip46_e2e` matrix

The likely flake class is therefore:

- relay-backed tests that usually pass in isolation
- but can exceed short fixed waits when the composed acceptance lane is under
  heavier load

`rpv1-i7w.2` addressed that class by increasing the readiness, relay publication,
and response budgets in the repo-local relay-backed tests and the consumer-side
`platform-integration` suites.

## primary suspect

The highest-confidence instability source is the use of short fixed async waits
around relay readiness and event publication:

- [`tests/nip46_e2e.rs`](../tests/nip46_e2e.rs) uses five-second waits in
  `wait_for_subscription_count` and `wait_for_published_events_by_author`
- the consumer-side `platform-integration` `myc_nip46` suite uses five-second
  subscription and persisted-state waits
- the consumer-side `platform-integration` `myc_support` helpers use a
  ten-second transport connect timeout and a fixed five-hundred-millisecond
  post-connect grace sleep

Those values are reasonable for fast local proof, but they leave little headroom
when the release gate is composing:

- a full `cargo test --locked`
- additional relay-backed live suites
- fresh compilation or slower host conditions

## secondary destabilizer

Repeated pressure-testing also showed that acceptance probes contend on the shared
cargo target directory under `.local/build/cargo`. That contention is not the
root flake itself, but it is a real destabilizer for repeated release-gate
stress runs because overlapping probes block on the same build lock.

## host-runtime constraint

The remaining observed red state during `rpv1-i7w.3` was not a `myc` logic
failure. The local OrbStack Docker daemon temporarily stopped responding and
left `docker info` hanging or returning socket-level connect errors while the
consumer-side relay stack was being prepared.

That surfaced through the root relay-stack helpers, not through `myc` itself.
The relay stack helper now applies bounded timeout-and-retry handling for
transient Docker daemon failures so the acceptance lane no longer wedges
forever on a dead socket. A fully stopped local Docker daemon will still keep
the consumer-side suites red until the host runtime is brought back.

## reproduction split

Use this split when working the follow-up hardening slice:

1. isolate the repo-local relay test:

```bash
/nix/var/nix/profiles/default/bin/nix develop --command bash -lc \
  'cargo test --locked --test nip46_e2e live_listener_retries_until_all_delivery_policy_is_met -- --exact --nocapture'
```

2. isolate the repo-local acceptance lane without consumer-side integration:

```bash
MYC_RELEASE_ACCEPTANCE_SKIP_PLATFORM_INTEGRATION=1 \
  /nix/var/nix/profiles/default/bin/nix develop --command bash -lc \
  './scripts/release-acceptance.sh'
```

3. isolate the consumer-side suites directly:

```bash
/nix/var/nix/profiles/default/bin/nix develop --command bash -lc '
  export PATH="${HOME}/.rustup/toolchains/1.92.0-aarch64-apple-darwin/bin:$PATH"
  manifest="/path/to/integrated-workspace/testing/rs/platform-integration/Cargo.toml"
  cargo run --manifest-path "$manifest" -- suite myc-nip46
  cargo run --manifest-path "$manifest" -- suite myc-app-remote-signer
'
```

## residual constraints

- run repeated full-gate proofs serially when possible so unrelated cargo work
  does not contend on `.local/build/cargo`
- keep an eye on free disk space before long repeated proofs because
  `.local/build/cargo` can grow significantly during cold rebuilds
- if the local Docker daemon is hard-down rather than transiently unhealthy,
  restore it first; the consumer-side relay suites are intentionally real and
  still require a working local container runtime

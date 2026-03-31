# release acceptance stability

This note captures the `rpv1-i7w.1` isolation pass for the `myc`
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

## follow-up target

The next slice should stay narrow:

- harden the relay-backed acceptance waits so they are deterministic under the
  composed release gate
- keep the fix focused on readiness/publish timing rather than unrelated `myc`
  behavior
- only address shared cargo target contention if it is still needed after the
  timing hardening

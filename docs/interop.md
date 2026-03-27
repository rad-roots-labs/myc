# interop

`myc` keeps two compatibility lanes for live NIP-46 behavior:

- a repo-local external client lane that uses the upstream `nostr` crate `0.44.2` NIP-46 message types against a live `myc` listener
- a consumer-side live suite outside this repo that uses the checked-in `radroots-nostr-connect` client message types against a live `myc` service boundary
- a product onboarding lane that uses the current Radroots app remote signer client against a live `myc` service boundary

The repo-local lane exists to prove that `myc` accepts and returns standard `id` / `method` / `params` and `id` / `result` / `error` message shapes from an independent client surface, not only the `radroots-nostr-connect` crate.

Current repo-local compatibility coverage:

- `connect`, `get_public_key`, and `ping` over a live session created through the upstream `nostr` NIP-46 connect request shape
- `sign_event`, `nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`, and `nip44_decrypt` over a live approved session while still using the upstream `nostr` request and response envelope types
- explicit-approval pending state
- `auth_url` challenge responses
- queued listener-response recovery after restart for an upstream `nostr` `connect` request
- response matching remains stable even when the relay already contains unrelated signer-authored `kind:24133` events

Current consumer-side live compatibility coverage outside this repo:

- `connect`, `ping`, and `switch_relays` through the `platform-it` `myc-nip46` suite
- requested-permission negotiation for `switch_relays`, including persistence of the requested and granted permission set on the live `myc` signer state
- direct verification of the live listener publish audit emitted for external client request ids

Current known boundary:

- `switch_relays` is not covered by the pinned upstream `nostr` `0.44.2` lane because that crate surface does not expose that request type, but it is now covered by the consumer-side live `platform-it` lane
- the pinned upstream `nostr` `0.44.2` connect request shape does not carry requested permissions, so requested-permission negotiation is proven through the consumer-side live `platform-it` lane instead of the upstream typed lane
- the app remote signer product-client onboarding proof is maintained outside this repo because it validates the consumer-side service boundary rather than a repo-local unit or integration seam; that lane covers bunker and discovery-url initiation, pending approval, restart before approval, and approved identity resolution through the current client poll flow

Run the repo-local compatibility lane from this repo root with:

```bash
cargo test --locked --test nip46_e2e external_nostr_client
```

Run the consumer-side live compatibility lane from the outer repo root with:

```bash
cargo run --manifest-path testing/rs/platform-it/Cargo.toml -- suite myc-nip46
```

These tests complement, but do not replace, the broader `nip46_e2e` relay harness. The native harness remains the source of truth for delivery policy, connect-secret consumption, discovery publication, and targeted repair semantics.

For the final production release gate, run [`./scripts/release-acceptance.sh`](../scripts/release-acceptance.sh) from the `myc` repo root. That lane composes the repo-local proof surface with the consumer-side live suites when the integrated workspace is available.

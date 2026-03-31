<div align="center">

# mycorrhiza | rad roots

_nostr remote signer_

<p align="center"><a href="https://opensource.org/license/agpl-v3"><img src="https://img.shields.io/badge/license-AGPLv3-blue.svg"></a></p>
<pre align="center">
          .      . * .      .
          . *    .-~~~~~~~~-.    * .
     .     .~~*   . ** .   *~~.    .
     *    .~*   .-********-.   *~.    *
     .~*   .* **  **  ** *.   *~.
.   ~    .* ** ** **** ** ** *.   ~   .
     *~   .* ** ************** ** *.  ~*
.    ~  .* ** *****    ***** ** *.  ~    .
     .~ .* ** ****  ****  **** ** *. ~.
*    ~ .* ** **** ****** **** ** *. ~    *
     .~ .* ** ****  ****  **** ** *. ~.
.    ~  .* ** *****    ***** ** *.  ~    .
     *~   .* ** ************** ** *.  ~*
.   ~    .* ** ** **** ** ** *.   ~   .
     .~*   .* **  **  ** *.   *~.
     *    .~*   .-********-.   *~.    *
     .     .~~*   . ** .   *~~.    .
          . *    .-~~~~~~~~-.    * .
          .      . * .      .
</pre>
</div>

## Overview

Mycorrhiza is a Nostr remote signer that implements the NIP-46 specification. It is built to enable delegated account access and secure signing flows.

## Runtime Config

`myc` loads its runtime configuration from `.env` in the repo root by default.

Use `.env.example` as the checked starting point:

```bash
cp .env.example .env
```

Then replace the example paths, relays, and discovery host with real local values before running the service.

Transport delivery is explicit:

- `MYC_TRANSPORT_DELIVERY_POLICY=any` succeeds when at least one configured transport relay acknowledges a publish
- `MYC_TRANSPORT_DELIVERY_POLICY=quorum` requires `MYC_TRANSPORT_DELIVERY_QUORUM`
- `MYC_TRANSPORT_DELIVERY_POLICY=all` requires every configured transport relay to acknowledge
- `MYC_TRANSPORT_PUBLISH_MAX_ATTEMPTS`, `MYC_TRANSPORT_PUBLISH_INITIAL_BACKOFF_MILLIS`, and `MYC_TRANSPORT_PUBLISH_MAX_BACKOFF_MILLIS` control bounded retry and backoff for listener responses, `connect accept`, auth replay, and discovery publication

Publish flows are also durable:

- listener responses, `connect accept`, auth replay, and discovery publication are written to a persistent delivery outbox before relay send
- `myc run` performs startup recovery for unfinished delivery jobs before the service is treated as ready
- `myc persistence backup --out ...` and `myc persistence restore --from ...` provide the first-class offline backup and restore workflow
- after JSON-to-SQLite migration or `restore`, run `myc persistence verify-restore` before `myc run`
- see [`docs/delivery.md`](./docs/delivery.md) for the durable-delivery and restart-recovery contract

Policy and auth are typed:

- `MYC_POLICY_CONNECTION_APPROVAL` sets the default connect policy for unknown clients
- `MYC_POLICY_TRUSTED_CLIENT_PUBKEYS` and `MYC_POLICY_DENIED_CLIENT_PUBKEYS` override that default per client pubkey
- `MYC_POLICY_PERMISSION_CEILING` and `MYC_POLICY_ALLOWED_SIGN_EVENT_KINDS` bound what can ever be granted or executed
- `MYC_POLICY_AUTH_URL`, `MYC_POLICY_AUTH_PENDING_TTL_SECS`, `MYC_POLICY_AUTHORIZED_TTL_SECS`, and `MYC_POLICY_REAUTH_AFTER_INACTIVITY_SECS` control auth challenge expiry and trusted-session reauth
- `MYC_POLICY_CONNECT_RATE_LIMIT_*` optionally throttles inbound `connect` attempts per client pubkey
- `MYC_POLICY_AUTH_CHALLENGE_RATE_LIMIT_*` optionally throttles automatic auth challenge reissuance per trusted client pubkey
- trusted sessions that have exceeded the configured auth TTL or inactivity reauth window are downgraded back to pending auth during bootstrap before `myc` starts serving requests

Custody is backend-aware:

- filesystem remains the default signer, user, and discovery app identity backend
- `MYC_PATHS_SIGNER_IDENTITY_BACKEND` and `MYC_PATHS_USER_IDENTITY_BACKEND` support `filesystem`, `os_keyring`, `managed_account`, and `external_command`
- `MYC_DISCOVERY_APP_IDENTITY_BACKEND` may be left unset to reuse the signer identity, or set explicitly for a dedicated filesystem, keyring-backed, managed-account, or external-command discovery app identity
- `managed_account` stores selected public identities in an account-store file and secrets in the configured OS keyring namespace
- `external_command` executes a role-specific signer helper over JSON stdin/stdout, so `myc` can request public identity, signing, `nip04`, and `nip44` operations without loading that role's secret into the `myc` process
- `myc custody list|generate|import-file|select|remove` manages the selected signer, user, or discovery app identity when that role uses `managed_account`
- `*_KEYRING_ACCOUNT_ID` selects the public identity id stored in the local keyring vault
- `*_KEYRING_SERVICE_NAME` scopes the local keyring service name
- `*_PROFILE_PATH` may be set for `os_keyring` identities when local profile metadata should be merged onto the loaded secret
- for `managed_account`, `*_PATH` points to the role-specific account store file
- for `external_command`, `*_PATH` points to the helper executable for that role
- see [`docs/custody.md`](./docs/custody.md) for the backend contract and migration guidance

Observability is local-only:

- `MYC_OBSERVABILITY_ENABLED=true` enables the read-only admin surface
- `MYC_OBSERVABILITY_BIND_ADDR` must stay on a loopback address such as `127.0.0.1:9460`
- `myc status --view summary|full` emits machine-readable service status from the CLI
- `myc metrics --format json|prometheus` emits stable runtime counters from a persisted-audit startup baseline plus live in-memory updates
- `myc status` includes custody backend and resolution state for signer, user, and discovery app identities
- `myc status` also includes signer backend capability projection for the local signer, active remote sessions, and active publish workflows
- when enabled, the local admin server exposes `/healthz`, `/readyz`, `/status`, and `/metrics`

See [`docs/operability.md`](./docs/operability.md) for the status, metrics, and endpoint contract.
See [`docs/delivery.md`](./docs/delivery.md) for delivery outbox, startup recovery, and restart semantics.

## Validation

This repository uses Nix as the canonical local validation surface:

```bash
nix run .#fmt
nix run .#check
nix run .#test
```

Enter the repo shell when you want narrower focused cargo commands:

```bash
nix develop
```

Run the relay-backed NIP-46 proof lane directly inside the shell when you want the transport/discovery end-to-end suite:

```bash
cargo test --locked --test nip46_e2e
```

Run the operability-focused lanes directly inside the shell when you want CLI and admin-surface proof:

```bash
cargo test --locked --test operability_cli
cargo test --locked --test operability_server
```

Run the final release-acceptance gate when preparing a production candidate:

```bash
nix run .#release-acceptance
```

See [`docs/release.md`](./docs/release.md) for the exact matrix and the integrated-workspace consumer-side interop lanes.

## License

This project is licensed under the AGPL-3.0.

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

`myc` loads its runtime configuration from the canonical `config.env` path for the
active runtime profile unless `--env-file` is passed explicitly.

Default profile posture:

- manual operator runs default to `interactive_user`
- managed-service wrappers should set `MYC_PATHS_PROFILE=service_host`
- repo-local labs should prefer the root `.env.local` control plane plus
  `scripts/dev/lib/radroots-runtime-env.sh`, which derives `MYC_PATHS_PROFILE=repo_local` and
  `MYC_PATHS_REPO_LOCAL_ROOT` automatically

Canonical default config locations:

- macOS/Linux `interactive_user`: `~/.radroots/config/services/myc/config.env`
- Windows `interactive_user`: `%APPDATA%\\Radroots\\config\\services\\myc\\config.env`
- `service_host`: `/etc/radroots/services/myc/config.env`

The checked-in `.env.example` is a canonical `service_host` sample.
Use it either as the file you pass to `--env-file`, or copy it into the resolved runtime location:

```bash
cp .env.example /etc/radroots/services/myc/config.env
```

For local ad hoc runs on macOS/Linux, copy the same file into `~/.radroots/config/services/myc/config.env`
and change `MYC_PATHS_PROFILE` to `interactive_user`, or omit that line entirely.

For repo-owned local runs inside the outer monorepo, prefer the shared root control plane in
`.env.local` instead of editing repo-local `MYC_PATHS_*` values by hand.

When you keep the canonical profile-derived defaults, do not set the path variables explicitly.
`myc` will derive:

- logs under the runtime logs root
- state under the runtime data root
- encrypted-file identities under the runtime secrets root
- discovery `nostr.json` output under the runtime data root

Only set `MYC_LOGGING_OUTPUT_DIR`, `MYC_PATHS_STATE_DIR`, `MYC_PATHS_*_IDENTITY_PATH`,
or `MYC_DISCOVERY_NIP05_OUTPUT_PATH` when you intentionally want a non-canonical override.

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

- `encrypted_file` remains the default signer, user, and discovery app identity backend
- `MYC_PATHS_SIGNER_IDENTITY_BACKEND` and `MYC_PATHS_USER_IDENTITY_BACKEND` support `encrypted_file`, `host_vault`, `managed_account`, `external_command`, and `plaintext_file`
- `MYC_DISCOVERY_APP_IDENTITY_BACKEND` may be left unset to reuse the signer identity, or set explicitly for a dedicated `encrypted_file`, `host_vault`, `managed_account`, `external_command`, or `plaintext_file` discovery app identity
- `managed_account` stores selected public identities in an account-store file and secrets in the configured OS keyring namespace
- `external_command` executes a role-specific signer helper over JSON stdin/stdout, so `myc` can request public identity, signing, `nip04`, and `nip44` operations without loading that role's secret into the `myc` process
- the canonical default identity and account-store file locations are derived from `MYC_PATHS_PROFILE`
- `myc custody status` reports backend-specific status for a single role
- `myc custody export-nip49|import-nip49|rotate` provides explicit operator-facing NIP-49 import/export and backend-specific storage rotation where supported
- `myc custody list|generate|import-file|select|remove` manages the selected signer, user, or discovery app identity when that role uses `managed_account`
- `*_KEYRING_ACCOUNT_ID` selects the public identity id stored in the local keyring vault
- `*_KEYRING_SERVICE_NAME` scopes the local keyring service name
- `*_PROFILE_PATH` may be set for `host_vault` identities when local profile metadata should be merged onto the loaded secret
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

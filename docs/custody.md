# custody

`myc` supports backend-aware identity custody for the signer identity, managed user identity, and optional discovery app identity.

## backends

Supported backends:

- `filesystem`
- `os_keyring`
- `managed_account`

`filesystem` remains the default backend for all identities.

`os_keyring` loads the secret key from the local OS keyring and reconstructs the identity in memory at runtime.

`managed_account` uses a role-specific account store file plus the local OS keyring. The account store keeps public identity metadata and the selected account pointer; the keyring service keeps the secret material.

## config

Signer and managed user identities use:

- `MYC_PATHS_SIGNER_IDENTITY_BACKEND`
- `MYC_PATHS_SIGNER_IDENTITY_PATH`
- `MYC_PATHS_SIGNER_IDENTITY_KEYRING_ACCOUNT_ID`
- `MYC_PATHS_SIGNER_IDENTITY_KEYRING_SERVICE_NAME`
- `MYC_PATHS_SIGNER_IDENTITY_PROFILE_PATH`
- `MYC_PATHS_USER_IDENTITY_BACKEND`
- `MYC_PATHS_USER_IDENTITY_PATH`
- `MYC_PATHS_USER_IDENTITY_KEYRING_ACCOUNT_ID`
- `MYC_PATHS_USER_IDENTITY_KEYRING_SERVICE_NAME`
- `MYC_PATHS_USER_IDENTITY_PROFILE_PATH`

Discovery app identity uses:

- `MYC_DISCOVERY_APP_IDENTITY_BACKEND`
- `MYC_DISCOVERY_APP_IDENTITY_PATH`
- `MYC_DISCOVERY_APP_IDENTITY_KEYRING_ACCOUNT_ID`
- `MYC_DISCOVERY_APP_IDENTITY_KEYRING_SERVICE_NAME`
- `MYC_DISCOVERY_APP_IDENTITY_PROFILE_PATH`

When `MYC_DISCOVERY_APP_IDENTITY_BACKEND` is unset and `MYC_DISCOVERY_APP_IDENTITY_PATH` is unset, discovery reuses the signer identity.

## semantics

For `filesystem`:

- `*_PATH` must point to a loadable Radroots identity file

For `os_keyring`:

- `*_KEYRING_ACCOUNT_ID` must be the public identity id for the secret stored in the keyring
- `*_KEYRING_SERVICE_NAME` selects the local keyring namespace
- `*_PROFILE_PATH` is optional and may point to a public/profile identity file whose profile metadata should be merged onto the keyring-backed secret

For `managed_account`:

- `*_PATH` must point to the account store file for that role
- `*_KEYRING_SERVICE_NAME` selects the local keyring namespace for that role
- `*_KEYRING_ACCOUNT_ID` must stay unset
- `*_PROFILE_PATH` must stay unset
- the selected account in the store is the active runtime identity for that role

`myc` verifies that:

- the resolved secret matches the configured keyring account id for `os_keyring`
- any configured profile file matches the same public identity for `os_keyring`
- the selected managed account has a secret in the configured keyring service before runtime boot
- the persisted signer-state public identity still matches the configured signer identity

## lifecycle commands

`managed_account` adds explicit local key lifecycle commands:

```bash
cargo run -- custody list --role signer
cargo run -- custody generate --role signer --label primary --select
cargo run -- custody import-file --role user --path ./user-identity.json --label migrated --select
cargo run -- custody select --role signer --account-id <identity-id>
cargo run -- custody remove --role signer --account-id <identity-id>
```

Supported roles are:

- `signer`
- `user`
- `discovery-app`

These commands only apply when that role uses `managed_account`. If discovery currently reuses the signer identity, `--role discovery-app` is rejected until a dedicated discovery backend is configured.

## status

`myc status --view full` reports:

- which backend is active for signer, user, and discovery app identities
- the configured backend path
- any configured keyring account id or keyring service name
- for `managed_account`, the selected account id and selection state
- whether each identity resolved successfully

For `managed_account`, `path` in the custody status is the account store file path.

## migration

The safest path from `filesystem` to `managed_account` is:

1. choose a role-specific account store path
2. switch that role to `managed_account`
3. run `myc custody import-file --role <role> --path <legacy-identity-file> --select`
4. verify `myc status --view full` shows the role as resolved with `selected_account_state=ready`
5. remove the legacy identity file only after the new backend is working as expected

The safest path from `os_keyring` to `managed_account` is:

1. keep the same keyring service name if you want to preserve the local secret namespace
2. import or generate the managed account for that role
3. verify the selected account is `ready`
4. update automation to use the new `managed_account` config

Do not rotate the signer public identity without also migrating signer-state persistence that is already bound to that signer id.

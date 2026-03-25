# custody

`myc` supports backend-aware identity custody for the signer identity, managed user identity, and optional discovery app identity.

## backends

Supported backends:

- `filesystem`
- `os_keyring`

`filesystem` remains the default backend for all identities.

`os_keyring` loads the secret key from the local OS keyring and reconstructs the identity in memory at runtime.

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

`myc` verifies that:

- the resolved secret matches the configured keyring account id
- any configured profile file matches the same public identity
- the persisted signer-state public identity still matches the configured signer identity

## status

`myc status --view full` reports:

- which backend is active for signer, user, and discovery app identities
- any configured keyring account id or profile path
- whether each identity resolved successfully

## migration

The safest path is:

1. keep the current filesystem identity available
2. store the same secret in the OS keyring under the target account id
3. switch the backend to `os_keyring`
4. keep a profile file only if local profile metadata must still be merged

Do not rotate the signer public identity without also migrating signer-state persistence that is already bound to that signer id.

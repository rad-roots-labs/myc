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

## Validation

Run the full repo-root validation lane:

```bash
cargo metadata --format-version 1 --no-deps
cargo check --locked
cargo test --locked
cargo fmt --all --check
```

Run the relay-backed NIP-46 proof lane directly when you want the transport/discovery end-to-end suite:

```bash
cargo test --locked --test nip46_e2e
```

## License

This project is licensed under the AGPL-3.0.

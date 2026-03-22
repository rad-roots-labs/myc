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

## Validation

Run the relay-backed NIP-46 proof lane from the repo root:

```bash
cargo test --locked --test nip46_e2e
```

## License

This project is licensed under the AGPL-3.0.

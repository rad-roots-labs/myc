# discovery

`myc` can render discovery artifacts for NIP-46 and can explicitly publish a NIP-89 handler event. Discovery is operator-driven. It is not published automatically at startup.

## commands

Render the NIP-05 `nostr.json` artifact to stdout:

```bash
cargo run -- discovery render-nip05 --stdout
```

Render the NIP-05 artifact to a specific path:

```bash
cargo run -- discovery render-nip05 --out ./.well-known/nostr.json
```

If `discovery.nip05_output_path` is configured, `cargo run -- discovery render-nip05` writes to that configured path.

Render the signed NIP-89 handler event for inspection:

```bash
cargo run -- discovery render-nip89
```

Publish the signed NIP-89 handler event to the configured discovery relays:

```bash
cargo run -- discovery publish-nip89
```

## boundary

`myc` renders NIP-05 artifacts and may publish NIP-89 metadata, but it does not own HTTPS serving for `/.well-known/nostr.json`.

Serve the rendered `nostr.json` artifact from an external web surface:

- at `https://<domain>/.well-known/nostr.json`
- without redirects
- with CORS headers when browser-based clients need to fetch it

The NIP-05 artifact maps `names._` to the configured discovery app pubkey and includes the `nip46` relay and `nostrconnect_url` metadata described in NIP-46.

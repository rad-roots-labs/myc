# myc - code directives

- this repo defines `myc`, a NIP-46 signer service; signing, key material handling, approval flows, session control, and signer-facing transport belong here
- treat this repo root as the source of truth for runtime, release, validation, and documentation
- keep docs and manifests honest about current implementation status and documented command surfaces
- prefer the smallest coherent change that fully addresses the request; do not mix unrelated cleanup, speculative refactors, or roadmap work into the same change
- read `README.md`, `docs/nix.md`, and `Cargo.toml` before broad edits, and inspect the current implementation before changing behavior
- validate from this repo root with documented Nix commands first; start with `nix run .#check` and `nix run .#test`, then run the narrowest additional validation that credibly covers the change
- use `nix run .#release-acceptance` when preparing a production candidate
- use raw cargo commands only for narrower follow-up work after entering `nix develop`
- if validation cannot run, report the blocker clearly instead of guessing past it
- toolchain: Rust 1.92, edition 2024
- avoid `unsafe`
- prefer explicit typed models, deterministic behavior, and direct service boundaries over stringly or implicit behavior

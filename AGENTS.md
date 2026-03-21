# myc - code directives

- this repo defines `myc`, a NIP-46 signer service; signing, key material handling, approval flows, session control, and signer-facing transport belong here
- treat this repo root as the source of truth for runtime, release, validation, and documentation
- keep docs and manifests honest about current implementation status and documented command surfaces
- prefer the smallest coherent change that fully addresses the request; do not mix unrelated cleanup, speculative refactors, or roadmap work into the same change
- read `README.md` and `Cargo.toml` before broad edits, and inspect the current implementation before changing behavior
- validate from this repo root with documented commands first; for Rust changes start with `cargo metadata --format-version 1 --no-deps` and `cargo check`, then run the narrowest additional validation that credibly covers the change
- if validation cannot run, report the blocker clearly instead of guessing past it
- toolchain: Rust 1.92, edition 2024
- avoid `unsafe`
- prefer explicit typed models, deterministic behavior, and direct service boundaries over stringly or implicit behavior

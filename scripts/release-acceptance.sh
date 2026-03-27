#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
platform_it_manifest="$(cd "$repo_root/../../../../" && pwd)/testing/rs/platform-it/Cargo.toml"

run() {
  printf '+ %s\n' "$*"
  "$@"
}

cd "$repo_root"

run cargo metadata --format-version 1 --no-deps
run cargo check --locked
run cargo test --locked
run cargo fmt --all --check

if [[ "${MYC_RELEASE_ACCEPTANCE_SKIP_PLATFORM_IT:-0}" == "1" ]]; then
  printf 'skipping consumer-side platform-it lanes because MYC_RELEASE_ACCEPTANCE_SKIP_PLATFORM_IT=1\n'
  exit 0
fi

if [[ ! -f "$platform_it_manifest" ]]; then
  printf 'skipping consumer-side platform-it lanes because %s is not present\n' "$platform_it_manifest"
  exit 0
fi

run cargo check --manifest-path "$platform_it_manifest"
run cargo run --manifest-path "$platform_it_manifest" -- suite myc-nip46
run cargo run --manifest-path "$platform_it_manifest" -- suite myc-app-remote-signer

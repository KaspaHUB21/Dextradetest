#!/usr/bin/env bash
set -euo pipefail
case "${RUSTFLAGS:-} ${CARGO_ENCODED_RUSTFLAGS:-}" in
  *tlsn_insecure*) printf '%s\n' 'Refusing insecure TLSNotary build flags.' >&2; exit 1 ;;
esac
command -v cargo >/dev/null || { printf '%s\n' 'Rust/Cargo is required. Install the repository prerequisites first.' >&2; exit 1; }
experiment_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
experiment_target=${ORACLE_EXPERIMENT_TARGET_DIR:-"$experiment_root/engine/target"}
cargo build --locked --release --manifest-path "$experiment_root/engine/Cargo.toml" --target-dir "$experiment_target"
mkdir -p -- "$experiment_root/bin"
for binary in notary prove present verify; do
  install -m 755 -- "$experiment_target/release/$binary" "$experiment_root/bin/$binary"
done
printf '%s\n' 'Experimental binaries built. Production node binaries and service settings were not changed.'

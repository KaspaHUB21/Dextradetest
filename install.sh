#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ $(uname -s) == Linux ]] || { echo 'Linux is required.' >&2; exit 1; }
replace=false
case "${1:-}" in
  '') ;;
  --replace-binaries) replace=true ;;
  *) echo 'Usage: bash install.sh [--replace-binaries]' >&2; exit 1 ;;
esac
[[ $# -le 1 ]] || { echo 'Unexpected installation arguments.' >&2; exit 1; }
for tool in node cargo rustc openssl cc readlink mktemp; do
  command -v "$tool" >/dev/null || { printf 'Missing prerequisite: %s\n' "$tool" >&2; exit 1; }
done
node -e 'if (Number(process.versions.node.split(".")[0]) < 22) { console.error("Node.js 22+ required"); process.exit(1); }'
for source in oracle-node.mjs jobs.mjs discovery-address.mjs mesh-link.mjs job-queue.mjs witness-selection.mjs network-defaults.mjs; do
  [[ -f "$source" ]] || { echo "Missing node source: $source" >&2; exit 1; }
  node --check "$source"
done
openssl version >/dev/null
[[ -f tlsn-engine/Cargo.lock && -f vendor/tlsn/Cargo.toml ]] || { echo 'Missing locked dependencies or TLSNotary vendor source.' >&2; exit 1; }
for executable in notary prove present verify; do
  [[ -f "tlsn-engine/src/bin/$executable.rs" ]] || { echo "Missing engine source: $executable" >&2; exit 1; }
done
[[ ! -L bin ]] || { echo 'Refusing symlinked bin directory.' >&2; exit 1; }
for executable in notary prove present verify; do
  if [[ -e "bin/$executable" || -L "bin/$executable" ]]; then
    [[ $replace == true && -f "bin/$executable" && ! -L "bin/$executable" ]] || { echo 'Existing binaries preserved; use --replace-binaries for an intentional update.' >&2; exit 1; }
  fi
done
# No package-manager changes and no downloaded script execution. Cargo's lockfile
# fixes the dependency graph; it is not a release authenticity guarantee.
cargo build --locked --release --manifest-path tlsn-engine/Cargo.toml --bins
target_dir=${CARGO_TARGET_DIR:-"$PWD/tlsn-engine/target"}
target_dir=$(readlink -f -- "$target_dir")
stage=$(mktemp -d "$PWD/.install-stage.XXXXXXXX")
cleanup_stage() {
    # Only remove the exact mktemp directory inside this checked-out source.
    if [[ $stage == "$PWD"/.install-stage.* && -d $stage && ! -L $stage ]]; then
        rm -rf -- "$stage"
    fi
}
trap cleanup_stage EXIT
for executable in notary prove present verify; do
    [[ -f "$target_dir/release/$executable" && -x "$target_dir/release/$executable" ]] || { echo "Missing built executable: $executable" >&2; exit 1; }
    cp -- "$target_dir/release/$executable" "$stage/$executable"
    chmod 755 "$stage/$executable"
done
mkdir -p bin
for executable in notary prove present verify; do
    mv -- "$stage/$executable" "bin/$executable"
done
printf 'Installed locally. Run: node oracle-node.mjs init --data node-data --address HOST:9443 --listen 0.0.0.0:9443\n'

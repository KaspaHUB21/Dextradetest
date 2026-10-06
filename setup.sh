#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
case "${1:-}" in
  ''|--replace-binaries) ;;
  --help) printf 'Usage: bash setup.sh [--replace-binaries]\nInstalls missing runtimes locally, then builds the engines. Requires Linux, cc, OpenSSL, curl and tar.\n'; exit 0 ;;
  *) echo 'Unknown setup option.' >&2; exit 1 ;;
esac
[[ $# -le 1 && $(uname -s) == Linux ]] || { echo 'Linux and at most one option required.' >&2; exit 1; }
for tool in cc openssl curl tar sha256sum readlink mktemp; do
  command -v "$tool" >/dev/null || { echo "Missing: $tool. On Ubuntu/Debian: sudo apt install build-essential openssl ca-certificates curl xz-utils git" >&2; exit 1; }
done
case "$(uname -m)" in
  x86_64) node_arch=x64; rust_host=x86_64-unknown-linux-gnu ;;
  aarch64) node_arch=arm64; rust_host=aarch64-unknown-linux-gnu ;;
  *) echo 'Only Linux x86_64 and aarch64 supported by setup.' >&2; exit 1 ;;
esac
[[ ! -L .tools ]] || { echo 'Refusing symlinked runtime directory.' >&2; exit 1; }
mkdir -p .tools
tools_root=$(cd .tools && pwd -P)
stage=$(mktemp -d "$tools_root/setup.XXXXXXXX")
cleanup() {
  if [[ $stage == "$tools_root"/setup.* && -d $stage && ! -L $stage ]]; then rm -rf -- "$stage"; fi
}
trap cleanup EXIT
download() { curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error "$1" --output "$2"; }
export PATH="$tools_root/node/bin:$tools_root/cargo/bin:$PATH"
if ! command -v node >/dev/null || ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)'; then
  node_version=24.19.0
  archive="node-v$node_version-linux-$node_arch.tar.xz"
  base="https://nodejs.org/dist/v$node_version"
  download "$base/$archive" "$stage/$archive"
  download "$base/SHASUMS256.txt" "$stage/SHASUMS256.txt"
  awk -v file="$archive" '$2 == file { print }' "$stage/SHASUMS256.txt" > "$stage/node.sha256"
  [[ $(wc -l < "$stage/node.sha256") == 1 ]] || { echo 'Missing unique Node checksum.' >&2; exit 1; }
  (cd "$stage" && sha256sum --check node.sha256)
  [[ ! -e $tools_root/node && ! -L $tools_root/node ]] || { echo 'Existing local Node runtime is invalid; refusing overwrite.' >&2; exit 1; }
  tar -xJf "$stage/$archive" -C "$stage" --no-same-owner
  mv -- "$stage/node-v$node_version-linux-$node_arch" "$tools_root/node"
fi
rust_ok=false
if command -v cargo >/dev/null && command -v rustc >/dev/null; then
  rust_version=$(rustc --version | awk '{print $2}')
  if [[ $(printf '%s\n' 1.85.0 "$rust_version" | sort -V | head -n 1) == 1.85.0 ]]; then rust_ok=true; fi
fi
if [[ $rust_ok == false ]]; then
  export CARGO_HOME="$tools_root/cargo" RUSTUP_HOME="$tools_root/rustup"
  if [[ ! -x $CARGO_HOME/bin/rustup ]]; then
    base="https://static.rust-lang.org/rustup/archive/1.28.2/$rust_host/rustup-init"
    download "$base" "$stage/rustup-init"
    download "$base.sha256" "$stage/rustup-init.sha256"
    digest=$(awk 'NR == 1 {print $1}' "$stage/rustup-init.sha256")
    [[ $digest =~ ^[a-f0-9]{64}$ ]] || { echo 'Invalid rustup checksum.' >&2; exit 1; }
    (cd "$stage" && printf '%s  rustup-init\n' "$digest" | sha256sum --check -)
    chmod 700 "$stage/rustup-init"
    "$stage/rustup-init" -y --no-modify-path --profile minimal --default-toolchain 1.99.0
  else
    "$CARGO_HOME/bin/rustup" toolchain install 1.99.0 --profile minimal
    "$CARGO_HOME/bin/rustup" default 1.99.0
  fi
elif [[ -x $tools_root/cargo/bin/cargo && $(command -v cargo) == "$tools_root/cargo/bin/cargo" ]]; then
  export CARGO_HOME="$tools_root/cargo" RUSTUP_HOME="$tools_root/rustup"
fi
bash install.sh "$@"
chmod 755 oracle-node
printf '\nReady. Initialize: ./oracle-node init --data /private/linux/path/node-data --address HOST:9443 --listen 0.0.0.0:9443\n'

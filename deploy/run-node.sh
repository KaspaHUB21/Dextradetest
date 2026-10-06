#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(uname -s) == Linux ]] || { echo 'Linux is required.' >&2; exit 1; }
[[ $EUID != 0 ]] || { echo 'Run the node as a dedicated unprivileged user.' >&2; exit 1; }
[[ $# == 1 && $1 == /* ]] || { echo 'Usage: bash deploy/run-node.sh /absolute/data-directory' >&2; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
node_binary=$(command -v node)
[[ $node_binary == /* && -x $node_binary ]] || { echo 'Use Node.js via an absolute executable path.' >&2; exit 1; }
node_binary=$(readlink -f -- "$node_binary")
node_path=$(dirname -- "$node_binary")
[[ -d $1 && ! -L $1 && -f $1/config.json ]] || { echo 'Initialize a private data directory first; no symlink allowed.' >&2; exit 1; }
data=$(cd -- "$1" && pwd -P)
[[ $(stat -c %u -- "$data") == "$EUID" ]] || { echo 'Data directory must belong to the current user.' >&2; exit 1; }
[[ $(stat -c %a -- "$data") == 700 ]] || { echo 'Data directory must have mode 0700.' >&2; exit 1; }
for engine in notary prove present verify; do
  [[ -f $root/bin/$engine && -x $root/bin/$engine && ! -L $root/bin/$engine ]] || { echo 'Build the native engines first.' >&2; exit 1; }
done
# Remove inherited loader/runtime injection variables. Dependencies use explicit
# paths; only Node's own directory and system tools are exposed in PATH.
exec env -i PATH="$node_path:/usr/bin:/bin" LANG=C.UTF-8 \
  ORACLE_ENGINE_DIR="$root/bin" "$node_binary" "$root/oracle-node.mjs" start --data "$data"

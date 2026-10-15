#!/bin/sh
# Fetch the workerd this relay's config was made for (workerd/WORKERD.lock) into
# ~/.local/sezi-workerd/<version>/, check it against the lock's sha512 BEFORE it is unpacked or run,
# and point ~/.local/sezi-workerd/current at it. Prints the binary's path on success.
#
# The app's installer does the same in Dart (mobile/lib/src/platform/relay_provision_io.dart); this
# is the terminal recipe's half, so both install the same binary into the same place. No root, no
# Node, nothing outside your home. Needs curl, tar and sha512sum.
set -eu

cd "$(dirname "$0")/.."
lock=workerd/WORKERD.lock
[ -f "$lock" ] || { echo "no $lock: this checkout predates the bare-workerd relay (git pull)" >&2; exit 1; }

version=$(awk '$1 == "version" { print $2 }' "$lock")
case "$(uname -m)" in
  x86_64 | amd64) arch=linux-64 ;;
  aarch64 | arm64) arch=linux-arm64 ;;
  *) echo "workerd is published for 64-bit Linux only (this is $(uname -m))" >&2; exit 1 ;;
esac
want=$(awk -v a="$arch" '$1 == a { print $3 }' "$lock")
[ -n "$version" ] && [ -n "$want" ] || { echo "$lock names no version or no digest for $arch" >&2; exit 1; }

base="$HOME/.local/sezi-workerd"
dir="$base/$version"
if ! "$dir/workerd" --version >/dev/null 2>&1; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fL --progress-bar -o "$tmp/workerd.tgz" \
    "https://registry.npmjs.org/@cloudflare/workerd-$arch/-/workerd-$arch-$version.tgz"
  got=$(sha512sum "$tmp/workerd.tgz" | awk '{ print $1 }')
  [ "$got" = "$want" ] || { echo "workerd download does not match $lock — not installed" >&2; exit 1; }
  tar -xzf "$tmp/workerd.tgz" -C "$tmp" package/bin/workerd
  mkdir -p "$dir"
  install -m 755 "$tmp/package/bin/workerd" "$dir/workerd.new"
  mv "$dir/workerd.new" "$dir/workerd"
fi
ln -sfn "$version" "$base/current"
echo "$dir/workerd"

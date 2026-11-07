#!/usr/bin/env bash
# Install the exact upstream Syft release, checking immutable release provenance.
set -euo pipefail
version=1.57.0
repo=anchore/syft
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  echo 'Syft release is for Linux x86-64' >&2; exit 2;
}
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
archive="syft_${version}_linux_amd64.tar.gz"
checksums="syft_${version}_checksums.txt"
base="https://github.com/${repo}/releases/download/v${version}"
curl --fail --silent --show-error --location --retry 3 "$base/$archive" -o "$work/$archive"
curl --fail --silent --show-error --location --retry 3 "$base/$checksums" -o "$work/$checksums"
# These checks verify the GitHub-hosted release's immutable status and the
# downloaded binary's identity independently of the downloaded checksum list.
gh release verify "v${version}" --repo "$repo"
gh release verify-asset "v${version}" "$work/$archive" --repo "$repo"
gh release verify-asset "v${version}" "$work/$checksums" --repo "$repo"
expected="$(awk -v file="$archive" '$2 == file && length($1) == 64 && $1 ~ /^[0-9a-f]+$/ {print $1}' "$work/$checksums")"
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'Syft upstream checksum missing or ambiguous' >&2; exit 2
fi
printf '%s  %s\n' "$expected" "$work/$archive" | sha256sum --check --status
mkdir -p "$HOME/.local/bin"
tar -xzf "$work/$archive" -C "$work" syft
install -m 0755 "$work/syft" "$HOME/.local/bin/syft"

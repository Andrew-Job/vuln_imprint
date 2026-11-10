#!/usr/bin/env bash
# Install the pinned Syft build tool and verify its downloaded checksum.
set -euo pipefail
# Dependency lock is the single source of truth for the release SBOM tool.
release="$(python3 -c 'import json; from pathlib import Path; c=json.loads(Path("external/DEPENDENCIES.json").read_text())["release_sbom_tool"]; assert c["name"] == "syft" and c["platform"] == "linux_amd64"; print(c["version"], c["repository"])')"
read -r version repo <<< "$release"
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
expected="$(awk -v file="$archive" '$2 == file && length($1) == 64 && $1 ~ /^[0-9a-f]+$/ {print $1}' "$work/$checksums")"
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'Syft upstream checksum missing or ambiguous' >&2; exit 2
fi
printf '%s  %s\n' "$expected" "$work/$archive" | sha256sum --check --status
mkdir -p "$HOME/.local/bin"
tar -xzf "$work/$archive" -C "$work" syft
install -m 0755 "$work/syft" "$HOME/.local/bin/syft"
"$HOME/.local/bin/syft" version

#!/bin/sh
# Dependency-free user entrypoint for the supported Linux release bundle.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
command_name=${0##*/}
root=$(dirname -- "$here")
scanner="$here/vulnimprint-scan"
db="$root/share/vulnimprint/db"
if [ ! -x "$scanner" ] || [ ! -s "$db/database.yarc" ] || [ ! -s "$db/SHA256SUMS" ]; then
  printf 'VulnImprint: incomplete installation\n' >&2
  exit 2
fi
case "${1:-}" in
  scan)
    shift
    if [ "$#" -eq 0 ]; then
      printf 'Usage: %s scan [--json] [--recursive] FILE_OR_DIRECTORY\n' "$command_name" >&2
      exit 2
    fi
    (cd "$db" && sha256sum --status --check SHA256SUMS) || {
      printf 'VulnImprint: DB integrity check failed\n' >&2; exit 2;
    }
    version=$(cat "$root/share/vulnimprint/RELEASE_VERSION")
    exec "$scanner" scan --compiled "$db/database.yarc" --db-version "$version" "$@"
    ;;
  version)
    cat "$root/share/vulnimprint/RELEASE_VERSION"
    ;;
  *)
    printf 'Usage: %s scan [--json] [--recursive] FILE_OR_DIRECTORY\n       %s version\n' "$command_name" "$command_name" >&2
    exit 2
    ;;
esac

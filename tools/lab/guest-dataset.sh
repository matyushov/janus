#!/usr/bin/env bash
# Generate a data set of unique random files and verify it later (before a backup, and after
# a restore). The hashes go to <dir>.sha, next to the directory (not inside it).
#
#   guest-dataset.sh make DIR [--big N] [--big-mb MB] [--small N]
#   guest-dataset.sh verify DIR [SHA_FILE]      (SHA_FILE defaults to DIR.sha)
#
# Defaults: 5 files of 100 MB, 200 small files of up to ~100 KB spread over a/b/ and one
# marker.txt with the creation time.
set -euo pipefail

hashes() { (cd "$1" && find . -type f -exec shasum -a 256 {} + | sort -k2); }

case "${1:-}" in
  make)
    dir="${2:?usage: make DIR}"; shift 2
    big=5; big_mb=100; small=200
    while [ $# -gt 0 ]; do
      case "$1" in
        --big) big="$2"; shift 2;;
        --big-mb) big_mb="$2"; shift 2;;
        --small) small="$2"; shift 2;;
        *) echo "unknown argument: $1" >&2; exit 2;;
      esac
    done
    dir="${dir%/}"
    mkdir -p "$dir/big" "$dir/small/a/b"
    for i in $(seq 1 "$big"); do head -c $((big_mb * 1000000)) /dev/urandom > "$dir/big/file$i.bin"; done
    for i in $(seq 1 "$small"); do head -c $((RANDOM * 3 + 1)) /dev/urandom > "$dir/small/a/b/s$i.dat"; done
    echo "dataset created $(date)" > "$dir/small/marker.txt"
    hashes "$dir" > "$dir.sha"
    echo "$(wc -l < "$dir.sha" | tr -d ' ') files, $(du -sh "$dir" | cut -f1); hashes in $dir.sha"
    ;;
  verify)
    dir="${2:?usage: verify DIR [SHA_FILE]}"; dir="${dir%/}"
    sha="${3:-$dir.sha}"
    if diff <(sort -k2 "$sha") <(hashes "$dir" | sort -k2) > /dev/null; then
      echo "ALL $(wc -l < "$sha" | tr -d ' ') FILES IDENTICAL"
    else
      echo "DIFFERENCES:"; diff <(sort -k2 "$sha") <(hashes "$dir" | sort -k2) | head -10; exit 1
    fi
    ;;
  *) sed -n '2,10p' "$0" >&2; exit 2;;
esac

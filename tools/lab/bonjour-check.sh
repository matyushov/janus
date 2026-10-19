#!/usr/bin/env bash
# Check what janus-smbd advertises through Bonjour (run on the machine where it runs; it
# must advertise: a configured share with advertise_bonjour, or JANUS_LAB_BONJOUR=1 for a
# dev run). The services are registered local-only (dns-sd -lo), so they are visible here
# and nowhere else.
#
#   bonjour-check.sh
set -euo pipefail

command -v dns-sd >/dev/null || { echo "dns-sd not found (macOS only)"; exit 1; }
tmp="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$tmp"' EXIT

dns-sd -B _adisk._tcp local > "$tmp/browse" 2>&1 &
dns-sd -L janus _adisk._tcp local > "$tmp/adisk" 2>&1 &
dns-sd -L janus _smb._tcp local > "$tmp/smb" 2>&1 &
sleep 4
echo "== browse _adisk._tcp"; grep -E ' Add ' "$tmp/browse" || echo "(nothing advertised)"
echo "== _adisk._tcp"; grep -E 'can be reached|adVN|adVF' "$tmp/adisk" || true
echo "== _smb._tcp"; grep -E 'can be reached' "$tmp/smb" || true
echo "daemon children: $(pgrep -f 'dns-sd -lo' | wc -l | tr -d ' ') (expected 2 while advertising)"

#!/usr/bin/env bash
# Reverse SSH tunnel from this (host) machine into the guest: the guest then reaches the
# receiver on 127.0.0.1:<port>.
#
# Why: macOS withdraws the "Local Network" permission from a third-party binary that is not
# started from a GUI session (SSH, nohup) after about a minute, so janus-smbd in a lab VM
# cannot keep a connection to a receiver on the LAN. System binaries such as ssh and nc are
# not affected. The receiver certificate must be valid for 127.0.0.1 (dev-pki.sh does that).
#
#   JANUS_LAB_GUEST=user@192.168.10.127 JANUS_LAB_RECEIVER=192.168.10.135:7443 \
#     tools/lab/tunnel.sh start|stop|status
#
# JANUS_LAB_TUNNEL_PORT (default 17443) is the port opened on the guest's loopback.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
lab_need JANUS_LAB_GUEST "user@host of the guest"
port="${JANUS_LAB_TUNNEL_PORT:-17443}"
pattern="ssh -f -N .* -R 127.0.0.1:$port:"

case "${1:-status}" in
  start)
    lab_need JANUS_LAB_RECEIVER "host:port of the receiver"
    pkill -f "$pattern" 2>/dev/null || true
    ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 \
        -R "127.0.0.1:$port:$JANUS_LAB_RECEIVER" "$JANUS_LAB_GUEST"
    echo "tunnel up: guest 127.0.0.1:$port -> $JANUS_LAB_RECEIVER"
    ;;
  stop)
    pkill -f "$pattern" && echo "tunnel stopped" || echo "no tunnel running"
    ;;
  status)
    if pgrep -f "$pattern" >/dev/null; then echo "tunnel running"; else echo "no tunnel"; fi
    ssh "$JANUS_LAB_GUEST" "nc -z -w3 127.0.0.1 $port && echo 'guest sees 127.0.0.1:$port' || echo 'guest does NOT see 127.0.0.1:$port'"
    ;;
  *) echo "usage: tunnel.sh start|stop|status" >&2; exit 2;;
esac

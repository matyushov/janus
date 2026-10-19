#!/usr/bin/env bash
# Start, stop or inspect janus-smbd on the machine that is backed up (the macOS guest).
#
#   guest-daemon.sh start|stop|status
#
# Variables (all but the password have defaults):
#   JANUS_LAB_SMB_PASSWORD  password of the SMB account (required for start)
#   JANUS_LAB_SMB_USER      SMB account (default: janus)
#   JANUS_LAB_RECEIVER      receiver host:port, e.g. 127.0.0.1:17443 through tunnel.sh
#   JANUS_LAB_PKI           directory with ca.pem, <machine>.pem, <machine>.key
#   JANUS_LAB_MACHINE       machine id of the certificate (default: vm-mac)
#   JANUS_LAB_SHARE         share name (default: backup)
#   JANUS_LAB_SMB_ADDR      SMB listen address (default: 127.0.0.1:4455)
#   JANUS_LAB_CONTROL       control address (default: 127.0.0.1:50061)
#   JANUS_LAB_LOCAL_ROOT    serve this directory instead of a receiver (no mTLS, dev only)
#   JANUS_LAB_TRACE         JANUS_SMB_TRACE level, 0..2 (default: 1; 2 dumps every request)
#   JANUS_LAB_BONJOUR       1 = advertise the share when no share is configured
#   JANUS_LAB_BIN           directory with janus-smbd and janus-cli (default: $LAB_DIR/bin)
# Files: $LAB_DIR/config (daemon config), $LAB_DIR/journal, $LAB_DIR/smbd.log.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

bin="${JANUS_LAB_BIN:-$LAB_DIR/bin}"
control="${JANUS_LAB_CONTROL:-127.0.0.1:50061}"
smb_addr="${JANUS_LAB_SMB_ADDR:-127.0.0.1:4455}"
share="${JANUS_LAB_SHARE:-backup}"
machine="${JANUS_LAB_MACHINE:-vm-mac}"
cli() { JANUS_CLIENT_ADDR="$control" "$bin/janus-cli" "$@"; }

stop_daemon() {
  cli client shutdown >/dev/null 2>&1 || true
  sleep 1
  pkill -f "$bin/janus-smbd" 2>/dev/null || true
}

case "${1:-status}" in
  stop) stop_daemon; echo "stopped";;
  status) cli client status; cli client ready;;
  start)
    lab_need JANUS_LAB_SMB_PASSWORD "password of the SMB account"
    stop_daemon
    mkdir -p "$LAB_DIR"
    export JANUS_CONFIG="$LAB_DIR/config" JANUS_CLIENT_ADDR="$control" JANUS_SMB_ADDR="$smb_addr" \
           JANUS_SMB_USER="${JANUS_LAB_SMB_USER:-janus}" JANUS_SMB_PASSWORD="$JANUS_LAB_SMB_PASSWORD" \
           JANUS_SMB_TRACE="${JANUS_LAB_TRACE:-1}"
    [ -n "${JANUS_LAB_BONJOUR:-}" ] && export JANUS_BONJOUR="$JANUS_LAB_BONJOUR"
    if [ -n "${JANUS_LAB_LOCAL_ROOT:-}" ]; then
      export JANUS_SMB_LOCAL_ROOT="$JANUS_LAB_LOCAL_ROOT"
    fi
    nohup "$bin/janus-smbd" --dev >> "$LAB_DIR/smbd.log" 2>&1 < /dev/null &
    sleep 3
    if [ -z "${JANUS_LAB_LOCAL_ROOT:-}" ]; then
      lab_need JANUS_LAB_RECEIVER "host:port of the receiver"
      lab_need JANUS_LAB_PKI "directory with ca.pem, $machine.pem, $machine.key"
      cli client configure --endpoint "$JANUS_LAB_RECEIVER" \
        --client-cert "$JANUS_LAB_PKI/$machine.pem" --client-key "$JANUS_LAB_PKI/$machine.key" \
        --ca "$JANUS_LAB_PKI/ca.pem" --share "$share" --port "$(lab_port_of "$smb_addr")"
      cli client ready
    fi
    echo "janus-smbd up on $smb_addr (log: $LAB_DIR/smbd.log)"
    ;;
  *) echo "usage: guest-daemon.sh start|stop|status" >&2; exit 2;;
esac

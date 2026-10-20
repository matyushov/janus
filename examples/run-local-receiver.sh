#!/usr/bin/env bash
# Starts a janus receiver on this machine with a throw-away PKI, so the examples that talk to a
# receiver (02, 03, 05) can run without any infrastructure. DEVELOPMENT ONLY.
#
#   examples/run-local-receiver.sh [workdir] [port]
#
# It builds janus-receiverd, creates certificates (tools/dev-pki.sh), starts the receiver on
# 127.0.0.1:<port> (default 7443) and writes <workdir>/env.sh. In another terminal:
#
#   source <workdir>/env.sh        # sets JANUS_EXAMPLE_ENDPOINT / _CERT / _KEY / _CA / _STATE_DIR
#   ./build/examples/02_mount_and_copy
#
# Ctrl-C stops the receiver. The uploaded data is in <workdir>/store.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="${1:-$(mktemp -d "${TMPDIR:-/tmp}/janus-example.XXXXXX")}"
port="${2:-7443}"
mkdir -p "$work/store" "$work/state"

(cd "$root" && cargo build -q -p janus-receiverd)
"$root/tools/dev-pki.sh" "$work/pki" dev-mac >/dev/null

cat > "$work/env.sh" <<ENV
export JANUS_EXAMPLE_ENDPOINT=127.0.0.1:$port
export JANUS_EXAMPLE_CERT=$work/pki/dev-mac.pem
export JANUS_EXAMPLE_KEY=$work/pki/dev-mac.key
export JANUS_EXAMPLE_CA=$work/pki/ca.pem
export JANUS_EXAMPLE_STATE_DIR=$work/state
ENV

echo "receiver on 127.0.0.1:$port, data in $work/store"
echo "in another terminal:  source $work/env.sh"
exec env \
  JANUS_TLS_CERT="$work/pki/server.pem" JANUS_TLS_KEY="$work/pki/server.key" \
  JANUS_TLS_CA="$work/pki/ca.pem" JANUS_MACHINES="$work/pki/machines.json" \
  JANUS_STORE="$work/store" \
  "$root/target/debug/janus-receiverd" --listen "127.0.0.1:$port"

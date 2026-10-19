#!/usr/bin/env bash
# Copy the janus binaries, the guest-side lab scripts and (optionally) one machine's mTLS
# material from the host to the guest.
#
#   JANUS_LAB_GUEST=user@192.168.10.127 \
#   JANUS_LAB_PKI=./vm-mac-pki JANUS_LAB_MACHINE=vm-mac \
#     tools/lab/push-to-guest.sh
#
# Variables:
#   JANUS_LAB_GUEST        user@host (required)
#   JANUS_LAB_REMOTE_DIR   directory on the guest, relative to its home (default: j4)
#   JANUS_LAB_BINDIR       where janus-smbd and janus-cli are (default: <repo>/target/debug)
#   JANUS_LAB_PKI          directory with ca.pem, <machine>.pem, <machine>.key (optional)
#   JANUS_LAB_MACHINE      machine id of that certificate (default: vm-mac)
# The guest needs the same architecture as the host (build once, copy).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib.sh"
lab_need JANUS_LAB_GUEST "user@host of the guest"
remote="${JANUS_LAB_REMOTE_DIR:-j4}"
bindir="${JANUS_LAB_BINDIR:-$here/../../target/debug}"
machine="${JANUS_LAB_MACHINE:-vm-mac}"
for b in janus-smbd janus-cli; do
  [ -x "$bindir/$b" ] || lab_die "$bindir/$b not found (run: cargo build -p janus-smbd -p janus-cli)"
done

ssh "$JANUS_LAB_GUEST" "mkdir -p $remote/bin $remote/lab $remote/pki"
scp -q "$bindir/janus-smbd" "$bindir/janus-cli" "$JANUS_LAB_GUEST:$remote/bin/"
scp -q "$here"/lib.sh "$here"/guest-*.sh "$here"/bonjour-check.sh "$JANUS_LAB_GUEST:$remote/lab/"
ssh "$JANUS_LAB_GUEST" "chmod +x $remote/lab/*.sh"
if [ -n "${JANUS_LAB_PKI:-}" ]; then
  scp -q "$JANUS_LAB_PKI/ca.pem" "$JANUS_LAB_PKI/$machine.pem" "$JANUS_LAB_PKI/$machine.key" \
      "$JANUS_LAB_GUEST:$remote/pki/"
  ssh "$JANUS_LAB_GUEST" "chmod 600 $remote/pki/$machine.key"
fi
echo "pushed to $JANUS_LAB_GUEST:~/$remote (bin/, lab/, pki/)"

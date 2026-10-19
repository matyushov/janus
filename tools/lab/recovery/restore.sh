#!/bin/sh
# Run in the Terminal of macOS Recovery (it is /bin/sh there, as root). Starts janus-smbd so that
# the "Restore from Time Machine" wizard can reach the share. LAB USE: see tools/lab/README.md.
#
#   cd /tmp/janus      # the kit: janus-smbd janus-cli <machine>.pem <machine>.key ca.pem restore.sh
#   sh restore.sh <receiver host:port> [manual]
#
#   (no argument)  start the daemon, then in the wizard use "Other Server..." with
#                  smb://<user>:<password>@10.99.99.1/<share>
#   manual         also mount the share and attach the sparsebundle by hand
#
# Why 10.99.99.1: the wizard refuses 127.0.0.1 ("There was a problem connecting"), but it accepts
# an ordinary address. The address is an alias of lo0, so nothing leaves the machine. Recovery
# runs as root, so the daemon can listen on the standard port 445 and the address needs no port.
#
# Variables: JANUS_LAB_SMB_PASSWORD (default: janus-lab-pass; change it), JANUS_LAB_SMB_USER
# (janus), JANUS_LAB_MACHINE (vm-mac), JANUS_LAB_SHARE (backup).
D="$(pwd)"
A=10.99.99.1
RECEIVER="${1:?usage: sh restore.sh <receiver host:port> [manual]}"
MACHINE="${JANUS_LAB_MACHINE:-vm-mac}"
SHARE="${JANUS_LAB_SHARE:-backup}"
SMB_USER="${JANUS_LAB_SMB_USER:-janus}"
SMB_PASSWORD="${JANUS_LAB_SMB_PASSWORD:-janus-lab-pass}"
for f in janus-smbd janus-cli "$MACHINE.pem" "$MACHINE.key" ca.pem; do
  [ -s "$f" ] || { echo "missing $D/$f"; exit 1; }
done

# detach what an earlier run left, then stop the old daemon (pkill is not reliable in Recovery)
for v in /Volumes/Backups*; do [ -d "$v" ] && hdiutil detach -force "$v" >/dev/null 2>&1; done
umount -f /Volumes/"$SHARE" >/dev/null 2>&1
JANUS_CLIENT_ADDR=127.0.0.1:50061 ./janus-cli client shutdown >/dev/null 2>&1; sleep 2
for p in $(ps aux | grep janus-smbd | grep -v grep | awk '{print $2}'); do kill -9 "$p" 2>/dev/null; done; sleep 1

ifconfig lo0 alias "$A/32" 2>/dev/null; ifconfig lo0 | grep "$A" || echo "WARNING: alias $A not set"
mkdir -p "$D/cfg"; chmod +x janus-smbd janus-cli; chmod 600 "$MACHINE.key"
export JANUS_CONFIG="$D/cfg/config" JANUS_CLIENT_ADDR=127.0.0.1:50061 JANUS_SMB_ADDR="$A:445" \
       JANUS_SMB_USER="$SMB_USER" JANUS_SMB_PASSWORD="$SMB_PASSWORD" JANUS_SMB_TRACE=1
# a subshell, so that closing the Terminal window cannot reach the daemon
( nohup ./janus-smbd --dev > "$D/smbd.log" 2>&1 < /dev/null & )
sleep 3
grep -E "SMB on|ERROR" "$D/smbd.log"
./janus-cli client configure --endpoint "$RECEIVER" --client-cert "$D/$MACHINE.pem" \
  --client-key "$D/$MACHINE.key" --ca "$D/ca.pem" --share "$SHARE" --port 445
./janus-cli client ready

if [ "$2" = manual ]; then
  mkdir -p /Volumes/"$SHARE"
  mount_smbfs -N "//$SMB_USER:$SMB_PASSWORD@$A/$SHARE" /Volumes/"$SHARE" || exit 1
  echo "share mounted"; ls /Volumes/"$SHARE"
  hdiutil attach /Volumes/"$SHARE"/*.sparsebundle
  ls /Volumes
fi
echo "=== DONE: you can close this Terminal; the daemon keeps running"
echo "In the wizard: Other Server...  ->  smb://$SMB_USER:<password>@$A/$SHARE"

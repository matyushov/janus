#!/usr/bin/env bash
# Point Time Machine of the macOS guest at janus-smbd, run a backup, and undo all of it.
# Changes the guest's Time Machine configuration and System keychain: LAB VMs ONLY.
#
#   guest-timemachine.sh setup              add the destination and make backupd able to log in
#   guest-timemachine.sh exclude PATH...    exclude paths from backups (fixed-path, recorded)
#   guest-timemachine.sh backup [--wait]    start a backup (and wait until it ends)
#   guest-timemachine.sh status             Time Machine and daemon status
#   guest-timemachine.sh cleanup [--snapshots]
#                                           remove destination, keychain entries, exclusions
#                                           (and, with --snapshots, local snapshots)
#
# Variables: JANUS_LAB_SMB_PASSWORD (required for setup), JANUS_LAB_SMB_USER (janus),
# JANUS_LAB_SMB_ADDR (127.0.0.1:4455), JANUS_LAB_SHARE (backup), JANUS_LAB_SUDO_PASSWORD
# (optional, otherwise sudo asks), JANUS_LAB_BACKUP_TIMEOUT (seconds, default 7200),
# JANUS_LAB_CONTROL (127.0.0.1:50061).
#
# Why the keychain work: `tmutil setdestination` stores the password in System.keychain with
# port 0 and without access for NetAuthSysAgent, and backupd then fails with
# "NetAuth is not in the ACL" / error 80. The entries are recreated for port 0 and for the
# real port, trusting NetAuthSysAgent and tmutil.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

user="${JANUS_LAB_SMB_USER:-janus}"
smb_addr="${JANUS_LAB_SMB_ADDR:-127.0.0.1:4455}"
port="$(lab_port_of "$smb_addr")"
share="${JANUS_LAB_SHARE:-backup}"
bin="${JANUS_LAB_BIN:-$LAB_DIR/bin}"
control="${JANUS_LAB_CONTROL:-127.0.0.1:50061}"
kc=/Library/Keychains/System.keychain
agent=/System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent
changes="$LAB_DIR/changes-made.txt"
excl="$LAB_DIR/exclusions-added.txt"
mkdir -p "$LAB_DIR"

keychain_clear() {
  for _ in 1 2 3 4 5 6 7 8; do
    lab_sudo security delete-internet-password -a "$user" -s 127.0.0.1 "$kc" >/dev/null 2>&1 || true
  done
}

keychain_add() { # keychain_add PORT
  lab_sudo security add-internet-password -a "$user" -s 127.0.0.1 -r "smb " -p "/$share" -P "$1" \
    -D "Time Machine Network Password" -w "$JANUS_LAB_SMB_PASSWORD" \
    -T "$agent" -T /usr/bin/tmutil "$kc" >/dev/null
}

tm_running() { tmutil status | grep -q 'Running = 1'; }

case "${1:-status}" in
  setup)
    lab_need JANUS_LAB_SMB_PASSWORD "password of the SMB account"
    { tmutil destinationinfo || true; } > "$LAB_DIR/tm-before.txt" 2>&1
    { lab_sudo defaults read /Library/Preferences/com.apple.TimeMachine || true; } > "$LAB_DIR/tm-prefs-before.txt" 2>&1
    # NB: the password is visible in the process list for a moment: lab only.
    lab_sudo tmutil setdestination "smb://$user:$JANUS_LAB_SMB_PASSWORD@127.0.0.1:$port/$share"
    keychain_clear
    keychain_add 0
    keychain_add "$port"
    echo "setup: destination + keychain entries for $user@127.0.0.1 (ports 0 and $port)" >> "$changes"
    tmutil destinationinfo | sed -n '1,6p'
    ;;
  exclude)
    shift
    for p in "$@"; do
      lab_sudo tmutil addexclusion -p "$p"
      echo "$p" >> "$excl"
    done
    ;;
  backup)
    lab_sudo tmutil startbackup --auto
    if [ "${2:-}" = "--wait" ]; then
      limit="${JANUS_LAB_BACKUP_TIMEOUT:-7200}"; waited=0
      sleep 10
      while tm_running && [ "$waited" -lt "$limit" ]; do
        printf '%s %s\n' "$(date +%T)" "$(tmutil status | grep -E 'BackupPhase|Percent' | head -2 | tr -d ' ;"' | tr '\n' ' ')"
        sleep 30; waited=$((waited + 30))
      done
      log show --last 15m --info --style compact --predicate 'subsystem == "com.apple.TimeMachine"' 2>/dev/null \
        | grep -E 'Successfully completed|Backup failed|BACKUP_FAILED' | tail -3 || true
    fi
    ;;
  status)
    tmutil status | grep -E 'Running|BackupPhase|Percent' | tr -d ';' || true
    JANUS_CLIENT_ADDR="$control" "$bin/janus-cli" client status 2>/dev/null | grep -E 'backlog|uploaded|errors' || true
    ;;
  cleanup)
    id="$(tmutil destinationinfo 2>/dev/null | awk '/^ID/ {print $NF}' | head -1)"
    [ -n "$id" ] && lab_sudo tmutil removedestination "$id" && echo "destination $id removed"
    keychain_clear
    if [ -f "$excl" ]; then
      while read -r p; do [ -n "$p" ] && lab_sudo tmutil removeexclusion -p "$p"; done < "$excl"
      rm -f "$excl"
    fi
    if [ "${2:-}" = "--snapshots" ]; then
      for d in $(tmutil listlocalsnapshotdates / | grep -E '^[0-9]{4}-'); do
        lab_sudo tmutil deletelocalsnapshots "$d" >/dev/null
      done
    fi
    echo "cleanup done; tmutil destinationinfo now says:"; tmutil destinationinfo 2>&1 | head -2
    ;;
  *) sed -n '2,14p' "$0" >&2; exit 2;;
esac

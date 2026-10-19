#!/usr/bin/env bash
# Check a finished backup from the guest: mount the share, attach the Time Machine
# sparsebundle read-only, compare the files of a data set with the newest backup, and
# restore one file with `tmutil restore`. Everything is detached again at the end.
#
#   guest-verify-restore.sh --dataset-sha FILE --subpath Users/user/tmdata [--file big/file1.bin]
#
#   --dataset-sha   hashes made by guest-dataset.sh (relative paths, "./big/file1.bin")
#   --subpath       where the data set sits inside the backed up volume (no leading slash)
#   --file          one file (relative to the data set) to restore with tmutil and compare
#
# Variables: JANUS_LAB_SMB_PASSWORD (required), JANUS_LAB_SMB_USER (janus),
# JANUS_LAB_SMB_ADDR (127.0.0.1:4455), JANUS_LAB_SHARE (backup), JANUS_LAB_SUDO_PASSWORD.
# The password must not contain characters that need URL encoding (/ @ : #).
#
# Notes: the newest backup is the folder named *.backup or, once Time Machine has finished
# and renamed it, *.previous. Two backups are snapshots of the same volume; the folder
# shows the state of the newest one. `hdiutil attach -nobrowse` keeps the volume out of
# Finder: that is fine here and avoids touching volumes the user has mounted.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

sha=""; sub=""; file=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dataset-sha) sha="$2"; shift 2;;
    --subpath) sub="$2"; shift 2;;
    --file) file="$2"; shift 2;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
[ -n "$sha" ] && [ -n "$sub" ] || { sed -n '2,12p' "$0" >&2; exit 2; }
lab_need JANUS_LAB_SMB_PASSWORD

user="${JANUS_LAB_SMB_USER:-janus}"
smb_addr="${JANUS_LAB_SMB_ADDR:-127.0.0.1:4455}"
share="${JANUS_LAB_SHARE:-backup}"
mnt="$LAB_DIR/mnt"
mkdir -p "$mnt"
volume=""

cleanup() {
  [ -n "$volume" ] && hdiutil detach -force "$volume" >/dev/null 2>&1 || true
  umount "$mnt" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mount_smbfs -N -o nobrowse "//$user:$JANUS_LAB_SMB_PASSWORD@$smb_addr/$share" "$mnt"
bundle="$(ls -d "$mnt"/*.sparsebundle | head -1)"
echo "bundle: $bundle"

# The line of `hdiutil attach` for the APFS volume ends with its mount point.
volume="$(hdiutil attach "$bundle" -nobrowse -readonly | awk -F'\t' '/\/Volumes\// {print $NF}' | tail -1)"
[ -n "$volume" ] || lab_die "attach failed"
echo "volume: $volume"
ls "$volume"

latest="$(ls -d "$volume"/*.backup "$volume"/*.previous 2>/dev/null | sort | tail -1)"
[ -n "$latest" ] || lab_die "no *.backup or *.previous folder in $volume"
echo "latest backup: $latest"
src="$latest/Data/$sub"
[ -d "$src" ] || lab_die "$src not found (check --subpath)"

(cd "$src" && find . -type f -exec shasum -a 256 {} + | sort -k2) > "$LAB_DIR/backup.sha"
if diff <(sort -k2 "$sha") <(sort -k2 "$LAB_DIR/backup.sha") >/dev/null; then
  echo "ALL $(wc -l < "$LAB_DIR/backup.sha" | tr -d ' ') FILES IDENTICAL to $sha"
else
  echo "DIFFERENCES between $sha and the backup:"
  diff <(sort -k2 "$sha") <(sort -k2 "$LAB_DIR/backup.sha") | head -10
  exit 1
fi

if [ -n "$file" ]; then
  out="$LAB_DIR/restored-$(basename "$file")"
  rm -f "$out"
  lab_sudo tmutil restore "$src/$file" "$out"
  got="$(shasum -a 256 "$out" | cut -d' ' -f1)"
  want="$(grep -F "./$file" "$sha" | cut -d' ' -f1)"
  [ "$got" = "$want" ] && echo "tmutil restore of $file: identical" || { echo "tmutil restore of $file: DIFFERENT"; exit 1; }
fi

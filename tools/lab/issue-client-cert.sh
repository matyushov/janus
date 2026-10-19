#!/usr/bin/env bash
# Issue a client certificate for one machine from an EXISTING janus CA, and prepare the
# receiver's machines.json entry for it. Runs on the machine that holds the CA key.
#
#   issue-client-cert.sh --ca-dir ~/janus-pki --out ./vm-mac-pki --machine vm-mac \
#                        [--days 30] [--machines-file ~/janus-pki/machines.json]
#
# Writes into --out: <machine>.key, <machine>.pem, ca.pem and, with --machines-file,
# machines.new.json (the given list plus the new machine; the original is not touched).
# The CA key is only read, never copied. Install machines.new.json on the receiver yourself
# (and restart it): see tools/lab/README.md.
set -euo pipefail

ca_dir=""; out=""; machine=""; days=30; machines_file=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ca-dir) ca_dir="$2"; shift 2;;
    --out) out="$2"; shift 2;;
    --machine) machine="$2"; shift 2;;
    --days) days="$2"; shift 2;;
    --machines-file) machines_file="$2"; shift 2;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
[ -n "$ca_dir" ] && [ -n "$out" ] && [ -n "$machine" ] || { sed -n '2,12p' "$0" >&2; exit 2; }
[ -f "$ca_dir/ca.pem" ] && [ -f "$ca_dir/ca.key" ] || { echo "no ca.pem/ca.key in $ca_dir" >&2; exit 1; }
case "$machine" in *[!A-Za-z0-9._-]*|"") echo "machine id: letters, digits, . _ - only" >&2; exit 2;; esac

# absolute paths: the script changes into --out
ca_dir="$(cd "$ca_dir" && pwd)"
if [ -n "$machines_file" ]; then
  [ -f "$machines_file" ] || { echo "no such file: $machines_file" >&2; exit 1; }
  machines_file="$(cd "$(dirname "$machines_file")" && pwd)/$(basename "$machines_file")"
  # refuse early, before anything is issued
  python3 -I - "$machines_file" "$machine" <<'EOF2'
import json, sys
path, machine = sys.argv[1:3]
if any(m["id"] == machine for m in json.load(open(path))["machines"]):
    sys.exit(f"machine {machine!r} is already in {path}")
EOF2
fi

umask 077
mkdir -p "$out"
cd "$out"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$machine.key" 2>/dev/null
openssl req -new -key "$machine.key" -subj "/CN=$machine" -out "$machine.csr"
printf 'extendedKeyUsage=clientAuth\n' > "$machine.ext"
openssl x509 -req -in "$machine.csr" -CA "$ca_dir/ca.pem" -CAkey "$ca_dir/ca.key" \
  -CAcreateserial -CAserial "$PWD/ca.srl" -sha256 -days "$days" -extfile "$machine.ext" \
  -out "$machine.pem" 2>/dev/null
rm -f "$machine.csr" "$machine.ext"
cp "$ca_dir/ca.pem" ca.pem

openssl verify -CAfile ca.pem "$machine.pem" >/dev/null
fp=$(openssl x509 -in "$machine.pem" -outform DER | openssl dgst -sha256 | awk '{print $NF}')
echo "machine:     $machine"
echo "fingerprint: $fp"
openssl x509 -in "$machine.pem" -noout -subject -enddate

if [ -n "$machines_file" ]; then
  python3 -I - "$machines_file" "$machine" "$fp" <<'EOF'
import json, sys
path, machine, fp = sys.argv[1:4]
data = json.load(open(path))
data["machines"].append({"id": machine, "fingerprint": fp, "store": machine, "quota_bytes": 0})
open("machines.new.json", "w").write(json.dumps(data, indent=1) + "\n")
EOF
  echo "wrote $PWD/machines.new.json (install it on the receiver, then restart janus-receiverd)"
else
  echo "machines.json entry: {\"id\":\"$machine\",\"fingerprint\":\"$fp\",\"store\":\"$machine\",\"quota_bytes\":0}"
fi

#!/usr/bin/env bash
# Throw-away PKI for running janus-receiverd in production mode (mTLS) by hand.
# DEVELOPMENT ONLY: keys are unencrypted, the CA lives next to them.
#
#   tools/dev-pki.sh <outdir> [machine-id ...]      (default machine: dev-mac)
#
# Creates in <outdir> (mode 0600 for keys):
#   ca.pem ca.key                 CA that signs both server and client certificates
#   server.pem server.key         server certificate for localhost / 127.0.0.1
#   <machine>.pem <machine>.key   client certificate per machine id
#   (env JANUS_DEV_SAN_EXTRA adds names to the server certificate, see below)
#   machines.json                 IdentityMap file (fingerprint -> machine -> store -> quota)
#
# Then:
#   JANUS_TLS_CERT=<outdir>/server.pem JANUS_TLS_KEY=<outdir>/server.key \
#   JANUS_TLS_CA=<outdir>/ca.pem JANUS_MACHINES=<outdir>/machines.json \
#   JANUS_STORE=<dir> janus-receiverd --listen 127.0.0.1:7443
# and configure the client with --ca <outdir>/ca.pem --client-cert <outdir>/<machine>.pem
# --client-key <outdir>/<machine>.key --endpoint 127.0.0.1:7443
set -euo pipefail

out="${1:?usage: dev-pki.sh <outdir> [machine-id ...]}"
shift || true
machines=("$@")
[ ${#machines[@]} -gt 0 ] || machines=(dev-mac)
quota="${JANUS_DEV_QUOTA:-0}"   # bytes per machine, 0 = default quota of the receiver

mkdir -p "$out"
umask 077
cd "$out"

genkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

genkey ca.key
openssl req -x509 -new -key ca.key -sha256 -days 30 -subj "/CN=janus dev CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.pem

issue() { # name, extension-file-content
  local name="$1" ext="$2"
  genkey "$name.key"
  openssl req -new -key "$name.key" -subj "/CN=$name" -out "$name.csr"
  printf '%s\n' "$ext" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 30 \
    -extfile "$name.ext" -out "$name.pem" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}

# JANUS_DEV_SAN_EXTRA="IP:192.168.1.5,DNS:host.local" adds names the server certificate is valid for
# (a receiver that other machines, such as a VM, reach over the network).
issue server "subjectAltName=DNS:localhost,IP:127.0.0.1${JANUS_DEV_SAN_EXTRA:+,$JANUS_DEV_SAN_EXTRA}
extendedKeyUsage=serverAuth"

fingerprint() { # SHA-256 of the DER certificate, lowercase hex
  openssl x509 -in "$1" -outform DER | openssl dgst -sha256 | awk '{print $NF}'
}

{
  echo '{"machines":['
  first=1
  for m in "${machines[@]}"; do
    issue "$m" "extendedKeyUsage=clientAuth"
    [ $first -eq 1 ] || echo ','
    first=0
    printf '  {"id":"%s","fingerprint":"%s","store":"%s","quota_bytes":%s}' \
      "$m" "$(fingerprint "$m.pem")" "$m" "$quota"
  done
  echo
  echo ']}'
} > machines.json
rm -f ca.srl
chmod 600 ./*.key machines.json
echo "PKI written to $out (machines: ${machines[*]})"

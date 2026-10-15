# janus-receiverd

The receiving side: gRPC (`BandTransport`) → files in a per-machine store.

## Modes

| | production (no flag) | `--dev` |
|---|---|---|
| transport | mTLS, **TLS 1.3 minimum**, client certificate required (rustls, `ring` provider) | plain gRPC, **no TLS** |
| identity | SHA-256 fingerprint of the client certificate → IdentityMap | none |
| stores | one subdirectory per machine below `JANUS_STORE` | one built-in store |
| quota | per machine (machines file, else `JANUS_QUOTA`) | `JANUS_QUOTA` |

Production start requires `JANUS_TLS_CERT`, `JANUS_TLS_KEY`, `JANUS_TLS_CA` and `JANUS_MACHINES`;
if any is missing the daemon names it and exits (it never falls back to plain gRPC). Key files
wider than 0600 only produce a warning. Private keys are never logged.

## Machine identity and the machines file

The identity of a machine is the **SHA-256 fingerprint of its client certificate (DER)**, not
a name inside it: a CA may sign any CN/SAN, but only the exact enrolled certificate maps to a
machine, and revoking a machine is deleting its line. Renewing a certificate means updating the
fingerprint (certificate rotation and CRLs are out of scope for now).

`JANUS_MACHINES` is a JSON file (mode 0600):

```json
{ "machines": [
  { "id": "alex-mbp",
    "fingerprint": "e2aa2c0e30fdd8c34a24c226ae12522af94e172a0280767e793176b19a563f04",
    "store": "alex-mbp",
    "quota_bytes": 107374182400 }
] }
```

- `fingerprint`: 64 hex digits (`:` separators and upper case accepted);
  `openssl x509 -in client.pem -outform DER | openssl dgst -sha256`
- `store`: one plain directory name below `JANUS_STORE` (no `/`, `..`, leading dot), unique;
  ids and fingerprints are unique too. A bad file fails the start.
- `quota_bytes`: optional; `0` = unlimited; omitted = `JANUS_QUOTA`.

Outcomes: a connection without a certificate, with one from another CA, or with TLS < 1.3 is
dropped during the handshake. A certificate signed by the CA but not listed reaches the
application and gets `PERMISSION_DENIED`. Each machine has its own worker (store root, quota,
usage cache); `StatFs` reports that machine's quota and usage; `janus-cli server machines`
lists the machines from the file with their usage and whether a worker is running.

Paths inside a store are validated again on the server (no `..`, absolute paths, `:`, backslash
or symlinks), independently of the client.

## Wire contract

`proto_rev` 2 (see `janus-proto/proto/janus.proto`). Rev 1 clients keep working: every rev-2
field defaults to the rev-1 behaviour. Fine-grained errors travel in the trailing metadata key
`janus-error`. `WriteRange`/`ReadRange` are limited to 1 MiB per call.

## Running by hand

```sh
tools/dev-pki.sh /tmp/janus-pki alpha beta          # throw-away CA, server + client certs, machines.json
JANUS_TLS_CERT=/tmp/janus-pki/server.pem JANUS_TLS_KEY=/tmp/janus-pki/server.key \
JANUS_TLS_CA=/tmp/janus-pki/ca.pem JANUS_MACHINES=/tmp/janus-pki/machines.json \
JANUS_STORE=/tmp/janus-stores janus-receiverd --listen 127.0.0.1:7443
```

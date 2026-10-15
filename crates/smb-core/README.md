# smb-core

The janus SMB server core. State as of J1: **SMB 3.1.1 (the only dialect), SESSION_SETUP
(SPNEGO/NTLMv2), mandatory AES-128-CMAC signing, TREE_CONNECT / TREE_DISCONNECT /
LOGOFF / ECHO, credits**, plus a virtual empty share root so that macOS can mount the share.
File commands (READ/WRITE/…) return a signed `STATUS_NOT_IMPLEMENTED`; the file model is J2.

## Guarantees

- Only dialect 3.1.1. A client without it gets `STATUS_NOT_SUPPORTED`; one without
  PREAUTH_INTEGRITY (SHA-512) gets `STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP`. The SMB1
  multi-protocol NEGOTIATE ("SMB 2.???") that macOS starts with is answered with a wildcard
  reply, 0x02FF (MS-SMB2 §3.3.5.3.1); SMB1 itself is not served.
- Signing is mandatory: after SESSION_SETUP, frames without a valid signature get
  `STATUS_ACCESS_DENIED` (the command is not executed), all replies are signed, and every
  element of a compound chain is signed.
- There is no guest access. Without credentials, logon is impossible. The reason for a failed
  logon is never disclosed to the client (`STATUS_LOGON_FAILURE`); 3 failures on a connection
  drop it; an unfinished authentication lives 30 s; at most 4 may be in flight per connection.
- Encryption is not enabled (ENCRYPTION_CAPABILITIES is parsed but unused);
  multichannel/session binding is not supported (`STATUS_INVALID_PARAMETER`).

## Credentials

`janus-smbd` takes a single login/password pair (see `janus_lib::credentials`):

1. dev: `JANUS_SMB_USER` + `JANUS_SMB_PASSWORD`;
2. otherwise the file `JANUS_SMB_CREDS_FILE` or `~/.config/janus/smb-credentials`
   (`user:password`, mode 0600). If there is no pair, `janus-cli client configure` creates a
   random one (user `janus`, a 128-bit password in hex).

## Tests

```
cargo test -p smb-wire -p smb-core
```

- Microsoft vectors (`smb_wire::ms_vectors`, taken from the publication "SMB 2 and SMB 3
  security in Windows 10: the anatomy of signing and cryptographic keys"): the preauth hash
  chain, SessionKey → SigningKey, the signature of a real SESSION_SETUP reply, a real NTLM
  exchange (NTProofStr, ExportedSessionKey, MIC), plus RFC 4493 (AES-CMAC).
- `src/dispatch.rs`: the dispatcher's transition table, driven by the `smb_wire::testclient`
  client (an NTLM client, frame builders, an independent derivation of the signing key).
- `tests/handshake.rs`: the **end-to-end test**: real TCP + `DevServer` + the same scripted
  client: NEGOTIATE → SESSION_SETUP ×2 → signed TREE_CONNECT/ECHO/TREE_DISCONNECT/LOGOFF,
  a macOS-style start (SMB1 wildcard), a wrong password, an unsigned request, a client
  without 3.1.1.

## Manual run with a macOS client

```
cargo build -p janus-smbd -p janus-cli
JANUS_SMB_TRACE=1 JANUS_SMB_USER=janus JANUS_SMB_PASSWORD='…' \
JANUS_SMB_ADDR=127.0.0.1:4445 JANUS_CLIENT_ADDR=127.0.0.1:50061 \
  target/debug/janus-smbd --dev                      # in one terminal

mkdir -p /tmp/janus-mnt
mount_smbfs -N -o nobrowse '//janus:…@127.0.0.1:4445/backup' /tmp/janus-mnt
smbutil statshares -a
JANUS_CLIENT_ADDR=127.0.0.1:50061 target/debug/janus-cli client shutdown
```

`JANUS_SMB_TRACE=1` prints every command and the reply status (no secrets); `=2` also dumps
the request hex. If the client drops the connection, use
`sudo tcpdump -i lo0 port 4445 -w janus.pcap` and Wireshark.

Result (macOS, `mount_smbfs`): SMB1 wildcard → NEGOTIATE 3.1.1 → NTLMv2 (with MIC) →
signed TREE_CONNECT → a compound CREATE(root) + QUERY_INFO + CLOSE → **the mount succeeds**:
`mount` shows `//janus@127.0.0.1:4445/backup (smbfs…)`, `smbutil statshares -a` shows
`SMB_VERSION SMB_3.1.1`, `SMB_CURR_SIGN_ALGORITHM AES_128_CMAC`, `SMB_CURR_ENCRYPT_ALGORITHM
OFF`, and `df` shows 1.0 TiB (the share quota, 1 TiB by default). `ls` gives an empty
directory, `touch` gives "Operation not supported" (the file model is J2).

## Virtual root (J1-lite)

So that a client can mount the share, only its root is served, as an empty directory:
CREATE of the empty path (OPEN/OPEN_IF; the MxAc context), QUERY_INFO
(FileFs{Volume,Size,Device,Attribute,FullSize}, File{Basic,Standard,Internal,All,NetworkOpen}),
QUERY_DIRECTORY (`NO_SUCH_FILE`, then `NO_MORE_FILES`) and CLOSE; related operations in a
compound inherit the FileId and the error of the previous one. CREATE of any other path:
OPEN → `OBJECT_NAME_NOT_FOUND`, creation → `NOT_IMPLEMENTED`; READ/WRITE/FLUSH/IOCTL/… →
`NOT_IMPLEMENTED`.

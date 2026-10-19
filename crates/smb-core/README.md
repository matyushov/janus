# smb-core

The janus SMB server core. State as of J2: **SMB 3.1.1 (the only dialect), SESSION_SETUP
(SPNEGO/NTLMv2), mandatory AES-128-CMAC signing, TREE_CONNECT / TREE_DISCONNECT /
LOGOFF / ECHO, credits**, and the **file model** on top of `janus_lib::vfs::StorageBackend`:
CREATE (files and directories, all dispositions), CLOSE, READ, WRITE, FLUSH, QUERY_INFO,
QUERY_DIRECTORY and SET_INFO. LOCK, CHANGE_NOTIFY, CANCEL and OPLOCK_BREAK return a signed
`STATUS_NOT_IMPLEMENTED`, IOCTL `STATUS_NOT_SUPPORTED`.

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

`janus-smbd` serves the share from the receiver (`GrpcBackend` over mTLS), configured with
`janus-cli client configure`. For a run without a receiver set `JANUS_SMB_LOCAL_ROOT=<dir>` to
serve a plain local folder instead (dev only).

Result (macOS, `mount_smbfs`): SMB1 wildcard → NEGOTIATE 3.1.1 → NTLMv2 (with MIC) →
signed TREE_CONNECT → **the mount succeeds**: `smbutil statshares -a` shows
`SMB_VERSION SMB_3.1.1`, `SMB_CURR_SIGN_ALGORITHM AES_128_CMAC`, `SMB_CURR_ENCRYPT_ALGORITHM
OFF`, and `df` shows the share quota (1 TiB by default). `touch`, `echo > f`, `cp` in both
directions, `mv`, `mkdir`, `rm` and `rm -r` work; a 5 MB file copied onto the share and back
has the same SHA-256 on the client, in the mount and in the share directory.

## File model (J2)

- `files.rs` holds one handler per command; `dispatch.rs` decodes, resolves the FileId
  (related compound operations inherit the FileId of the CREATE) and signs the reply. The
  dispatcher is generic over `B: StorageBackend` and `async`; the tests drive it without sockets.
- Opens live in the session table (`session::Open`); the SMB FileId is `(n, n)`. TREE_DISCONNECT,
  LOGOFF and the end of the TCP connection close every backend handle that is still open, so a
  delete-on-close file does not outlive a dead client.
- QUERY_DIRECTORY snapshots the listing when the scan starts (`.` and `..` first), filters it
  with the SMB wildcard rules (`*`, `?`, and the DOS `<` `>` `"`; case-sensitivity from
  `CompatCaps`), and returns as many entries as fit the client's buffer. Classes: Directory,
  FullDirectory, BothDirectory, Names, IdBothDirectory, IdFullDirectory.
- Only a failed CREATE poisons the rest of a related chain (MS-SMB2 §3.3.5.2.7.2); a failed
  QUERY_DIRECTORY or SET_INFO still lets the trailing CLOSE run.
- Backend errors map to NTSTATUS in `files::status_of`; `NoSpace` → `STATUS_DISK_FULL`.
- FileFsSizeInformation comes from `StorageBackend::statfs` (quota and usage).
- READ/WRITE are limited to 64 KiB (no LARGE_MTU yet); the channel fields (RDMA) must be 0.

Known gaps: no LOCK (macOS sends an exclusive whole-file `LOCK` with FAIL_IMMEDIATELY after
every open and diskimages sends it for the bundle's `lock` file; both cope with
NOT_IMPLEMENTED, checked with a real Time Machine backup), no CHANGE_NOTIFY, no
`FileRenameInformationEx`, other opens under a renamed directory keep their old path, no
STATUS_DELETE_PENDING for new opens of a file marked for deletion, SET_INFO of security and
file attributes (read-only, hidden) is not applied.

## Time Machine support (J4)

Checked with a real `backupd` (macOS 26): a full backup completes, files restore byte for byte,
and killing the daemon in the middle of a backup does not break it. The lab scripts are in
`tools/lab/`.

- **AAPL** (`apple.rs`): the server query on CREATE is answered with `FULL_SYNC | CASE_SENSITIVE` in
  the *volume* capabilities (`tmutil` refuses the share without FULL_SYNC), server capabilities 0,
  model string. Profile driven (`CompatCaps`), no OS branching.
- **Durable handles V2 and lease V2** (`shared.rs`, `session.rs`, `files.rs`): `DH2Q`/`DH2C`/`RqLs`
  (v1 and v2). The NEGOTIATE reply advertises `LEASING` for the Time Machine profile only (without
  it the kernel answers ENOTSUP; persistent handles or directory leasing make the client drop the
  connection, so they are not advertised). A durable handle is granted only together with a lease
  that has H. When the connection drops it is parked and reclaimed with DH2C by the same user and
  ClientGuid within the timeout (0 asks for the 60 s default, capped at 300 s). Durable opens are
  persisted when granted, with a once-a-second heartbeat, in `parked-handles.json` next to the
  journal, so a reconnect also works after a daemon restart or `kill -9` (the file is reopened by
  path; the deadline is the last heartbeat plus the timeout).
- **Lease breaks**: a conflicting open (data access under another lease key) breaks the holder's lease;
  the holder gets an unsolicited LEASE_BREAK and the opener waits for the acknowledgment, forced after
  35 s. If the holder is the opener's own connection the opener does not wait (the ack could only
  arrive on the blocked connection); a lease of a parked handle gives way at once.
- **`F_FULLFSYNC`** is FLUSH with `Reserved1 = 0xffff`; plain and full flushes both wait for a real fsync.
- Request trace: `JANUS_SMB_TRACE=2` dumps every request (WRITE payload cut off);
  `tools/smb-trace-summary.py` summarises it.

Not done: a CREATE does not wait for a receiver that is down (it fails at once, and a backup image
does not survive that); no byte-range locks; share modes are not enforced.

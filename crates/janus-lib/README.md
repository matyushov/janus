# janus-lib

The client side outside the SMB protocol: the storage abstraction (`vfs::StorageBackend` and its
backends) and the control layer (`control`, `config`, `remote`).

## Backends (cargo features)

| Feature | Type | Notes |
|---|---|---|
| `backend-local` (default) | `LocalFsBackend` | a local folder; the behavioural reference |
| `backend-grpc` | `GrpcBackend`, `SwitchBackend` | the own `janus-receiverd` over gRPC/mTLS |
| `backend-s3` | skeleton | not built by default |

`tests/backend_contract.rs` runs one set of assertions against `LocalFsBackend` and
`GrpcBackend` (against a real receiver on loopback).

### `GrpcBackend` without the journal: sync-through (J3a)

(`journal.enabled = false`; the journal mode is described in the next section.)

**Every operation goes to the receiver immediately.** There is no local journal, uploader or read
overlay. Consequences, on purpose:

- the latency of an SMB reply equals the round trip to the receiver (plus its disk);
- `flush` (also `F_FULLFSYNC`) is an end-to-end `Fsync` on the receiver, so it is honest;
- while the receiver is unreachable, operations fail with `RemoteUnavailable`
  (SMB `STATUS_UNEXPECTED_NETWORK_ERROR`, never "not found"); nothing is buffered;

Handles live on the client (`handle → current path, kind, flags`); the receiver sees paths only,
so every write is idempotent (by offset). Writes and reads are cut into pieces of at most 1 MiB;
`write_id` is monotonic. Only idempotent calls (reads, stat, list, `WriteRange`, `Fsync`,
truncate, set-times) are retried, 3 attempts with backoff, and only on transport failure.
Exclusive create, rename and delete-on-close are never retried.

### `GrpcBackend` with the journal (J3b, the default)

Writes are appended to a local write-ahead journal and acknowledged at once; an uploader sends
them to the receiver in the background (4 concurrent `WriteRange`s of up to 1 MiB). The journal
exists for **speed** (no round trip per write) and to **smooth over short outages** (a receiver
frozen for tens of seconds does not abort a copy). It must **not hide a long outage**: Time
Machine must not think a backup is done while the data exists only on the laptop.

- **Limit by backlog, not by time.** At most `max_backlog_bytes` (default 1 GiB) of unuploaded
  data. At the limit a write waits for the uploader (backpressure) for the operation budget, then
  fails with `RemoteUnavailable` (`UNEXPECTED_NETWORK_ERROR`). It is never `DISK_FULL`: that
  means the receiver is out of quota, and is returned at once when
  `receiver used + backlog + write > quota` (from a cached `statfs`), so Time Machine gets its
  thinning signal while it writes.
- **Honest fsync (`SYNC_THROUGH`).** `flush` / `F_FULLFSYNC` and the close of a file with
  unuploaded data wait until the data reached the receiver and was fsynced there. If the receiver
  is unreachable for longer than the barrier budget (26 s) they fail (the backup aborts and is retried
  in the next cycle); they never report a false success.
- **`LOCAL_JOURNAL` (off by default, UNSAFE for backups).** `flush` returns after an fsync of the
  journal; the network catches up later. A lost laptop or disk means lost "durable" data, and Time
  Machine will believe a backup exists that the server does not have.
- **Read-your-writes.** `read`, `stat` and listings overlay the unuploaded bytes on the
  receiver's data (holes between them read as zeros, like a sparse file); `statfs` counts the
  journal.
- **Metadata stays synchronous** (create, rename, delete, truncate, set-times) and is ordered
  after the data of the files it touches: rename, set-times and `truncate(n>0)` wait for the
  file's upload first; delete, `truncate(0)` and an overwriting open discard the unuploaded bytes
  (durably, with a `Drop` record) after waiting for batches already on the wire. Because of this
  a listing or `stat` needs the receiver: while it is frozen they fail rather than guess.
- **Errors.** Transient ones (transport, timeout) pause the uploader with an exponential
  backoff; the journal grows up to the limit. Permanent ones (no space, access denied) become the
  *sticky* error of that file: returned by its next flush/close and shown in `status`, and
  cleared by a new write to it (so retrying after Time Machine freed space works).
- **Crash safety.** Every record has a CRC. After `kill -9` the next start replays everything the
  receiver has not acknowledged (above the stored watermark), cuts a torn tail and continues;
  `WriteRange` is idempotent so a replay of what had already arrived changes nothing. A file that
  was deleted or renamed meanwhile is not resurrected. A graceful `shutdown --drain` waits for
  the journal to empty (and refuses to stop while it cannot); without `--drain` the journal stays
  on disk and is uploaded at the next start.
- **Reconfigure.** `Configure` with the same journal directory keeps the running journal and
  points the uploader at the new link.
- **Where.** `<state-dir>/journal` (`~/.config/janus/journal`) with mode 0700, files 0600; on
  macOS it is excluded from Time Machine (`tmutil addexclusion`, best effort). Segments are
  ~64 MiB. **Known limit: the journal holds user data unencrypted**; protection is the file
  permissions only.

Configuration (`janus-cli client configure`): `--journal on|off`, `--journal-dir <path>`,
`--max-backlog <MiB>`, `--flush-policy sync-through|local-journal`.
`janus-cli client status` shows the backlog, the age of the oldest unuploaded record, the last
upload error and the time of the last acknowledgement; `drain` waits for an empty journal.

#### Time limits (`remote::Timeouts`)

A frozen receiver (TCP alive, no replies) must not hold an SMB request longer than the macOS
client is willing to wait (`max_resp_timeout`, 30 s by default). The limits are therefore one
shared deadline per backend operation, not "timeout x attempts":

| Limit | Default | Why |
|---|---|---|
| operation budget | 18 s | all attempts and backoff of one operation; leaves ~12 s of margin to 30 s |
| barrier (journal mode) | 26 s | how long a flush / close of a file with unuploaded data waits for the receiver; it is what absorbs a receiver frozen for ~20 s, and still ends 4 s before the client gives up |
| request attempt | 6 s | far above a healthy RTT + disk fsync, short enough for 2-3 attempts |
| bulk attempt (`ReadRange`/`WriteRange`) | 10 s | up to 1 MiB per call on a slow link; still < budget |
| connect | 4 s | an unreachable host must not eat the budget |
| HTTP/2 keepalive | ping every 5 s, ack within 3 s, also while idle | a stopped peer is detected in <= 8 s and its dead connection is dropped, so the next attempt reconnects |

Every attempt is capped by `min(attempt limit, time left)`; a retry starts only if the backoff
plus 0.5 s still fit into what is left. A timeout counts as a transport failure
(`RemoteUnavailable`), retried only for idempotent calls. Operations made of several RPCs
(`open`, multi-chunk `read`/`write`) are bounded as a whole by the same budget; a reply that
arrives after that is discarded. Keepalive pings are cheap and only flow while a connection
exists (the channel is still lazy). The values live in named constants in `remote.rs` and
can be overridden through `RemoteConfig::timeouts` (tests scale them to milliseconds).

**Degraded mode.** The macOS client retries a failed WRITE (and probes extended attributes) in a
loop, so with a frozen receiver each retry would cost another full budget (measured: `cp` stayed
blocked ~70 s although every single reply came after 18 s). Therefore, after a call has timed
out, the backend is "degraded": calls fail immediately for 2 s (`fail_fast`), then one call is
let through as a single 2 s probe (`degraded_probe`, no retries). The first success restores
normal operation, so a resumed receiver is picked up within ~2 s without restarting anything.
Only timeouts set the flag; a refused connection or an `UNAVAILABLE` from a live receiver
already fails quickly and does not.

Error mapping: `RESOURCE_EXHAUSTED` → `NoSpace` (SMB `STATUS_DISK_FULL`, the signal Time Machine
thins backups on); `PERMISSION_DENIED`/`UNAUTHENTICATED` → `AccessDenied`; transport failures,
deadlines and TLS refusals → `RemoteUnavailable`; the `janus-error` trailer refines
`PathNotFound`, `NotADirectory`, `IsADirectory`, `DirectoryNotEmpty`.

#### Documented differences between the two backends

- `LocalFsBackend` reports a quota but does not enforce it; the receiver does (`NoSpace`).
- When the receiver has no quota (0), `statfs` reports the configured `quota_bytes`, else 1 TiB.
- Writing through a handle opened without write access fails in both, but as `Io` in
  `LocalFsBackend` and `AccessDenied` in `GrpcBackend`.
- `close` of a delete-on-close handle fails with `RemoteUnavailable` if the receiver is down; the
  handle is gone and the file stays (the journal of J3b will own such retries).
- Setting times on a directory is accepted and ignored in both.

### `SwitchBackend`

What `janus-smbd` serves the share with. `Configure` installs a new `GrpcBackend` into it
without a restart; handles issued before keep using the backend they came from until closed.
Before the first `Configure` every operation fails with `RemoteUnavailable`.

## Configuration (`config`)

`Configure` is the source of truth; the persisted file lets the daemon come back after a restart
without waiting for the agent.

- Location: `JANUS_CONFIG`, else `~/.config/janus/config`.
- Format: **JSON** (`{"version":1,"share":{…}}`), machine-written. Chosen over TOML because the
  data already has a JSON-shaped contract, the dependency (`serde_json`) is tiny and pure Rust,
  and nobody edits the file by hand. Unknown fields are ignored and missing ones default, so
  neighbouring versions can read each other's files; a newer `version` is refused.
- Write: validate → temp file in the same directory → `fsync` → `rename` → (unix) directory
  `fsync`, mode `0600`, then publish in memory. A rejected config changes nothing.
- A missing file is not an error (first start); a corrupt one is (the daemon refuses to guess).
- Secrets are references or paths only (`smb_password_ref`, key file paths), never values; the CA
  certificate is public and stored inline.

## Transport security (`remote`)

With `ca_pem` + `client_cert_path` + `client_key_path` the channel is mTLS (rustls, `ring`
provider; the receiver requires TLS 1.3 and a client certificate from its CA). With none of the
three it is plain gRPC (the `--dev` receiver). A partial set, `https://` without material, or
`http://` with it is a configuration error, never a silent downgrade. The server name is checked
against the host in the endpoint, so the endpoint must be a name or IP present in the server
certificate's SAN. `tls_identity_ref` (Keychain) is not implemented yet.

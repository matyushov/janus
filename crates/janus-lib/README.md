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

### `GrpcBackend` in J3a: sync-through

**Every operation goes to the receiver immediately.** There is no local journal, uploader or read
overlay yet (J3b). Consequences, on purpose:

- the latency of an SMB reply equals the round trip to the receiver (plus its disk);
- `flush` (also `F_FULLFSYNC`) is an end-to-end `Fsync` on the receiver, so it is honest;
- while the receiver is unreachable, operations fail with `RemoteUnavailable`
  (SMB `STATUS_UNEXPECTED_NETWORK_ERROR`, never "not found"); nothing is buffered;
- `FlushPolicy::LocalJournal` is refused by `Configure` ("not supported yet").

Handles live on the client (`handle → current path, kind, flags`); the receiver sees paths only,
so every write is idempotent (by offset). Writes and reads are cut into pieces of at most 1 MiB;
`write_id` is monotonic. Only idempotent calls (reads, stat, list, `WriteRange`, `Fsync`,
truncate, set-times) are retried, 3 attempts with backoff, and only on transport failure.
Exclusive create, rename and delete-on-close are never retried.

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

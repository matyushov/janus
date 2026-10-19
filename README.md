# janus

**A secure transport pair: an SMB client ↔ an arbitrary storage, with no Samba and no kext.**

The job of janus is to give any SMB client a local share on `127.0.0.1` and to redirect everything the
client writes into it to the chosen storage backend **over a secure channel**. SMB terminates
on loopback and never leaves the machine; only the backend transport goes onto the network (mTLS-gRPC or direct S3).
The client sees an ordinary local disk and the storage sees a controlled stream; our code sits between them.
The name: Janus, the two-faced god of doors: one face looks at the SMB client, the other at the storage.

**The first supported mode is macOS Time Machine** (`backupd` writes a sparsebundle into the local
share → janus carries it into the storage): this is the most demanding SMB client, and the Apple semantics
(AAPL, F_FULLFSYNC, durable handles V2, lease V2) that no open non-GPL SMB server has are
implemented specifically for it. But the model is wider than TM: the same transport layer serves
Windows and Linux clients (profiles below) and arbitrary backends (Features below). TM is a mode,
not the purpose of the project.

## Main modules

| Crate | What it is |
|---|---|
| `smb-wire` | the SMB2/3 codec: bytes ↔ types, crypto primitives, NTLMSSP. Zero I/O and no state |
| `smb-core` | the server core: connections, sessions, durable handles V2, lease V2, AAPL/F_FULLFSYNC |
| `janus-lib` | the client side: `StorageBackend` (storage backends), the sparsebundle model, the WAL journal, the uploader, the control plane |
| `janus-proto` | the protobuf contract (band transport + control plane), tonic/prost |
| `janus-smbd` | the SMB daemon binary (foreground `--dev` / launchd socket activation) |
| `janus-cli` | the CLI for managing the daemons: `janus-cli smbd …` and `janus-cli receiver …` |
| `janus-receiverd` | an optional receiving server (gRPC/mTLS → files) for your own storage |

**Topology.** The SMB server (`janus-smbd`) is always on the client side, on loopback. What stands behind
the share is determined by the **backend** (`StorageBackend`); there are several (see Features): the own
receiver `janus-receiverd`, a local folder, S3. Janus identifies the client by mTLS; the share host is
fixed (`127.0.0.1`), only the port and the share name vary (set through `configure`).

## Client compatibility (profiles)

The profile is set per share (`Configure.profile`); the core branches only on capabilities
(`CompatCaps`), not on "platforms". Invariants for all: dialect **3.1.1 only**
(this removes FSCTL_VALIDATE_NEGOTIATE_INFO), **signing is mandatory**, NTLM with no guest access.

| Profile | Client | Specifics | Status |
|---|---|---|---|
| `TIME_MACHINE` | macOS `backupd` | case-sensitive, AAPL, F_FULLFSYNC, durable V2 + lease V2 | **first target** |
| `WINDOWS_GENERIC` | Explorer / robocopy / wbadmin / File History | case-insensitive lookup, no AAPL, "empty" replies to ADS/SD probes | roadmap |
| `POSIX_GENERIC` | Linux `cifs.ko` / smbclient | case-sensitive, SMB 3.1.1 POSIX extensions (optional), symlinks | roadmap |

Server platforms: macOS (loopback topology), Linux/FreeBSD. Windows as a server is not a target
(445 is taken by the system LanmanServer).

## Features (storage backends)

What stands behind the SMB share is a choice of implementation of the `StorageBackend` trait in `janus-lib`. The backends
are enabled by cargo features so that the main build does not pull in unneeded dependencies.

| Feature | Backend | Where it writes | Status |
|---|---|---|---|
| `backend-local` | `LocalFsBackend` | a local folder | dev/tests |
| `backend-grpc` | `GrpcBackend` | the own `janus-receiverd` over gRPC/mTLS | write-ahead journal + background upload (J3b, default); sync-through with `--journal off` |
| `backend-s3` | `S3Backend` | **any S3-compatible bucket** (AWS S3, MinIO, R2, B2, Wasabi, Ceph) | planned |

### `backend-s3`: direct upload to S3 (planned)

The final consumer is **any S3 bucket**, and `janus-receiverd` is not needed: `janus-smbd`
is itself the bucket's client. It is built on the official `aws-sdk-s3` (async/tokio, works with
any S3-compatible endpoint via `endpoint_url`; Apache-2.0/MIT license).

Architecturally it fits in without rework: `S3Backend` is one more implementation of the same `StorageBackend`
trait, next to the gRPC and local backends. The non-trivial part is the **write semantics**:
SMB issues offset writes into band files, while an S3 object is atomic (no partial overwrite). Our
WAL journal and uploader (already designed) cover this: offset writes accumulate in the journal,
and the uploader uploads bands/chunks as objects in batches (`PutObject`/multipart). The mapping fork
"band = object / chunk = object" is an open question in the S3 backend design.

## Build

```
cargo build --workspace     # protoc is NOT needed: janus-proto pulls protoc-bin-vendored
cargo test  --workspace
```

The toolchain is pinned in `rust-toolchain.toml`. CI (GitHub Actions, `.github/workflows/ci.yml`):
fmt + clippy (`-D warnings`) on Linux, build+test on Linux and Windows.

**Dev run:**
```
janus-smbd --dev                       # a foreground SMB server on 127.0.0.1
janus-cli smbd configure --endpoint … --client-cert … --client-key … --ca … [--port N] [--share NAME]
```

## Implementation status

J1 is done: SMB 3.1.1 (the only dialect, signing mandatory), NEGOTIATE with preauth
integrity, SESSION_SETUP over SPNEGO/NTLMv2, TREE_CONNECT/TREE_DISCONNECT/LOGOFF/ECHO,
credits. J2 is done: the file model (CREATE, CLOSE, READ, WRITE, FLUSH, QUERY_INFO,
QUERY_DIRECTORY, SET_INFO) over `StorageBackend`, with `LocalFsBackend` as the first backend; a
real macOS client (`mount_smbfs`) mounts the share, copies files both ways and the hashes
match (details and the run are in `crates/smb-core/README.md`). J3 is done: `GrpcBackend` over mTLS,
the write-ahead journal with background upload, interim STATUS_PENDING for slow operations.
J4 is implemented: Time Machine (`backupd`) completes a backup through the share (AAPL, durable and
lease V2, `F_FULLFSYNC`, Bonjour); see `crates/smb-core/README.md` and the lab scripts in `tools/lab/`.
Business logic marked `todo!()` (S3 backend, launchd socket activation, event broadcast) is tied to the
architecture sections below.

## License

MIT. See [LICENSE](LICENSE).

---

# Architecture (how the modules are built)

> The detailed structure of every module: types, state tables, state machines, flows.
> UML is in Mermaid (classDiagram / stateDiagram / sequenceDiagram). The status is a design model;
> type boundaries may shift after the PoC (the `backupd` trace, the audit of the `smb-rs` donor).


## Layer 2: SMB termination (`smb-wire` + `smb-core`)

The watershed between the two crates: **`smb-wire` is bytes ↔ types, zero I/O,
zero long-lived state; `smb-core` is all protocol state and I/O.** If a type describes
"what is in the packet", it is in wire; if "what we remember between packets", it is in core.

### 2.1. `smb-wire`: the codec

> **Why the types say "SMB2" when we need SMB3:** "SMB3" is not a separate protocol but the later
> **dialects** of the SMB2 protocol (0x0300/0x0302/0x0311), negotiated in NEGOTIATE; the frame format and
> the command set are the same SMB2 (the MS spec is itself titled *"[MS-SMB2]: … Versions 2 and 3"*,
> and the Apple extension is "SMB2 FLUSH with Reserved1=0xFFFF"). The "threeness" lives not in structures
> but in the plumbing: preauth SHA-512, SP800-108 keys, AES-CMAC signing, the encryption transform header,
> which for us is `crypto` + `ConnState.dialect(3.1.1)`. A separate protocol is only the legacy SMB1/CIFS
> (a different frame format), which we do not implement at all.

**Responsibilities:** parsing/serialization of SMB2 frames and all structures, crypto primitives
(signature/hash/key derivation) as pure functions, NTLMSSP/SPNEGO tokens.
**NOT responsibilities:** sockets, tokio, session tables, timers, decisions of "what to answer".

```mermaid
classDiagram
    direction TB

    class Frame {
        <<enum>>
        Plain(Smb2Message)
        Encrypted(TransformHeader, bytes)
        +decode(bytes) Result~Frame~
        +encode() bytes
    }

    class Smb2Header {
        +command: Command
        +flags: HeaderFlags
        +message_id: u64
        +session_id: u64
        +tree_id: u32
        +credit_charge: u16
        +credit_request: u16
        +async_id: Option~u64~
        +signature: [u8;16]
    }

    class Smb2Message {
        +header: Smb2Header
        +body: MessageBody
        +next_compound: Option~Smb2Message~
    }

    class MessageBody {
        <<enum>>
        Negotiate(NegotiateReq/Resp)
        SessionSetup(SessionSetupReq/Resp)
        TreeConnect(...)
        Create(CreateReq/Resp)
        Read / Write / Flush / Close
        QueryDirectory / QueryInfo / SetInfo
        Lock / Ioctl / ChangeNotify / Echo
        LeaseBreakNotify / LeaseBreakAck
        OplockBreak
    }

    class CreateReq {
        +path: SmbPath
        +desired_access: AccessMask
        +create_disposition: Disposition
        +contexts: Vec~CreateContext~
    }

    class CreateContext {
        <<enum>>
        DurableHandleRequestV2(timeout, flags, create_guid)
        DurableHandleReconnectV2(file_id, create_guid, flags)
        LeaseV2Request(lease_key, lease_state, epoch)
        Aapl(AaplContext)
        QueryMaximalAccess
        Unknown(tag, bytes)
    }

    class AaplContext {
        +command: ServerQuery|ResolveId
        +caps: AAPL_CAPS  // kAAPL_SUPPORTS_FULL_SYNC=0x04
        +volume_caps: u64
        +model_string: String
    }

    class crypto {
        <<module>>
        +preauth_chain(prev_hash, frame_bytes) [u8;64]  // SHA-512
        +derive_key(session_key, label, context) [u8;16] // SP800-108-CTR
        +sign_cmac(key, frame) [u8;16]                   // AES-CMAC (3.x)
        +verify(key, frame) bool
    }

    class auth {
        <<module>>
        +SpnegoToken: parse/build
        +NtlmsspNegotiate / Challenge / Authenticate
        +session_key(exchange) [u8;16]   // server-side NTLMv2 (ntlm.rs); sspi evaluated and rejected
    }

    class WireError {
        <<enum>>
        Truncated
        BadMagic
        UnknownCommand(u16)
        BadContext(tag)
    }

    Frame --> Smb2Message
    Smb2Message --> Smb2Header
    Smb2Message --> MessageBody
    MessageBody --> CreateReq
    CreateReq --> CreateContext
    CreateContext --> AaplContext
```

**Key decisions:**
- `Frame::decode` is **total**: any byte input gives `Ok` or a typed `WireError`,
  a panic is unacceptable (fuzzing is a mandatory CI stage of this crate; the corpus is the backupd trace from the PoC).
- `CreateContext::Unknown(tag, bytes)`: unknown contexts are **preserved and pass through**,
  not dropped: the Apple client sends contexts that are absent from MS-SMB2, and CREATE must not fail.
- A compound chain (`next_compound`) is parsed in wire (that is the format) and executed in core
  (that is the related/unrelated semantics).
- `crypto`/`auth` are pure functions over bytes; state (which hash is accumulated, which NTLM leg) is in core.
- If the `smb-rs` donor is confirmed: the `Smb2Header`/`MessageBody` structures are candidates to be replaced
  by the `smb-msg`/`smb-dtyp`/`smb-fscc` types; the server-side Create contexts (the durable/lease/AAPL
  **response** side) we will almost certainly write ourselves.

---

### 2.2. `smb-core`: structure (actors and tables)

The execution model is **tokio, an actor per TCP connection** + shared tables. Everything that has to
outlive a connection (durable handles, leases, sessions) lives NOT in the actor but in the
`ServerShared` tables; the actor holds only the link and per-connection state.

```mermaid
classDiagram
    direction TB

    class Server {
        +run(listeners: Vec~TcpListener~, shared)
        // sockets come from launchd (socket activation)
    }

    class ConnectionActor {
        <<tokio task>>
        +conn_state: ConnState
        +outbound_tx: mpsc::Sender~Frame~
        -read_loop()
        -write_loop()   // a separate task: only it writes to the socket
        -dispatch(msg)
    }

    class ConnState {
        +dialect: Dialect        // 3.1.1
        +preauth_hash: [u8;64]
        +credits: CreditWindow
        +pending_async: AsyncOpRegistry
    }

    class ServerShared {
        <<Arc>>
        +sessions: SessionTable
        +opens: OpenTable
        +leases: LeaseTable
        +parked: DurableParkRegistry
        +backend: Arc~dyn StorageBackend~
        +events: EventBus
        +config: ArcSwap~ShareConfig~
    }

    class Session {
        +session_id: u64
        +signing_key: [u8;16]
        +auth: AuthState  // NtlmInProgress | Complete
        +trees: Map~tree_id, TreeConnect~
    }

    class TreeConnect {
        +share: ShareConfig
        +aapl_negotiated: bool  // AAPL: on the FIRST tcon, global
    }

    class OpenHandle {
        +file_id: FileId
        +path: SmbPath
        +backend_file: BackendHandle
        +lease: Option~LeaseKey~
        +durable: Option~DurableConfig~
        +state: HandleState
    }

    class DurableConfig {
        +create_guid: Guid
        +timeout: Duration   // the server's answer; TM compares it!
    }

    class HandleState {
        <<enum>>
        Active(conn_id)
        Parked(expires_at)
        Closing
    }

    class Lease {
        +key: LeaseKey
        +state: RWH-flags
        +epoch: u16
        +break_state: LeaseBreakState
        +owner_conn: Option~conn_id~
    }

    class AsyncOpRegistry {
        +register(msg_id) AsyncId
        +complete(async_id, resp)
        // interim STATUS_PENDING for FLUSH(sync-through)/CHANGE_NOTIFY/Lock
    }

    class AppleExt {
        +on_create_root(ctx: AaplContext) AaplResponse
        +is_fullfsync(flush: FlushReq) bool  // Reserved1 == 0xFFFF
    }

    class Dispatcher {
        +handle(msg, conn, shared) Result~Reply~
        // Reply = Now(frame) | Async(async_id) | None
    }

    Server --> ConnectionActor : spawn per accept
    ConnectionActor --> ConnState
    ConnectionActor --> Dispatcher
    Dispatcher --> ServerShared
    Dispatcher --> AppleExt
    ServerShared --> Session
    ServerShared --> OpenHandle
    ServerShared --> Lease
    Session --> TreeConnect
    OpenHandle --> HandleState
    OpenHandle --> DurableConfig
    ConnState --> AsyncOpRegistry
```

**Key decisions:**
- **`write_loop` is the single writer to the socket** (an mpsc queue). This is the mechanics of
  server-initiated send: a lease break is put into the same queue from anywhere
  (`LeaseTable::request_break`), without waiting for the request/response cycle.
- **`OpenTable`/`LeaseTable`/`DurableParkRegistry` are outside the actor** (in `ServerShared`): the death of a
  connection kills the actor but NOT the handle, which moves `Active → Parked(expires_at)` with a timer.
  This is a direct embodiment of the requirement "durable survives TCP".
- **Credits** (`CreditWindow`) are per-connection and granted in every reply; an interim reply
  (STATUS_PENDING) carries credits too, otherwise the client chokes on a long FLUSH.
- `ArcSwap<ShareConfig>`: hot config change on `Configure`/`RotateCredentials` without
  restarting connections.
- `Dispatcher` is a pure function of `(msg, state)`: the whole transition table is tested without
  sockets (unit level), and sockets exist only in the actor.

---

### 2.3. State machines (UML statecharts)

**Connection (per TCP):**
```mermaid
stateDiagram-v2
    [*] --> Negotiating : accept (socket from launchd)
    Negotiating --> Authenticating : NEGOTIATE ok (dialect 3.1.1, the preauth chain runs)
    Authenticating --> Authenticating : SESSION_SETUP (NTLM legs 1..n, STATUS_MORE_PROCESSING)
    Authenticating --> Active : SESSION_SETUP ok (keys derived, signing ON)
    Active --> Active : TREE_CONNECT / CREATE / READ / WRITE / FLUSH / ...
    Active --> Dead : TCP drop / fatal protocol error
    Dead --> [*] : the actor dies.\nHandles: Active(conn) → Parked (see below)
```

**Open handle (durable V2): the heart of the Apple semantics:**
```mermaid
stateDiagram-v2
    [*] --> Opening : CREATE + DurableHandleRequestV2
    Opening --> Active : backend open ok\n(the reply Timeout is recorded; TM will compare it)
    Active --> Parked : TCP drop of the owning connection\n(timer = DurableConfig.timeout)
    Parked --> Active : CREATE + DurableHandleReconnectV2\n(create_guid matched, new conn_id)
    Parked --> Expired : the timer expired
    Active --> Closed : SMB2 CLOSE
    Expired --> [*] : backend close, lease released\n(TM will handle the failed pass itself)
    Closed --> [*]
```

**Lease V2 (with a server-initiated break):**
```mermaid
stateDiagram-v2
    [*] --> Granted : CREATE + LeaseV2Request\n(state ⊆ requested, epoch++)
    Granted --> BreakPending : a conflicting CREATE from another client\n→ write_loop: LeaseBreakNotify (server-initiated!)
    BreakPending --> Downgraded : LeaseBreakAck from the client
    BreakPending --> Downgraded : ack timeout → forced downgrade
    Downgraded --> Granted : a new CREATE may raise the state
    Granted --> [*] : all handles of the lease are closed
```
> Note on scale: we have one client (backupd) and one share, so conflicting opens are rare
> (a second mount, Finder browsing). But the break path must work: validation may trigger it,
> and the spec requires correctness unconditionally.

---

### 2.4. Key scenarios (sequence)

**Durable reconnect after a drop (the junction with the Layer 1 journal):**
```mermaid
sequenceDiagram
    participant BD as backupd
    participant C1 as ConnectionActor #1
    participant SH as ServerShared (OpenTable/Parked)
    participant BE as StorageBackend (journal)

    BD->>C1: WRITE band/17 (durable handle H, lease L)
    C1->>BE: write() → WAL append
    Note over C1: TCP drop
    C1->>SH: park(H): Active→Parked, 30 s timer\n(lease L is kept for H)
    Note over BD: reconnect (within the Timeout window)
    BD->>SH: new connection → NEGOTIATE/SESSION_SETUP/TREE_CONNECT
    BD->>SH: CREATE + DurableHandleReconnectV2(create_guid H)
    SH-->>BD: handle restored (the same FileId)
    BD->>SH: WRITE band/17 (continuing from the same offset)
    SH->>BE: write(): the WAL guarantees no holes:\nunacknowledged ranges are not lost
```

**F_FULLFSYNC under sync-through (why AsyncOpRegistry):**
```mermaid
sequenceDiagram
    participant BD as backupd
    participant CA as ConnectionActor
    participant BE as StorageBackend
    participant AP as janus-receiverd

    BD->>CA: FLUSH (Reserved1=0xFFFF) on band/17
    CA->>CA: AppleExt: this is F_FULLFSYNC
    CA-->>BD: interim STATUS_PENDING (+credits): we do not hold the client
    CA->>BE: flush(handle)
    BE->>AP: catch up the WAL band/17 → gRPC Fsync(file)
    AP-->>BE: durable on the receiver
    BE-->>CA: ok
    CA-->>BD: the final FLUSH reply (async_id)
```

---

### 2.5. Open design questions of the layer (resolved by the PoC/audit)

- ❓ **Donor boundaries:** how much of §2.1 is really covered by `smb-msg`/`smb-dtyp`/`smb-fscc`
  (especially the response side of Create contexts): the `smb-rs` audit.
- ❓ **Preauth hash and signature on compound chains:** the exact semantics per MS-SMB2 (which bytes
  go into the hash for a related compound): check against the trace.
- ❓ **One write_loop vs priority queues:** whether LeaseBreakNotify/interim needs a separate priority
  ahead of bulky READ replies (loopback is fast, so perhaps not).
- ❓ **Where the lease lives for a Parked handle:** the spec permits keeping a lease for a disconnected
  durable handle: confirm backupd's behaviour (affects `Lease.owner_conn`).
- ❓ **CHANGE_NOTIFY:** whether backupd sends it at all (trace); if it does, `AsyncOpRegistry`
  is extended with a subscription to `sparsebundle-model` events.

---

## Layer 1: storage (`janus-lib`: vfs / sparsebundle-model / journal / uploader)

The job of the layer: turn the stream of SMB operations from Layer 2 into reliably delivered band files on
the appliance, answering fast (WAL) and not depending on instant availability of the network. Both
durability policies and the Drain barrier live here.

### 1.1. `vfs`: the StorageBackend trait (the layer boundary)

The only door through which `smb-core` sees storage. An async trait, two implementations.

```mermaid
classDiagram
    direction TB

    class StorageBackend {
        <<async trait>>
        +open(path, disposition) BackendHandle
        +read(h, offset, len) Bytes
        +write(h, offset, data)
        +flush(h, fullfsync: bool)
        +close(h)
        +rename(from, to, replace)
        +delete(path)
        +truncate(h, new_len)
        +list(dir) Vec~FileStat~
        +stat(path) FileStat
        +statfs() FsStats        // quota/usage → FileFsSizeInformation
    }

    class GrpcBackend {
        -model: SparsebundleModel
        -journal: Journal
        -uploader: UploaderHandle
        -remote: BandTransportClient
    }

    class LocalFsBackend {
        // for tests: writes to a local folder,
        // the reference behaviour against Samba
    }

    class BackendError {
        <<enum>>
        NotFound
        AlreadyExists
        NoSpace          // → NT STATUS_DISK_FULL (important for TM thinning!)
        Busy             // backpressure
        RemoteUnavailable
    }

    StorageBackend <|.. GrpcBackend
    StorageBackend <|.. LocalFsBackend
    GrpcBackend --> BackendError
```

- **Error mapping is part of the contract:** `smb-core` translates `BackendError` into NTSTATUS.
  Critical: `NoSpace → STATUS_DISK_FULL` is the signal on which TM starts thinning;
  lying here means TM will not clean up old points.
- `flush(h, fullfsync)`: the flag is forwarded from `AppleExt::is_fullfsync`; a plain FLUSH and
  F_FULLFSYNC may have different costs (see §1.3).

### 1.2. `sparsebundle-model`: path classification and per-type policy

```mermaid
classDiagram
    class SparsebundleModel {
        +classify(rel_path) ObjectKind
        +policy(kind) WritePolicy
    }
    class ObjectKind {
        <<enum>>
        Band(band_no: u32)      // "bands/1a7" (hex)
        InfoPlist               // Info.plist / Info.bckup
        MachineId               // com.apple.TimeMachine.MachineID.*
        LockToken               // lock / token
        ValidationProbe         // .com.apple.timemachine.supported
        Dir
        Other(path)
    }
    class WritePolicy {
        <<enum>>
        Journaled       // hot path: WAL + uploader (bands)
        WriteThrough    // small metafiles: BundleOp+WriteRange+Fsync right away
    }
    SparsebundleModel --> ObjectKind
    SparsebundleModel --> WritePolicy
```

- **Bands** are 99% of the traffic, fixed-size offset writes → `Journaled`.
- **Metafiles** (`Info.plist`, MachineID, lock/token) are small and rare, but their integrity is
  critical for the validity of the bundle → `WriteThrough` (synchronously up to the appliance): it simplifies
  reasoning, and the cost is negligible.
- `ValidationProbe` is the validation-handshake file: an ordinary `WriteThrough`, nothing special,
  but useful as a marker in events (`validation_passed`).

### 1.3. `journal`: the WAL (the point of local durability)

```mermaid
classDiagram
    direction TB

    class Journal {
        +append(file, offset, data) Seq
        +read_overlay(file, offset, len) Vec~Chunk~  // read-your-writes
        +mark_uploaded(watermark: Seq)
        +recover() JournalState   // at startup
        -segments: Vec~Segment~
        -index: DirtyIndex
    }
    class Segment {
        // an append-only file of ~64 MB, /var/db/janus-smbd/wal/NNNN.seg
        +records: [RecordHeader + data]
    }
    class RecordHeader {
        +seq: u64
        +file: PathId
        +offset: u64
        +len: u32
        +crc32: u32
    }
    class DirtyIndex {
        // per-file interval map: range → (seq, where it lies in the segment)
        // later-wins on overlaps
        +insert(file, range, loc)
        +lookup(file, range) Vec~Chunk~
        +dirty_ranges(file) iterator  // for flush(file)
    }
    class ParkedHandleStore {
        // persistence of Layer 2 durable state (create_guid, path, lease)
        // next to the WAL: survive a daemon crash, not only a TCP drop
    }

    Journal --> Segment
    Segment --> RecordHeader
    Journal --> DirtyIndex
    Journal ..> ParkedHandleStore : a neighbouring file, a shared fsync mode
```

**Decisions:**
- **`read_overlay` is mandatory:** READ must see not-yet-uploaded writes
  (read-your-writes). The answer to a READ is a merge: ranges from the WAL (fresh) on top of data from
  the appliance (`ReadRange`). Otherwise backupd would read old bytes and decide the image is corrupt.
- **Later-wins in `DirtyIndex`:** overlapping writes collapse even before upload,
  so reordering on the network is safe, because already non-overlapping ranges are sent.
- **The segment fsync mode depends on the policy (§8.2):** LOCAL_JOURNAL: the WAL fsync is the answer
  to F_FULLFSYNC (the durability point on the Mac); SYNC_THROUGH: the WAL may be fsynced lazily
  (the durability point is on the receiver), and the WAL is then only transit+overlay.
- **Recovery at startup:** scan segments from the last checkpoint, restore
  `DirtyIndex` + `ParkedHandleStore` → after a crash the daemon continues from the same place, and durable
  handles survive not only a TCP drop but also our restart.
- **A size limit → `Busy`** upward (Layer 2 slows down WRITE replies: backpressure on backupd,
  which TM tolerates normally, just slower).

### 1.4. `uploader`: delivery to the appliance

```mermaid
classDiagram
    direction TB
    class Uploader {
        <<tokio task>>
        -planner: BatchPlanner
        -window: InflightWindow
        -retry: RetryPolicy
        -acks: AckTracker
        +flush_barrier(file) await      // F_FULLFSYNC sync-through
        +drain_barrier() await          // Drain before fixing a point
    }
    class BatchPlanner {
        // reads dirty_ranges from the checkpoint,
        // coalesces adjacent ones, cuts at ≤1 MiB
    }
    class InflightWindow {
        // a semaphore of N parallel WriteRange (start: 4)
        // order between non-overlapping ones does not matter
    }
    class RetryPolicy {
        // exponential backoff + jitter; WriteRange is idempotent → a repeat is safe
        // RemoteUnavailable → pause, the WAL accumulates
    }
    class AckTracker {
        // watermark: all seq ≤ W are acknowledged by the appliance
        // → journal.mark_uploaded(W) → trim segments
        // → "uploaded_bytes / backlog" for Status
    }
    Uploader --> BatchPlanner
    Uploader --> InflightWindow
    Uploader --> RetryPolicy
    Uploader --> AckTracker
```

**Barriers are the only synchronization points:**
- `flush_barrier(file)`: wait for the acks of all dirty ranges of the file → `Fsync(file)` on the
  receiver → return control (an honest F_FULLFSYNC under SYNC_THROUGH stands on this);
- `drain_barrier()`: the same for the whole bundle + `Fsync(all_bundle)` (`Drain` stands on this
  before fixing a point);
- outside the barriers the uploader is fully asynchronous and does not affect SMB reply latency.

### 1.5. End-to-end scenario: WRITE → READ of the same range → FLUSH

```mermaid
sequenceDiagram
    participant SC as smb-core
    participant BE as GrpcBackend
    participant J as Journal
    participant U as Uploader
    participant AP as janus-receiverd

    SC->>BE: write(band/17, off=1M, 64K)
    BE->>J: append → seq=101, DirtyIndex[band/17][1M..1M+64K]=101
    BE-->>SC: ok (the WRITE Response has gone out)

    SC->>BE: read(band/17, off=1M-4K, 72K)
    BE->>J: read_overlay → a 4K tail outside the WAL, 64K from the WAL
    BE->>AP: ReadRange(band/17, 1M-4K, 4K)   // only what is missing
    BE-->>SC: merge: [4K from the appliance][64K from the WAL]

    SC->>BE: flush(band/17, fullfsync=true)
    alt SYNC_THROUGH
        BE->>U: flush_barrier(band/17)
        U->>AP: WriteRange(...the remaining dirty...)
        U->>AP: Fsync(band/17)
        AP-->>U: durable on the receiver
        U-->>BE: ok
    else LOCAL_JOURNAL
        BE->>J: fsync of the WAL segments
    end
    BE-->>SC: ok → FLUSH Response
```

### 1.6. Open questions of the layer

- ❓ **Placement WAL:** `/var/db/janus-smbd/` (root-only) vs `/Library/Application Support/…`;
  the limit size (a first estimate is 2–8 GB, configurable) and behaviour on small disks.
- ❓ **The group-commit interval** of the WAL fsync under LOCAL_JOURNAL (F_FULLFSYNC latency vs SSD wear).
- ❓ **WriteThrough for metafiles when the appliance is unavailable:** refuse at once (honest) or
  journal and degrade to Journaled (harder, but more resilient)? We lean towards "refuse":
  without the appliance the backup does not run anyway.
- ❓ **Reads while browsing points** (the user walks through history): a ReadRange cache on the Mac is
  a separate decision after the PoC and does not change the contract.
- ❓ **PathId interning** in the WAL (there are thousands of band paths, a string in every record is wasteful).

---

## Layer 3: management (control / config / bonjour / observability)

A layer without "clever" logic of its own: a facade over Layers 1–2 for the agent. The main principle is
**nothing in this layer is on the hot path** (WRITE/READ do not see it; the exception is
a single atomic `WriteGate` check).

### 3.1. `control` + `config`: the agent service and the configuration

```mermaid
classDiagram
    direction TB

    class ControlService {
        <<tonic, unix socket 0600>>
        +configure(req) Ack
        +ensure_ready() Readiness
        +status() StatusReply
        +drain(timeout) DrainReply
        +quiesce() / resume()
        +watch_events() stream
        +rotate_credentials(req) Ack
        +get_diagnostics() Bundle
        +shutdown(drain_first)
    }

    class ConfigStore {
        +apply(ConfigureRequest) Result
        +current() Arc~ShareConfig~   // ArcSwap: readers without locks
        -persist()  // atomic: tmp + rename, 0600
        -load()     // at startup, before control is ready
    }

    class ShareConfig {
        +appliance_endpoint
        +tls_identity_ref     // a Keychain reference, the key is not in the config's memory
        +share_name, smb_user, smb_password_ref
        +quota_bytes
        +flush_policy
        +advertise_bonjour
    }

    class WriteGate {
        <<AtomicU8>>
        Open | Quiesced
        // checked in GrpcBackend.write:
        // the only touch of the hot path
    }

    class ReadinessCheck {
        // chain: is the config loaded? → is the SMB listener alive? →
        // do the Keychain refs resolve? → does the appliance's gRPC Ping work?
        // the first failing step = Readiness.blocker
    }

    ControlService --> ConfigStore
    ControlService --> WriteGate
    ControlService --> ReadinessCheck
    ControlService ..> Uploader : drain_barrier()
    ControlService ..> EventBus : watch_events
    ConfigStore --> ShareConfig
```

**Decisions:**
- **`Configure` is the only writer of the config**; applying = validation → persist →
  `ArcSwap` → rebuilding dependents (a gRPC channel reconnect, a Bonjour re-advert). SMB sessions
  are NOT torn down on a config change (except a change of SMB credentials, which makes new SESSION_SETUPs use the new ones).
- **`Quiesce` = `WriteGate::Quiesced`**: `GrpcBackend.write` answers with a delay/retry
  (backpressure), sessions stay alive. There are no other gates in the layer.
- **`Drain` is just a pass-through** to `Uploader::drain_barrier(timeout)` (§1.4); control does not know
  what a "band" is.
- `ReadinessCheck` is an ordered chain with the first failing step in `blocker`: the agent
  gets not "not ready" but "what exactly to fix".

### 3.2. `bonjour`: the mDNS advertisement

```mermaid
classDiagram
    class BonjourAdvertiser {
        +sync_with(cfg: ShareConfig)  // advertise_bonjour on/off
        -register_smb()    // _smb._tcp port 445
        -register_adisk()  // _adisk._tcp, TXT: adVN=share, adVF=0x82
        // ONE service name for both records (a spec requirement)
        // implementation: FFI to dnssd (DNSServiceRegister)
    }
```
A trivial wrapper module; all the complexity is the question of "whether it is needed at all" (a PoC knot).
The registration is made on behalf of this same Mac (we advertise ourselves).

### 3.3. `observability`

```mermaid
classDiagram
    direction LR
    class Metrics {
        <<atomics, lock-free>>
        smb_sessions, open_handles, parked
        journal_backlog_bytes, uploaded_total
        upload_errors, last_ack_ms
        +snapshot() StatusReply
    }
    class EventBus {
        <<tokio broadcast>>
        +emit(Event)
        // subscribers: the agent's WatchEvents streams + DiagRing
    }
    class DiagRing {
        // a ring buffer of the last N events/errors
    }
    class DiagnosticsCollector {
        +bundle() tar.gz  // DiagRing + a log tail + a metrics snapshot
        // + the config WITH SECRETS REDACTED (refs are not secrets anyway,
        //   but password values are never logged anywhere, by design)
    }
    Metrics <.. DiagnosticsCollector
    EventBus --> DiagRing
    DiagRing <.. DiagnosticsCollector
```
- All counters are atomics, and `Status` only reads them (the promise that "Status
  never slows down the hot path" is kept by construction).
- Layers 1–2 write to `Metrics`/`EventBus` directly (injected at assembly) and know nothing about control.

---

## Layer 4: the process (the `janus-smbd` binary)

Only glue, zero logic:

```mermaid
sequenceDiagram
    participant LD as launchd
    participant RT as main()
    participant L3 as Layer 3
    participant L2 as smb-core
    participant L1 as janus-lib

    LD->>RT: start (socket activation / kickstart)
    RT->>RT: launchd check-in → the SMB listener fd + the control socket fd
    RT->>L3: ConfigStore.load() (may be empty: we do not fail)
    RT->>L1: Journal.recover() → DirtyIndex + ParkedHandleStore
    RT->>L1: Uploader.spawn()
    RT->>L2: Server.run(smb_fd) — we accept SMB
    RT->>L3: ControlService.serve(ctl_fd) — we accept the agent
    Note over RT: running…
    LD->>RT: SIGTERM
    RT->>L2: stop accept, hand over in-flight replies (grace ~5 s)
    RT->>L1: WAL fsync + persist ParkedHandleStore
    RT->>LD: exit 0   // durable state is on disk, a restart will continue
```

- **Panic policy: process-abort, not catch.** Integrity is provided by WAL recovery, not by
  catching panics: we crashed → launchd brought us up → `Journal.recover()`. A half-broken state in a live
  process is more dangerous than a restart.
- Graceful shutdown does NOT Drain by default (that is the agent's `Shutdown(drain_first)` command),
  it only fixes the durable state.

---

## janus-receiverd (the appliance, Linux/FreeBSD)

### R.1. Structure: router / worker (the rsync-proxy pattern)

```mermaid
classDiagram
    direction TB

    class Router {
        <<process with network>>
        -tonic server (mTLS, a client cert is mandatory)
        -identity: IdentityMap
        -workers: WorkerPool
        // terminates TLS, routes the call to the machine's worker
    }
    class IdentityMap {
        +resolve(client_cert) MachineId
        // cert → machine → dataset; cert issuance is the agent's registration channel
        // an unknown cert = reject at the handshake, it never reaches the application
    }
    class WorkerPool {
        +get_or_spawn(machine) WorkerHandle
        // idle timeout → stop the worker
    }
    class DatasetWorker {
        <<process WITHOUT network: jail (FreeBSD) / netns+uid (Linux)>>
        -root: cap_std::Dir   // ONLY the machine's dataset (nullfs/bind)
        -store: FileStore
        -quota: QuotaMeter
        // link to the Router: gRPC over a unix socket (the same proto)
    }
    class FileStore {
        +write_range(rel, off, data)   // pwrite: idempotent by construction
        +read_range(rel, off, len)
        +bundle_op(op)
        +fsync(scope)   // file: fsync(fd); all: fsync of the dirty set + directories
        -validate(rel_path)  // normalization, forbid "..", only inside root
    }
    class QuotaMeter {
        +check(len) Result   // used+len > quota → NoSpace
        +usage() (quota, used)  // → StatFs → FileFsSizeInformation on the Mac
    }

    Router --> IdentityMap
    Router --> WorkerPool
    WorkerPool --> DatasetWorker
    DatasetWorker --> FileStore
    DatasetWorker --> QuotaMeter
```

**Decisions:**
- **Double path protection:** dataset authorization is at the process level (the worker physically sees
  only its own dataset via nullfs/bind + `cap_std::Dir`), `rel_path` validation is the second line.
  Even a bug in validation does not let anything out of the dataset.
- **Workers are disposable and cheap:** spawned on a machine's first call, stopped when idle:
  exactly the lifecycle of jails in `rsync-proxy`.
- **`QuotaMeter` is the source of `NoSpace`**, which travels through `BandTransport → GrpcBackend →
  STATUS_DISK_FULL` to TM and starts thinning. The end-to-end chain is designed
  explicitly (see §1.1).
- Router and worker speak **the same `janus-proto`** over a unix socket: one contract,
  no second internal protocol.

### R.2. End-to-end path of a single WriteRange

```mermaid
sequenceDiagram
    participant SM as janus-smbd (Mac)
    participant RT as Router (appliance, network)
    participant WK as DatasetWorker (no network)
    participant FS as store

    SM->>RT: gRPC WriteRange (mTLS, the cert of machine M)
    RT->>RT: IdentityMap: cert → machine M → worker M
    RT->>WK: the same WriteRange over the unix socket
    WK->>WK: validate(rel_path), QuotaMeter.check
    WK->>FS: pwrite(bands/17, off, data)
    WK-->>RT: ok
    RT-->>SM: ok
    Note over SM,FS: Fsync(scope) goes along the same route;<br/>snapshots are OUTSIDE the receiver (the agent↔appliance channel)
```

### R.3. Open questions

- ❓ **Linux isolation:** the minimal sufficient set (uid + mount-ns + no-net-ns?):
  align it with the actual platform of the production appliance.
- ❓ **`QuotaMeter.usage`:** a query to the backend (exact, but costly per call) vs accounting in the worker
  (fast, drifts): probably a hybrid with periodic reconciliation.
- ❓ **Fsync(all_bundle):** tracking the dirty set in the worker vs a `syncfs` analogue on the dataset:
  measure the cost on a real pool.

---

*All layers are described. Further detail will follow the PoC (the backupd trace) and the `smb-rs` audit.*

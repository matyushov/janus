# How long the macOS SMB client waits

Measured 2026-10-21 on macOS (Darwin 27) with `mount_smbfs` against `janus-smbd` on loopback.
Method: a temporary hook in the server delayed every request of one command type for 100 s while a
user-space program issued exactly that operation on the mounted share (files opened with
`F_NOCACHE` where the page cache would hide the request). The client side was timed from the system
call. The hook is gone; the numbers are what remains.

## 1. The server stays silent (no interim response)

| Silent command | Client gives up after | What the application sees | What happens to the mount |
|---|---|---|---|
| READ | ~46 s | `EINVAL` | stays mounted, TCP reconnect |
| WRITE | ~45 s | `EIO` | stays mounted, TCP reconnect |
| FLUSH | ~98 s | `EIO` | stays mounted, TCP reconnect |
| CREATE | ~91 s | `ENOTCONN` | **unmounted by the client** |
| CLOSE | ~91 s | `ENOENT` | **unmounted by the client** |
| QUERY_DIRECTORY | never | the call hangs (process in `UN`) | the client reconnects and re-sends the request again and again (8+ times in 15 min) |
| QUERY_INFO | not measured | `fstat` was answered from the client's attribute cache, no request reached the server | - |

A reconnect always opens a new TCP connection and a new session; the old one is closed by the client.

**Caveat.** In this experiment the hook slept inside the connection loop, so the client's
keepalive ECHO went unanswered as well. Section 2.1 later showed that an unanswered ECHO alone
makes the client drop the connection and unmount the share after ~93 s. The ~91-98 s figures for
CREATE, CLOSE and FLUSH above are therefore most likely that ECHO limit, not a per-request limit;
the 45-46 s figures for READ and WRITE are shorter than it and are the request limits. Section
2.1 (ECHO answered) gives the limits that matter for the gateway.

## 2. The server answers with an interim `STATUS_PENDING`

Measured on FLUSH (`F_FULLFSYNC`) with the receiver frozen (`kill -STOP`):

- With a server-side limit of 120 s the final error came from the server after 120 s, and the client
  waited that long.
- With the server holding the operation for 331 s the **client gave up after ~123 s** with
  `ETIMEDOUT`, although the server kept the operation and finished it successfully later. The
  mount stayed up.

So an interim response extends the client's wait, but only to **~120 s per operation**, not
indefinitely. A pending ceiling above ~120 s (the default is 600 s) cannot be reached on the client
side; it only matters for what the server does after the client has left.

### 2.1 Through the real gateway (frozen receiver, interim responses, ECHO answered)

Measured with the finished J4.1 gateway against `janus-receiverd` stopped with `kill -STOP`
(drop_after raised so that it did not interfere), 260 s outage:

| Operation | Client result | After |
|---|---|---|
| CREATE (`touch`) | succeeds when the receiver is back | 260 s, nothing dropped |
| READ (uncached) | `ETIMEDOUT`, share stays mounted | 121.8 s |
| listing (`QUERY_DIRECTORY`) | `ENOENT`, share stays mounted | 122.1 s |

**ECHO must be answered while a request waits.** A first version of the gateway left the client's
keepalive ECHO unanswered while a request was pending; the client then dropped the connection and
unmounted the share after ~93 s whatever the operation was. Since the gateway answers ECHO during
the wait (and while a barrier waits for pipelined I/O), the limit is the ~122 s above.

## 3. Consequences for janus

- The interim `STATUS_PENDING` must go out well before 45 s for READ/WRITE (the shortest silent
  limit); the default `interim_after` of 1.5 s leaves a large margin.
- An outage longer than ~120 s cannot be ridden out by pending alone. Something has to give the
  client a different outcome before then (see section 4 once measured).
- An operation that fails with a transport error on CREATE or CLOSE can make the client unmount the
  share, which takes the disk image down with it.

## 4. The server drops the TCP connection

A temporary hook held the first request containing the chosen command for a moment and then closed
the TCP connection. The client was `mount_smbfs`; no disk image or Time Machine was involved here.

One drop, command re-sent by the client on a fresh connection (answered normally the second time):

| Command | Result | Time |
|---|---|---|
| CREATE, READ, WRITE, FLUSH, CLOSE | the operation succeeds, the mount stays up | drop delay + ~0.3 s |

The server dropped every attempt (the connection is closed again on each re-sent request) for a
whole outage window, then stopped:

| Command | Hold per attempt | Outage | Result |
|---|---|---|---|
| READ | 5 s | 200 s | succeeds when the outage ends (200.7 s, 40 reconnects) |
| WRITE | 5 s | 100 s | succeeds (100.5 s, 20 reconnects) |
| FLUSH | 5 s | 100 s | succeeds (100.2 s, 20 reconnects) |
| CREATE | 5 s | 200 s | **fails after the 2nd drop (10 s), `ENOTCONN`, mount unmounted** |
| CREATE | 0.5 s | 40 s | **fails after the 2nd drop (1 s), mount unmounted** |
| CLOSE | 5 s | 100 s | **fails after the 2nd drop (10 s), `ENOENT`, mount unmounted** |

So READ, WRITE and FLUSH can be kept alive by dropping the connection over and over: the client
reconnects (about every 5 s here) and re-sends, with no sign of giving up for at least 200 s.
CREATE and CLOSE survive **one** drop and are given up on the second, which also unmounts the share.

## 5. What this means for the design

- READ/WRITE/FLUSH: an outage of any length up to the server's own ceiling can be ridden out by
  closing the TCP connection before the client's own timer (~45 s for READ/WRITE) expires.
- CREATE/CLOSE: at most one drop is safe. The server has to answer with an interim
  `STATUS_PENDING` (client limit ~120 s) and may use the one drop for a second window.
  An outage longer than that cannot be ridden out for these two commands.
- Not measured, to be done later: how Time Machine (`backupd`) and the disk-image layer behave when
  these drops happen. Do not infer it from the numbers above.
- Not measured: a CREATE/CLOSE that is held with interim responses before the single drop, QUERY_INFO/QUERY_DIRECTORY under repeated drops.

## 6. What the gateway does

- Every request that can wait for the receiver goes through the foreground path of the
  connection loop (`run_foreground`): CREATE, CLOSE, FLUSH, READ, WRITE, QUERY_INFO,
  QUERY_DIRECTORY, SET_INFO, alone or in a compound chain. Pipelined READ/WRITE have their own
  timers. The loop keeps reading while the handler waits.
- After `interim_after` (1.5 s) the client gets an interim `STATUS_PENDING` (MS-SMB2 §3.3.4.2)
  for the command of the chain that is running, no credits, unsigned; the final reply carries
  the async header (§3.3.4.1.1) and the credits. For a chain, the replies of the elements before
  the pending one go out first, then the pending one, then the rest, each signed on its own.
- A signed CANCEL (§3.3.5.16) ends the wait with `STATUS_CANCELLED`. ECHO is answered at once
  (credit window unchanged). Everything else queues and runs afterwards, in order.
- The backend does not give up after 18 s: `Timeouts::patience` (default 120 s, `--down-after`)
  keeps retrying the call while the receiver is down. Create and Delete are repeated too; a
  repeated Create that finds the file is a success.
- At `drop_after` (100 s, below the ~122 s of the client) the TCP connection is dropped and the
  client re-sends. When `max_wait` (default 300 s, `--max-wait`) is not above `drop_after`, the
  wait ends with `STATUS_UNEXPECTED_NETWORK_ERROR` instead.
- A CREATE that waits has not granted a handle or a lease yet: both are produced by the handler
  when it finishes. A durable reconnect (DH2C) is a CREATE and takes the same path.

Known limits: lease-break notifications for this connection are delivered after the waiting
request finishes; a request cancelled or dropped after the handler opened a backend handle leaves
that handle to the cleanup at the end of the connection; Rename is not repeated (it waits until
the receiver answers a ping, then is tried once).

## 7. Time Machine itself (`backupd`, macOS 26.6.2 guest, janus-receiverd on a Linux VM)

Real backups of a fresh macOS guest through the gateway to a remote receiver; the receiver
process was frozen with `kill -STOP` while `backupd` was in the Copying phase.

| Outage | Result |
|---|---|
| 15 s, 45 s | the backup completes; one request waits 8-45 s |
| 121 s (frozen at 100 s: connection dropped, request repeated) | the backup completes |
| stop and start of the receiver process, 10 s apart | the backup completes |
| 150 s, 300 s (twice) | `backupd` aborts the backup 126-140 s after the last progress (no more writes to the image, `pwrite` errno 5, the image is ejected); the partial backup is kept as `.interrupted` / `.inprogress` |

So Time Machine gives up on a destination that makes no progress for about **2 minutes**
(between 122 s, survived, and 126 s, aborted). The gateway's pending requests and connection drops
carry it through outages up to that point; beyond it only progress during the outage helps, i.e.
the metadata operations (create, rename, list, stat) must not wait for the receiver.
The data of the completed backups matched the data sets byte for byte (626 files in three
sets).

**A bug found this way:** after the connection is dropped the client reconnects and re-opens
each handle with a durable reconnect (DH2C). The reply was built from a live `stat` of the
receiver, so the reconnect stalled while the receiver was down, and `smbfs` gave up reconnecting
after ~60 s (`smb_iod_reconnect: Failed to reconnect TM share`). The backend now answers a
`stat` that the receiver has not answered within 2 s from the last answer it had for the path
(delete and rename drop it).

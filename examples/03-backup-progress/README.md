# 03 — watching the journal drain

With the write-ahead journal (default) a write is acknowledged once it is on the local disk;
a background uploader sends it to the receiver. This example writes 8 × 8 MiB, polls
`status()` until the backlog is zero, and calls `drain()` — the barrier a real application
uses before it says "backup complete" or exits.

```sh
cmake -S examples -B build/examples && cmake --build build/examples --target 03_backup_progress
source /tmp/janus-demo/env.sh            # a receiver is required, see ../README.md
./build/examples/03_backup_progress
```

Expected:

```
writes finished; the application sees them as done
  backlog 0 KiB, uploaded 65568 KiB, errors 0, waiting SMB ops 0
drained: all data is on the receiver
```
On a slow link you will see several lines with a shrinking backlog. On a fast loopback receiver
the journal is usually empty by the first poll.

## What to read in `main.cpp`

- `max_backlog_bytes` caps the unuploaded data; when it is reached, writes wait instead of
  filling the disk.
- `try_status()` / `try_drain()` return `janus::Result<T>` even with exceptions on — handy in
  loops where failure is routine.
- `Status::journal_backlog_bytes` is data written but not yet on the receiver;
  `upload_errors` and `last_upload_error` show trouble with the link; `log_dropped` counts log
  lines discarded because the callback was too slow.
- `drain(timeout)` returns `Error::Timeout` when the receiver did not catch up in time. Nothing
  is lost: the journal keeps the data.

# 02 — mount and copy

Starts the client, mounts the loopback SMB share and uses it like any folder: writes a 16 MiB
file, reads it back, compares CRC-32, unmounts, and stops while waiting for the upload.

```sh
cmake -S examples -B build/examples && cmake --build build/examples --target 02_mount_and_copy

# a) development mode, a local folder instead of a receiver:
./build/examples/02_mount_and_copy

# b) with a receiver (see ../README.md for run-local-receiver.sh):
source /tmp/janus-demo/env.sh
./build/examples/02_mount_and_copy
```

Expected (b):

```
SMB endpoint: smb://127.0.0.1:53391/backup
receiver reachable over mTLS
mounted at /Volumes/backup
wrote 16 MiB in 426 ms; CRC written 518dc1e8, read back 518dc1e8  OK
stopped
```

## What to read in `main.cpp`

- `client.ready()` checks the whole chain (share configured, receiver answering over mTLS);
  the exception text names the missing link.
- **macOS:** `janus::Mount::mount(info)` (header `janus/mount_macos.hpp`, NetFS) mounts at
  `/Volumes/<share>`; pass a directory as 2nd argument to choose the place. `Mount`'s
  destructor unmounts. Link `janus::mount_macos` (CMake does it).
- **Other platforms:** the program prints URL, user and password and waits for you to mount
  the share by hand (`net use` on Windows, your CIFS client on Linux), then enter the folder.
- `client.stop(std::chrono::seconds(60))` is "wait up to a minute for everything to reach the
  receiver, then close". A plain `stop()` or the destructor closes immediately; the journal
  keeps unsent data for the next start.

# 01 — hello, embed

The smallest possible embedding: start janus inside the process, ask how to mount it, look at
the status, stop. No receiver, no certificates, nothing is mounted.

```sh
cmake -S examples -B build/examples && cmake --build build/examples --target 01_hello_embed
./build/examples/01_hello_embed
```

Expected output (the port differs):

```
libjanus 0.1.0
SMB endpoint : smb://127.0.0.1:53384/backup
user         : janus
password     : (32 characters, not printed)
configured   : no (no receiver in this mode)
backlog      : 0 bytes
stopped; the client's port is free again
```
(plus the library's log lines, prefixed `[janus …]`, on stderr).

## What to read in `main.cpp`

- `config.local_root` is the development mode: a local folder stands in for the receiver.
- `smb_listen` is left at its default, `127.0.0.1:0`: the OS picks a free port, you read it from
  `mount_info()`.
- The password is generated; with `config.state_dir` set it would be stored there and stay the
  same after a restart (example 05 relies on that).
- `Client::start(config, callback)` — the callback receives log lines on a library thread.
  It must be quick and must not call `stop()`.
- Errors are `janus::Exception` here. Example 04 shows the exception-free variant.

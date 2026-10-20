# 05 — configure later

Start the client without a receiver, learn the details later, and see that the configuration
survives a restart.

```sh
cmake -S examples -B build/examples && cmake --build build/examples --target 05_configure_later
source /tmp/janus-demo/env.sh            # a receiver is required, see ../README.md
./build/examples/05_configure_later
```

Expected:

```
before configure: not ready (not ready: no-config)
after configure: ready
after restart, configured from disk: yes
ready again without calling configure()
```

## What to read in `main.cpp`

- No `share` in the `Config`: the client runs and serves the (not yet usable) endpoint;
  `ready()` says `NotReady` with the blocker (`no-config`).
- `configure(Share)` validates, **persists** into `state_dir` and installs the receiver link.
  The connection is lazy, so the example polls `try_ready()` with a deadline.
- The second `start()` has the same `state_dir` and no share: the stored one is restored.
  Without `state_dir` nothing is persisted and the application must configure on every start.
- The certificate and key are **file paths**; the CA is **PEM text** (`Share::ca_pem`).

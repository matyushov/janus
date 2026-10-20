# 04 — no exceptions

For code bases built with `-fno-exceptions`. Define `JANUS_NO_EXCEPTIONS` (done automatically
when the compiler has exceptions off) and every function that would throw returns
`janus::Result<T>`; the `try_*` functions return it in both modes. The target is compiled with
`-fno-exceptions` when the compiler supports it, so the build itself proves that the header
and the helpers need no exceptions.

```sh
cmake -S examples -B build/examples && cmake --build build/examples --target 04_no_exceptions
./build/examples/04_no_exceptions
```

Expected (abridged):

```
started: smb://127.0.0.1:53385/backup
expected: second start refused (a janus client is already running)
expected: not ready (not ready: no-config)
expected: configure refused [-2] appliance_endpoint is required
status after the errors: {"configured":false,"journal_backlog_bytes":0,…}
expected: a janus client is already running
done
```
Output of stdout and stderr may interleave differently when piped.

## What to read in `main.cpp`

- `Result<T>`: `if (!r)` for failure, `*r` / `r->` for the value, `r.error().code` compared with
  `janus::Error::AlreadyStarted`, `NotReady`, `Bind`, `InvalidConfig`, `Timeout`, …
- `Client` is move-only: `janus::Client c = std::move(*started);`.
- A failed call leaves the client running; errors are values, not state.
- The `Client` destructor stops the client (RAII) — see the scoped block at the end.
- `Status::json` is the full status document if you need fields the struct does not mirror.

# janus-ffi — libjanus, the client SDK

Embeds the janus client into any application: a loopback-only SMB endpoint, the write-ahead
journal and the mTLS link to the receiver run **inside the host process**. The application
mounts the endpoint like a normal SMB share and works with plain files.

- C ABI: `janus/janus.h`, **generated** from `src/lib.rs` by cbindgen and not committed. CMake
  produces it in the build tree and installs it; by hand:
  `cargo run -p janus-ffi --example gen_header -- build/include/janus/janus.h`.
- C++ wrapper (header only, C++17): [`janus/janus.hpp`](../../include/janus/janus.hpp), macOS
  mounting helper [`janus/mount_macos.hpp`](../../include/janus/mount_macos.hpp) (NetFS).
- Examples: [`examples/`](../../examples/README.md).

## Build and install

```sh
cmake -S . -B build/janus && cmake --build build/janus
cmake --install build/janus --prefix /opt/janus      # headers, libjanus.a/.dylib/.so, CMake + pkg-config files
```
Consume: `find_package(janus CONFIG REQUIRED)` and `janus::client_static` or
`janus::client_shared` (macOS helper: `janus::mount_macos`); pkg-config: `janus.pc`, `janus-static.pc`.

System libraries of the static archive (`cargo rustc -p janus-ffi --release -- --print native-static-libs`):

| Platform | Libraries |
|----------|-----------|
| macOS (checked) | `-liconv -lSystem -lc -lm` (the mounting helper adds frameworks NetFS, CoreFoundation) |
| Linux (rustc's usual set, to be confirmed by CI) | `-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc` |
| Windows MSVC (same caveat) | `ws2_32 userenv bcrypt ntdll advapi32 kernel32 synchronization` |

The shared library exports only the eleven `janus_*` functions; on macOS its install name is
`@rpath/libjanus.dylib`.

## Rules of the C ABI

- Return `0` on success or a negative `JANUS_E_*` code; details of the last failure on the
  calling thread: `janus_last_error`.
- Panics never cross the boundary; null pointers and invalid UTF-8 are errors.
- Calls are safe from any thread. `janus_client_stop` from the log callback is refused
  (`JANUS_E_CALLBACK_CONTEXT`). A slow log callback never blocks the client: a 1024-line queue
  drops the oldest lines and counts them (`log_dropped` in the status JSON).
- Strings returned through `char **` are freed with `janus_free_string`.
- One client per process; `start` after `stop` works and leaves no threads, ports or `dns-sd`
  processes behind. The library reads neither the environment nor `HOME`.
- Config document for `janus_client_start`: `{"version":1,"share":{…},"client":{…}}`; `share` is
  the daemon's `ConfigStore` schema, `client` has `smb_listen` (default `127.0.0.1:0`),
  `state_dir`, `smb_user`/`smb_password`/`smb_credentials_file`, `bonjour`, `trace`,
  `control_listen`, `local_root` (development), `worker_threads`, `log_stderr`.

Limits: port 445 needs root, so the default is a free high port. On macOS the Local Network
permission belongs to the application that embeds the library.

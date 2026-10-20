# janus examples — embedding the client SDK in a C++ application

Each example is a small C++23 program that links **libjanus statically**, starts the janus
client **inside its own process** and works with the remote folder like a normal SMB share.
SMB never leaves the loopback interface; the network only sees the mTLS link to the receiver.

The logic every example follows:

```
1. link libjanus (CMake: janus::client_static) and include <janus/janus.hpp>
2. build a janus::Config                     where the receiver is, certificates, state directory
3. janus::Client::start(config)              loopback SMB endpoint + journal + mTLS link, in-process
4. client.mount_info()                       URL, user, password of the local SMB share
5. mount it (macOS: <janus/mount_macos.hpp>; elsewhere your own code) and use plain files
6. client.status() / drain() / stop(timeout) watch the backlog, wait for the upload, shut down
```

| # | Example | Shows | Needs a receiver |
|---|---------|-------|------------------|
| 01 | [01-hello-embed](01-hello-embed/README.md) | the life cycle: start, mount info, status, stop | no |
| 02 | [02-mount-and-copy](02-mount-and-copy/README.md) | mounting the share, writing and reading a file, CRC check | optional |
| 03 | [03-backup-progress](03-backup-progress/README.md) | write-ahead journal: watching the backlog drain, `drain()` | yes |
| 04 | [04-no-exceptions](04-no-exceptions/README.md) | the exception-free API (`Result<T>`), error codes | no |
| 05 | [05-configure-later](05-configure-later/README.md) | start unconfigured, `configure()` later, state restored on restart | yes |

## Build

Requirements: CMake ≥ 3.20, a C++23 compiler (the SDK headers themselves need only C++17) and the Rust toolchain (`cargo`; the version is
pinned by `rust-toolchain.toml`, rustup installs it by itself). From the repository root:

```sh
cmake -S examples -B build/examples
cmake --build build/examples
```

This builds `libjanus.a` from the sources with cargo (the first build takes a few minutes) and
links it into every example. Nothing has to be installed or found at run time.

Against an **installed** package instead (see [`crates/janus-ffi/README.md`](../crates/janus-ffi/README.md)):

```sh
cmake -S . -B build/janus && cmake --build build/janus && cmake --install build/janus --prefix ~/janus-sdk
cmake -S examples -B build/examples -DCMAKE_PREFIX_PATH=~/janus-sdk
cmake --build build/examples
```

In your own project the only lines you need are:

```cmake
find_package(janus CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE janus::client_static)      # macOS mounting helper:
if(APPLE)                                                       #   also janus::mount_macos
  target_link_libraries(my_app PRIVATE janus::mount_macos)
endif()
```

`janus::client_static` brings the include path, `cxx_std_17` and the system libraries the
static archive needs (macOS: `iconv`, `m`). Use `janus::client_shared` for the dynamic library.

## A receiver on your machine (examples 02, 03, 05)

```sh
examples/run-local-receiver.sh /tmp/janus-demo        # terminal 1: creates a throw-away PKI, runs the receiver
source /tmp/janus-demo/env.sh                         # terminal 2: JANUS_EXAMPLE_* variables
./build/examples/02_mount_and_copy
```

Or pass `--endpoint host:port --cert client.pem --key client.key --ca ca.pem [--state-dir dir]`
to any example to use a real receiver. The PKI of the script is for development only.

## Good to know

- **One client per process.** A second `start()` fails with `Error::AlreadyStarted` until the first is stopped.
- **macOS, Local Network permission.** The permission is asked of the application that embeds
  the library (your executable or its app bundle), not of libjanus. Loopback mounts normally
  do not trigger it; reaching a receiver on your LAN does.
- **Port 445** needs root, so the default is a free high port; read it from `MountInfo::port`.
- **Secrets.** `MountInfo::password` is a credential. The examples print it only on platforms
  where the user must type it into a mount dialog, and say so; real code should not log it.
- Mounting by the library itself exists for macOS only (NetFS). On Linux and Windows
  the examples print the URL and credentials and wait while you mount by hand.

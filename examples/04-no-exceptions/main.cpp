// Example 04 — janus without C++ exceptions.
//
// Many applications (games, embedded hosts, some Chromium-style code bases) build with
// -fno-exceptions. janus.hpp supports this: define JANUS_NO_EXCEPTIONS (it is also defined
// automatically when the compiler has exceptions off) and every function that normally
// throws returns janus::Result<T> instead. The try_* functions return Result<T> in both
// modes, so this style is available everywhere.
//
// A Result converts to bool; `*r` / `r->` give the value; `r.error()` has the code and the
// message. This example also shows the failure cases the SDK reports as codes:
//   * a second start() in the same process  -> Error::AlreadyStarted
//   * a busy port                           -> Error::Bind
//   * a bad configuration                   -> Error::InvalidConfig
//   * asking an unconfigured client if it is ready -> Error::NotReady
//
// This file is compiled with -fno-exceptions when the compiler accepts it (see CMakeLists.txt).
#define JANUS_NO_EXCEPTIONS 1
#include <janus/janus.hpp>

#include <cstdio>
#include <string>

#include "example_util.hpp"

static int report(const char* what, const janus::Error& e) {
  std::fprintf(stderr, "%s: [%d] %s\n", what, e.code, e.message.c_str());
  return 1;
}

int main() {
  janus::Config config;
  config.local_root = example::make_temp_dir("janus-noexc");

  // try_start returns Result<Client>. Client is move-only, so the value is moved out of it.
  auto started = janus::Client::try_start(config, example::printer(janus::LogLevel::Warn));
  if (!started) return report("start", started.error());
  janus::Client client = std::move(*started);
  std::printf("started: %s\n", client.try_mount_info()->url.c_str());

  // --- failure 1: only one client per process ------------------------------------------------
  auto second = janus::Client::try_start(config);
  if (!second && second.error().code == janus::Error::AlreadyStarted) {
    std::printf("expected: second start refused (%s)\n", second.error().message.c_str());
  }

  // --- failure 2: not ready --------------------------------------------------------------------
  auto ready = client.try_ready();
  if (!ready && ready.error().code == janus::Error::NotReady) {
    std::printf("expected: not ready (%s)\n", ready.error().message.c_str());
  }

  // --- failure 3: a configuration the library refuses -------------------------------------------
  janus::Share bad;  // no receiver address
  auto configured = client.try_configure(bad);
  if (!configured) {
    std::printf("expected: configure refused [%d] %s\n", configured.error().code,
                configured.error().message.c_str());
  }

  // The client survived all of that.
  auto st = client.try_status();
  if (!st) return report("status", st.error());
  std::printf("status after the errors: %s\n", st->json.c_str());

  auto stopped = client.try_stop();
  if (!stopped) return report("stop", stopped.error());

  // --- failure 4: a busy port, now that the process may start a client again -------------------
  {
    auto first = janus::Client::try_start(config);
    if (!first) return report("restart", first.error());
    janus::Config clash;
    clash.local_root = config.local_root;
    clash.smb_listen = first->try_mount_info()->host + ":" + std::to_string(first->try_mount_info()->port);
    // Same process: the first client still runs, so AlreadyStarted comes first. With another
    // process holding the port the code would be Error::Bind.
    auto busy = janus::Client::try_start(clash);
    std::printf("expected: %s\n", busy ? "(unexpectedly started)" : busy.error().message.c_str());
  }  // `first` is destroyed here: the destructor stops the client (RAII)

  std::printf("done\n");
  return 0;
}

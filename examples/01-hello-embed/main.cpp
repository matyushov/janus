// Example 01 — the smallest embedding: start janus inside this process, look at it, stop it.
//
// No receiver, no certificates, no mounting. The client serves a local temporary directory
// through its loopback SMB endpoint (the "local_root" development mode), which is enough to
// show the whole life cycle of the SDK:
//
//   1. build a janus::Config
//   2. janus::Client::start()      -> the SMB endpoint is listening on 127.0.0.1:<free port>
//   3. client.mount_info()         -> URL, user and a generated password to mount it with
//   4. client.status()             -> backlog, errors, pending operations
//   5. client.stop()               -> listeners closed, port free again
//
// Errors are exceptions here (the default). Example 04 shows the exception-free style.
#include <janus/janus.hpp>

#include <iostream>

#include "example_util.hpp"

int main() {
  try {
    // --- 1. configuration -------------------------------------------------------------------
    janus::Config config;
    // Development mode: serve this folder instead of a remote receiver.
    config.local_root = example::make_temp_dir("janus-hello");
    // smb_listen stays at its default "127.0.0.1:0": a free port is chosen for us. SMB never
    // leaves the loopback interface; only the (here absent) mTLS link would use the network.

    std::cout << "libjanus " << janus::version() << "\n";

    // --- 2. start ---------------------------------------------------------------------------
    // The second argument receives the library's log lines on a library thread.
    janus::Client client = janus::Client::start(config, example::printer());

    // --- 3. how to mount it -----------------------------------------------------------------
    janus::MountInfo info = client.mount_info();
    std::cout << "SMB endpoint : " << info.url << "\n"
              << "user         : " << info.user << "\n"
              << "password     : (" << info.password.size() << " characters, not printed)\n";

    // --- 4. status --------------------------------------------------------------------------
    janus::Status status = client.status();
    std::cout << "configured   : " << (status.configured ? "yes" : "no (no receiver in this mode)") << "\n"
              << "backlog      : " << status.journal_backlog_bytes << " bytes\n";

    // --- 5. stop ----------------------------------------------------------------------------
    // With a non-zero argument stop() would first wait for the journal to reach the receiver.
    client.stop();
    std::cout << "stopped; the client's port is free again\n";
    return 0;
  } catch (const janus::Exception& e) {
    // e.code() is one of janus::Error::Code, e.what() the library's message.
    std::cerr << "janus error " << e.code() << ": " << e.what() << "\n";
    return 1;
  }
}

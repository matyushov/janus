// Example 02 — mount the share and use it like a folder.
//
// The point of janus is that the application does not learn a new file API: it starts the
// client, mounts the loopback SMB share and then reads and writes ordinary files.
//
//   start -> mount_info -> mount (macOS: NetFS helper) -> write a file -> read it back,
//   compare CRC-32 -> unmount -> stop (waiting for the upload)
//
// Modes:
//   * with --endpoint/--cert/--key/--ca (or the env file of run-local-receiver.sh): the data
//     goes to a receiver over mTLS through the write-ahead journal;
//   * without them: a local directory stands in for the receiver (development mode).
//
// On macOS the share is mounted for you (janus/mount_macos.hpp, NetFS). On other platforms
// the example prints the URL and credentials and waits while you mount it with your own
// tools (Windows: net use; Linux: your CIFS client), then you press Enter.
#include <janus/janus.hpp>

#include <chrono>
#include <iostream>

#include "example_util.hpp"

#ifdef __APPLE__
#include <janus/mount_macos.hpp>
#endif

namespace {

constexpr std::size_t kFileBytes = 16u << 20;  // 16 MiB

}  // namespace

int main(int argc, char** argv) {
  example::Options opt = example::parse_options(argc, argv);
  if (opt.help) {
    example::print_receiver_usage(argv[0]);
    return 2;
  }

  try {
    // --- configuration ----------------------------------------------------------------------
    janus::Config config;
    config.state_dir = opt.state_dir.empty() ? example::make_temp_dir("janus-state") : opt.state_dir;
    if (opt.has_receiver()) {
      config.share = example::make_share(opt);
    } else {
      config.local_root = example::make_temp_dir("janus-share");
      std::cout << "(no receiver given: using a local directory)\n";
    }

    // --- start ------------------------------------------------------------------------------
    janus::Client client = janus::Client::start(config, example::printer(janus::LogLevel::Warn));
    janus::MountInfo info = client.mount_info();
    std::cout << "SMB endpoint: " << info.url << "\n";

    if (opt.has_receiver()) {
      // ready() checks the whole chain: a share is configured and the receiver answers over
      // mTLS. The exception message says which link is missing.
      client.ready();
      std::cout << "receiver reachable over mTLS\n";
    }

    // --- mount ------------------------------------------------------------------------------
    std::string folder;  // where the application sees the share
#ifdef __APPLE__
    // Mounts at /Volumes/<share>; pass a directory as the second argument to choose the place.
    // The destructor of Mount unmounts, but we do it explicitly below so errors are visible.
    janus::Mount mount = janus::Mount::mount(info);
    folder = mount.path();
    std::cout << "mounted at " << folder << "\n";
#else
    std::cout << "Mount it yourself:\n"
              << "  url      " << info.url << "\n"
              << "  user     " << info.user << "\n"
              << "  password " << info.password << "   (demo only; never print secrets in real code)\n"
              << "Then type the mount folder and press Enter: ";
    std::getline(std::cin, folder);
#endif

    // --- use it like any folder ---------------------------------------------------------------
    const std::string file = folder + "/example-02.bin";
    auto t0 = std::chrono::steady_clock::now();
    std::uint32_t written = example::write_test_file(file, kFileBytes);
    auto t1 = std::chrono::steady_clock::now();
    std::uint32_t read_back = example::crc32_file(file);
    std::cout << "wrote " << kFileBytes / (1 << 20) << " MiB in "
              << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count() << " ms; "
              << "CRC written " << std::hex << written << ", read back " << read_back << std::dec
              << (written == read_back ? "  OK\n" : "  MISMATCH\n");

    // --- unmount, then stop and wait for the upload -------------------------------------------
#ifdef __APPLE__
    mount.unmount();
#endif
    // The journal acknowledged the writes as soon as they were on the local disk; the upload
    // continues in the background. stop(timeout) waits for it, then closes everything.
    // Error::Timeout is thrown if the receiver did not catch up in time; the client is stopped
    // anyway and the journal keeps the rest for the next start.
    client.stop(std::chrono::seconds(60));
    std::cout << "stopped\n";
    return written == read_back ? 0 : 1;
  } catch (const janus::Exception& e) {
    std::cerr << "janus error " << e.code() << ": " << e.what() << "\n";
    return 1;
  }
}

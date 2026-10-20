// Example 03 — watch the write-ahead journal drain.
//
// With the journal on (the default) a write is acknowledged to the application as soon as it
// is on the local disk, and a background uploader sends it to the receiver. Status shows the
// gap: `journal_backlog_bytes` is data the application believes written but the receiver
// does not have yet. This example writes a burst of files, then prints the backlog every
// 250 ms until it reaches zero, and finally uses drain() as the barrier a real application
// would call before it shuts down or reports "backup complete".
//
// Needs a receiver (see ../README.md): without one there is no upload to watch.
#include <janus/janus.hpp>

#include <chrono>
#include <iostream>
#include <thread>

#include "example_util.hpp"

#ifdef __APPLE__
#include <janus/mount_macos.hpp>
#endif

int main(int argc, char** argv) {
  example::Options opt = example::parse_options(argc, argv);
  if (opt.help || !opt.has_receiver()) {
    example::print_receiver_usage(argv[0]);
    return 2;
  }

  try {
    janus::Config config;
    config.state_dir = opt.state_dir.empty() ? example::make_temp_dir("janus-state") : opt.state_dir;
    config.share = example::make_share(opt);
    // The backlog cap: when this much is unuploaded, writes wait instead of filling the disk.
    config.share.max_backlog_bytes = 256ull << 20;

    janus::Client client = janus::Client::start(config, example::printer(janus::LogLevel::Warn));
    client.ready();
    janus::MountInfo info = client.mount_info();

    std::string folder;
#ifdef __APPLE__
    janus::Mount mount = janus::Mount::mount(info);
    folder = mount.path();
#else
    std::cout << "Mount " << info.url << " (user " << info.user << ", password " << info.password
              << ") and enter the folder: ";
    std::getline(std::cin, folder);
#endif

    // A burst of 8 files x 8 MiB.
    for (int i = 0; i < 8; ++i) {
      example::write_test_file(folder + "/burst-" + std::to_string(i) + ".bin", 8u << 20);
    }
    std::cout << "writes finished; the application sees them as done\n";

    // Poll the status. try_status() returns a Result instead of throwing; for a monitoring
    // loop that is often what you want.
    for (;;) {
      auto st = client.try_status();
      if (!st) {
        std::cerr << "status failed: " << st.error().message << "\n";
        break;
      }
      std::cout << "  backlog " << st->journal_backlog_bytes / 1024 << " KiB, uploaded "
                << st->uploaded_bytes_total / 1024 << " KiB, errors " << st->upload_errors
                << ", waiting SMB ops " << st->pending_smb_ops << "\n";
      if (st->journal_backlog_bytes == 0) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    // drain() is the guarantee: on return everything accepted so far is on the receiver.
    auto drained = client.try_drain(std::chrono::seconds(30));
    std::cout << (drained ? "drained: all data is on the receiver\n"
                          : "drain failed: " + drained.error().message + "\n");

#ifdef __APPLE__
    mount.unmount();
#endif
    client.stop();
    return drained ? 0 : 1;
  } catch (const janus::Exception& e) {
    std::cerr << "janus error " << e.code() << ": " << e.what() << "\n";
    return 1;
  }
}

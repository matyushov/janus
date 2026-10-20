// Example 05 — start first, learn the receiver later.
//
// Often the application knows how to reach the receiver only after startup: after login, a
// call to its own backend, a user dialog. janus supports this: start without a `share`, then
// call configure() when the details arrive. Until then ready() reports NotReady with the
// reason; afterwards it turns Ok once the receiver answers over mTLS.
//
// Because the configuration is persisted in state_dir, the next start comes back with the
// same share by itself, so the application only needs to configure on the first run or when
// something changes. The example starts twice to show it.
//
// Needs a receiver (see ../README.md).
#include <janus/janus.hpp>

#include <chrono>
#include <iostream>
#include <thread>

#include "example_util.hpp"

int main(int argc, char** argv) {
  example::Options opt = example::parse_options(argc, argv);
  if (opt.help || !opt.has_receiver()) {
    example::print_receiver_usage(argv[0]);
    return 2;
  }

  try {
    janus::Config config;  // no share
    config.state_dir = opt.state_dir.empty() ? example::make_temp_dir("janus-state") : opt.state_dir;

    {
      janus::Client client = janus::Client::start(config, example::printer(janus::LogLevel::Warn));
      auto r = client.try_ready();
      std::cout << "before configure: " << (r ? "ready" : "not ready (" + r.error().message + ")") << "\n";

      // The receiver details arrive. The CA is PEM text, the certificate and key are files.
      client.configure(example::make_share(opt));

      // The link is established lazily; poll ready() with a deadline.
      auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
      while (!(r = client.try_ready()) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
      }
      std::cout << "after configure: " << (r ? "ready" : "not ready (" + r.error().message + ")") << "\n";
      client.stop();
    }

    {
      // Second start with the same state_dir and NO share: the stored one is restored.
      janus::Client client = janus::Client::start(config, example::printer(janus::LogLevel::Warn));
      std::cout << "after restart, configured from disk: "
                << (client.status().configured ? "yes" : "no") << "\n";
      client.ready();
      std::cout << "ready again without calling configure()\n";
      client.stop();
    }
    return 0;
  } catch (const janus::Exception& e) {
    std::cerr << "janus error " << e.code() << ": " << e.what() << "\n";
    return 1;
  }
}

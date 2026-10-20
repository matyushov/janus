// Small helpers shared by the examples: command line / environment options, a temporary
// directory, CRC-32 and a log printer. Nothing here is part of the janus API.
#pragma once

#include <janus/janus.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace example {

namespace fs = std::filesystem;

/// What the examples that talk to a receiver need. Filled from the command line, with the
/// environment variables written by examples/run-local-receiver.sh as defaults:
///   --endpoint host:port   JANUS_EXAMPLE_ENDPOINT
///   --cert  client.pem     JANUS_EXAMPLE_CERT
///   --key   client.key     JANUS_EXAMPLE_KEY
///   --ca    ca.pem         JANUS_EXAMPLE_CA
///   --state-dir dir        JANUS_EXAMPLE_STATE_DIR   (journal, config, SMB password)
struct Options {
  std::string endpoint, cert, key, ca, state_dir;
  bool help = false;

  bool has_receiver() const { return !endpoint.empty(); }
};

inline std::string env_or(const char* name, const std::string& fallback = {}) {
  const char* v = std::getenv(name);
  return v ? v : fallback;
}

inline std::string read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

inline Options parse_options(int argc, char** argv) {
  Options o;
  o.endpoint = env_or("JANUS_EXAMPLE_ENDPOINT");
  o.cert = env_or("JANUS_EXAMPLE_CERT");
  o.key = env_or("JANUS_EXAMPLE_KEY");
  o.ca = env_or("JANUS_EXAMPLE_CA");
  o.state_dir = env_or("JANUS_EXAMPLE_STATE_DIR");
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : std::string(); };
    if (a == "--endpoint") o.endpoint = next();
    else if (a == "--cert") o.cert = next();
    else if (a == "--key") o.key = next();
    else if (a == "--ca") o.ca = next();
    else if (a == "--state-dir") o.state_dir = next();
    else if (a == "-h" || a == "--help") o.help = true;
    else { std::cerr << "unknown argument: " << a << "\n"; o.help = true; }
  }
  return o;
}

inline void print_receiver_usage(const char* program) {
  std::cout << "usage: " << program
            << " [--endpoint host:port --cert client.pem --key client.key --ca ca.pem]"
               " [--state-dir dir]\n"
               "Without --endpoint the example runs against a local directory (no receiver).\n"
               "To get a receiver on this machine run examples/run-local-receiver.sh and\n"
               "'source' the env file it prints.\n";
}

/// The share configuration for the options (the CA file is read here: janus wants PEM text).
inline janus::Share make_share(const Options& o) {
  janus::Share s;
  s.appliance_endpoint = o.endpoint;
  s.client_cert_path = o.cert;
  s.client_key_path = o.key;
  s.ca_pem = read_file(o.ca);
  s.share_name = "backup";
  return s;
}

/// A fresh directory under the system temp directory (portable: no mkdtemp). Exits the
/// program on failure, which keeps the helper usable without exceptions.
inline std::string make_temp_dir(const std::string& prefix) {
  std::random_device rd;
  std::error_code ec;
  fs::path base = fs::temp_directory_path(ec);
  for (int attempt = 0; attempt < 100 && !ec; ++attempt) {
    fs::path dir = base / (prefix + "-" + std::to_string(rd()));
    if (fs::create_directories(dir, ec) && !ec) return dir.string();
  }
  std::fprintf(stderr, "cannot create a temporary directory\n");
  std::exit(1);
}

inline std::uint32_t crc32_update(std::uint32_t crc, const void* data, std::size_t n) {
  static std::uint32_t table[256];
  static bool ready = false;
  if (!ready) {
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
      table[i] = c;
    }
    ready = true;
  }
  crc = ~crc;
  auto* p = static_cast<const unsigned char*>(data);
  for (std::size_t i = 0; i < n; ++i) crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
  return ~crc;
}

inline std::uint32_t crc32_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  std::vector<char> buf(1 << 20);
  std::uint32_t crc = 0;
  while (f) {
    f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    crc = crc32_update(crc, buf.data(), static_cast<std::size_t>(f.gcount()));
  }
  return crc;
}

/// Deterministic pseudo-random test file of `bytes` bytes.
inline std::uint32_t write_test_file(const std::string& path, std::size_t bytes) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  std::vector<char> buf(1 << 20);
  std::uint64_t x = 0x9E3779B97F4A7C15ull ^ bytes;
  std::uint32_t crc = 0;
  for (std::size_t done = 0; done < bytes;) {
    std::size_t n = std::min(buf.size(), bytes - done);
    for (std::size_t i = 0; i < n; ++i) {
      x ^= x << 13; x ^= x >> 7; x ^= x << 17;  // xorshift64
      buf[i] = static_cast<char>(x);
    }
    f.write(buf.data(), static_cast<std::streamsize>(n));
    crc = crc32_update(crc, buf.data(), n);
    done += n;
  }
  f.flush();
  return crc;
}

inline const char* level_name(janus::LogLevel l) {
  switch (l) {
    case janus::LogLevel::Debug: return "DEBUG";
    case janus::LogLevel::Info: return "INFO ";
    case janus::LogLevel::Warn: return "WARN ";
    default: return "ERROR";
  }
}

/// A log callback that prints Info and above, prefixed so it stands out from the example's own
/// output. It runs on a library thread; printing is all it does.
inline janus::LogCallback printer(janus::LogLevel min = janus::LogLevel::Info) {
  return [min](janus::LogLevel level, std::string_view component, std::string_view message) {
    if (level < min) return;
    std::fprintf(stderr, "  [janus %s %.*s] %.*s\n", level_name(level),
                 static_cast<int>(component.size()), component.data(),
                 static_cast<int>(message.size()), message.data());
  };
}

}  // namespace example


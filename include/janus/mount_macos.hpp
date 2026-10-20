// janus/mount_macos.hpp — mount the client's SMB share on macOS with NetFS (optional helper).
//
// A separate header so that janus.hpp does not depend on platform frameworks. Link the
// frameworks NetFS and CoreFoundation (the CMake target janus::mount_macos does it).
// On other platforms the application mounts MountInfo itself (net use, mount.cifs, …).
//
// Local Network privacy: on macOS 15+ the app that mounts needs the "Local Network"
// permission. It is granted to the application that embeds libjanus, not to the library.
#pragma once

#ifndef __APPLE__
#error "janus/mount_macos.hpp is for macOS only; mount MountInfo with your platform's tools"
#endif

#include <CoreFoundation/CoreFoundation.h>
#include <NetFS/NetFS.h>
#include <sys/mount.h>

#include <cerrno>
#include <climits>

#include <string>
#include <utility>

#include <janus/janus.hpp>

namespace janus {

namespace detail {

struct CFStr {
  CFStringRef ref;
  explicit CFStr(const std::string& s)
      : ref(CFStringCreateWithBytes(nullptr, reinterpret_cast<const UInt8*>(s.data()),
                                    static_cast<CFIndex>(s.size()), kCFStringEncodingUTF8, false)) {}
  ~CFStr() { if (ref) CFRelease(ref); }
  CFStr(const CFStr&) = delete;
  CFStr& operator=(const CFStr&) = delete;
};

}  // namespace detail

/// A mounted share. Move-only; the destructor unmounts.
class Mount {
 public:
  Mount() = default;
  Mount(Mount&& o) noexcept : path_(std::move(o.path_)) { o.path_.clear(); }
  Mount& operator=(Mount&& o) noexcept {
    if (this != &o) {
      (void)try_unmount();
      path_ = std::move(o.path_);
      o.path_.clear();
    }
    return *this;
  }
  Mount(const Mount&) = delete;
  Mount& operator=(const Mount&) = delete;
  ~Mount() { (void)try_unmount(); }

  /// Mount `info` at the existing directory `mount_dir` (an empty string lets macOS pick
  /// /Volumes/<share>). Blocks until the mount is done.
  static Result<Mount> try_mount(const MountInfo& info, const std::string& mount_dir = {}) {
    detail::CFStr url_s(info.url), user(info.user), pass(info.password);
    CFURLRef url = CFURLCreateWithString(nullptr, url_s.ref, nullptr);
    if (!url) return Error{Error::InvalidArg, "invalid mount URL " + info.url};

    CFURLRef dir = nullptr;
    CFMutableDictionaryRef open_opts = nullptr;
    if (!mount_dir.empty()) {
      detail::CFStr dir_s(mount_dir);
      dir = CFURLCreateWithFileSystemPath(nullptr, dir_s.ref, kCFURLPOSIXPathStyle, true);
      // Mount exactly at that directory instead of under /Volumes.
      open_opts = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                            &kCFTypeDictionaryValueCallBacks);
      CFDictionarySetValue(open_opts, kNetFSMountAtMountDirKey, kCFBooleanTrue);
    }
    CFArrayRef mountpoints = nullptr;
    int rc = NetFSMountURLSync(url, dir, user.ref, pass.ref, open_opts, nullptr, &mountpoints);
    CFRelease(url);
    if (dir) CFRelease(dir);
    if (open_opts) CFRelease(open_opts);

    // 0 = mounted; EEXIST = it is already mounted (the mount point is still returned).
    if (rc != 0 && rc != EEXIST) {
      if (mountpoints) CFRelease(mountpoints);
      return Error{Error::Internal, "NetFSMountURLSync failed with code " + std::to_string(rc)};
    }
    Mount m;
    if (mountpoints && CFArrayGetCount(mountpoints) > 0) {
      auto first = static_cast<CFStringRef>(CFArrayGetValueAtIndex(mountpoints, 0));
      char buf[PATH_MAX];
      if (CFStringGetCString(first, buf, sizeof buf, kCFStringEncodingUTF8)) m.path_ = buf;
    }
    if (mountpoints) CFRelease(mountpoints);
    if (m.path_.empty()) return Error{Error::Internal, "NetFS returned no mount point"};
    return m;
  }
  static Ret<Mount> mount(const MountInfo& info, const std::string& mount_dir = {}) {
    JANUS_RETURN(try_mount(info, mount_dir));
  }

  /// Where the share is mounted.
  const std::string& path() const noexcept { return path_; }
  bool mounted() const noexcept { return !path_.empty(); }

  /// Unmount (`force` also drops open files). Safe to call twice.
  Result<void> try_unmount(bool force = false) {
    if (path_.empty()) return {};
    if (::unmount(path_.c_str(), force ? MNT_FORCE : 0) != 0) {
      return Error{Error::Internal, "unmount " + path_ + " failed: errno " + std::to_string(errno)};
    }
    path_.clear();
    return {};
  }
  Ret<void> unmount(bool force = false) { JANUS_RETURN(try_unmount(force)); }

 private:
  std::string path_;
};

}  // namespace janus


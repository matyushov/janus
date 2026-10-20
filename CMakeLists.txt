# janus client SDK (libjanus): builds the Rust crate `janus-ffi` with cargo and exposes it as
# CMake targets, and installs a relocatable package:
#
#   cmake -S . -B build && cmake --build build && cmake --install build --prefix /opt/janus
#
#   # in an application:
#   find_package(janus CONFIG REQUIRED)
#   target_link_libraries(app PRIVATE janus::client_static)   # or janus::client_shared
#
# Targets (the same names in this build tree and in the installed package):
#   janus::client_static  libjanus.a + the system libraries it needs + headers
#   janus::client_shared  libjanus.dylib / .so / .dll + headers
#   janus::mount_macos    (macOS only) frameworks for <janus/mount_macos.hpp>
cmake_minimum_required(VERSION 3.20)
project(janus VERSION 0.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(JANUS_BUILD_EXAMPLES "Build the examples/ directory" OFF)
set(JANUS_CARGO_PROFILE "release" CACHE STRING "cargo profile of libjanus: release or debug")

# ---- build libjanus with cargo -------------------------------------------------------------
find_program(JANUS_CARGO cargo HINTS "$ENV{HOME}/.cargo/bin" "$ENV{CARGO_HOME}/bin")
if(NOT JANUS_CARGO)
  message(FATAL_ERROR "cargo not found: install Rust (https://rustup.rs); the toolchain is pinned by rust-toolchain.toml")
endif()

set(JANUS_CARGO_DIR "${CMAKE_BINARY_DIR}/cargo")
if(JANUS_CARGO_PROFILE STREQUAL "release")
  set(_cargo_profile_flag --release)
endif()
set(_out "${JANUS_CARGO_DIR}/${JANUS_CARGO_PROFILE}")

if(WIN32)
  set(_static "${_out}/janus.lib")
  set(_shared "${_out}/janus.dll")
  set(_implib "${_out}/janus.dll.lib")
elseif(APPLE)
  set(_static "${_out}/libjanus.a")
  set(_shared "${_out}/libjanus.dylib")
else()
  set(_static "${_out}/libjanus.a")
  set(_shared "${_out}/libjanus.so")
endif()

# cargo is incremental: running it every build is a no-op when nothing changed.
add_custom_target(janus_cargo ALL
  COMMAND "${JANUS_CARGO}" build -p janus-ffi ${_cargo_profile_flag} --target-dir "${JANUS_CARGO_DIR}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  BYPRODUCTS "${_static}" "${_shared}"
  COMMENT "cargo build -p janus-ffi (${JANUS_CARGO_PROFILE})"
  VERBATIM)

# The C header is generated from crates/janus-ffi/src/lib.rs by cbindgen (not committed).
# By hand:  cargo run -p janus-ffi --example gen_header -- <dir>/janus/janus.h
set(JANUS_GEN_INCLUDE "${CMAKE_BINARY_DIR}/include")
set(JANUS_HEADER "${JANUS_GEN_INCLUDE}/janus/janus.h")
add_custom_command(OUTPUT "${JANUS_HEADER}"
  COMMAND "${JANUS_CARGO}" run -q -p janus-ffi ${_cargo_profile_flag} --example gen_header
          --target-dir "${JANUS_CARGO_DIR}" -- "${JANUS_HEADER}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  DEPENDS crates/janus-ffi/src/lib.rs crates/janus-ffi/cbindgen.toml crates/janus-ffi/examples/gen_header.rs
  COMMENT "cbindgen: janus.h"
  VERBATIM)
add_custom_target(janus_header ALL DEPENDS "${JANUS_HEADER}")

# System libraries the static library needs (`cargo rustc -p janus-ffi --release --
# --print native-static-libs`). macOS was checked locally; Linux/Windows are the values rustc
# reports for these targets and are verified by CI.
if(APPLE)
  set(JANUS_NATIVE_LIBS iconv m)
elseif(WIN32)
  set(JANUS_NATIVE_LIBS ws2_32 userenv bcrypt ntdll advapi32 kernel32 synchronization)
else()
  set(JANUS_NATIVE_LIBS gcc_s util rt pthread m dl c)
endif()

add_library(janus_client_static INTERFACE)
add_library(janus::client_static ALIAS janus_client_static)
target_include_directories(janus_client_static INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include" "${JANUS_GEN_INCLUDE}")
target_link_libraries(janus_client_static INTERFACE "${_static}" ${JANUS_NATIVE_LIBS})
target_compile_features(janus_client_static INTERFACE cxx_std_17)
add_dependencies(janus_client_static janus_cargo janus_header)

add_library(janus_client_shared INTERFACE)
add_library(janus::client_shared ALIAS janus_client_shared)
target_include_directories(janus_client_shared INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include" "${JANUS_GEN_INCLUDE}")
if(WIN32)
  target_link_libraries(janus_client_shared INTERFACE "${_implib}")
else()
  target_link_libraries(janus_client_shared INTERFACE "${_shared}")
endif()
target_compile_definitions(janus_client_shared INTERFACE JANUS_SHARED)
target_compile_features(janus_client_shared INTERFACE cxx_std_17)
add_dependencies(janus_client_shared janus_cargo janus_header)

if(APPLE)
  add_library(janus_mount_macos INTERFACE)
  add_library(janus::mount_macos ALIAS janus_mount_macos)
  target_link_libraries(janus_mount_macos INTERFACE "-framework NetFS" "-framework CoreFoundation")
endif()

# ---- install --------------------------------------------------------------------------------
install(DIRECTORY include/janus DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}" FILES_MATCHING PATTERN "*.hpp")
install(FILES "${JANUS_HEADER}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/janus")
install(FILES "${_static}" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
if(WIN32)
  install(FILES "${_shared}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
  install(FILES "${_implib}" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
else()
  install(FILES "${_shared}" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

set(JANUS_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/janus")
configure_package_config_file(cmake/janus-config.cmake.in "${CMAKE_BINARY_DIR}/janus-config.cmake"
  INSTALL_DESTINATION "${JANUS_INSTALL_CMAKEDIR}"
  PATH_VARS CMAKE_INSTALL_INCLUDEDIR CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_BINDIR)
write_basic_package_version_file("${CMAKE_BINARY_DIR}/janus-config-version.cmake"
  VERSION "${PROJECT_VERSION}" COMPATIBILITY SameMajorVersion ARCH_INDEPENDENT)
install(FILES "${CMAKE_BINARY_DIR}/janus-config.cmake" "${CMAKE_BINARY_DIR}/janus-config-version.cmake"
  DESTINATION "${JANUS_INSTALL_CMAKEDIR}")

# pkg-config: janus.pc (shared) and janus-static.pc (static + its system libraries)
set(_pc_libs "")
foreach(l ${JANUS_NATIVE_LIBS})
  string(APPEND _pc_libs " -l${l}")
endforeach()
set(JANUS_PC_PRIVATE_LIBS "${_pc_libs}")
if(APPLE)
  set(JANUS_PC_MOUNT_LIBS "-framework NetFS -framework CoreFoundation")
endif()
configure_file(cmake/janus.pc.in "${CMAKE_BINARY_DIR}/janus.pc" @ONLY)
configure_file(cmake/janus-static.pc.in "${CMAKE_BINARY_DIR}/janus-static.pc" @ONLY)
install(FILES "${CMAKE_BINARY_DIR}/janus.pc" "${CMAKE_BINARY_DIR}/janus-static.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

if(JANUS_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

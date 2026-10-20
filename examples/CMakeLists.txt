# Examples of embedding libjanus into a C++ application, statically linked.
#
# Build (from the repository root; the library is built from source with cargo):
#   cmake -S examples -B build/examples && cmake --build build/examples
#
# Build against an installed package instead:
#   cmake -S examples -B build/examples -DCMAKE_PREFIX_PATH=/opt/janus
#
# Each example's README says how to run it.
cmake_minimum_required(VERSION 3.20)
project(janus_examples LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The installed package if there is one; else the library is built from this checkout.
if(NOT TARGET janus::client_static)
  find_package(janus CONFIG QUIET)
endif()
if(NOT TARGET janus::client_static)
  message(STATUS "janus package not found: building libjanus from ${CMAKE_CURRENT_SOURCE_DIR}/..")
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/.." "${CMAKE_BINARY_DIR}/libjanus")
endif()

include(CheckCXXCompilerFlag)

# One helper for all examples: executable + static janus (+ the macOS mount helper).
function(janus_example name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE common)
  # STATIC: libjanus is part of the executable; nothing to ship or find at run time.
  target_link_libraries(${name} PRIVATE janus::client_static)
  if(APPLE)
    target_link_libraries(${name} PRIVATE janus::mount_macos)
  endif()
  if(MSVC)
    target_compile_options(${name} PRIVATE /W4)
  else()
    target_compile_options(${name} PRIVATE -Wall -Wextra)
  endif()
endfunction()

janus_example(01_hello_embed 01-hello-embed/main.cpp)
janus_example(02_mount_and_copy 02-mount-and-copy/main.cpp)
janus_example(03_backup_progress 03-backup-progress/main.cpp)
janus_example(04_no_exceptions 04-no-exceptions/main.cpp)
janus_example(05_configure_later 05-configure-later/main.cpp)

# Example 04 demonstrates a build without exceptions, if the compiler can do it.
check_cxx_compiler_flag(-fno-exceptions JANUS_HAVE_NO_EXCEPTIONS)
if(JANUS_HAVE_NO_EXCEPTIONS)
  target_compile_options(04_no_exceptions PRIVATE -fno-exceptions)
endif()

cmake_minimum_required(VERSION 3.22)

project(aavjni CXX)

# Build the engine (static libaav, with APK/miniz support) from the repo root.
# The CLI, tooling, tests and fuzzers are host-only, so disable them here.
get_filename_component(AAV_ROOT
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../../.." ABSOLUTE)
set(AAV_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(AAV_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(AAV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(AAV_BUILD_FUZZERS OFF CACHE BOOL "" FORCE)
set(AAV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(AAV_INSTALL OFF CACHE BOOL "" FORCE)
set(AAV_ENABLE_APK ON CACHE BOOL "" FORCE)
add_subdirectory("${AAV_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/aav")

# The JNI bridge is a pure consumer of the public SDK facade (include/aav),
# obtained transitively from libaav. APK unpacking and directory traversal
# happen inside the engine, so the bridge carries no engine internals. liblog is
# propagated transitively (PUBLIC) by libaav on Android, so it needs no separate
# find_library here.
add_library(aavjni SHARED
  aavjni.cc
  jniutil.cc
)
target_link_libraries(aavjni PRIVATE aav)

# 3.21 is the CMakePresets.json schema v3, which CMake reads only from 3.21.
# Nothing else in this file needs more than 3.13, so CMakePresets.json alone
# sets the floor. v3 is what lets a preset omit "generator" and inherit the
# platform default; on schema v2 (3.20) that field is required, so every preset
# would hard-code Ninja or Makefiles. Dropping presets is therefore what
# lowering the floor would cost.
cmake_minimum_required(VERSION 3.21)

project(anti_android_virus
  VERSION 0.1.0
  DESCRIPTION "Efficient Android malware static detection engine (DEX)"
  LANGUAGES C CXX)

option(AAV_BUILD_CLI   "Build the aavscan CLI executable" ON)
option(AAV_BUILD_TOOLS "Build sigtool (feature/DB tooling)" ON)
option(AAV_BUILD_TESTS "Build unit tests" OFF)
option(AAV_ENABLE_APK    "Enable APK (zip) scanning via miniz" ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# ---------------------------------------------------------------------------
# Warnings. Applied per target rather than globally, because third_party/ is
# vendored verbatim -- miniz and doctest are not ours to fix, and their
# diagnostics would bury ours. Each subtree calls this on the targets it owns;
# the vendored sources are silenced where they are compiled or included.
# ---------------------------------------------------------------------------
function(aav_apply_warnings tgt)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # -Wall -Wextra only: no -Werror. A warning should stop the person who
    # wrote it, not whoever next builds on a compiler one version newer, which
    # is what -Werror means for a project built by three of them (gcc, distro
    # clang, Apple clang).
    target_compile_options(${tgt} PRIVATE -Wall -Wextra)
  elseif(MSVC)
    target_compile_options(${tgt} PRIVATE /W4)
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Dependencies. zlib inflates the signature database, which is gzip-compressed
# inside its encryption.
# ---------------------------------------------------------------------------
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Optional APK (zip) support via miniz. miniz is compiled straight into the
# engine library, so the shipped .a is self-contained. MINIZ_DIR and
# AAV_MINIZ_AVAILABLE are consumed by src/ (engine) and apps/ (sample fixtures).
# ---------------------------------------------------------------------------
set(AAV_MINIZ_AVAILABLE FALSE)
set(MINIZ_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/miniz")
if(AAV_ENABLE_APK AND EXISTS "${MINIZ_DIR}/miniz.c")
  set(AAV_MINIZ_AVAILABLE TRUE)
elseif(AAV_ENABLE_APK)
  message(WARNING
    "AAV_ENABLE_APK is ON but ${MINIZ_DIR}/miniz.c was not found; "
    "APK/zip scanning will be disabled.")
endif()

# ---------------------------------------------------------------------------
# Targets: the engine (src/) and its consumers (apps/, tests/). Each subtree
# owns its own target definitions.
# ---------------------------------------------------------------------------
add_subdirectory(src)
add_subdirectory(apps)

if(AAV_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

message(STATUS "aav: APK/zip support (miniz): ${AAV_MINIZ_AVAILABLE}")
message(STATUS "aav: build tools: ${AAV_BUILD_TOOLS}  tests: ${AAV_BUILD_TESTS}")

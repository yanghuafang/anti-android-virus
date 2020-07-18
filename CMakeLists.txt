# Two different numbers, and the larger one wins:
#   3.13  the newest command used in this file (target_link_options)
#   3.21  the CMakePresets.json schema, v3, which CMake reads only from 3.21
# So the floor is 3.21 and CMakePresets.json alone sets it. v3 is what lets a
# preset omit "generator" and inherit the platform default; on schema v2 (3.20)
# that field is required, so every preset would hard-code Ninja or Makefiles.
# Dropping presets is therefore what lowering the floor to 3.13 would cost.
cmake_minimum_required(VERSION 3.21)

project(anti_android_virus
  VERSION 0.1.0
  DESCRIPTION "Efficient Android malware static detection engine (DEX)"
  LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(AAV_BUILD_CLI     "Build the aavscan CLI executable" ON)
option(AAV_BUILD_TOOLS   "Build sigtool (feature/DB tooling)" ON)
option(AAV_BUILD_TESTS   "Build unit tests" OFF)
option(AAV_BUILD_FUZZERS "Build libFuzzer harnesses (clang only)" OFF)
option(AAV_ENABLE_APK    "Enable APK (zip) scanning via miniz" ON)
option(AAV_BUILD_SHARED  "Build the shared engine library (.so/.dylib)" ON)
option(AAV_ENABLE_COVERAGE "Instrument for code coverage (--coverage)" OFF)
option(AAV_ENABLE_ASAN "Instrument with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(AAV_ENABLE_TSAN "Instrument with ThreadSanitizer" OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(AAV_DEFAULT_INSTALL ON)
else()
  set(AAV_DEFAULT_INSTALL OFF)
endif()
option(AAV_INSTALL "Generate install rules for the aav SDK" ${AAV_DEFAULT_INSTALL})

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
    # is what -Werror means for a project built by four of them (gcc, distro
    # clang, Apple clang, the NDK's).
    target_compile_options(${tgt} PRIVATE -Wall -Wextra)
  elseif(MSVC)
    target_compile_options(${tgt} PRIVATE /W4)
  endif()
endfunction()

# ---------------------------------------------------------------------------
# AddressSanitizer + UndefinedBehaviorSanitizer. Global, like coverage below:
# the engine and everything that drives it have to agree, since a partly
# instrumented link is either a link error or a false report.
#
# Global is also what the `asan` preset could not express when it set
# CMAKE_CXX_FLAGS by hand: that reaches C++ only, so miniz.c -- the one C file
# in the build, and the one parsing attacker-controlled zip data -- was the
# single translation unit ASan never covered.
#
# -fno-sanitize-recover=all is what makes the build worth running in CI. UBSan
# defaults to printing a diagnostic and continuing, so an overflow left the
# process exit status at 0 and ctest reported a pass; aborting turns a finding
# into a failed test. ASan already aborts.
# ---------------------------------------------------------------------------
if(AAV_ENABLE_ASAN)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "AAV_ENABLE_ASAN needs GCC or Clang (have ${CMAKE_CXX_COMPILER_ID})")
  endif()
  if(AAV_ENABLE_TSAN)
    message(FATAL_ERROR "AAV_ENABLE_ASAN and AAV_ENABLE_TSAN cannot both be on: "
                        "the two runtimes cannot be linked into one binary. Use "
                        "the asan and tsan presets separately.")
  endif()
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all
                      -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------------------
# ThreadSanitizer, for the scan thread pool in src/engine/engine.cc. Global for
# the same reason ASan is: TSan only sees a race if both sides of it were
# instrumented, and the engine and the tests that drive it are separate targets.
#
# Its own option rather than a mode of AAV_ENABLE_ASAN because the two runtimes
# are mutually exclusive at link time -- hence the guard above.
#
# There is no -fno-sanitize-recover=all here, unlike ASan/UBSan: TSan is not one
# of the sanitizers that flag reaches. A race is reported and the process keeps
# going, so the abort has to come from TSAN_OPTIONS=halt_on_error=1, which the
# tsan test preset sets.
# ---------------------------------------------------------------------------
if(AAV_ENABLE_TSAN)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "AAV_ENABLE_TSAN needs GCC or Clang (have ${CMAKE_CXX_COMPILER_ID})")
  endif()
  add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=thread)
endif()

# ---------------------------------------------------------------------------
# Code coverage (gcov/llvm-cov via --coverage), applied globally so the engine
# library and the tests that drive it are both instrumented. Report via
# scripts/coverage.sh (gcovr).
# ---------------------------------------------------------------------------
if(AAV_ENABLE_COVERAGE)
  add_compile_options(--coverage -O0 -g)
  add_link_options(--coverage)
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Optional APK (zip) support via miniz. miniz is compiled straight into the
# engine libraries, so the shipped .a / .so are self-contained. MINIZ_DIR and
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
# Targets: the engine (src/) and its consumers (apps/, tests/, fuzz/). Each
# subtree owns its own target definitions.
# ---------------------------------------------------------------------------
add_subdirectory(src)
add_subdirectory(apps)

if(AAV_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(AAV_BUILD_FUZZERS)
  add_subdirectory(fuzz)
endif()

# ---------------------------------------------------------------------------
# Install / SDK packaging: public headers + static + shared + CMake config so
# consumers can `find_package(aav)` and link `aav::aav` (static) or
# `aav::shared`.
# ---------------------------------------------------------------------------
if(AAV_INSTALL)
  set(AAV_INSTALL_TARGETS aav)
  if(AAV_BUILD_SHARED)
    list(APPEND AAV_INSTALL_TARGETS aav_shared)
  endif()

  install(TARGETS ${AAV_INSTALL_TARGETS}
    EXPORT aavTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

  # Public interface headers only (include/aav/*.h -> <prefix>/include/aav/).
  install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/aav
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h")

  install(EXPORT aavTargets
    FILE aavTargets.cmake
    NAMESPACE aav::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/aav)
  configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/aavConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/aavConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/aav)
  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/aavConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/aavConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/aavConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/aav)
endif()

message(STATUS "aav: APK/zip support (miniz): ${AAV_MINIZ_AVAILABLE}")
message(STATUS "aav: shared library: ${AAV_BUILD_SHARED}  install rules: ${AAV_INSTALL}")
message(STATUS "aav: build tools: ${AAV_BUILD_TOOLS}  tests: ${AAV_BUILD_TESTS}")
message(STATUS "aav: asan+ubsan: ${AAV_ENABLE_ASAN}  tsan: ${AAV_ENABLE_TSAN}  coverage: ${AAV_ENABLE_COVERAGE}")

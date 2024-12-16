cmake_minimum_required(VERSION 3.20)

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

# Unit tests (doctest, vendored single header)
add_executable(aav_unit_tests
  unit/test_main.cc
  unit/test_crc32.cc
  unit/test_leb128.cc
  unit/test_actree.cc
  unit/test_pathlogic.cc
  unit/test_dexparse.cc
  unit/test_blowfish.cc
  unit/test_gzip.cc
  unit/test_log.cc
  unit/test_platform.cc
  unit/test_detection.cc)
# White-box tests drive internal components directly, so they need the engine
# and its internal header paths, not a public surface.
aav_apply_warnings(aav_unit_tests)
target_link_libraries(aav_unit_tests PRIVATE aav aav_internal)
# tests/ is the root for the suite's own headers: "unit/test_support.h".
target_include_directories(aav_unit_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR})
# doctest is vendored and included by every test file; SYSTEM keeps -Wall
# -Wextra from reporting the header once per translation unit.
target_include_directories(aav_unit_tests SYSTEM PRIVATE
  ${PROJECT_SOURCE_DIR}/third_party/doctest)
add_test(NAME unit COMMAND aav_unit_tests)

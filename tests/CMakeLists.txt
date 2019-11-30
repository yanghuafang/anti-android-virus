# Two kinds of test live here: unit/ holds the doctest white-box tests (one
# aav_unit_tests binary), e2e/ holds the end-to-end drivers that generate a
# sample with sigtool and scan it with aavscan.

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
  unit/test_fileid.cc
  unit/test_log.cc
  unit/test_platform.cc
  unit/test_detection.cc
  unit/test_sigmgr.cc
  unit/test_engine.cc)
# White-box tests drive internal components directly: aav_internal supplies the
# internal header paths, sigtool_sample the shared DB/DEX fixtures (and
# transitively the engine and zlib).
aav_apply_warnings(aav_unit_tests)
target_link_libraries(aav_unit_tests PRIVATE aav_internal sigtool_sample)
# tests/ is the root for the suite's own headers: "unit/test_support.h".
target_include_directories(aav_unit_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR})
# doctest is vendored and included by every test file; SYSTEM keeps -Wall
# -Wextra from reporting the header once per translation unit.
target_include_directories(aav_unit_tests SYSTEM PRIVATE
  ${PROJECT_SOURCE_DIR}/third_party/doctest)
add_test(NAME unit COMMAND aav_unit_tests)

# End-to-end golden test: sigtool generates a sample, aavscan must detect it.
if(TARGET sigtool AND TARGET aavscan)
  add_test(NAME e2e_sample COMMAND ${CMAKE_COMMAND}
    -DSIGTOOL=$<TARGET_FILE:sigtool>
    -DAAVSCAN=$<TARGET_FILE:aavscan>
    -DWORKDIR=${CMAKE_CURRENT_BINARY_DIR}/sample_e2e
    -P ${CMAKE_CURRENT_SOURCE_DIR}/e2e/scan_sample.cmake)
endif()

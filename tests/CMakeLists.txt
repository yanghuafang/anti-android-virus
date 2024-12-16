# Two kinds of test live here: unit/ holds the doctest white-box tests (one
# aav_unit_tests binary), e2e/ holds the end-to-end drivers that generate a
# sample with sigtool and scan it with aavscan / the mem checker.

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
  unit/test_dexanalysis.cc
  unit/test_log.cc
  unit/test_platform.cc
  unit/test_detection.cc
  unit/test_sigmgr.cc
  unit/test_apkscanner.cc
  unit/test_engine.cc)
# White-box unit tests drive internal components directly; aav_internal supplies
# the engine's internal header search paths, and sigtool_sample provides the
# shared in-memory DB/DEX/APK fixtures (and, transitively, the aav engine, zlib,
# and the AAV_HAVE_MINIZ definition).
target_link_libraries(aav_unit_tests PRIVATE aav_internal sigtool_sample)
target_include_directories(aav_unit_tests PRIVATE
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

# Memory-scan e2e: the same sample is scanned entirely from RAM via
# IEngine::ScanBuffer -- the DEX directly, and an APK assembled in-memory (miniz)
# unpacked internally. Exercises MemStream (apk id) + MemTarget (dex) paths.
if(TARGET sigtool AND AAV_MINIZ_AVAILABLE)
  add_executable(aav_memscan_check e2e/mem_scan_check.cc)
  target_link_libraries(aav_memscan_check PRIVATE aav)
  add_test(NAME e2e_memscan COMMAND ${CMAKE_COMMAND}
    -DSIGTOOL=$<TARGET_FILE:sigtool>
    -DMEMSCAN=$<TARGET_FILE:aav_memscan_check>
    -DWORKDIR=${CMAKE_CURRENT_BINARY_DIR}/mem_e2e
    -P ${CMAKE_CURRENT_SOURCE_DIR}/e2e/scan_sample_mem.cmake)
endif()

# Multidex e2e: an APK with classes.dex + classes2.dex must have both members
# unpacked and scanned (requires the APK scanner's miniz support).
if(TARGET sigtool AND TARGET aavscan AND AAV_MINIZ_AVAILABLE)
  add_test(NAME e2e_multidex COMMAND ${CMAKE_COMMAND}
    -DSIGTOOL=$<TARGET_FILE:sigtool>
    -DAAVSCAN=$<TARGET_FILE:aavscan>
    -DWORKDIR=${CMAKE_CURRENT_BINARY_DIR}/multidex_e2e
    -P ${CMAKE_CURRENT_SOURCE_DIR}/e2e/scan_multidex.cmake)
endif()

# Directory + multi-threaded e2e: aavscan --mt walks a directory of DEX files
# across worker threads. Exercises directory traversal, per-worker scanner sets,
# the atomic work queue, and serialized callbacks.
if(TARGET sigtool AND TARGET aavscan)
  add_test(NAME e2e_multithread COMMAND ${CMAKE_COMMAND}
    -DSIGTOOL=$<TARGET_FILE:sigtool>
    -DAAVSCAN=$<TARGET_FILE:aavscan>
    -DWORKDIR=${CMAKE_CURRENT_BINARY_DIR}/mt_e2e
    -P ${CMAKE_CURRENT_SOURCE_DIR}/e2e/scan_dir.cmake)
endif()

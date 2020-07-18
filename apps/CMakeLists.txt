# ---------------------------------------------------------------------------
# CLI scanner -- a thin, pure consumer of the public engine facade (include/).
# ---------------------------------------------------------------------------
if(AAV_BUILD_CLI)
  add_executable(aavscan aavscan/aavscan.cc)
  aav_apply_warnings(aavscan)
  target_link_libraries(aavscan PRIVATE aav)
endif()

# ---------------------------------------------------------------------------
# Sample-fixture generator (DEX + signature DB + APK). Uses engine internals
# (crc32/blowfish, the on-disk structs); shared by sigtool and the unit tests so
# the two cannot drift.
# ---------------------------------------------------------------------------
if(AAV_BUILD_TOOLS OR AAV_BUILD_TESTS)
  add_library(sigtool_sample STATIC
    sigtool/sample_data.cc
    sigtool/sample_apk.cc)
  # apps/ is the root, so the fixture header is "sigtool/sample_data.h".
  aav_apply_warnings(sigtool_sample)
  target_include_directories(sigtool_sample
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(sigtool_sample
    PUBLIC aav
    PRIVATE aav_internal ZLIB::ZLIB)
  if(AAV_MINIZ_AVAILABLE)
    target_include_directories(sigtool_sample SYSTEM PRIVATE "${MINIZ_DIR}")
    target_compile_definitions(sigtool_sample PUBLIC AAV_HAVE_MINIZ)
  endif()
endif()

if(AAV_BUILD_TOOLS)
  add_executable(sigtool sigtool/sigtool.cc)
  aav_apply_warnings(sigtool)
  target_link_libraries(sigtool PRIVATE sigtool_sample)
endif()

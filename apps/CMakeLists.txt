# ---------------------------------------------------------------------------
# CLI scanner -- a thin, pure consumer of the public engine facade (include/).
# ---------------------------------------------------------------------------
if(AAV_BUILD_CLI)
  add_executable(aavscan aavscan/aavscan.cc)
  target_link_libraries(aavscan PRIVATE aav)
endif()

# ---------------------------------------------------------------------------
# Sample-fixture generator (DEX + signature DB + APK). Coupled to engine
# internals (crc32/blowfish, dex + sig on-disk structs); shared by sigtool and
# the unit tests so the two never drift apart.
# ---------------------------------------------------------------------------
if(AAV_BUILD_TOOLS OR AAV_BUILD_TESTS)
  add_library(sigtool_sample STATIC
    sigtool/sample_data.cc
    sigtool/sample_apk.cc)
  target_include_directories(sigtool_sample
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/sigtool)
  target_link_libraries(sigtool_sample
    PUBLIC aav
    PRIVATE aav_internal ZLIB::ZLIB)
  if(AAV_MINIZ_AVAILABLE)
    target_include_directories(sigtool_sample PRIVATE "${MINIZ_DIR}")
    target_compile_definitions(sigtool_sample PUBLIC AAV_HAVE_MINIZ)
  endif()
endif()

if(AAV_BUILD_TOOLS)
  add_executable(sigtool sigtool/sigtool.cc)
  target_link_libraries(sigtool PRIVATE sigtool_sample)
endif()

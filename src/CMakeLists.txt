# ---------------------------------------------------------------------------
# Core engine library. Static for now; the layers land on top of these
# primitives.
# ---------------------------------------------------------------------------
set(AAV_SOURCES
  platform/libplatform_export.cc
  platform/file_map.cc
  platform/file_system.cc
  platform/file_stream.cc
  platform/file_target.cc
  platform/mem_stream.cc
  platform/mem_target.cc
  platform/module.cc
  utils/crc32.cc
  utils/log.cc
  utils/leb128.cc
  utils/blowfish.cc
  utils/file_uncompress.cc
  sig/sig_mgr.cc
  sig/libsigmgr_export.cc
  scan/file_id.cc
  scan/libfileid_export.cc
  scan/apk_scanner.cc
  scan/libapk_export.cc
  dex/libdex_export.cc
  dex/dex_sig_mgr.cc
  dex/dex_path_sig_mgr.cc
  dex/dex_code_sig_mgr.cc
  dex/dex_path_scan_result.cc
  dex/dex_path_scan_result_mgr.cc
  dex/dex_code_scan_result.cc
  dex/dex_code_scan_result_mgr.cc
  dex/dex_parser.cc
  dex/dex_file.cc
  dex/dex_code.cc
  dex/dex_scanner.cc
  dex/ac_matcher.cc
  engine/engine.cc
  engine/object.cc
)
if(AAV_MINIZ_AVAILABLE)
  list(APPEND AAV_SOURCES "${MINIZ_DIR}/miniz.c")
endif()

# Internal header search paths. Two roots, not one per module. With a root per
# module `#include "log.h"` compiled from anywhere and said nothing about which
# layer it reached into; with these two every internal include names its
# directory ("utils/log.h"), which is also the Google rule. api/ keeps its own
# root so interface headers are spelled "aav/factory.h", matching the namespace
# and the public include/aav/ surface -- the two directories share the prefix
# and no file name, so a spelling resolves to exactly one header.
add_library(aav_internal INTERFACE)
target_include_directories(aav_internal INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/api)

add_library(aav STATIC ${AAV_SOURCES})
target_compile_features(aav PUBLIC cxx_std_17)
# The public surface: include/aav/ is what a consumer sees. PROJECT_SOURCE_DIR
# rather than CMAKE_SOURCE_DIR so it still resolves when a parent project pulls
# aav in with add_subdirectory().
target_include_directories(aav PUBLIC ${PROJECT_SOURCE_DIR}/include)
aav_apply_warnings(aav)
target_link_libraries(aav
  PUBLIC ZLIB::ZLIB Threads::Threads ${CMAKE_DL_LIBS}
  PRIVATE aav_internal)
if(ANDROID)
  # log.cc uses __android_log_vprint from liblog.
  target_link_libraries(aav PUBLIC log)
endif()
if(AAV_MINIZ_AVAILABLE)
  # SYSTEM so miniz.h's own diagnostics do not arrive attributed to whichever
  # engine source included it.
  target_include_directories(aav SYSTEM PRIVATE "${MINIZ_DIR}")
  target_compile_definitions(aav PRIVATE AAV_HAVE_MINIZ)
  # miniz.c rides along in this target, so the target's warning flags reach it.
  # It is vendored verbatim and upstream's warnings are not ours to fix, so it
  # is silenced per source rather than split into a target of its own.
  set_source_files_properties("${MINIZ_DIR}/miniz.c"
    PROPERTIES COMPILE_OPTIONS "-w")
endif()
if(UNIX AND NOT APPLE)
  # 32-bit off_t would cap a mapped file at 2 GiB on glibc; APKs get large.
  target_compile_definitions(aav PRIVATE _FILE_OFFSET_BITS=64)
endif()
add_library(aav::aav ALIAS aav)

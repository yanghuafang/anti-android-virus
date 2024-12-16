# ---------------------------------------------------------------------------
# Core engine library, shipped as an SDK:
#   public headers (include/aav) + static (libaav.a) + shared (libaav.so/.dylib)
#
# The translation units are compiled once into an OBJECT library and reused by
# both the static and shared libraries, so a full build never compiles the
# engine twice.
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
  dex/dex_analysis.cc
  dex/dex_scanner.cc
  dex/ac_matcher.cc
  engine/engine.cc
  engine/object.cc
)
if(AAV_MINIZ_AVAILABLE)
  list(APPEND AAV_SOURCES "${MINIZ_DIR}/miniz.c")
endif()

# Internal header search paths, shared by the engine and its white-box consumers
# (the sample-fixture lib, unit tests, and fuzzers). Defined once and linked
# everywhere so the list can never drift. The PUBLIC surface (include/) stays
# tiny; these low-level headers live under src/api/aav (never installed) and the
# module dirs.
add_library(aav_internal INTERFACE)
target_include_directories(aav_internal INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/api
  ${CMAKE_CURRENT_SOURCE_DIR}/platform
  ${CMAKE_CURRENT_SOURCE_DIR}/utils
  ${CMAKE_CURRENT_SOURCE_DIR}/sig
  ${CMAKE_CURRENT_SOURCE_DIR}/scan
  ${CMAKE_CURRENT_SOURCE_DIR}/dex)

# Public usage requirements every consumer of the engine inherits: the tiny
# include/ surface plus the runtime deps.
function(aav_apply_public_usage tgt)
  target_compile_features(${tgt} PUBLIC cxx_std_17)
  # PROJECT_SOURCE_DIR (not CMAKE_SOURCE_DIR) so the public include/ resolves to
  # the aav root even when aav is pulled in via add_subdirectory() by a parent
  # project (e.g. the Android app's JNI build).
  target_include_directories(${tgt}
    PUBLIC
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
  target_link_libraries(${tgt}
    PUBLIC ZLIB::ZLIB Threads::Threads ${CMAKE_DL_LIBS})
  if(ANDROID)
    # log.cc uses __android_log_vprint, which lives in Android's liblog. PUBLIC
    # so it propagates to in-tree and SDK consumers (e.g. the JNI bridge).
    target_link_libraries(${tgt} PUBLIC log)
  endif()
endfunction()

# Compile the engine once (PIC, so the objects also serve the shared library).
add_library(aav_objects OBJECT ${AAV_SOURCES})
set_target_properties(aav_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)
aav_apply_public_usage(aav_objects)
target_link_libraries(aav_objects PRIVATE aav_internal)
if(AAV_MINIZ_AVAILABLE)
  target_include_directories(aav_objects PRIVATE "${MINIZ_DIR}")
  target_compile_definitions(aav_objects PRIVATE AAV_HAVE_MINIZ)
endif()
if(UNIX AND NOT APPLE)
  target_compile_definitions(aav_objects PRIVATE _FILE_OFFSET_BITS=64)
endif()

# Static library (libaav.a) -- also what the in-tree apps/tests/fuzzers link.
# Built from the shared object set; no interface reference to aav_objects, so it
# installs/exports cleanly on its own.
add_library(aav STATIC $<TARGET_OBJECTS:aav_objects>)
aav_apply_public_usage(aav)
# A target built purely from an object library carries no sources of its own, so
# set the linker language explicitly.
set_target_properties(aav PROPERTIES OUTPUT_NAME aav LINKER_LANGUAGE CXX)
add_library(aav::aav ALIAS aav)

# Shared library (libaav.so / libaav.dylib) for the SDK.
if(AAV_BUILD_SHARED)
  add_library(aav_shared SHARED $<TARGET_OBJECTS:aav_objects>)
  aav_apply_public_usage(aav_shared)
  set_target_properties(aav_shared PROPERTIES
    OUTPUT_NAME aav
    EXPORT_NAME shared
    LINKER_LANGUAGE CXX
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
  add_library(aav::shared ALIAS aav_shared)
endif()

# ---------------------------------------------------------------------------
# Core engine library. Static for now; the layers land on top of these
# primitives.
# ---------------------------------------------------------------------------
set(AAV_SOURCES
  platform/libplatform_export.cc
  platform/module.cc
  utils/crc32.cc
  utils/log.cc
  utils/leb128.cc
  engine/object.cc
)

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
target_link_libraries(aav PRIVATE aav_internal ${CMAKE_DL_LIBS})
if(ANDROID)
  # log.cc uses __android_log_vprint from liblog.
  target_link_libraries(aav PUBLIC log)
endif()
add_library(aav::aav ALIAS aav)

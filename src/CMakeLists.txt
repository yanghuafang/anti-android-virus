# ---------------------------------------------------------------------------
# Core engine library. Static for now; the layers land on top of these
# primitives.
# ---------------------------------------------------------------------------
set(AAV_SOURCES
  utils/crc32.cc
  utils/log.cc
  utils/leb128.cc
)

# Internal header search path. One root, not one per module: with a root per
# module `#include "log.h"` compiled from anywhere and said nothing about which
# layer it reached into; with this one every internal include names its
# directory ("utils/log.h"), which is also the Google rule.
add_library(aav_internal INTERFACE)
target_include_directories(aav_internal INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

add_library(aav STATIC ${AAV_SOURCES})
target_compile_features(aav PUBLIC cxx_std_17)
aav_apply_warnings(aav)
target_link_libraries(aav PRIVATE aav_internal)
if(ANDROID)
  # log.cc uses __android_log_vprint from liblog.
  target_link_libraries(aav PUBLIC log)
endif()
add_library(aav::aav ALIAS aav)

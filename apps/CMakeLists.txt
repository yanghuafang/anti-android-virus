# ---------------------------------------------------------------------------
# CLI scanner -- a thin, pure consumer of the public engine facade (include/).
# ---------------------------------------------------------------------------
if(AAV_BUILD_CLI)
  add_executable(aavscan aavscan/aavscan.cc)
  aav_apply_warnings(aavscan)
  target_link_libraries(aavscan PRIVATE aav)
endif()

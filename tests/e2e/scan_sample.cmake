# Driver for the end-to-end golden test: generate the sample pair with sigtool,
# scan it with aavscan, and assert both signatures fire.
# Args: -DSIGTOOL= -DAAVSCAN= -DWORKDIR=

file(MAKE_DIRECTORY "${WORKDIR}")

execute_process(COMMAND "${SIGTOOL}" gen-sample "${WORKDIR}"
                RESULT_VARIABLE gen_rc)
if(NOT gen_rc EQUAL 0)
  message(FATAL_ERROR "sigtool gen-sample failed (${gen_rc})")
endif()

execute_process(
  COMMAND "${AAVSCAN}" "${WORKDIR}/sample.sig" "${WORKDIR}/sample.dex"
  OUTPUT_VARIABLE scan_out
  RESULT_VARIABLE scan_rc)
message(STATUS "aavscan output:\n${scan_out}")

if(NOT scan_rc EQUAL 0)
  message(FATAL_ERROR "aavscan failed (${scan_rc})")
endif()
if(NOT scan_out MATCHES "sigID: 1002")
  message(FATAL_ERROR "expected code signature 1002 not reported")
endif()
if(NOT scan_out MATCHES "sigID: 1001")
  message(FATAL_ERROR "expected path signature 1001 not reported")
endif()

message(STATUS "e2e sample scan OK")

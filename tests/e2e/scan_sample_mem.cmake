# Driver for the memory-scan e2e: generate the sample pair with sigtool, pack the
# DEX into a zip/APK, then run the ScanBuffer check (DEX + APK scanned from RAM).
# Args: -DSIGTOOL= -DMEMSCAN= -DWORKDIR=

file(MAKE_DIRECTORY "${WORKDIR}")

execute_process(COMMAND "${SIGTOOL}" gen-sample "${WORKDIR}"
                RESULT_VARIABLE gen_rc)
if(NOT gen_rc EQUAL 0)
  message(FATAL_ERROR "sigtool gen-sample failed (${gen_rc})")
endif()

# Pack sample.dex as classes.dex inside sample.apk (a zip) using cmake -E tar.
configure_file("${WORKDIR}/sample.dex" "${WORKDIR}/classes.dex" COPYONLY)
execute_process(
  COMMAND ${CMAKE_COMMAND} -E tar cf sample.apk --format=zip classes.dex
  WORKING_DIRECTORY "${WORKDIR}"
  RESULT_VARIABLE tar_rc)
if(NOT tar_rc EQUAL 0)
  message(FATAL_ERROR "failed to build sample.apk (${tar_rc})")
endif()

execute_process(
  COMMAND "${MEMSCAN}" "${WORKDIR}/sample.sig" "${WORKDIR}/sample.dex"
          "${WORKDIR}/sample.apk"
  OUTPUT_VARIABLE mem_out
  RESULT_VARIABLE mem_rc)
message(STATUS "memscan output:\n${mem_out}")
if(NOT mem_rc EQUAL 0)
  message(FATAL_ERROR "memory-scan check failed (${mem_rc})")
endif()

message(STATUS "e2e memory-scan OK")

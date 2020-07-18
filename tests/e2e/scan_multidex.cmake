# Multidex e2e: build an APK containing classes.dex AND classes2.dex (both the
# malicious sample) and assert the APK scanner unpacks and scans *every* member
# -- the merged report must carry the signature from both dexes.
# Args: -DSIGTOOL= -DAAVSCAN= -DWORKDIR=

file(MAKE_DIRECTORY "${WORKDIR}")

execute_process(COMMAND "${SIGTOOL}" gen-sample "${WORKDIR}"
                RESULT_VARIABLE gen_rc)
if(NOT gen_rc EQUAL 0)
  message(FATAL_ERROR "sigtool gen-sample failed (${gen_rc})")
endif()

# Two DEX members carved from the same malicious sample (binary-safe copy).
execute_process(COMMAND ${CMAKE_COMMAND} -E copy
                "${WORKDIR}/sample.dex" "${WORKDIR}/classes.dex")
execute_process(COMMAND ${CMAKE_COMMAND} -E copy
                "${WORKDIR}/sample.dex" "${WORKDIR}/classes2.dex")
execute_process(
  COMMAND ${CMAKE_COMMAND} -E tar cf multi.apk --format=zip
          classes.dex classes2.dex
  WORKING_DIRECTORY "${WORKDIR}"
  RESULT_VARIABLE tar_rc)
if(NOT tar_rc EQUAL 0)
  message(FATAL_ERROR "failed to build multidex apk (${tar_rc})")
endif()

execute_process(
  COMMAND "${AAVSCAN}" "${WORKDIR}/sample.sig" "${WORKDIR}/multi.apk"
  OUTPUT_VARIABLE out
  RESULT_VARIABLE rc)
message(STATUS "multidex apk scan output:\n${out}")

if(NOT rc EQUAL 0)
  message(FATAL_ERROR "aavscan multidex apk failed (${rc})")
endif()
if(NOT out MATCHES "isMalware: 1")
  message(FATAL_ERROR "multidex apk not flagged as malware")
endif()
# Both dexes must have been scanned -> the path signature (1001) fires twice.
string(REGEX MATCHALL "sigID: 1001" hits "${out}")
list(LENGTH hits n)
if(n LESS 2)
  message(FATAL_ERROR "expected sigID 1001 from both dexes, got ${n}")
endif()

message(STATUS "e2e multidex scan OK")

# Driver for the directory + multi-threaded end-to-end test: generate the sample
# pair with sigtool, populate a directory with several DEX copies, then scan the
# directory with `aavscan --mt`. This exercises the engine's directory traversal,
# per-worker scanner sets, the atomic work queue, and serialized callbacks --
# paths the single-file / single-buffer tests do not touch.
# Args: -DSIGTOOL= -DAAVSCAN= -DWORKDIR=

file(MAKE_DIRECTORY "${WORKDIR}")

execute_process(COMMAND "${SIGTOOL}" gen-sample "${WORKDIR}"
                RESULT_VARIABLE gen_rc)
if(NOT gen_rc EQUAL 0)
  message(FATAL_ERROR "sigtool gen-sample failed (${gen_rc})")
endif()

# A directory with four DEX copies, so four worker threads all get work.
set(tree "${WORKDIR}/tree")
file(MAKE_DIRECTORY "${tree}")
foreach(n 1 2 3 4)
  execute_process(COMMAND ${CMAKE_COMMAND} -E copy
                  "${WORKDIR}/sample.dex" "${tree}/sample${n}.dex"
                  RESULT_VARIABLE copy_rc)
  if(NOT copy_rc EQUAL 0)
    message(FATAL_ERROR "failed to stage sample${n}.dex (${copy_rc})")
  endif()
endforeach()

execute_process(
  COMMAND "${AAVSCAN}" --mt 4 "${WORKDIR}/sample.sig" "${tree}"
  OUTPUT_VARIABLE scan_out
  RESULT_VARIABLE scan_rc)
message(STATUS "aavscan output:\n${scan_out}")

if(NOT scan_rc EQUAL 0)
  message(FATAL_ERROR "aavscan failed (${scan_rc})")
endif()
# All four files must be walked, flagged, and resolved to the sample name.
if(NOT scan_out MATCHES "scanned 4 file")
  message(FATAL_ERROR "expected 4 files scanned")
endif()
if(NOT scan_out MATCHES "4 flagged")
  message(FATAL_ERROR "expected 4 files flagged")
endif()
if(NOT scan_out MATCHES "Trojan!SampleFam.a@Android.Dex")
  message(FATAL_ERROR "expected malware name not reported")
endif()

message(STATUS "e2e directory/multi-thread scan OK")

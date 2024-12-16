# ---------------------------------------------------------------------------
# libFuzzer harness for the DEX parser (Clang only). White-box: drives the
# internal parser directly, so it links the engine and its internal headers.
# ---------------------------------------------------------------------------
add_executable(fuzz_dexfile fuzz_dexfile.cc)
target_link_libraries(fuzz_dexfile PRIVATE aav aav_internal)
target_compile_options(fuzz_dexfile PRIVATE
  -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
target_link_options(fuzz_dexfile PRIVATE -fsanitize=fuzzer,address,undefined)

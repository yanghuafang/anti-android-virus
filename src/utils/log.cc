#include "utils/log.h"

#include <cstdarg>
#include <cstdio>

#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace aav {
namespace {

// Set once (e.g. from --debug) before scanning begins, then only read, so a
// plain int is sufficient.
int g_log_level = kLogError;

#if defined(__ANDROID__)
int ToAndroidPriority(int level) {
  switch (level) {
    case kLogError:
      return ANDROID_LOG_ERROR;
    case kLogInfo:
      return ANDROID_LOG_INFO;
    case kLogDebug:
      return ANDROID_LOG_DEBUG;
    default:
      return ANDROID_LOG_DEFAULT;
  }
}
#endif

}  // namespace

void SetLogLevel(int level) { g_log_level = level; }

int GetLogLevel() { return g_log_level; }

void LogPrint(int level, const char* fmt, ...) {
  // No initializer: va_list is an array type on most ABIs (Linux x86-64,
  // arm64), where `= nullptr` is a hard error. va_start is what initializes it.
  va_list args;  // NOLINT(cppcoreguidelines-init-variables)
  va_start(args, fmt);
#if defined(__ANDROID__)
  __android_log_vprint(ToAndroidPriority(level), "aav", fmt, args);
#else
  (void)level;
  std::vfprintf(stderr, fmt, args);
  fputc('\n', stderr);
#endif
  va_end(args);
}

}  // namespace aav

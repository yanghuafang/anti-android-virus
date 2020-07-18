#ifndef AAV_UTILS_LOG_H_
#define AAV_UTILS_LOG_H_

namespace aav {

// Process-wide runtime log threshold. A message is emitted when its level is
// <= the current threshold. Default is kLogError (quiet: only errors), which
// keeps real-time scanning cheap; the CLI raises it to kLogDebug for --debug.
enum LogLevel {
  kLogSilent = 0,
  kLogError = 1,
  kLogInfo = 2,
  kLogDebug = 3,
};

void SetLogLevel(int level);
int GetLogLevel();

// printf-style sink. Prefer the macros below: they skip argument evaluation and
// formatting entirely when the level is disabled. Messages should not include a
// trailing newline (the sink adds one on host; logcat adds its own on Android).
void LogPrint(int level, const char* fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

}  // namespace aav

#define AAV_LOG_AT(level, ...)                                              \
  do {                                                                      \
    if (aav::GetLogLevel() >= (level)) aav::LogPrint((level), __VA_ARGS__); \
  } while (0)

#define AAV_LOGE(...) AAV_LOG_AT(aav::kLogError, __VA_ARGS__)
#define AAV_LOGI(...) AAV_LOG_AT(aav::kLogInfo, __VA_ARGS__)
#define AAV_LOGD(...) AAV_LOG_AT(aav::kLogDebug, __VA_ARGS__)

#endif

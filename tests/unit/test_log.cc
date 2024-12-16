#include "doctest.h"
#include "log.h"

using namespace aav;

TEST_CASE("Log level get/set and macro sink") {
  const int prev = GetLogLevel();

  SetLogLevel(kLogSilent);
  CHECK(GetLogLevel() == kLogSilent);
  SetLogLevel(kLogDebug);
  CHECK(GetLogLevel() == kLogDebug);

  // Exercise the sink at an enabled and a disabled level (no output asserted --
  // this just drives LogPrint / the level gate for coverage).
  AAV_LOGD("unit-test debug message %d", 42);
  AAV_LOGE("unit-test error message %s", "ok");
  SetLogLevel(kLogSilent);
  AAV_LOGD("this one is gated out");

  SetLogLevel(prev);
}

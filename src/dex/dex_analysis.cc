#include "dex_analysis.h"

namespace aav {
namespace {

// Set once (from --analysis) before scanning and only read during a scan, so a
// plain global is fine. The report, however, is filled by the scanning thread
// and read back by that same thread's Emit(); making it thread_local keeps each
// worker in a multi-threaded directory scan writing into its own report.
bool g_analysis_enabled = false;
thread_local DexAnalysisReport g_report;

}  // namespace

void SetDexAnalysisEnabled(bool enabled) { g_analysis_enabled = enabled; }

bool IsDexAnalysisEnabled() { return g_analysis_enabled; }

DexAnalysisReport& MutableDexAnalysisReport() { return g_report; }

const DexAnalysisReport& GetDexAnalysisReport() { return g_report; }

}  // namespace aav

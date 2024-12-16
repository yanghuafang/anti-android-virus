#ifndef AAV_SIGTOOL_SAMPLE_DATA_H_
#define AAV_SIGTOOL_SAMPLE_DATA_H_

#include <cstdint>
#include <string>
#include <vector>

// Generators for the self-consistent sample fixtures used by both `sigtool`
// (which writes them to disk) and the unit tests (which build them in memory):
// a tiny DEX, its matching signature DB, and an APK wrapping the DEX. Keeping
// them in one place guarantees the tool and the tests never drift apart.

namespace aav {
namespace sample {

using Bytes = std::vector<uint8_t>;

// Sig IDs the sample encodes and the malware name they resolve to.
constexpr uint32_t kPathSigId = 1001;  // com.aav.sample.evil (class-path sig)
constexpr uint32_t kCodeSigId = 1002;  // Worker.work() (code sig + AND logic)
inline constexpr char kMalwareName[] = "Trojan!SampleFam.a@Android.Dex";

// A well-formed DEX with two classes (Evil: path match, Worker: code match).
// `version` is the 3-digit magic version, "035".."040".
Bytes BuildSampleDex(const std::string& version = "035");

// The matching signature DB (Blowfish-encrypted + gzip-compressed) the engine
// loads. Detects both kPathSigId and kCodeSigId in the sample DEX.
Bytes BuildSampleSig();

#ifdef AAV_HAVE_MINIZ
// An APK/zip holding `classes_dex` as classes.dex (and `classes2_dex` as
// classes2.dex when non-empty), for scanning APKs from memory.
Bytes BuildSampleApk(const Bytes& classes_dex, const Bytes& classes2_dex = {});
#endif

}  // namespace sample
}  // namespace aav

#endif

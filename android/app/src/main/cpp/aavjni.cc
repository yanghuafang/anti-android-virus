// JNI bridge: com.av.aav.Engine <-> the aav engine.
//
// This is a pure consumer of the public SDK facade (aav/engine_interface.h):
// MakeEngine -> Init(sig_db) -> Scan (results arrive through a callback) ->
// Destroy. File identification, APK unpacking and directory traversal all
// happen inside the engine, so the bridge carries no engine internals.

#include "aavjni.h"

#include <android/log.h>
#include <jni.h>

#include <vector>

#include "aav/engine_interface.h"
#include "jniutil.h"

#define LOG_TAG "aavjni"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

namespace {

// One engine per process; released by uninit() (or replaced by a fresh init()).
aav::IEngine* g_engine = nullptr;

// Build a Java ScanResult from a POD ScanReport. All ScanReport pointers are
// engine-owned and valid only for this call, so everything is copied into Java
// objects here.
jobject BuildScanResult(JNIEnv* env, const aav::ScanReport* report) {
  jclass cls = LoadClassByClassName(env, AAV_SCANRESULT_CLS);
  if (nullptr == cls) {
    LOGE("failed to load class %s.", AAV_SCANRESULT_CLS);
    return nullptr;
  }
  jmethodID ctor = FindMethodFromClass(
      env, cls, "<init>", "(Ljava/lang/String;ZZ[I[Ljava/lang/String;)V");
  if (nullptr == ctor) {
    LOGE("failed to find %s::<init>.", AAV_SCANRESULT_CLS);
    return nullptr;
  }

  const int count = static_cast<int>(report->sig_count);
  jstring jpath = StrToJstring(env, report->path ? report->path : "");
  jintArray jsig_ids =
      IntArrayToJintArray(env, reinterpret_cast<const int*>(report->sig_ids),
                          report->sig_ids ? count : 0);

  jclass str_cls = LoadClassByClassName(env, "java/lang/String");
  jobjectArray jnames = env->NewObjectArray(count, str_cls, nullptr);
  for (int i = 0; i < count; i++) {
    const char* name =
        (report->names && report->names[i]) ? report->names[i] : "";
    jstring jname = StrToJstring(env, name);
    env->SetObjectArrayElement(jnames, i, jname);
    env->DeleteLocalRef(jname);
  }

  jobject result = env->NewObject(
      cls, ctor, jpath, static_cast<jboolean>(report->is_malware),
      static_cast<jboolean>(report->is_white), jsig_ids, jnames);
  env->DeleteLocalRef(jpath);
  env->DeleteLocalRef(jsig_ids);
  env->DeleteLocalRef(jnames);
  env->DeleteLocalRef(str_cls);
  env->DeleteLocalRef(cls);
  return result;
}

// Callback context threaded through IEngine::Scan (see ScanCallback). The scan
// runs single-threaded (EngineConfig::scan_threads stays 1), so the callback
// fires on this same JNI thread and `env` is valid.
struct ScanContext {
  JNIEnv* env;
  std::vector<jobject> results;
};

void OnReport(const aav::ScanReport* report, void* user_data) {
  ScanContext* ctx = static_cast<ScanContext*>(user_data);
  jobject result = BuildScanResult(ctx->env, report);
  if (result) ctx->results.push_back(result);
}

jint Init(JNIEnv* env, jobject thiz, jstring sig_db_path) {
  if (g_engine) {
    g_engine->Destroy();
    g_engine = nullptr;
  }
  const char* path = env->GetStringUTFChars(sig_db_path, nullptr);
  jint ret = -1;
  if (path && path[0]) {
    g_engine = aav::MakeEngine();
    aav::EngineConfig config;  // defaults: scan apk + dex, recurse dirs
    if (g_engine && 0 == g_engine->Init(path, &config)) {
      ret = 0;
    } else {
      LOGE("failed to init engine with sig db: %s", path);
      if (g_engine) {
        g_engine->Destroy();
        g_engine = nullptr;
      }
    }
  } else {
    LOGE("invalid sigDbPath.");
  }
  if (path) env->ReleaseStringUTFChars(sig_db_path, path);
  return ret;
}

void Uninit(JNIEnv* env, jobject thiz) {
  if (g_engine) {
    g_engine->Destroy();
    g_engine = nullptr;
  }
}

jobjectArray Scan(JNIEnv* env, jobject thiz, jstring file_path) {
  if (!g_engine) {
    LOGE("engine not initialized (call init first).");
    return nullptr;
  }
  const char* path = env->GetStringUTFChars(file_path, nullptr);
  if (nullptr == path) return nullptr;

  ScanContext ctx;
  ctx.env = env;
  int rc = g_engine->Scan(path, OnReport, &ctx);
  env->ReleaseStringUTFChars(file_path, path);

  jclass cls = LoadClassByClassName(env, AAV_SCANRESULT_CLS);
  if (0 != rc || nullptr == cls) {
    for (jobject r : ctx.results) env->DeleteLocalRef(r);
    if (nullptr == cls) LOGE("failed to load class %s.", AAV_SCANRESULT_CLS);
    return nullptr;
  }

  jobjectArray array =
      env->NewObjectArray(static_cast<jsize>(ctx.results.size()), cls, nullptr);
  for (size_t i = 0; i < ctx.results.size(); i++) {
    env->SetObjectArrayElement(array, static_cast<jsize>(i), ctx.results[i]);
    env->DeleteLocalRef(ctx.results[i]);
  }
  env->DeleteLocalRef(cls);
  return array;
}

JNINativeMethod kNativeMethods[] = {
    {"init", "(Ljava/lang/String;)I", (void*)Init},
    {"uninit", "()V", (void*)Uninit},
    {"scan", "(Ljava/lang/String;)[Lcom/av/aav/ScanResult;", (void*)Scan},
};

int RegisterNativeMethods(JNIEnv* env) {
  jclass clazz = env->FindClass(AAV_ENGINE_CLS);
  if (nullptr == clazz) {
    LOGE("failed to find class %s.", AAV_ENGINE_CLS);
    return JNI_FALSE;
  }
  int count =
      static_cast<int>(sizeof(kNativeMethods) / sizeof(kNativeMethods[0]));
  if (env->RegisterNatives(clazz, kNativeMethods, count) < 0) {
    LOGE("failed to register natives for %s.", AAV_ENGINE_CLS);
    return JNI_FALSE;
  }
  return JNI_TRUE;
}

}  // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
  JNIEnv* env = nullptr;
  if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
    LOGE("JNI version 1.6 unavailable.");
    return -1;
  }
  if (JNI_TRUE != RegisterNativeMethods(env)) {
    LOGE("failed to register native methods.");
    return -1;
  }
  LOGI("aavjni loaded.");
  return JNI_VERSION_1_6;
}

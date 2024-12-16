#include "jniutil.h"

#include <string.h>

jstring StrToJstring(JNIEnv* env, const char* str) {
  int strLen = strlen(str);
  jclass jstrObj = env->FindClass("java/lang/String");
  jmethodID methodId =
      env->GetMethodID(jstrObj, "<init>", "([BLjava/lang/String;)V");
  jbyteArray byteArray = env->NewByteArray(strLen);
  jstring encode = env->NewStringUTF("utf-8");

  env->SetByteArrayRegion(byteArray, 0, strLen, (jbyte*)str);
  return (jstring)env->NewObject(jstrObj, methodId, byteArray, encode);
}

jintArray IntArrayToJintArray(JNIEnv* env, const int* data, const int size) {
  if (size < 0) return nullptr;

  jintArray result;
  result = env->NewIntArray(size);
  if (result == nullptr) return nullptr;

  env->SetIntArrayRegion(result, 0, size, data);
  return result;
}

jclass LoadClassByClassName(JNIEnv* env, const char* cls) {
  jclass jcls = nullptr;
  if (env->ExceptionCheck()) env->ExceptionClear();
  jcls = env->FindClass(cls);
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    return nullptr;
  }
  return jcls;
}

jmethodID FindMethodFromClass(JNIEnv* env, jclass cls, const char* method,
                              const char* para) {
  jmethodID jmethod = nullptr;
  if (env->ExceptionCheck()) env->ExceptionClear();
  jmethod = env->GetMethodID(cls, method, para);
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    return nullptr;
  }
  return jmethod;
}

jmethodID FindStaticMethodFromClass(JNIEnv* env, jclass cls, const char* method,
                                    const char* para) {
  jmethodID jmethod = nullptr;
  if (env->ExceptionCheck()) env->ExceptionClear();
  jmethod = env->GetStaticMethodID(cls, method, para);
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    return nullptr;
  }
  return jmethod;
}

jfieldID FindFieldFromClass(JNIEnv* env, jclass cls, const char* field,
                            const char* type) {
  jfieldID jfield = nullptr;
  if (env->ExceptionCheck()) env->ExceptionClear();
  jfield = env->GetFieldID(cls, field, type);
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    return nullptr;
  }
  return jfield;
}

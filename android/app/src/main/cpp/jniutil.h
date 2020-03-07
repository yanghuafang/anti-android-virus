#ifndef AAV_APP_JNIUTIL_H_
#define AAV_APP_JNIUTIL_H_

#include <jni.h>

jstring StrToJstring(JNIEnv* env, const char* str);
jintArray IntArrayToJintArray(JNIEnv* env, const int* data, const int size);
jclass LoadClassByClassName(JNIEnv* env, const char* cls);
jmethodID FindMethodFromClass(JNIEnv* env, jclass cls, const char* method,
                              const char* para);
jmethodID FindStaticMethodFromClass(JNIEnv* env, jclass cls, const char* method,
                                    const char* para);
jfieldID FindFieldFromClass(JNIEnv* env, jclass cls, const char* field,
                            const char* type);

#endif

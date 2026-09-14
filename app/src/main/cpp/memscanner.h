#ifndef MEMSCANNER_H
#define MEMSCANNER_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeStartScan(
    JNIEnv* env, jobject thiz, jlong value, jint type, jint condition);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeNextScan(
    JNIEnv* env, jobject thiz, jlong value, jint condition);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeCancelScan(
    JNIEnv* env, jobject thiz);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeClearResults(
    JNIEnv* env, jobject thiz);

JNIEXPORT jlongArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetResults(
    JNIEnv* env, jobject thiz);

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeWriteMemory(
    JNIEnv* env, jobject thiz, jlong address, jbyteArray data);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeToggleFreeze(
    JNIEnv* env, jobject thiz, jlong address, jlong value, jint type, jboolean enable);

JNIEXPORT jbyteArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeReadMemory(
    JNIEnv* env, jobject thiz, jlong address, jint size);

#ifdef __cplusplus
}
#endif

#endif
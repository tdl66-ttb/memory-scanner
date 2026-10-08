#ifndef MEMSCANNER_H
#define MEMSCANNER_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================== Config ====================

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetWorkDir(
    JNIEnv* env, jobject thiz, jstring path);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetRegionFilter(
    JNIEnv* env, jobject thiz, jint mask);

// ==================== Value scans ====================

// value2 só usado em COND_RANGE (3). Para outras condições, passe value == value2.
JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeStartScan(
    JNIEnv* env, jobject thiz,
    jlong value, jlong value2, jint type, jint condition);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeNextScan(
    JNIEnv* env, jobject thiz,
    jlong value, jlong value2, jint condition);

// ==================== AoB scan ====================
// Padrão tipo "FF ?? AA 12" (wildcards = ?? ou ?). Separadores aceitos: espaço, vírgula, hífen.
JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeAoBScan(
    JNIEnv* env, jobject thiz, jstring pattern, jint limit);

// ==================== Pointer scan ====================
// Encontra pointers que apontam para targetAddr, até maxDepth níveis.
// Resultados vêm via onPointerBatch(long[] addrs, int[] levels).
JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativePointerScan(
    JNIEnv* env, jobject thiz, jlong targetAddr, jint maxDepth);

// ==================== Controle ====================

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetDisplayFull(
    JNIEnv* env, jobject thiz);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeCancelScan(
    JNIEnv* env, jobject thiz);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeClearResults(
    JNIEnv* env, jobject thiz);

// ==================== Resultados ====================

JNIEXPORT jlongArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetResults(
    JNIEnv* env, jobject thiz);

// ==================== Acesso à memória ====================

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeWriteMemory(
    JNIEnv* env, jobject thiz, jlong address, jbyteArray data);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeToggleFreeze(
    JNIEnv* env, jobject thiz, jlong address, jlong value, jint type, jboolean enable);

JNIEXPORT jbyteArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeReadMemory(
    JNIEnv* env, jobject thiz, jlong address, jint size);

JNIEXPORT jbyteArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeReadRegion(
    JNIEnv* env, jobject thiz, jlong start, jint size);

#ifdef __cplusplus
}
#endif

#endif
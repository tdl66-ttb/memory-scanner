#ifndef MEMSCANNER_H
#define MEMSCANNER_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// v5: as funções de scan agora retornam jboolean (JNI_FALSE = não iniciou: scan já em
// andamento, entrada inválida ou falha ao criar a thread). Assim a UI nunca fica
// esperando um onScanComplete que não virá.

// ==================== Config ====================

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetWorkDir(
    JNIEnv* env, jobject thiz, jstring path);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetRegionFilter(
    JNIEnv* env, jobject thiz, jint mask);

// Filtro "Só estáticos" para Pointer Scan (libs .so + executáveis).
JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetPointerStaticFilter(
    JNIEnv* env, jobject thiz, jboolean enabled);

// Filtro por módulo (substring no path). "" desativa.
JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetModuleFilter(
    JNIEnv* env, jobject thiz, jstring pattern);

// ==================== Módulos ====================

JNIEXPORT jobjectArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeListModules(
    JNIEnv* env, jobject thiz);

// Endereço base (menor start) do módulo cujo basename casa com o nome. 0 se não achar.
JNIEXPORT jlong JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetModuleBase(
    JNIEnv* env, jobject thiz, jstring moduleName);

// Nome do módulo que contém o endereço. "" se não for file-backed.
JNIEXPORT jstring JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeFindModuleForAddr(
    JNIEnv* env, jobject thiz, jlong addr);

// ==================== Pointer Path ====================

// base, depois para cada offset: addr = *(addr) + offset (offset COM SINAL).
// Retorna o endereço final (do valor). 0 se falhar.
JNIEXPORT jlong JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeResolvePointerPath(
    JNIEnv* env, jobject thiz, jlong baseAddr, jintArray offsets);

// ==================== Value scans ====================

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeStartScan(
    JNIEnv* env, jobject thiz,
    jlong value, jlong value2, jint type, jint condition);

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeNextScan(
    JNIEnv* env, jobject thiz,
    jlong value, jlong value2, jint condition);

// ==================== String scan ====================
// encoding: 0 = UTF-8, 1 = UTF-16LE
JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeStringScan(
    JNIEnv* env, jobject thiz, jstring text, jint encoding);

// ==================== AoB scan ====================
// Padrão: "FF ?? AA 1?" (?? = byte curinga, "1?"/"?A" = nibble curinga).
// Retorna JNI_FALSE se o padrão for inválido ou não tiver nenhum byte fixo.
JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeAoBScan(
    JNIEnv* env, jobject thiz, jstring pattern, jint limit);

// ==================== Pointer scan ====================
JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativePointerScan(
    JNIEnv* env, jobject thiz, jlong targetAddr, jint maxDepth);

// ==================== Snapshot / Diff ====================
// Retorna >=0 (quantidade), -1 (scan em andamento) ou -2 (erro/sem snapshot).
JNIEXPORT jint JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSnapshotSave(
    JNIEnv* env, jobject thiz);

// mode: 0=changed, 1=unchanged, 2=increased, 3=decreased
JNIEXPORT jint JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSnapshotDiff(
    JNIEnv* env, jobject thiz, jint mode);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSnapshotClear(
    JNIEnv* env, jobject thiz);

// ==================== Controle ====================

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetDisplayFull(
    JNIEnv* env, jobject thiz);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeCancelScan(
    JNIEnv* env, jobject thiz);

// Tipo (DataType) do último scan, para o Java manter-se sincronizado com o nativo.
JNIEXPORT jint JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetLastScanType(
    JNIEnv* env, jobject thiz);

// Chamar no onDestroy: para scan/freeze e solta a referência global do Service.
JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeShutdown(
    JNIEnv* env, jobject thiz);

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeClearResults(
    JNIEnv* env, jobject thiz);

// ==================== Resultados ====================

// maxCount <= 0 => sem limite.
JNIEXPORT jlongArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetResults(
    JNIEnv* env, jobject thiz, jint maxCount);

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

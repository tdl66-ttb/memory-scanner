// ============================================================
//  memscanner.cpp
//  Memory Scanner - parte nativa (JNI)
//  Versão impecável - leitura direta com recuperação de SIGSEGV
// ============================================================

#include "memscanner.h"

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <atomic>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <utility>
#include <chrono>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>
#include <android/log.h>
#include <condition_variable>

#define LOG_TAG "MemScanner"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============================================================
//  Enums e helpers
// ============================================================
enum DataType {
    TYPE_BYTE   = 0,
    TYPE_SHORT  = 1,
    TYPE_INT    = 2,
    TYPE_LONG   = 3,
    TYPE_FLOAT  = 4,
    TYPE_DOUBLE = 5
};

enum ScanCondition {
    COND_EXACT   = 0,
    COND_GREATER = 1,
    COND_LESS    = 2
};

static const char* typeName(int t) {
    switch (t) {
        case TYPE_BYTE:   return "BYTE";
        case TYPE_SHORT:  return "SHORT";
        case TYPE_INT:    return "INT";
        case TYPE_LONG:   return "LONG";
        case TYPE_FLOAT:  return "FLOAT";
        case TYPE_DOUBLE: return "DOUBLE";
        default:          return "UNKNOWN";
    }
}

static const char* condName(int c) {
    switch (c) {
        case COND_EXACT:   return "EXACT";
        case COND_GREATER: return "GREATER";
        case COND_LESS:    return "LESS";
        default:           return "UNKNOWN";
    }
}

// ============================================================
//  Estruturas
// ============================================================
struct MemoryRegion {
    uintptr_t start, end;
    bool readable, writable, executable;
    std::string path;
};

struct ScanResult {
    uintptr_t address;
    int dataType;
    size_t valueSize;
    std::vector<uint8_t> previousValue;
};

// ============================================================
//  Estado global
// ============================================================
static std::vector<ScanResult> g_results;
static std::shared_mutex       g_resultsMutex;

static std::unordered_map<uintptr_t, std::pair<std::vector<uint8_t>, int>> g_frozen;
static std::shared_mutex       g_frozenMutex;

static std::atomic<bool>       g_scanRunning{false};
static std::atomic<bool>       g_scanCancelled{false};
static std::thread             g_scanThread;

static std::thread             g_freezeThread;
static std::atomic<bool>       g_freezeRunning{false};
static std::condition_variable g_freezeCv;
static std::mutex              g_freezeCvMutex;

static JavaVM*    g_jvm               = nullptr;
static jobject    g_callbackObj       = nullptr;
static jmethodID  g_onProgressMethod  = nullptr;
static jmethodID  g_onCompleteMethod  = nullptr;

// ============================================================
//  Infraestrutura de SIGSEGV / SIGBUS para leitura direta
// ============================================================
static __thread sigjmp_buf              t_jmpBuf;
static __thread volatile sig_atomic_t   t_inSafeRead    = 0;

static struct sigaction g_oldSegvAction;
static struct sigaction g_oldBusAction;
static bool             g_haveOldSegvAction = false;
static bool             g_haveOldBusAction  = false;
static std::atomic<bool> g_sigHandlersInstalled{false};

static void memScannerFaultHandler(int sig, siginfo_t* info, void* ctx) {
    if (t_inSafeRead) {
        // A nossa leitura segura detectou acesso inválido: volta pro ponto seguro
        siglongjmp(t_jmpBuf, 1);
    }

    // Não foi nosso: repassa para o handler anterior (Unity/ART/etc.)
    struct sigaction* old = nullptr;
    if (sig == SIGBUS) {
        if (g_haveOldBusAction) old = &g_oldBusAction;
    } else {
        if (g_haveOldSegvAction) old = &g_oldSegvAction;
    }

    if (old) {
        if (old->sa_flags & SA_SIGINFO) {
            if (old->sa_sigaction) {
                old->sa_sigaction(sig, info, ctx);
                return;
            }
        } else {
            if (old->sa_handler != SIG_IGN && old->sa_handler != SIG_DFL) {
                old->sa_handler(sig);
                return;
            }
        }
    }

    // Fallback: comportamento padrão (crash legítimo)
    signal(sig, SIG_DFL);
    raise(sig);
}

static void installSigHandlers() {
    bool expected = false;
    if (!g_sigHandlersInstalled.compare_exchange_strong(expected, true)) {
        LOGD("[INIT] Signal handlers já estavam instalados");
        return;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = memScannerFaultHandler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, &g_oldSegvAction) == 0) {
        g_haveOldSegvAction = true;
        LOGI("[INIT] SIGSEGV handler instalado");
    } else {
        LOGE("[INIT] Falha ao instalar SIGSEGV handler: %s", strerror(errno));
    }

    if (sigaction(SIGBUS, &sa, &g_oldBusAction) == 0) {
        g_haveOldBusAction = true;
        LOGI("[INIT] SIGBUS handler instalado");
    } else {
        LOGW("[INIT] Falha ao instalar SIGBUS handler: %s", strerror(errno));
    }
}

// ============================================================
//  JNI Thread Attacher
// ============================================================
class JniThreadAttacher {
public:
    explicit JniThreadAttacher(JavaVM* vm)
        : m_vm(vm), m_env(nullptr), m_attached(false) {
        if (m_vm->GetEnv((void**)&m_env, JNI_VERSION_1_6) == JNI_OK) {
            LOGD("[JNI] Thread já anexada");
        } else {
            if (m_vm->AttachCurrentThread(&m_env, nullptr) == JNI_OK) {
                m_attached = true;
                LOGD("[JNI] Thread anexada");
            } else {
                m_env = nullptr;
                LOGE("[JNI] Falha ao anexar thread");
            }
        }
    }

    ~JniThreadAttacher() {
        if (m_attached && m_env) {
            m_vm->DetachCurrentThread();
            LOGD("[JNI] Thread desanexada");
        }
    }

    JNIEnv* getEnv() const { return m_env; }

private:
    JavaVM* m_vm;
    JNIEnv* m_env;
    bool    m_attached;
};

// ============================================================
//  parseMaps
// ============================================================
static std::vector<MemoryRegion> parseMaps() {
    LOGD("[MAPS] Abrindo /proc/self/maps");
    std::vector<MemoryRegion> regions;
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) {
        LOGE("[MAPS] Falha ao abrir /proc/self/maps (errno=%d: %s)", errno, strerror(errno));
        return regions;
    }

    std::string line;
    int lineNum = 0, accepted = 0, skippedSpecial = 0, skippedNotReadable = 0;

    while (std::getline(maps, line)) {
        lineNum++;
        std::istringstream iss(line);
        uintptr_t start, end;
        char dash;
        std::string perms, path;
        iss >> std::hex >> start >> dash >> end;
        iss >> perms;
        std::string tmp;
        iss >> tmp >> tmp >> tmp;
        std::getline(iss, path);
        if (!path.empty() && path[0] == ' ') path.erase(0, 1);

        if (path.find("[vsyscall]") != std::string::npos ||
            path.find("[vvar]")     != std::string::npos ||
            path.find("[vdso]")     != std::string::npos ||
            path.find("libmemscanner.so") != std::string::npos) {
            skippedSpecial++;
            continue;
        }

        if (perms.size() < 3 || perms[0] != 'r' || end <= start ||
            (end - start) > (uintptr_t)1024 * 1024 * 1024) {
            skippedNotReadable++;
            continue;
        }

        MemoryRegion r;
        r.start      = start;
        r.end        = end;
        r.readable   = true;
        r.writable   = (perms[1] == 'w');
        r.executable = (perms[2] == 'x');
        r.path       = path;
        regions.push_back(r);
        accepted++;
    }

    LOGI("[MAPS] Linhas=%d | aceitas=%d | puladas(esp)=%d | puladas(não-legíveis)=%d",
         lineNum, accepted, skippedSpecial, skippedNotReadable);

    size_t n = regions.size() < 15 ? regions.size() : 15;
    for (size_t i = 0; i < n; i++) {
        LOGD("[MAPS]   [%zu] 0x%08lx-0x%08lx r=%d w=%d x=%d  %s",
             i,
             (unsigned long)regions[i].start,
             (unsigned long)regions[i].end,
             (int)regions[i].readable, (int)regions[i].writable, (int)regions[i].executable,
             regions[i].path.empty() ? "(anônima)" : regions[i].path.c_str());
    }
    if (regions.size() > n) {
        LOGD("[MAPS]   ... (+%zu regiões omitidas do log)", regions.size() - n);
    }

    return regions;
}

// ============================================================
//  Leitura de memória (direta com fallback /proc/self/mem)
// ============================================================
static bool safeReadMemory(uintptr_t address, void* buffer, size_t size) {
    if (sigsetjmp(t_jmpBuf, 1) == 0) {
        t_inSafeRead = 1;
        memcpy(buffer, (const void*)address, size);
        t_inSafeRead = 0;
        return true;
    }
    t_inSafeRead = 0;
    return false;
}

static bool safeWriteMemory(uintptr_t address, const void* buffer, size_t size) {
    if (sigsetjmp(t_jmpBuf, 1) == 0) {
        t_inSafeRead = 1;
        memcpy((void*)address, buffer, size);
        t_inSafeRead = 0;
        return true;
    }
    t_inSafeRead = 0;
    return false;
}

static bool readMemory(uintptr_t address, void* buffer, size_t size) {
    // 1) Leitura direta (deve sempre funcionar em self-process)
    if (safeReadMemory(address, buffer, size)) {
        return true;
    }

    // 2) Fallback: /proc/self/mem (bloqueado em Android 11+ em muitos dispositivos)
    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) return false;
    errno = 0;
    ssize_t n = pread64(fd, buffer, size, (off64_t)address);
    close(fd);
    return (n == (ssize_t)size);
}

static bool writeMemory(uintptr_t address, const void* buffer, size_t size) {
    // 1) Tenta /proc/self/mem (funciona em alguns dispositivos)
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd >= 0) {
        errno = 0;
        ssize_t n = pwrite64(fd, buffer, size, (off64_t)address);
        close(fd);
        if (n == (ssize_t)size) {
            return true;
        }
    }

    // 2) Escrita direta
    if (safeWriteMemory(address, buffer, size)) {
        return true;
    }

    // 3) mprotect + escrita direta
    size_t pageSize = sysconf(_SC_PAGE_SIZE);
    uintptr_t pageStart = (address / pageSize) * pageSize;
    size_t pageLen = ((address - pageStart + size + pageSize - 1) / pageSize) * pageSize;
    if (mprotect((void*)pageStart, pageLen, PROT_READ | PROT_WRITE) == 0) {
        if (safeWriteMemory(address, buffer, size)) {
            return true;
        }
    }

    LOGE("[WRITE] Todas as vias falharam em 0x%lx (errno=%d: %s)",
         (unsigned long)address, errno, strerror(errno));
    return false;
}

// ============================================================
//  Comparação e conversão
// ============================================================
static bool compareValue(const uint8_t* data, const void* target,
                         int type, int condition, size_t& outSize) {
    outSize = 0;
    switch (type) {
        case TYPE_BYTE: {
            uint8_t a = *data; uint8_t b = *(const uint8_t*)target;
            outSize = 1;
            if (condition == COND_EXACT)   return a == b;
            if (condition == COND_GREATER) return a >  b;
            if (condition == COND_LESS)    return a <  b;
            return true;
        }
        case TYPE_SHORT: {
            int16_t a, b;
            memcpy(&a, data, 2); memcpy(&b, target, 2);
            outSize = 2;
            if (condition == COND_EXACT)   return a == b;
            if (condition == COND_GREATER) return a >  b;
            if (condition == COND_LESS)    return a <  b;
            return true;
        }
        case TYPE_INT: {
            int32_t a, b;
            memcpy(&a, data, 4); memcpy(&b, target, 4);
            outSize = 4;
            if (condition == COND_EXACT)   return a == b;
            if (condition == COND_GREATER) return a >  b;
            if (condition == COND_LESS)    return a <  b;
            return true;
        }
        case TYPE_LONG: {
            int64_t a, b;
            memcpy(&a, data, 8); memcpy(&b, target, 8);
            outSize = 8;
            if (condition == COND_EXACT)   return a == b;
            if (condition == COND_GREATER) return a >  b;
            if (condition == COND_LESS)    return a <  b;
            return true;
        }
        case TYPE_FLOAT: {
            float a, b;
            memcpy(&a, data, 4); memcpy(&b, target, 4);
            outSize = 4;
            if (condition == COND_EXACT)   return a == b;
            if (condition == COND_GREATER) return a >  b;
            if (condition == COND_LESS)    return a <  b;
            return true;
        }
        case TYPE_DOUBLE: {
            double a, b;
            memcpy(&a, data, 8); memcpy(&b, target, 8);
            outSize = 8;
            if (condition == COND_EXACT)   return a == b;
            if (condition == COND_GREATER) return a >  b;
            if (condition == COND_LESS)    return a <  b;
            return true;
        }
        default: return false;
    }
}

static std::vector<uint8_t> intToBytes(long long value, int type) {
    std::vector<uint8_t> bytes;
    switch (type) {
        case TYPE_BYTE:
            bytes.push_back((uint8_t)value);
            break;
        case TYPE_SHORT: {
            int16_t v = (int16_t)value;
            bytes.assign((uint8_t*)&v, (uint8_t*)&v + 2);
            break;
        }
        case TYPE_INT: {
            int32_t v = (int32_t)value;
            bytes.assign((uint8_t*)&v, (uint8_t*)&v + 4);
            break;
        }
        case TYPE_LONG: {
            int64_t v = (int64_t)value;
            bytes.assign((uint8_t*)&v, (uint8_t*)&v + 8);
            break;
        }
        case TYPE_FLOAT: {
            float v = (float)value;
            bytes.assign((uint8_t*)&v, (uint8_t*)&v + 4);
            break;
        }
        case TYPE_DOUBLE: {
            double v = (double)value;
            bytes.assign((uint8_t*)&v, (uint8_t*)&v + 8);
            break;
        }
    }
    return bytes;
}

static std::string bytesToHexStr(const std::vector<uint8_t>& v, size_t maxLen = 8) {
    char buf[8];
    std::string out;
    size_t n = v.size() < maxLen ? v.size() : maxLen;
    for (size_t i = 0; i < n; i++) {
        snprintf(buf, sizeof(buf), "%02X ", v[i]);
        out += buf;
    }
    if (v.size() > maxLen) out += "...";
    return out;
}

// ============================================================
//  Thread de varredura
// ============================================================
static void scanThread(jobject callbackObj, long long value, int type,
                       int condition, bool isNext) {
    auto tStart = std::chrono::steady_clock::now();

    LOGI("=========================================================");
    LOGI("[SCAN] Thread iniciada | tipo=%s cond=%s valor=%lld isNext=%d",
         typeName(type), condName(condition), value, (int)isNext);
    LOGI("=========================================================");

    JniThreadAttacher attacher(g_jvm);
    JNIEnv* env = attacher.getEnv();
    if (!env) {
        LOGE("[SCAN] Falha crítica: sem JNIEnv");
        g_scanRunning = false;
        return;
    }

    // Prepara bytes do valor alvo
    std::vector<uint8_t> targetBytes;
    if (type == TYPE_FLOAT) {
        float f = (float)value;
        targetBytes.assign((uint8_t*)&f, (uint8_t*)&f + 4);
    } else if (type == TYPE_DOUBLE) {
        double d = (double)value;
        targetBytes.assign((uint8_t*)&d, (uint8_t*)&d + 8);
    } else {
        targetBytes = intToBytes(value, type);
    }

    if (targetBytes.empty()) {
        LOGE("[SCAN] Tipo de dado inválido: %d", type);
        g_scanRunning = false;
        return;
    }
    size_t targetSize = targetBytes.size();
    LOGD("[SCAN] Valor alvo em bytes (%zu): %s",
         targetSize, bytesToHexStr(targetBytes).c_str());

    std::vector<ScanResult> newResults;
    newResults.reserve(isNext ? (size_t)4096 : (size_t)65536);

    size_t totalReads  = 0;
    size_t failedReads = 0;
    size_t bytesScanned = 0;

    if (!isNext) {
        // ---------- PRIMEIRA VARREDURA ----------
        auto regions = parseMaps();
        if (regions.empty()) {
            LOGE("[SCAN] Nenhuma região válida. Abortando.");
            g_scanRunning = false;
            return;
        }

        int total = (int)regions.size();
        int processed = 0;
        const size_t BLOCK_SIZE = 64 * 1024;
        std::vector<uint8_t> block(BLOCK_SIZE);

        LOGI("[SCAN] Iniciando varredura completa em %d regiões (bloco=%zu KB)",
             total, BLOCK_SIZE / 1024);

        for (const auto& reg : regions) {
            if (g_scanCancelled.load()) {
                LOGW("[SCAN] Cancelado pelo usuário no meio da varredura");
                break;
            }
            if (!reg.readable || reg.start >= reg.end) continue;

            uintptr_t addr = reg.start;
            while (addr < reg.end && !g_scanCancelled.load()) {
                size_t remaining = reg.end - addr;
                size_t readSize  = remaining < BLOCK_SIZE ? remaining : BLOCK_SIZE;
                if (readSize < targetSize) break;

                totalReads++;
                if (!readMemory(addr, block.data(), readSize)) {
                    failedReads++;
                    addr += sysconf(_SC_PAGE_SIZE);
                    continue;
                }
                bytesScanned += readSize;

                for (size_t offset = 0; offset + targetSize <= readSize; offset++) {
                    if (g_scanCancelled.load()) break;
                    size_t sizeCheck = 0;
                    if (compareValue(block.data() + offset,
                                     targetBytes.data(),
                                     type, condition, sizeCheck)) {
                        ScanResult res;
                        res.address     = addr + offset;
                        res.dataType    = type;
                        res.valueSize   = sizeCheck;
                        res.previousValue.assign(block.data() + offset,
                                                 block.data() + offset + sizeCheck);
                        newResults.push_back(res);
                    }
                }
                addr += readSize;
            }

            processed++;
            if (env && callbackObj && g_onProgressMethod) {
                int percent = (processed * 100) / total;
                env->CallVoidMethod(callbackObj, g_onProgressMethod, percent);
            }
        }
    } else {
        // ---------- NEXT SCAN ----------
        std::shared_lock<std::shared_mutex> lock(g_resultsMutex);
        int total = (int)g_results.size();
        int processed = 0;

        LOGI("[SCAN] Refinando sobre %d resultados anteriores", total);

        for (const auto& res : g_results) {
            if (g_scanCancelled.load()) break;

            uint8_t buffer[8];
            size_t readSz = res.valueSize > 8 ? 8 : res.valueSize;
            if (!readMemory(res.address, buffer, readSz)) {
                failedReads++;
                processed++;
                continue;
            }
            totalReads++;
            bytesScanned += readSz;

            size_t sizeCheck = 0;
            if (compareValue(buffer, targetBytes.data(), type, condition, sizeCheck)) {
                ScanResult nr;
                nr.address     = res.address;
                nr.dataType    = type;
                nr.valueSize   = sizeCheck;
                nr.previousValue.assign(buffer, buffer + sizeCheck);
                newResults.push_back(nr);
            }
            processed++;
            if (env && callbackObj && g_onProgressMethod) {
                int percent = total > 0 ? (processed * 100) / total : 100;
                env->CallVoidMethod(callbackObj, g_onProgressMethod, percent);
            }
        }
    }

    // ---------- Atualiza resultados ----------
    {
        std::unique_lock<std::shared_mutex> lock(g_resultsMutex);
        g_results = std::move(newResults);
    }

    auto tEnd = std::chrono::steady_clock::now();
    auto ms   = std::chrono::duration_cast<std::chrono::milliseconds>(tEnd - tStart).count();

    LOGI("=========================================================");
    LOGI("[SCAN] CONCLUÍDO em %lld ms", (long long)ms);
    LOGI("[SCAN]   Leituras: %zu | Falhas: %zu | Bytes: %zu (%.2f MB)",
         totalReads, failedReads, bytesScanned, bytesScanned / 1048576.0);
    LOGI("[SCAN]   Resultados finais: %zu", g_results.size());
    LOGI("=========================================================");

    g_scanRunning   = false;
    g_scanCancelled = false;

    // ---------- Callback ----------
    if (env && callbackObj && g_onCompleteMethod) {
        jsize count = (jsize)g_results.size();
        LOGD("[SCAN] Enviando callback com %d endereços", count);

        jlongArray arr = env->NewLongArray(count);
        jclass byteArrayClass = env->FindClass("[B");
        jobjectArray valArray = env->NewObjectArray(count, byteArrayClass, nullptr);

        if (arr && valArray) {
            jlong* elements = env->GetLongArrayElements(arr, nullptr);
            for (jsize i = 0; i < count; ++i) {
                elements[i] = (jlong)g_results[i].address;
                jbyteArray ba = env->NewByteArray((jsize)g_results[i].valueSize);
                env->SetByteArrayRegion(ba, 0, (jsize)g_results[i].valueSize,
                                        (const jbyte*)g_results[i].previousValue.data());
                env->SetObjectArrayElement(valArray, i, ba);
                env->DeleteLocalRef(ba);
            }
            env->ReleaseLongArrayElements(arr, elements, 0);
            env->CallVoidMethod(callbackObj, g_onCompleteMethod, arr, valArray);
            env->DeleteLocalRef(arr);
            env->DeleteLocalRef(valArray);
        } else {
            LOGE("[SCAN] Falha ao alocar arrays JNI para callback");
            env->CallVoidMethod(callbackObj, g_onCompleteMethod, nullptr, nullptr);
        }
        if (byteArrayClass) env->DeleteLocalRef(byteArrayClass);
    }
}

// ============================================================
//  Thread de freeze
// ============================================================
static void freezeLoop() {
    LOGI("[FREEZE] Thread iniciada");
    std::unique_lock<std::mutex> lock(g_freezeCvMutex);

    while (g_freezeRunning) {
        g_freezeCv.wait_for(lock, std::chrono::milliseconds(100), [] {
            return !g_freezeRunning || !g_frozen.empty();
        });
        if (!g_freezeRunning) break;
        if (g_frozen.empty()) continue;

        std::unordered_map<uintptr_t, std::pair<std::vector<uint8_t>, int>> frozenCopy;
        {
            std::shared_lock<std::shared_mutex> fl(g_frozenMutex);
            frozenCopy = g_frozen;
        }

        int ok = 0, fail = 0;
        for (const auto& entry : frozenCopy) {
            if (writeMemory(entry.first,
                            entry.second.first.data(),
                            entry.second.first.size())) {
                ok++;
            } else {
                fail++;
            }
        }
        if (fail > 0) {
            LOGW("[FREEZE] Ciclo: %d OK, %d falhas", ok, fail);
        }
    }

    LOGI("[FREEZE] Thread encerrada");
}

// ============================================================
//  JNI IMPLEMENTATIONS
// ============================================================

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeStartScan(
    JNIEnv* env, jobject thiz, jlong value, jint type, jint condition) {

    LOGI("=========================================================");
    LOGI("[API] nativeStartScan | valor=%lld tipo=%s cond=%s",
         (long long)value, typeName(type), condName(condition));
    LOGI("=========================================================");

    if (g_scanRunning.load()) {
        LOGW("[API] Scan já em execução, ignorando chamada");
        return;
    }

    if (g_callbackObj == nullptr) {
        LOGD("[API] Registrando callback global");
        g_callbackObj = env->NewGlobalRef(thiz);
        jclass cls = env->GetObjectClass(thiz);
        g_onProgressMethod = env->GetMethodID(cls, "onScanProgress", "(I)V");
        g_onCompleteMethod = env->GetMethodID(cls, "onScanComplete", "([J[[B)V");
        if (!g_onProgressMethod || !g_onCompleteMethod) {
            LOGE("[API] Métodos de callback não encontrados");
            env->DeleteGlobalRef(g_callbackObj);
            g_callbackObj = nullptr;
            return;
        }
        LOGI("[API] Callback registrado com sucesso");
    }

    g_scanRunning   = true;
    g_scanCancelled = false;

    if (g_scanThread.joinable()) {
        LOGD("[API] Aguardando thread anterior...");
        g_scanThread.join();
    }
    LOGI("[API] Disparando nova thread de scan");
    g_scanThread = std::thread(scanThread, g_callbackObj,
                               (long long)value, (int)type, (int)condition, false);
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeNextScan(
    JNIEnv* env, jobject thiz, jlong value, jint condition) {

    LOGI("[API] nativeNextScan | valor=%lld cond=%s",
         (long long)value, condName(condition));

    if (g_scanRunning.load()) {
        LOGW("[API] Scan já em execução, ignorando chamada");
        return;
    }

    int    type;
    size_t count;
    {
        std::shared_lock<std::shared_mutex> lock(g_resultsMutex);
        if (g_results.empty()) {
            LOGW("[API] Nenhum resultado anterior para refinar");
            return;
        }
        type  = g_results[0].dataType;
        count = g_results.size();
    }
    LOGI("[API] Refinando %zu resultados (tipo=%s)", count, typeName(type));

    g_scanRunning   = true;
    g_scanCancelled = false;

    if (g_scanThread.joinable()) {
        g_scanThread.join();
    }
    g_scanThread = std::thread(scanThread, g_callbackObj,
                               (long long)value, type, (int)condition, true);
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeCancelScan(
    JNIEnv* env, jobject thiz) {
    LOGW("[API] nativeCancelScan chamado");
    g_scanCancelled = true;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeClearResults(
    JNIEnv* env, jobject thiz) {
    LOGI("[API] nativeClearResults chamado");

    {
        std::unique_lock<std::shared_mutex> lock(g_frozenMutex);
        size_t n = g_frozen.size();
        g_frozen.clear();
        LOGD("[API]   %zu entradas de freeze removidas", n);
    }
    {
        std::unique_lock<std::mutex> lock(g_freezeCvMutex);
        if (g_freezeRunning) {
            g_freezeRunning = false;
            g_freezeCv.notify_all();
        }
    }
    if (g_freezeThread.joinable()) {
        LOGD("[API]   Aguardando thread de freeze...");
        g_freezeThread.join();
    }
    {
        std::unique_lock<std::shared_mutex> lock(g_resultsMutex);
        size_t n = g_results.size();
        g_results.clear();
        LOGD("[API]   %zu resultados removidos", n);
    }
    LOGI("[API] Limpeza concluída");
}

JNIEXPORT jlongArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetResults(
    JNIEnv* env, jobject thiz) {
    LOGD("[API] nativeGetResults");
    std::shared_lock<std::shared_mutex> lock(g_resultsMutex);
    jsize count = (jsize)g_results.size();
    jlongArray arr = env->NewLongArray(count);
    if (arr) {
        jlong* elements = env->GetLongArrayElements(arr, nullptr);
        for (jsize i = 0; i < count; ++i) {
            elements[i] = (jlong)g_results[i].address;
        }
        env->ReleaseLongArrayElements(arr, elements, 0);
    }
    LOGD("[API]   Retornando %d endereços", count);
    return arr;
}

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeWriteMemory(
    JNIEnv* env, jobject thiz, jlong address, jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    jbyte* bytes = env->GetByteArrayElements(data, nullptr);
    LOGD("[API] nativeWriteMemory em 0x%lx (%d bytes)",
         (unsigned long)address, len);
    bool ok = writeMemory((uintptr_t)address, bytes, (size_t)len);
    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    LOGI("[API]   Escrita %s", ok ? "OK" : "FALHOU");
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeToggleFreeze(
    JNIEnv* env, jobject thiz, jlong address, jlong value, jint type, jboolean enable) {

    LOGI("[API] nativeToggleFreeze 0x%lx valor=%lld tipo=%s enable=%d",
         (unsigned long)address, (long long)value, typeName(type), (int)enable);

    std::unique_lock<std::shared_mutex> lock(g_frozenMutex);
    uintptr_t addr = (uintptr_t)address;

    if (enable) {
        std::vector<uint8_t> bytes;
        if (type == TYPE_FLOAT) {
            float f = (float)value;
            bytes.assign((uint8_t*)&f, (uint8_t*)&f + 4);
        } else if (type == TYPE_DOUBLE) {
            double d = (double)value;
            bytes.assign((uint8_t*)&d, (uint8_t*)&d + 8);
        } else {
            bytes = intToBytes(value, type);
        }
        if (bytes.empty()) {
            LOGE("[API]   Bytes vazios, abortando");
            return;
        }
        g_frozen[addr] = {bytes, type};
        LOGI("[API]   Congelado (%zu endereços no total)", g_frozen.size());

        if (!g_freezeRunning) {
            g_freezeRunning = true;
            if (g_freezeThread.joinable()) {
                g_freezeThread.join();
            }
            g_freezeThread = std::thread(freezeLoop);
        }
        g_freezeCv.notify_all();
    } else {
        g_frozen.erase(addr);
        LOGI("[API]   Descongelado (%zu restantes)", g_frozen.size());
        if (g_frozen.empty() && g_freezeRunning) {
            std::unique_lock<std::mutex> cvLock(g_freezeCvMutex);
            g_freezeRunning = false;
            g_freezeCv.notify_all();
        }
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeReadMemory(
    JNIEnv* env, jobject thiz, jlong address, jint size) {
    jbyteArray arr = env->NewByteArray(size);
    if (!arr) {
        LOGE("[API] nativeReadMemory: falha ao alocar jbyteArray");
        return nullptr;
    }
    jbyte* bytes = env->GetByteArrayElements(arr, nullptr);
    bool ok = readMemory((uintptr_t)address, bytes, (size_t)size);
    env->ReleaseByteArrayElements(arr, bytes, ok ? 0 : JNI_ABORT);
    return ok ? arr : nullptr;
}

// ============================================================
//  JNI_OnLoad
// ============================================================
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;

    LOGI("=========================================================");
    LOGI("[INIT] ███ MemScanner carregado com sucesso ███");
    LOGI("[INIT]   JavaVM: %p", (void*)vm);
    LOGI("[INIT]   JNI version: 1.6");
    LOGI("[INIT]   PID: %d", getpid());
    LOGI("[INIT]   Page size: %ld bytes", sysconf(_SC_PAGE_SIZE));
    LOGI("[INIT]   Arquitetura: %s", sizeof(void*) == 4 ? "32-bit" : "64-bit");

    installSigHandlers();

    // Teste rápido de leitura (pega a 1ª região legível do maps)
    {
        std::ifstream maps("/proc/self/maps");
        std::string line;
        int testedLines = 0;
        bool testDone = false;
        while (std::getline(maps, line) && !testDone && testedLines < 5) {
            testedLines++;
            unsigned long start = 0;
            char perms[5] = {0};
            if (sscanf(line.c_str(), "%lx-%*lx %4s", &start, perms) >= 2) {
                if (perms[0] == 'r') {
                    uint8_t buf[16] = {0};
                    if (readMemory((uintptr_t)start, buf, 16)) {
                        LOGI("[INIT] ✓ Teste de leitura OK em 0x%lx: %02X %02X %02X %02X",
                             start, buf[0], buf[1], buf[2], buf[3]);
                    } else {
                        LOGE("[INIT] ✗ Teste de leitura FALHOU em 0x%lx", start);
                    }
                    testDone = true;
                }
            }
        }
        if (!testDone) {
            LOGW("[INIT] Nenhuma região legível encontrada para teste inicial");
        }
    }

    LOGI("[INIT] ██████████████████████████████████████████");
    LOGI("=========================================================");
    return JNI_VERSION_1_6;
}
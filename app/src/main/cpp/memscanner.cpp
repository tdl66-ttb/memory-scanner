#include "memscanner.h"
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
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <android/log.h>
#include <condition_variable>

#define LOG_TAG "MemScanner"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Tipos de dados
enum DataType {
    TYPE_BYTE = 0,
    TYPE_SHORT = 1,
    TYPE_INT = 2,
    TYPE_LONG = 3,
    TYPE_FLOAT = 4,
    TYPE_DOUBLE = 5
};

enum ScanCondition {
    COND_EXACT = 0,
    COND_GREATER = 1,
    COND_LESS = 2
};

// Estrutura para região de memória
struct MemoryRegion {
    uintptr_t start, end;
    bool readable, writable, executable;
    std::string path;
};

// Resultado de uma varredura
struct ScanResult {
    uintptr_t address;
    int dataType;
    size_t valueSize;
    std::vector<uint8_t> previousValue;
};

// Estado global com mutexes
static std::vector<ScanResult> g_results;
static std::shared_mutex g_resultsMutex;
static std::unordered_map<uintptr_t, std::pair<std::vector<uint8_t>, int>> g_frozen;
static std::shared_mutex g_frozenMutex;
static std::atomic<bool> g_scanRunning{false};
static std::atomic<bool> g_scanCancelled{false};
static std::thread g_scanThread;
static std::thread g_freezeThread;
static std::atomic<bool> g_freezeRunning{false};
static std::condition_variable g_freezeCv;
static std::mutex g_freezeCvMutex;

static JavaVM* g_jvm = nullptr;
static jobject g_callbackObj = nullptr;
static jmethodID g_onProgressMethod = nullptr;
static jmethodID g_onCompleteMethod = nullptr;

// RAII para attach/detach JNI
class JniThreadAttacher {
public:
    JniThreadAttacher(JavaVM* vm) : m_vm(vm), m_env(nullptr), m_attached(false) {
        if (m_vm->GetEnv((void**)&m_env, JNI_VERSION_1_6) == JNI_OK) {
            // Já anexado
        } else {
            if (m_vm->AttachCurrentThread(&m_env, nullptr) == JNI_OK) {
                m_attached = true;
            } else {
                m_env = nullptr;
            }
        }
    }

    ~JniThreadAttacher() {
        if (m_attached && m_env) {
            m_vm->DetachCurrentThread();
        }
    }

    JNIEnv* getEnv() const { return m_env; }
    bool isValid() const { return m_env != nullptr; }

private:
    JavaVM* m_vm;
    JNIEnv* m_env;
    bool m_attached;
};

// ======================== UTILITÁRIOS ========================

static std::vector<MemoryRegion> parseMaps() {
    std::vector<MemoryRegion> regions;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream iss(line);
        uintptr_t start, end;
        char dash;
        std::string perms, path;
        iss >> std::hex >> start >> dash >> end;
        iss >> perms;
        std::string tmp;
        iss >> tmp; iss >> tmp; iss >> tmp;
        std::getline(iss, path);
        if (!path.empty() && path[0] == ' ') path.erase(0,1);

        // Pular regiões especiais e a própria biblioteca
        if (path.find("[vsyscall]") != std::string::npos ||
            path.find("[vvar]") != std::string::npos ||
            path.find("[vdso]") != std::string::npos ||
            path.find("libmemscanner.so") != std::string::npos) {
            continue;
        }
        // Apenas regiões legíveis e com tamanho razoável
        if (perms.size() < 3 || perms[0] != 'r' || end <= start || (end - start) > 1024*1024*1024) {
            continue;
        }

        regions.push_back({
            start, end,
            true,
            perms[1] == 'w',
            perms[2] == 'x',
            path
        });
    }
    return regions;
}

static bool readMemory(uintptr_t address, void* buffer, size_t size) {
    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = pread(fd, buffer, size, (off_t)address);
    close(fd);
    return (n == (ssize_t)size);
}

static bool writeMemory(uintptr_t address, const void* buffer, size_t size) {
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) {
        // Fallback: tenta mprotect
        size_t pageSize = sysconf(_SC_PAGE_SIZE);
        uintptr_t pageStart = (address / pageSize) * pageSize;
        size_t pageLen = ((address - pageStart + size + pageSize - 1) / pageSize) * pageSize;
        if (mprotect((void*)pageStart, pageLen, PROT_READ | PROT_WRITE) != 0) {
            LOGE("mprotect falhou: %s", strerror(errno));
            return false;
        }
        fd = open("/proc/self/mem", O_RDWR);
        if (fd < 0) return false;
    }
    ssize_t n = pwrite(fd, buffer, size, (off_t)address);
    close(fd);
    return (n == (ssize_t)size);
}

// Compara um buffer com um valor alvo, dado tipo e condição
static bool compareValue(const uint8_t* data, const void* target, int type, int condition, size_t& outSize) {
    outSize = 0;
    switch (type) {
        case TYPE_BYTE: {
            uint8_t a = *data, b = *(uint8_t*)target;
            outSize = 1;
            if (condition == COND_EXACT) return a == b;
            if (condition == COND_GREATER) return a > b;
            if (condition == COND_LESS) return a < b;
            return true;
        }
        case TYPE_SHORT: {
            int16_t a = *(int16_t*)data, b = *(int16_t*)target;
            outSize = 2;
            if (condition == COND_EXACT) return a == b;
            if (condition == COND_GREATER) return a > b;
            if (condition == COND_LESS) return a < b;
            return true;
        }
        case TYPE_INT: {
            int32_t a = *(int32_t*)data, b = *(int32_t*)target;
            outSize = 4;
            if (condition == COND_EXACT) return a == b;
            if (condition == COND_GREATER) return a > b;
            if (condition == COND_LESS) return a < b;
            return true;
        }
        case TYPE_LONG: {
            int64_t a = *(int64_t*)data, b = *(int64_t*)target;
            outSize = 8;
            if (condition == COND_EXACT) return a == b;
            if (condition == COND_GREATER) return a > b;
            if (condition == COND_LESS) return a < b;
            return true;
        }
        case TYPE_FLOAT: {
            float a = *(float*)data, b = *(float*)target;
            outSize = 4;
            if (condition == COND_EXACT) return a == b;
            if (condition == COND_GREATER) return a > b;
            if (condition == COND_LESS) return a < b;
            return true;
        }
        case TYPE_DOUBLE: {
            double a = *(double*)data, b = *(double*)target;
            outSize = 8;
            if (condition == COND_EXACT) return a == b;
            if (condition == COND_GREATER) return a > b;
            if (condition == COND_LESS) return a < b;
            return true;
        }
        default: return false;
    }
}

// Converte valor inteiro para bytes conforme tipo
static std::vector<uint8_t> intToBytes(long long value, int type) {
    std::vector<uint8_t> bytes;
    switch (type) {
        case TYPE_BYTE: bytes.push_back((uint8_t)value); break;
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

// ======================== SCAN THREAD ========================

static void scanThread(jobject callbackObj, long long value, int type, int condition, bool isNext) {
    JniThreadAttacher attacher(g_jvm);
    JNIEnv* env = attacher.getEnv();
    if (!env) {
        LOGE("Falha ao anexar thread JNI");
        g_scanRunning = false;
        return;
    }

    // Prepara o valor alvo em bytes
    std::vector<uint8_t> targetBytes = intToBytes(value, type);
    if (targetBytes.empty()) {
        LOGE("Tipo de dado inválido");
        g_scanRunning = false;
        return;
    }
    size_t targetSize = targetBytes.size();

    std::vector<ScanResult> newResults;
    // Pré-alocação para evitar realocações
    newResults.reserve(isNext ? g_results.size() : 10000);

    if (!isNext) {
        // Primeira varredura: percorre todas as regiões
        auto regions = parseMaps();
        int total = regions.size(), processed = 0;
        const size_t BLOCK_SIZE = 64 * 1024; // 64KB
        std::vector<uint8_t> block(BLOCK_SIZE);

        for (const auto& reg : regions) {
            if (g_scanCancelled.load()) break;
            if (!reg.readable || reg.start >= reg.end) continue;

            uintptr_t addr = reg.start;
            while (addr < reg.end && !g_scanCancelled.load()) {
                size_t remaining = reg.end - addr;
                size_t readSize = std::min(BLOCK_SIZE, remaining);
                // Garantir que leiamos pelo menos targetSize
                if (readSize < targetSize) {
                    // Se o bloco restante for menor que targetSize, podemos tentar ler diretamente
                    // Mas para simplificar, ajustamos para ler o mínimo necessário
                    readSize = targetSize;
                }
                if (!readMemory(addr, block.data(), readSize)) {
                    // Falha na leitura, pula para a próxima página (alinhada)
                    addr += sysconf(_SC_PAGE_SIZE);
                    continue;
                }
                // Comparar cada posição dentro do bloco
                for (size_t offset = 0; offset + targetSize <= readSize; offset += targetSize) {
                    if (g_scanCancelled.load()) break;
                    size_t sizeCheck = 0;
                    if (compareValue(block.data() + offset, targetBytes.data(), type, condition, sizeCheck)) {
                        ScanResult res;
                        res.address = addr + offset;
                        res.dataType = type;
                        res.valueSize = sizeCheck;
                        res.previousValue.assign(block.data() + offset, block.data() + offset + sizeCheck);
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
        // Next scan: apenas sobre os resultados anteriores
        std::shared_lock<std::shared_mutex> lock(g_resultsMutex);
        int total = g_results.size(), processed = 0;
        for (const auto& res : g_results) {
            if (g_scanCancelled.load()) break;
            uint8_t buffer[8];
            if (!readMemory(res.address, buffer, res.valueSize)) continue;
            size_t sizeCheck = 0;
            if (compareValue(buffer, targetBytes.data(), type, condition, sizeCheck)) {
                ScanResult nr;
                nr.address = res.address;
                nr.dataType = type;
                nr.valueSize = sizeCheck;
                nr.previousValue.assign(buffer, buffer + sizeCheck);
                newResults.push_back(nr);
            }
            processed++;
            if (env && callbackObj && g_onProgressMethod) {
                int percent = (processed * 100) / total;
                env->CallVoidMethod(callbackObj, g_onProgressMethod, percent);
            }
        }
    }

    // Atualiza resultados
    {
        std::unique_lock<std::shared_mutex> lock(g_resultsMutex);
        g_results = std::move(newResults);
    }
    g_scanRunning = false;
    g_scanCancelled = false;

    // Callback de conclusão
    if (env && callbackObj && g_onCompleteMethod) {
        jsize count = g_results.size();
        jlongArray arr = env->NewLongArray(count);
        jobjectArray valArray = env->NewObjectArray(count, env->FindClass("[B"), nullptr);
        if (arr && valArray) {
            jlong* elements = env->GetLongArrayElements(arr, nullptr);
            for (size_t i = 0; i < count; ++i) {
                elements[i] = (jlong)g_results[i].address;
                jbyteArray ba = env->NewByteArray(g_results[i].valueSize);
                env->SetByteArrayRegion(ba, 0, g_results[i].valueSize,
                                        (const jbyte*)g_results[i].previousValue.data());
                env->SetObjectArrayElement(valArray, i, ba);
                env->DeleteLocalRef(ba);
            }
            env->ReleaseLongArrayElements(arr, elements, 0);
            env->CallVoidMethod(callbackObj, g_onCompleteMethod, arr, valArray);
            env->DeleteLocalRef(arr);
            env->DeleteLocalRef(valArray);
        } else {
            env->CallVoidMethod(callbackObj, g_onCompleteMethod, nullptr, nullptr);
        }
    }
}

// ======================== FREEZE THREAD ========================

static void freezeLoop() {
    std::unique_lock<std::mutex> lock(g_freezeCvMutex);
    while (g_freezeRunning) {
        // Aguarda até que haja itens congelados ou sinal de parada
        g_freezeCv.wait_for(lock, std::chrono::milliseconds(100), []{
            return !g_freezeRunning || !g_frozen.empty();
        });
        if (!g_freezeRunning) break;
        if (g_frozen.empty()) {
            // Se estiver vazio, continua esperando
            continue;
        }
        // Copia os itens congelados para evitar segurar o mutex durante a escrita
        std::unordered_map<uintptr_t, std::pair<std::vector<uint8_t>, int>> frozenCopy;
        {
            std::shared_lock<std::shared_mutex> lock(g_frozenMutex);
            frozenCopy = g_frozen;
        }
        // Escreve cada endereço
        for (const auto& entry : frozenCopy) {
            writeMemory(entry.first, entry.second.first.data(), entry.second.first.size());
        }
    }
}

// ======================== JNI IMPLEMENTATIONS ========================

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeStartScan(
    JNIEnv* env, jobject thiz, jint value, jint type, jint condition) {

    if (g_scanRunning.load()) {
        LOGE("Scan já em execução");
        return;
    }

    // Guarda callback
    if (g_callbackObj == nullptr) {
        g_callbackObj = env->NewGlobalRef(thiz);
        jclass cls = env->GetObjectClass(thiz);
        g_onProgressMethod = env->GetMethodID(cls, "onScanProgress", "(I)V");
        g_onCompleteMethod = env->GetMethodID(cls, "onScanComplete", "([J[[B)V");
        if (!g_onProgressMethod || !g_onCompleteMethod) {
            LOGE("Métodos de callback não encontrados");
            env->DeleteGlobalRef(g_callbackObj);
            g_callbackObj = nullptr;
            return;
        }
    }

    g_scanRunning = true;
    g_scanCancelled = false;

    if (g_scanThread.joinable()) {
        g_scanThread.join();
    }
    g_scanThread = std::thread(scanThread, g_callbackObj, (long long)value, type, condition, false);
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeNextScan(
    JNIEnv* env, jobject thiz, jint value, jint condition) {

    if (g_scanRunning.load()) {
        LOGE("Scan já em execução");
        return;
    }
    {
        std::shared_lock<std::shared_mutex> lock(g_resultsMutex);
        if (g_results.empty()) {
            LOGE("Nenhum resultado para refinar");
            return;
        }
    }

    // Usa o tipo do primeiro resultado (assume que todos têm o mesmo tipo)
    int type;
    {
        std::shared_lock<std::shared_mutex> lock(g_resultsMutex);
        type = g_results[0].dataType;
    }

    g_scanRunning = true;
    g_scanCancelled = false;

    if (g_scanThread.joinable()) {
        g_scanThread.join();
    }
    g_scanThread = std::thread(scanThread, g_callbackObj, (long long)value, type, condition, true);
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeCancelScan(
    JNIEnv* env, jobject thiz) {
    g_scanCancelled = true;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeClearResults(
    JNIEnv* env, jobject thiz) {
    // Para o freeze
    {
        std::unique_lock<std::shared_mutex> lock(g_frozenMutex);
        g_frozen.clear();
    }
    {
        std::unique_lock<std::mutex> lock(g_freezeCvMutex);
        if (g_freezeRunning) {
            g_freezeRunning = false;
            g_freezeCv.notify_all();
        }
    }
    if (g_freezeThread.joinable()) {
        g_freezeThread.join();
    }

    // Limpa resultados
    {
        std::unique_lock<std::shared_mutex> lock(g_resultsMutex);
        g_results.clear();
    }
}

JNIEXPORT jlongArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetResults(
    JNIEnv* env, jobject thiz) {
    std::shared_lock<std::shared_mutex> lock(g_resultsMutex);
    jsize count = g_results.size();
    jlongArray arr = env->NewLongArray(count);
    if (arr) {
        jlong* elements = env->GetLongArrayElements(arr, nullptr);
        for (size_t i = 0; i < count; ++i) {
            elements[i] = (jlong)g_results[i].address;
        }
        env->ReleaseLongArrayElements(arr, elements, 0);
    }
    return arr;
}

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeWriteMemory(
    JNIEnv* env, jobject thiz, jlong address, jbyteArray data) {

    jsize len = env->GetArrayLength(data);
    jbyte* bytes = env->GetByteArrayElements(data, nullptr);
    bool ok = writeMemory((uintptr_t)address, bytes, len);
    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeToggleFreeze(
    JNIEnv* env, jobject thiz, jlong address, jint value, jint type, jboolean enable) {

    std::unique_lock<std::shared_mutex> lock(g_frozenMutex);
    uintptr_t addr = (uintptr_t)address;

    if (enable) {
        std::vector<uint8_t> bytes = intToBytes(value, type);
        if (bytes.empty()) return;
        g_frozen[addr] = {bytes, type};
        // Inicia thread de freeze se não estiver rodando
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
        if (g_frozen.empty() && g_freezeRunning) {
            // Avisa a thread para parar
            std::unique_lock<std::mutex> cvLock(g_freezeCvMutex);
            g_freezeRunning = false;
            g_freezeCv.notify_all();
        }
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeReadMemory(
    JNIEnv* env, jobject thiz, jlong address, jint size) {

    jbyteArray arr = env->NewByteArray(size);
    if (!arr) return nullptr;
    jbyte* bytes = env->GetByteArrayElements(arr, nullptr);
    bool ok = readMemory((uintptr_t)address, bytes, size);
    env->ReleaseByteArrayElements(arr, bytes, ok ? 0 : JNI_ABORT);
    return ok ? arr : nullptr;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}
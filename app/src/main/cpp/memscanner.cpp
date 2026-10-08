// ============================================================
//  memscanner.cpp
//  Memory Scanner (JNI) — UNIVERSAL + STREAMING EM ARQUIVO
//  Android 11 Go / SELinux Enforcing: /proc/self/mem NÃO funciona.
//  Leitura primária = memcpy + recuperação de SIGSEGV.
//  Handlers reinstalados a cada scan (IL2CPP sobrescreve os nossos).
//
//  v3:
//   - AoB scan (padrão "FF ?? AA 12")
//   - Pointer scan (níveis múltiplos)
//   - Reporter dedicado de progresso (monotônico, sem race)
//   - Resto da v2 (range scan, filtro opcional, vicinity)
// ============================================================

#include "memscanner.h"

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <new>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <chrono>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
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
//  Enums
// ============================================================
enum DataType { TYPE_BYTE=0, TYPE_SHORT=1, TYPE_INT=2,
                TYPE_LONG=3, TYPE_FLOAT=4, TYPE_DOUBLE=5 };

enum ScanCondition { COND_EXACT=0, COND_GREATER=1, COND_LESS=2, COND_RANGE=3 };

enum RegionFilterFlags {
    RF_NONE      = 0,
    RF_RW_ONLY   = 1 << 0,
    RF_SKIP_EXEC = 1 << 1,
    RF_ANON_ONLY = 1 << 2,
};

static const char* typeName(int t) {
    switch (t) {
        case TYPE_BYTE: return "BYTE";  case TYPE_SHORT: return "SHORT";
        case TYPE_INT:  return "INT";   case TYPE_LONG:  return "LONG";
        case TYPE_FLOAT:return "FLOAT"; case TYPE_DOUBLE:return "DOUBLE";
        default: return "UNKNOWN";
    }
}
static const char* condName(int c) {
    switch (c) {
        case COND_EXACT:   return "EXACT";
        case COND_GREATER: return "GREATER";
        case COND_LESS:    return "LESS";
        case COND_RANGE:   return "RANGE";
        default: return "UNKNOWN";
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

struct BatchEntry {
    uintptr_t addr;
    uint8_t   data[8];
    uint8_t   size;
    uint8_t   _pad[3];
};

// AoB pattern com máscara (0xFF = comparar, 0x00 = wildcard)
struct AoBPattern {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
    size_t size() const { return bytes.size(); }
    bool empty()  const { return bytes.empty(); }
    // Heurística: usa o byte mais "raro" (não-wildcard) como âncora
    size_t anchorIndex() const {
        for (size_t i = 0; i < mask.size(); i++) if (mask[i]) return i;
        return 0;
    }
};

// ============================================================
//  Armazenamento em arquivo (dois alternados)
// ============================================================
static std::string g_workDir;
static std::string g_pathA, g_pathB;
static std::atomic<int>    g_currentFile{0};
static std::atomic<size_t> g_scanCount{0};
static std::atomic<size_t> g_liveCount{0};
static std::atomic<int>    g_lastScanType{TYPE_INT};

static std::atomic<int>    g_regionFilter{RF_NONE};

static void ensurePaths() {
    if (!g_pathA.empty()) return;
    if (g_workDir.empty()) {
        const char* td = getenv("TMPDIR");
        g_workDir = td ? td : "/data/local/tmp";
    }
    g_pathA = g_workDir + "/memscan_a.bin";
    g_pathB = g_workDir + "/memscan_b.bin";
    LOGI("[INIT] Work dir: %s", g_workDir.c_str());
    struct statvfs st;
    if (statvfs(g_workDir.c_str(), &st) == 0) {
        uint64_t freeB = (uint64_t)st.f_bavail * st.f_frsize;
        LOGI("[INIT] Espaço livre: %llu MB", (unsigned long long)(freeB / 1048576));
    }
}
static inline const std::string& pathOf(int idx) { return (idx == 0) ? g_pathA : g_pathB; }

// ============================================================
//  Estado global
// ============================================================
static std::unordered_map<uintptr_t, std::pair<std::vector<uint8_t>, int>> g_frozen;
static std::shared_mutex       g_frozenMutex;

static std::atomic<bool> g_scanRunning{false};
static std::atomic<bool> g_scanCancelled{false};
static std::atomic<bool> g_memoryExhausted{false};
static std::atomic<bool> g_displayFull{false};
static std::thread       g_scanThread;

static std::thread             g_freezeThread;
static std::atomic<bool>       g_freezeRunning{false};
static std::condition_variable g_freezeCv;
static std::mutex              g_freezeCvMutex;

static JavaVM*    g_jvm              = nullptr;
static jobject    g_callbackObj      = nullptr;
static jmethodID  g_onProgressMethod = nullptr;
static jmethodID  g_onBatchMethod    = nullptr;
static jmethodID  g_onCountMethod    = nullptr;
static jmethodID  g_onCompleteMethod = nullptr;
static jmethodID  g_onPointerBatchMethod    = nullptr;
static jmethodID  g_onPointerCompleteMethod = nullptr;

static jclass     g_byteArrayClass   = nullptr;
static jclass     g_intArrayClass    = nullptr;

static std::atomic<size_t> g_recoveredFaults{0};

// ============================================================
//  SIGSEGV / SIGBUS
// ============================================================
static __thread sigjmp_buf              t_jmpBuf;
static __thread volatile sig_atomic_t   t_inSafeRead = 0;

static struct sigaction g_origSegvAction;
static struct sigaction g_origBusAction;
static bool             g_haveOrigSegv = false;
static bool             g_haveOrigBus  = false;

static void memScannerFaultHandler(int sig, siginfo_t* info, void* ctx);

static void installSigHandlers() {
    struct sigaction sa, prev;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = memScannerFaultHandler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, &prev) == 0) {
        if (prev.sa_sigaction != memScannerFaultHandler) {
            g_origSegvAction = prev;
            g_haveOrigSegv = true;
        }
    } else {
        LOGE("[INIT] sigaction(SIGSEGV) falhou: %s", strerror(errno));
    }

    if (sigaction(SIGBUS, &sa, &prev) == 0) {
        if (prev.sa_sigaction != memScannerFaultHandler) {
            g_origBusAction = prev;
            g_haveOrigBus = true;
        }
    }
}

static void memScannerFaultHandler(int sig, siginfo_t* info, void* ctx) {
    if (t_inSafeRead) {
        g_recoveredFaults.fetch_add(1, std::memory_order_relaxed);
        siglongjmp(t_jmpBuf, 1);
    }

    struct sigaction* orig = nullptr;
    if (sig == SIGSEGV && g_haveOrigSegv) orig = &g_origSegvAction;
    else if (sig == SIGBUS && g_haveOrigBus) orig = &g_origBusAction;

    if (orig) {
        if (orig->sa_flags & SA_SIGINFO) {
            if (orig->sa_sigaction) { orig->sa_sigaction(sig, info, ctx); return; }
        } else if (orig->sa_handler != SIG_IGN && orig->sa_handler != SIG_DFL) {
            orig->sa_handler(sig); return;
        }
    }

    signal(sig, SIG_DFL);
    raise(sig);
}

// ============================================================
//  JNI Thread Attacher
// ============================================================
class JniThreadAttacher {
public:
    explicit JniThreadAttacher(JavaVM* vm) : m_vm(vm), m_env(nullptr), m_attached(false) {
        if (m_vm->GetEnv((void**)&m_env, JNI_VERSION_1_6) == JNI_OK) return;
        if (m_vm->AttachCurrentThread(&m_env, nullptr) == JNI_OK) m_attached = true;
        else m_env = nullptr;
    }
    ~JniThreadAttacher() { if (m_attached && m_env) m_vm->DetachCurrentThread(); }
    JNIEnv* getEnv() const { return m_env; }
private:
    JavaVM* m_vm; JNIEnv* m_env; bool m_attached;
};

// ============================================================
//  FileSink
// ============================================================
class FileSink {
public:
    static const size_t STAGE = 1024;
    FileSink(int fd, std::mutex& mtx, std::atomic<size_t>& counter)
        : m_fd(fd), m_mtx(mtx), m_counter(counter) { m_stage.reserve(STAGE); }
    ~FileSink() { flush(); }

    inline void add(uintptr_t a) {
        m_stage.push_back(a);
        if (m_stage.size() >= STAGE) flush();
    }
    void flush() {
        if (m_stage.empty() || m_fd < 0) { m_stage.clear(); return; }
        std::lock_guard<std::mutex> lk(m_mtx);
        const uint8_t* p = (const uint8_t*)m_stage.data();
        size_t bytes = m_stage.size() * sizeof(uintptr_t);
        size_t written = 0;
        while (written < bytes) {
            ssize_t n = ::write(m_fd, p + written, bytes - written);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                LOGE("[SINK] write falhou: %s", strerror(errno));
                g_memoryExhausted.exchange(true);
                break;
            }
            written += (size_t)n;
        }
        m_counter.fetch_add(m_stage.size());
        m_stage.clear();
    }
private:
    int m_fd; std::mutex& m_mtx; std::atomic<size_t>& m_counter;
    std::vector<uintptr_t> m_stage;
};

// ============================================================
//  BatchFlusher — envia lotes para a UI
// ============================================================
static const size_t BATCH_SIZE = 1024;

class BatchFlusher {
public:
    BatchFlusher(JNIEnv* env, jobject cb, jmethodID m)
        : m_env(env), m_cb(cb), m_method(m) { m_entries.reserve(BATCH_SIZE); }

    inline void add(uintptr_t a, const uint8_t* v, size_t s) {
        if (g_displayFull.load(std::memory_order_relaxed)) return;
        BatchEntry e; e.addr = a; e.size = (uint8_t)(s > 8 ? 8 : s);
        memcpy(e.data, v, e.size);
        m_entries.push_back(e);
    }
    inline bool full() const { return m_entries.size() >= BATCH_SIZE; }

    void flush() {
        if (m_entries.empty()) return;
        if (g_displayFull.load(std::memory_order_relaxed)) { m_entries.clear(); return; }
        if (!m_env || !m_cb || !m_method) { m_entries.clear(); return; }
        if (m_env->ExceptionCheck()) { m_env->ExceptionClear(); m_entries.clear(); return; }

        jsize count = (jsize)m_entries.size();
        jlongArray arr = m_env->NewLongArray(count);
        if (!arr || m_env->ExceptionCheck()) { m_env->ExceptionClear(); m_entries.clear(); return; }

        if (g_byteArrayClass == nullptr) {
            jclass local = m_env->FindClass("[B");
            if (!local) { m_env->ExceptionClear(); m_env->DeleteLocalRef(arr); m_entries.clear(); return; }
            g_byteArrayClass = (jclass)m_env->NewGlobalRef(local);
            m_env->DeleteLocalRef(local);
        }

        jobjectArray vals = m_env->NewObjectArray(count, g_byteArrayClass, nullptr);
        if (!vals || m_env->ExceptionCheck()) {
            m_env->ExceptionClear(); m_env->DeleteLocalRef(arr); m_entries.clear(); return;
        }
        jlong* elems = m_env->GetLongArrayElements(arr, nullptr);
        bool abort = false;
        if (elems && !m_env->ExceptionCheck()) {
            for (jsize i = 0; i < count && !abort; i++) {
                elems[i] = (jlong)m_entries[i].addr;
                jbyteArray ba = m_env->NewByteArray((jsize)m_entries[i].size);
                if (!ba || m_env->ExceptionCheck()) { m_env->ExceptionClear(); abort = true; break; }
                m_env->SetByteArrayRegion(ba, 0, (jsize)m_entries[i].size,
                                          (const jbyte*)m_entries[i].data);
                m_env->SetObjectArrayElement(vals, i, ba);
                m_env->DeleteLocalRef(ba);
            }
            m_env->ReleaseLongArrayElements(arr, elems, 0);
        }
        if (!abort && !m_env->ExceptionCheck()) {
            m_env->CallVoidMethod(m_cb, m_method, arr, vals);
            if (m_env->ExceptionCheck()) { m_env->ExceptionDescribe(); m_env->ExceptionClear(); }
        }
        m_env->DeleteLocalRef(vals); m_env->DeleteLocalRef(arr);
        m_entries.clear();
    }
private:
    JNIEnv* m_env; jobject m_cb; jmethodID m_method;
    std::vector<BatchEntry> m_entries;
};

// ============================================================
//  parseMaps — Universal por padrão, filtro opcional
// ============================================================
static std::vector<MemoryRegion> parseMaps() {
    std::vector<MemoryRegion> regions;
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) { LOGE("[MAPS] Falha /proc/self/maps"); return regions; }

    const int filter = g_regionFilter.load(std::memory_order_relaxed);

    std::string line;
    int total = 0, accepted = 0, skippedSp = 0, skippedBad = 0, skippedFilt = 0;
    while (std::getline(maps, line)) {
        total++;
        std::istringstream iss(line);
        uintptr_t s, e; char dash; std::string perms, path;
        iss >> std::hex >> s >> dash >> e >> perms;
        std::string tmp; iss >> tmp >> tmp >> tmp;
        std::getline(iss, path);
        if (!path.empty() && path[0] == ' ') path.erase(0, 1);

        if (path.find("[vsyscall]") != std::string::npos ||
            path.find("[vvar]")     != std::string::npos ||
            path.find("[vdso]")     != std::string::npos ||
            path.find("libmemscanner.so") != std::string::npos) {
            skippedSp++; continue;
        }
        if (perms.size() < 3 || perms[0] != 'r' || e <= s ||
            (e - s) > (uintptr_t)512 * 1024 * 1024) {
            skippedBad++; continue;
        }
        if (filter != RF_NONE) {
            if ((filter & RF_RW_ONLY)   && perms[1] != 'w') { skippedFilt++; continue; }
            if ((filter & RF_SKIP_EXEC) && perms[2] == 'x') { skippedFilt++; continue; }
            if ((filter & RF_ANON_ONLY) && !path.empty() && path[0] == '/') { skippedFilt++; continue; }
        }
        MemoryRegion r; r.start=s; r.end=e;
        r.readable=true; r.writable=(perms[1]=='w'); r.executable=(perms[2]=='x');
        r.path=path; regions.push_back(r); accepted++;
    }
    std::sort(regions.begin(), regions.end(),
              [](const MemoryRegion& a, const MemoryRegion& b) {
                  return (a.end - a.start) > (b.end - b.start);
              });
    LOGI("[MAPS] %d linhas | %d aceitas | %d puladas(esp) | %d inválidas | %d filtradas (mask=0x%X)",
         total, accepted, skippedSp, skippedBad, skippedFilt, filter);
    return regions;
}

// ============================================================
//  Leitura/escrita protegidas por sinal
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

static bool writeMemory(uintptr_t address, const void* buffer, size_t size) {
    int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        errno = 0;
        ssize_t n = pwrite64(fd, buffer, size, (off64_t)address);
        close(fd);
        if (n == (ssize_t)size) return true;
    }
    if (safeWriteMemory(address, buffer, size)) return true;
    size_t ps = sysconf(_SC_PAGE_SIZE);
    uintptr_t pS = (address / ps) * ps;
    size_t pL = ((address - pS + size + ps - 1) / ps) * ps;
    if (mprotect((void*)pS, pL, PROT_READ | PROT_WRITE) == 0)
        if (safeWriteMemory(address, buffer, size)) return true;
    LOGE("[WRITE] Falhou 0x%lx (errno=%d)", (unsigned long)address, errno);
    return false;
}

// ============================================================
//  Comparação de valores
// ============================================================
template<typename T>
static inline bool cmpRange(T v, T a, T b) { return v >= a && v <= b; }

static bool compareValue(const uint8_t* data, const void* t1, const void* t2,
                         int type, int condition, size_t& outSize) {
    outSize = 0;
    switch (type) {
        case TYPE_BYTE: {
            uint8_t a = *data; outSize = 1;
            uint8_t b1 = *(const uint8_t*)t1;
            if (condition == COND_EXACT)   return a == b1;
            if (condition == COND_GREATER) return a >  b1;
            if (condition == COND_LESS)    return a <  b1;
            if (condition == COND_RANGE)   return cmpRange<uint8_t>(a, b1, *(const uint8_t*)t2);
            return true;
        }
        case TYPE_SHORT: {
            int16_t a; memcpy(&a, data, 2); outSize = 2;
            int16_t b1; memcpy(&b1, t1, 2);
            if (condition == COND_EXACT)   return a == b1;
            if (condition == COND_GREATER) return a >  b1;
            if (condition == COND_LESS)    return a <  b1;
            if (condition == COND_RANGE) { int16_t b2; memcpy(&b2, t2, 2); return cmpRange<int16_t>(a, b1, b2); }
            return true;
        }
        case TYPE_INT: {
            int32_t a; memcpy(&a, data, 4); outSize = 4;
            int32_t b1; memcpy(&b1, t1, 4);
            if (condition == COND_EXACT)   return a == b1;
            if (condition == COND_GREATER) return a >  b1;
            if (condition == COND_LESS)    return a <  b1;
            if (condition == COND_RANGE) { int32_t b2; memcpy(&b2, t2, 4); return cmpRange<int32_t>(a, b1, b2); }
            return true;
        }
        case TYPE_LONG: {
            int64_t a; memcpy(&a, data, 8); outSize = 8;
            int64_t b1; memcpy(&b1, t1, 8);
            if (condition == COND_EXACT)   return a == b1;
            if (condition == COND_GREATER) return a >  b1;
            if (condition == COND_LESS)    return a <  b1;
            if (condition == COND_RANGE) { int64_t b2; memcpy(&b2, t2, 8); return cmpRange<int64_t>(a, b1, b2); }
            return true;
        }
        case TYPE_FLOAT: {
            float a; memcpy(&a, data, 4); outSize = 4;
            float b1; memcpy(&b1, t1, 4);
            if (condition == COND_EXACT)   return a == b1;
            if (condition == COND_GREATER) return a >  b1;
            if (condition == COND_LESS)    return a <  b1;
            if (condition == COND_RANGE) { float b2; memcpy(&b2, t2, 4); return cmpRange<float>(a, b1, b2); }
            return true;
        }
        case TYPE_DOUBLE: {
            double a; memcpy(&a, data, 8); outSize = 8;
            double b1; memcpy(&b1, t1, 8);
            if (condition == COND_EXACT)   return a == b1;
            if (condition == COND_GREATER) return a >  b1;
            if (condition == COND_LESS)    return a <  b1;
            if (condition == COND_RANGE) { double b2; memcpy(&b2, t2, 8); return cmpRange<double>(a, b1, b2); }
            return true;
        }
        default: return false;
    }
}

static std::vector<uint8_t> intToBytes(long long v, int t) {
    std::vector<uint8_t> b;
    switch (t) {
        case TYPE_BYTE: b.push_back((uint8_t)v); break;
        case TYPE_SHORT: { int16_t x=(int16_t)v; b.assign((uint8_t*)&x,(uint8_t*)&x+2); break; }
        case TYPE_INT:   { int32_t x=(int32_t)v; b.assign((uint8_t*)&x,(uint8_t*)&x+4); break; }
        case TYPE_LONG:  { int64_t x=(int64_t)v; b.assign((uint8_t*)&x,(uint8_t*)&x+8); break; }
        case TYPE_FLOAT: { uint32_t x=(uint32_t)v; b.assign((uint8_t*)&x,(uint8_t*)&x+4); break; }
        case TYPE_DOUBLE:{ uint64_t x=(uint64_t)v; b.assign((uint8_t*)&x,(uint8_t*)&x+8); break; }
    }
    return b;
}

// ============================================================
//  AoB — parsing e matching
// ============================================================
static AoBPattern parseAoBPattern(const std::string& pattern) {
    AoBPattern result;
    std::string s = pattern;
    // Aceita vários separadores comuns
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (c == ',' || c == '-' || c == ':' || c == ';' || c == '\t' || c == '\n')
            s[i] = ' ';
    }

    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) {
        if (tok == "?" || tok == "??" || tok == "xx" || tok == "XX") {
            result.bytes.push_back(0);
            result.mask.push_back(0x00);
        } else {
            // Aceita "??" como parte do token (ex: "FF??AA")?
            // Simplificação: processa caractere a caractere dentro do token.
            bool anyParsed = false;
            if (tok.find('?') != std::string::npos && tok.size() > 2) {
                // Token misto tipo "FF??AA": divide em pares
                for (size_t i = 0; i + 1 < tok.size(); i += 2) {
                    std::string pair = tok.substr(i, 2);
                    if (pair == "??" || pair == "?x" || pair == "x?") {
                        result.bytes.push_back(0);
                        result.mask.push_back(0x00);
                    } else {
                        try {
                            unsigned int b = std::stoul(pair, nullptr, 16);
                            if (b <= 0xFF) {
                                result.bytes.push_back((uint8_t)b);
                                result.mask.push_back(0xFF);
                            }
                        } catch (...) {}
                    }
                }
                anyParsed = true;
            }
            if (!anyParsed) {
                try {
                    unsigned int b = std::stoul(tok, nullptr, 16);
                    if (b <= 0xFF) {
                        result.bytes.push_back((uint8_t)b);
                        result.mask.push_back(0xFF);
                    }
                } catch (...) {
                    // Token inválido — ignora
                }
            }
        }
    }
    return result;
}

static inline bool matchAoB(const uint8_t* data, const AoBPattern& p) {
    for (size_t i = 0; i < p.bytes.size(); i++) {
        if (p.mask[i] && data[i] != p.bytes[i]) return false;
    }
    return true;
}

// ============================================================
//  Escolha do número de threads
// ============================================================
static int pickThreadCount() {
    unsigned cores = std::thread::hardware_concurrency();
    int nThr = (int)(cores == 0 ? 2u : cores);
    if (sizeof(void*) == 4) { if (nThr > 3) nThr = 3; }
    else                    { if (nThr > 4) nThr = 4; }
    if (nThr < 1) nThr = 1;
    return nThr;
}

// ============================================================
//  >>> CONTINUA NA PARTE 2 <<<
//  (scanBuffer, scanRegion, scanThread, nextScanThread,
//   AoB scan thread, Pointer scan thread, freezeLoop,
//   JNI methods, JNI_OnLoad)
// ============================================================
// ============================================================
//  scanBuffer — varredura de um buffer
// ============================================================
template<typename Emit>
static void scanBuffer(const uint8_t* base, size_t len, uintptr_t baseAddr,
                       const std::vector<uint8_t>& tgt,
                       const std::vector<uint8_t>& tgt2,
                       size_t tgtSz, int type, int condition, Emit& emit) {
    if (len < tgtSz) return;
    const bool exact = (condition == COND_EXACT);
    const size_t limit = len - tgtSz;

    if (exact) {
        const uint8_t first = tgt[0];
        size_t off = 0;
        while (off <= limit) {
            if (g_scanCancelled.load(std::memory_order_relaxed)) return;
            if (g_memoryExhausted.load(std::memory_order_relaxed)) return;
            const uint8_t* p = (const uint8_t*)memchr(base + off, first, limit - off + 1);
            if (!p) break;
            size_t o = (size_t)(p - base);
            if (tgtSz == 1 || memcmp(p, tgt.data(), tgtSz) == 0)
                emit(baseAddr + o, p, tgtSz);
            off = o + 1;
        }
    } else {
        for (size_t o = 0; o <= limit; o++) {
            if (g_scanCancelled.load(std::memory_order_relaxed)) return;
            if (g_memoryExhausted.load(std::memory_order_relaxed)) return;
            size_t sz = 0;
            const void* t2 = tgt2.empty() ? tgt.data() : tgt2.data();
            if (compareValue(base + o, tgt.data(), t2, type, condition, sz))
                emit(baseAddr + o, base + o, sz);
        }
    }
}

// ============================================================
//  scanAoBBuffer — varredura AoB
// ============================================================
template<typename Emit>
static void scanAoBBuffer(const uint8_t* base, size_t len, uintptr_t baseAddr,
                          const AoBPattern& pat, Emit& emit) {
    const size_t psz = pat.size();
    if (psz == 0 || len < psz) return;
    const size_t limit = len - psz;
    const size_t anchorIdx = pat.anchorIndex();
    const uint8_t anchorByte = pat.bytes[anchorIdx];
    const bool hasAnchor = pat.mask[anchorIdx] != 0;

    if (!hasAnchor) {
        // Todos wildcards — não faz sentido, retorna
        return;
    }

    size_t off = 0;
    while (off <= limit) {
        if (g_scanCancelled.load(std::memory_order_relaxed)) return;
        if (g_memoryExhausted.load(std::memory_order_relaxed)) return;

        // Procura o byte de âncora
        const uint8_t* p = (const uint8_t*)memchr(
        base + off + anchorIdx, anchorByte, limit - off + 1);
        if (!p) break;
        size_t o = (size_t)(p - base) - anchorIdx;

        if (matchAoB(base + o, pat))
            emit(baseAddr + o, base + o, psz);

        off = o + 1;
    }
}

// ============================================================
//  scanRegion — página a página, buffer thread-local
// ============================================================
static thread_local std::vector<uint8_t> t_scanBuf;

template<typename Emit>
static void scanRegion(const MemoryRegion& reg,
                       const std::vector<uint8_t>& tgt,
                       const std::vector<uint8_t>& tgt2,
                       size_t tgtSz,
                       int type, int condition, Emit& emit,
                       std::atomic<size_t>& bytesOut,
                       std::atomic<size_t>& scannedOut,
                       std::atomic<size_t>& readsOut,
                       std::atomic<size_t>& failOut) {
    if (!reg.readable || reg.start >= reg.end) return;

    const size_t PS = (size_t)sysconf(_SC_PAGE_SIZE);
    const size_t BUF_SIZE = PS + 16;
    if (t_scanBuf.size() < BUF_SIZE) t_scanBuf.resize(BUF_SIZE);

    uintptr_t addr = reg.start;
    while (addr < reg.end
           && !g_scanCancelled.load(std::memory_order_relaxed)
           && !g_memoryExhausted.load(std::memory_order_relaxed)) {

        size_t rem = reg.end - addr;
        size_t rd = PS + tgtSz - 1;
        if (rd > rem) rd = rem;
        if (rd < tgtSz) break;

        readsOut.fetch_add(1, std::memory_order_relaxed);
        scannedOut.fetch_add(rd, std::memory_order_relaxed);

        if (safeReadMemory(addr, t_scanBuf.data(), rd)) {
            bytesOut.fetch_add(rd, std::memory_order_relaxed);
            scanBuffer(t_scanBuf.data(), rd, addr, tgt, tgt2, tgtSz, type, condition, emit);
        } else {
            failOut.fetch_add(1, std::memory_order_relaxed);
        }
        addr += PS;
    }
}

// ============================================================
//  scanAoBRegion — versão AoB
// ============================================================
template<typename Emit>
static void scanAoBRegion(const MemoryRegion& reg,
                          const AoBPattern& pat,
                          Emit& emit,
                          std::atomic<size_t>& bytesOut,
                          std::atomic<size_t>& scannedOut,
                          std::atomic<size_t>& readsOut,
                          std::atomic<size_t>& failOut) {
    if (!reg.readable || reg.start >= reg.end) return;
    const size_t psz = pat.size();
    if (psz == 0) return;

    const size_t PS = (size_t)sysconf(_SC_PAGE_SIZE);
    const size_t BUF_SIZE = PS + psz - 1 + 16;
    if (t_scanBuf.size() < BUF_SIZE) t_scanBuf.resize(BUF_SIZE);

    uintptr_t addr = reg.start;
    while (addr < reg.end
           && !g_scanCancelled.load(std::memory_order_relaxed)
           && !g_memoryExhausted.load(std::memory_order_relaxed)) {

        size_t rem = reg.end - addr;
        size_t rd = PS + psz - 1;
        if (rd > rem) rd = rem;
        if (rd < psz) break;

        readsOut.fetch_add(1, std::memory_order_relaxed);
        scannedOut.fetch_add(rd, std::memory_order_relaxed);

        if (safeReadMemory(addr, t_scanBuf.data(), rd)) {
            bytesOut.fetch_add(rd, std::memory_order_relaxed);
            scanAoBBuffer(t_scanBuf.data(), rd, addr, pat, emit);
        } else {
            failOut.fetch_add(1, std::memory_order_relaxed);
        }
        addr += PS;
    }
}

// ============================================================
//  scanThread — primeira varredura de valor
//  Fix do progresso: reporter dedicado + monotônico
// ============================================================
static void scanThread(jobject cb, long long value, long long value2,
                       int type, int condition) {
    auto t0 = std::chrono::steady_clock::now();
    LOGI("=========================================================");
    LOGI("[SCAN] Primeira varredura | %s %s v1=%lld v2=%lld",
         typeName(type), condName(condition), value, value2);
    LOGI("=========================================================");

    installSigHandlers();

    ensurePaths();
    JniThreadAttacher att(g_jvm);
    JNIEnv* env = att.getEnv();
    if (!env) { g_scanRunning = false; return; }

    std::vector<uint8_t> tgt  = intToBytes(value,  type);
    std::vector<uint8_t> tgt2 = intToBytes(value2, type);
    if (tgt.empty()) { g_scanRunning = false; return; }
    size_t tgtSz = tgt.size();

    auto regions = parseMaps();
    if (regions.empty()) {
        g_scanRunning = false; g_memoryExhausted = false;
        if (cb && g_onCompleteMethod)
            env->CallVoidMethod(cb, g_onCompleteMethod, 0, JNI_FALSE);
        return;
    }

    int outIdx = 1 - g_currentFile.load();
    const std::string& outPath = pathOf(outIdx);

    int outFd = open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (outFd < 0) {
        LOGE("[SCAN] open falhou: %s", strerror(errno));
        g_scanRunning = false;
        if (cb && g_onCompleteMethod)
            env->CallVoidMethod(cb, g_onCompleteMethod, 0, JNI_TRUE);
        return;
    }

    g_liveCount = 0;
    g_recoveredFaults.store(0);

    const int nReg = (int)regions.size();
    const int nThr = pickThreadCount();

    size_t totalRegionBytes = 0;
    for (const auto& r : regions) totalRegionBytes += (r.end - r.start);
    LOGI("[SCAN] %d regiões | %d threads | %.2f MB",
         nReg, nThr, totalRegionBytes / 1048576.0);

    std::atomic<int>    nextReg{0};
    std::atomic<size_t> bytesAt{0}, scannedAt{0}, readsAt{0}, failAt{0};
    std::mutex writeMutex;

    // ===== Reporter dedicado (progresso monotônico) =====
    std::atomic<bool> reporterRunning{true};
    std::thread reporter;
    if (cb && g_onProgressMethod) {
        reporter = std::thread([&, cb]() {
            JniThreadAttacher a(g_jvm);
            JNIEnv* e = a.getEnv();
            if (!e) return;
            int lastPct = -1;
            while (reporterRunning.load(std::memory_order_relaxed)) {
                size_t sc = scannedAt.load(std::memory_order_relaxed);
                int p = totalRegionBytes
                        ? (int)((sc * 100) / totalRegionBytes) : 0;
                if (p > 99) p = 99;
                if (p > lastPct) {
                    lastPct = p;
                    e->CallVoidMethod(cb, g_onProgressMethod, p);
                    if (e->ExceptionCheck()) e->ExceptionClear();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
            }
            e->CallVoidMethod(cb, g_onProgressMethod, 100);
            if (e->ExceptionCheck()) e->ExceptionClear();
        });
    }

    auto worker = [&]() {
        setpriority(PRIO_PROCESS, 0, 10);
        JniThreadAttacher a(g_jvm);
        JNIEnv* e = a.getEnv();

        FileSink sink(outFd, writeMutex, g_liveCount);
        BatchFlusher flusher(e, cb, g_onBatchMethod);

        auto emit = [&](uintptr_t addr, const uint8_t* val, size_t sz) {
            sink.add(addr);
            flusher.add(addr, val, sz);
            if (flusher.full()) flusher.flush();
        };

        while (true) {
            if (g_scanCancelled.load())   break;
            if (g_memoryExhausted.load()) break;
            int idx = nextReg.fetch_add(1);
            if (idx >= nReg) break;
            scanRegion(regions[idx], tgt, tgt2, tgtSz, type, condition, emit,
                       bytesAt, scannedAt, readsAt, failAt);
        }
        flusher.flush();
        sink.flush();
    };

    std::vector<std::thread> workers;
    workers.reserve(nThr);
    for (int i = 0; i < nThr; i++) workers.emplace_back(worker);
    for (auto& w : workers) w.join();

    // Para o reporter
    reporterRunning = false;
    if (reporter.joinable()) reporter.join();

    fsync(outFd);
    close(outFd);

    size_t finalCount = g_liveCount.load();
    g_currentFile.store(outIdx);
    g_scanCount.store(finalCount);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - t0).count();
    LOGI("=========================================================");
    LOGI("[SCAN] FIM em %lld ms | Endereços: %zu | Bytes: %.2f MB",
         (long long)ms, finalCount, bytesAt.load() / 1048576.0);
    LOGI("[SCAN]   Leituras: %zu | Páginas ruins: %zu | Faults: %zu",
         readsAt.load(), failAt.load(), g_recoveredFaults.load());
    LOGI("=========================================================");

    bool exhausted = g_memoryExhausted.load();
    g_scanRunning = false;
    g_scanCancelled = false;
    g_memoryExhausted = false;

    if (cb && g_onCompleteMethod)
        env->CallVoidMethod(cb, g_onCompleteMethod,
                            (jint)finalCount, exhausted ? JNI_TRUE : JNI_FALSE);
}

// ============================================================
//  nextScanThread — refino paralelo
// ============================================================
static void nextScanWorker(int inFd, off64_t startByte, size_t entries,
                           jobject cb,
                           const std::vector<uint8_t>& tgt,
                           const std::vector<uint8_t>& tgt2,
                           size_t tgtSz, int type, int condition,
                           FileSink& sink,
                           std::atomic<size_t>& processedOut,
                           std::atomic<size_t>& failedOut) {
    JniThreadAttacher a(g_jvm);
    JNIEnv* e = a.getEnv();
    BatchFlusher flusher(e, cb, g_onBatchMethod);

    const size_t CHUNK = 4096;
    std::vector<uintptr_t> buf(CHUNK);

    off64_t off = startByte;
    size_t remaining = entries;

    while (remaining > 0
           && !g_scanCancelled.load()
           && !g_memoryExhausted.load()) {
        size_t want = remaining > CHUNK ? CHUNK : remaining;
        ssize_t got = pread64(inFd, buf.data(), want * sizeof(uintptr_t), off);
        if (got <= 0) break;
        size_t cnt = (size_t)got / sizeof(uintptr_t);
        if (cnt == 0) break;

        for (size_t i = 0; i < cnt; i++) {
            if (g_scanCancelled.load() || g_memoryExhausted.load()) break;
            uintptr_t addr = buf[i];
            uint8_t v[8];
            if (!safeReadMemory(addr, v, tgtSz)) { failedOut.fetch_add(1); continue; }
            size_t sz = 0;
            const void* t2 = tgt2.empty() ? tgt.data() : tgt2.data();
            if (compareValue(v, tgt.data(), t2, type, condition, sz)) {
                sink.add(addr);
                flusher.add(addr, v, sz);
                if (flusher.full()) flusher.flush();
            }
        }
        off += (off64_t)cnt * sizeof(uintptr_t);
        remaining -= cnt;
        processedOut.fetch_add(cnt, std::memory_order_relaxed);
    }
    flusher.flush();
}

static void nextScanThread(jobject cb, long long value, long long value2,
                           int type, int condition) {
    auto t0 = std::chrono::steady_clock::now();
    LOGI("[SCAN] Refino | %s %s v1=%lld v2=%lld",
         typeName(type), condName(condition), value, value2);

    installSigHandlers();
    ensurePaths();
    JniThreadAttacher att(g_jvm);
    JNIEnv* env = att.getEnv();
    if (!env) { g_scanRunning = false; return; }

    std::vector<uint8_t> tgt  = intToBytes(value,  type);
    std::vector<uint8_t> tgt2 = intToBytes(value2, type);
    if (tgt.empty()) { g_scanRunning = false; return; }
    size_t tgtSz = tgt.size();

    int inIdx  = g_currentFile.load();
    int outIdx = 1 - inIdx;
    const std::string& inPath  = pathOf(inIdx);
    const std::string& outPath = pathOf(outIdx);

    int inFd  = open(inPath.c_str(),  O_RDONLY);
    int outFd = open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (inFd < 0 || outFd < 0) {
        LOGE("[SCAN] open falhou");
        if (inFd  >= 0) close(inFd);
        if (outFd >= 0) close(outFd);
        g_scanRunning = false;
        if (cb && g_onCompleteMethod)
            env->CallVoidMethod(cb, g_onCompleteMethod, 0, JNI_TRUE);
        return;
    }

    off64_t fileSize = lseek64(inFd, 0, SEEK_END);
    size_t totalEntries = (fileSize > 0) ? (size_t)(fileSize / sizeof(uintptr_t)) : 0;
    LOGI("[SCAN] Refinando %zu endereços", totalEntries);

    if (totalEntries == 0) {
        close(inFd); close(outFd);
        g_scanRunning = false;
        g_scanCancelled = false;
        g_memoryExhausted = false;
        if (cb && g_onCompleteMethod)
            env->CallVoidMethod(cb, g_onCompleteMethod, 0, JNI_FALSE);
        return;
    }

    std::mutex writeMutex;
    g_liveCount = 0;
    g_recoveredFaults.store(0);

    FileSink sink(outFd, writeMutex, g_liveCount);

    const int nThr = pickThreadCount();
    size_t perThread = (totalEntries + nThr - 1) / nThr;
    if (perThread == 0) perThread = 1;

    std::atomic<size_t> processedAt{0}, failedAt{0};

    // Reporter dedicado (progresso monotônico)
    std::atomic<bool> reporterRunning{true};
    std::thread reporter;
    if (cb && g_onProgressMethod) {
        reporter = std::thread([&, cb]() {
            JniThreadAttacher a(g_jvm);
            JNIEnv* e = a.getEnv();
            if (!e) return;
            int lastPct = -1;
            while (reporterRunning.load(std::memory_order_relaxed)) {
                size_t pr = processedAt.load(std::memory_order_relaxed);
                int p = totalEntries ? (int)((pr * 100) / totalEntries) : 0;
                if (p > 99) p = 99;
                if (p > lastPct) {
                    lastPct = p;
                    e->CallVoidMethod(cb, g_onProgressMethod, p);
                    if (e->ExceptionCheck()) e->ExceptionClear();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
            }
            e->CallVoidMethod(cb, g_onProgressMethod, 100);
            if (e->ExceptionCheck()) e->ExceptionClear();
        });
    }

    auto worker = [&](int tid) {
        setpriority(PRIO_PROCESS, 0, 10);
        off64_t startByte = (off64_t)tid * (off64_t)perThread * sizeof(uintptr_t);
        size_t myEntries = 0;
        if ((size_t)tid * perThread < totalEntries) {
            size_t startIdx = (size_t)tid * perThread;
            myEntries = std::min(perThread, totalEntries - startIdx);
        }
        if (myEntries == 0) return;
        nextScanWorker(inFd, startByte, myEntries, cb, tgt, tgt2, tgtSz,
                       type, condition, sink, processedAt, failedAt);
    };

    std::vector<std::thread> workers;
    workers.reserve(nThr);
    for (int i = 0; i < nThr; i++) workers.emplace_back(worker, i);
    for (auto& w : workers) w.join();

    reporterRunning = false;
    if (reporter.joinable()) reporter.join();

    sink.flush();
    fsync(outFd);
    close(inFd);
    close(outFd);

    size_t finalCount = g_liveCount.load();
    g_currentFile.store(outIdx);
    g_scanCount.store(finalCount);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - t0).count();
    LOGI("[SCAN] Refino FIM em %lld ms | %zu endereços | %zu falhas",
         (long long)ms, finalCount, failedAt.load());

    bool exhausted = g_memoryExhausted.load();
    g_scanRunning = false;
    g_scanCancelled = false;
    g_memoryExhausted = false;

    if (cb && g_onCompleteMethod)
        env->CallVoidMethod(cb, g_onCompleteMethod,
                            (jint)finalCount, exhausted ? JNI_TRUE : JNI_FALSE);
}

// ============================================================
//  aobScanThread — varredura por padrão AoB
// ============================================================
static void aobScanThread(jobject cb, AoBPattern pat) {
    auto t0 = std::chrono::steady_clock::now();
    LOGI("=========================================================");
    LOGI("[AOB] Padrão com %zu bytes (%zu fixos)",
         pat.size(), (size_t)std::count(pat.mask.begin(), pat.mask.end(), (uint8_t)0xFF));
    LOGI("=========================================================");

    installSigHandlers();
    ensurePaths();
    JniThreadAttacher att(g_jvm);
    JNIEnv* env = att.getEnv();
    if (!env) { g_scanRunning = false; return; }

    if (pat.empty()) {
        g_scanRunning = false;
        if (cb && g_onCompleteMethod)
            env->CallVoidMethod(cb, g_onCompleteMethod, 0, JNI_FALSE);
        return;
    }

    auto regions = parseMaps();
    if (regions.empty()) {
        g_scanRunning = false;
        if (cb && g_onCompleteMethod)
            env->CallVoidMethod(cb, g_onCompleteMethod, 0, JNI_FALSE);
        return;
    }

    int outIdx = 1 - g_currentFile.load();
    const std::string& outPath = pathOf(outIdx);

    int outFd = open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (outFd < 0) {
        g_scanRunning = false;
        if (cb && g_onCompleteMethod)
            env->CallVoidMethod(cb, g_onCompleteMethod, 0, JNI_TRUE);
        return;
    }

    g_liveCount = 0;
    g_recoveredFaults.store(0);

    const int nReg = (int)regions.size();
    const int nThr = pickThreadCount();

    size_t totalRegionBytes = 0;
    for (const auto& r : regions) totalRegionBytes += (r.end - r.start);

    std::atomic<int>    nextReg{0};
    std::atomic<size_t> bytesAt{0}, scannedAt{0}, readsAt{0}, failAt{0};
    std::mutex writeMutex;

    std::atomic<bool> reporterRunning{true};
    std::thread reporter;
    if (cb && g_onProgressMethod) {
        reporter = std::thread([&, cb]() {
            JniThreadAttacher a(g_jvm);
            JNIEnv* e = a.getEnv();
            if (!e) return;
            int lastPct = -1;
            while (reporterRunning.load(std::memory_order_relaxed)) {
                size_t sc = scannedAt.load(std::memory_order_relaxed);
                int p = totalRegionBytes ? (int)((sc * 100) / totalRegionBytes) : 0;
                if (p > 99) p = 99;
                if (p > lastPct) {
                    lastPct = p;
                    e->CallVoidMethod(cb, g_onProgressMethod, p);
                    if (e->ExceptionCheck()) e->ExceptionClear();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
            }
            e->CallVoidMethod(cb, g_onProgressMethod, 100);
            if (e->ExceptionCheck()) e->ExceptionClear();
        });
    }

    auto worker = [&]() {
        setpriority(PRIO_PROCESS, 0, 10);
        JniThreadAttacher a(g_jvm);
        JNIEnv* e = a.getEnv();

        FileSink sink(outFd, writeMutex, g_liveCount);
        BatchFlusher flusher(e, cb, g_onBatchMethod);

        auto emit = [&](uintptr_t addr, const uint8_t* val, size_t sz) {
            sink.add(addr);
            flusher.add(addr, val, sz);
            if (flusher.full()) flusher.flush();
        };

        while (true) {
            if (g_scanCancelled.load())   break;
            if (g_memoryExhausted.load()) break;
            int idx = nextReg.fetch_add(1);
            if (idx >= nReg) break;
            scanAoBRegion(regions[idx], pat, emit, bytesAt, scannedAt, readsAt, failAt);
        }
        flusher.flush();
        sink.flush();
    };

    std::vector<std::thread> workers;
    workers.reserve(nThr);
    for (int i = 0; i < nThr; i++) workers.emplace_back(worker);
    for (auto& w : workers) w.join();

    reporterRunning = false;
    if (reporter.joinable()) reporter.join();

    fsync(outFd);
    close(outFd);

    size_t finalCount = g_liveCount.load();
    g_currentFile.store(outIdx);
    g_scanCount.store(finalCount);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - t0).count();
    LOGI("[AOB] FIM em %lld ms | %zu hits", (long long)ms, finalCount);

    bool exhausted = g_memoryExhausted.load();
    g_scanRunning = false;
    g_scanCancelled = false;
    g_memoryExhausted = false;

    if (cb && g_onCompleteMethod)
        env->CallVoidMethod(cb, g_onCompleteMethod,
                            (jint)finalCount, exhausted ? JNI_TRUE : JNI_FALSE);
}

// ============================================================
//  Pointer scan
//  Encontra endereços cujo valor (4/8 bytes) aponta para target.
//  Multi-nível: nível 2 encontra pointers para os pointers do nível 1, etc.
// ============================================================
struct PointerHit {
    uintptr_t addr;
    int level;
};

static void pointerScanThread(jobject cb, uintptr_t targetAddr, int maxDepth) {
    auto t0 = std::chrono::steady_clock::now();
    if (maxDepth < 1) maxDepth = 1;
    if (maxDepth > 4) maxDepth = 4;

    LOGI("=========================================================");
    LOGI("[PTR] Pointer scan → 0x%lx | maxDepth=%d",
         (unsigned long)targetAddr, maxDepth);
    LOGI("=========================================================");

    installSigHandlers();
    JniThreadAttacher att(g_jvm);
    JNIEnv* env = att.getEnv();
    if (!env) { g_scanRunning = false; return; }

    const size_t PSIZE = sizeof(void*);     // 4 ou 8
    const size_t MAX_RESULTS_PER_LEVEL = 200000;
    const size_t MAX_TOTAL_RESULTS     = 500000;

    std::unordered_set<uintptr_t> targets;
    targets.insert(targetAddr);

    std::vector<PointerHit> allHits;

    for (int level = 1; level <= maxDepth; level++) {
        if (g_scanCancelled.load()) break;
        if (targets.empty()) break;
        if (allHits.size() >= MAX_TOTAL_RESULTS) break;

        LOGI("[PTR] Nível %d: procurando pointers para %zu alvo(s)...",
             level, targets.size());

        auto regions = parseMaps();
        if (regions.empty()) break;

        size_t totalBytes = 0;
        for (const auto& r : regions) totalBytes += (r.end - r.start);

        std::atomic<int>    nextReg{0};
        std::atomic<size_t> scannedAt{0};
        std::mutex          hitsMutex;
        std::vector<PointerHit> levelHits;

        const int nThr = pickThreadCount();

        auto worker = [&]() {
            setpriority(PRIO_PROCESS, 0, 10);
            const size_t PS = (size_t)sysconf(_SC_PAGE_SIZE);
            const size_t BUF_SZ = PS + PSIZE + 16;
            thread_local std::vector<uint8_t> buf;
            if (buf.size() < BUF_SZ) buf.resize(BUF_SZ);

            std::vector<PointerHit> localHits;

            while (true) {
                if (g_scanCancelled.load()) break;
                int idx = nextReg.fetch_add(1);
                if (idx >= (int)regions.size()) break;
                const auto& r = regions[idx];
                if (!r.readable || r.start >= r.end) continue;

                uintptr_t addr = r.start;
                while (addr < r.end && !g_scanCancelled.load()) {
                    size_t rem = r.end - addr;
                    size_t rd = PS + PSIZE;
                    if (rd > rem) rd = rem;
                    if (rd < PSIZE) break;

                    if (!safeReadMemory(addr, buf.data(), rd)) {
                        addr += PS;
                        scannedAt.fetch_add(rd, std::memory_order_relaxed);
                        continue;
                    }

                    // Varre offsets alinhados de 4 bytes
                    const size_t maxOff = rd - PSIZE;
                    for (size_t off = 0; off <= maxOff; off += 4) {
                        uintptr_t val = 0;
                        memcpy(&val, buf.data() + off, PSIZE);
                        if (targets.count(val)) {
                            PointerHit h{(uintptr_t)(addr + off), level};
                            localHits.push_back(h);
                            if (localHits.size() + allHits.size() >= MAX_TOTAL_RESULTS)
                                break;
                        }
                    }
                    addr += PS;
                    scannedAt.fetch_add(rd, std::memory_order_relaxed);

                    if (localHits.size() + allHits.size() >= MAX_TOTAL_RESULTS)
                        break;
                }
                if (localHits.size() + allHits.size() >= MAX_TOTAL_RESULTS) break;
            }

            if (!localHits.empty()) {
                std::lock_guard<std::mutex> lk(hitsMutex);
                size_t room = MAX_RESULTS_PER_LEVEL > levelHits.size()
                              ? MAX_RESULTS_PER_LEVEL - levelHits.size() : 0;
                size_t take = std::min(room, localHits.size());
                levelHits.insert(levelHits.end(), localHits.begin(),
                                 localHits.begin() + take);
            }
        };

        std::vector<std::thread> workers;
        workers.reserve(nThr);
        for (int i = 0; i < nThr; i++) workers.emplace_back(worker);
        for (auto& w : workers) w.join();

        LOGI("[PTR] Nível %d: %zu hits (%zu bytes varridos)",
             level, levelHits.size(), scannedAt.load());

        // Envia hits deste nível para a UI
        if (!levelHits.empty() && cb && g_onPointerBatchMethod) {
            const size_t CHUNK = 1024;
            for (size_t base = 0; base < levelHits.size(); base += CHUNK) {
                size_t n = std::min(CHUNK, levelHits.size() - base);
                jlongArray arr = env->NewLongArray((jsize)n);
                jintArray  lvl = env->NewIntArray((jsize)n);
                if (!arr || !lvl) { if (arr) env->DeleteLocalRef(arr); if (lvl) env->DeleteLocalRef(lvl); break; }
                jlong* a = env->GetLongArrayElements(arr, nullptr);
                jint*  l = env->GetIntArrayElements(lvl, nullptr);
                if (a && l) {
                    for (size_t i = 0; i < n; i++) {
                        a[i] = (jlong)levelHits[base + i].addr;
                        l[i] = (jint)levelHits[base + i].level;
                    }
                    env->ReleaseLongArrayElements(arr, a, 0);
                    env->ReleaseIntArrayElements(lvl, l, 0);
                    env->CallVoidMethod(cb, g_onPointerBatchMethod, arr, lvl);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                } else {
                    if (a) env->ReleaseLongArrayElements(arr, a, JNI_ABORT);
                    if (l) env->ReleaseIntArrayElements(lvl, l, JNI_ABORT);
                }
                env->DeleteLocalRef(arr);
                env->DeleteLocalRef(lvl);
            }
        }

        // Prepara próximo nível
        allHits.insert(allHits.end(), levelHits.begin(), levelHits.end());
        targets.clear();
        for (const auto& h : levelHits) targets.insert(h.addr);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - t0).count();
    LOGI("[PTR] FIM em %lld ms | total %zu hits", (long long)ms, allHits.size());

    g_scanRunning = false;
    g_scanCancelled = false;

    if (cb && g_onPointerCompleteMethod)
        env->CallVoidMethod(cb, g_onPointerCompleteMethod, (jint)allHits.size());
}

// ============================================================
//  freezeLoop
// ============================================================
static void freezeLoop() {
    LOGI("[FREEZE] Thread iniciada");
    std::unique_lock<std::mutex> lk(g_freezeCvMutex);
    while (g_freezeRunning) {
        g_freezeCv.wait_for(lk, std::chrono::milliseconds(100), [] {
            return !g_freezeRunning || !g_frozen.empty();
        });
        if (!g_freezeRunning) break;
        if (g_frozen.empty()) continue;

        // Copia rápida para fora do lock exclusivo
        std::unordered_map<uintptr_t, std::pair<std::vector<uint8_t>, int>> cp;
        {
            std::shared_lock<std::shared_mutex> fl(g_frozenMutex);
            cp = g_frozen;
        }
        int ok = 0, fail = 0;
        for (const auto& e : cp) {
            if (writeMemory(e.first, e.second.first.data(), e.second.first.size())) ok++;
            else fail++;
        }
        if (fail) LOGW("[FREEZE] %d OK, %d falhas", ok, fail);
    }
    LOGI("[FREEZE] Thread encerrada");
}

// ============================================================
//  JNI IMPLEMENTATIONS
// ============================================================
JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetWorkDir(
    JNIEnv* env, jobject, jstring jpath) {
    const char* p = env->GetStringUTFChars(jpath, nullptr);
    if (p) {
        g_workDir = p;
        env->ReleaseStringUTFChars(jpath, p);
        g_pathA.clear(); g_pathB.clear();
        ensurePaths();
    }
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetRegionFilter(
    JNIEnv*, jobject, jint mask) {
    LOGI("[API] nativeSetRegionFilter mask=0x%X", (int)mask);
    g_regionFilter.store((int)mask, std::memory_order_relaxed);
}

// ============================================================
//  Helper: registra callbacks uma única vez (thread-safe o
//  suficiente — só chamado antes de iniciar a thread).
// ============================================================
static bool ensureCallbacksRegistered(JNIEnv* env, jobject thiz) {
    if (g_callbackObj != nullptr) return true;
    jobject ref = env->NewGlobalRef(thiz);
    if (!ref) return false;
    jclass cls = env->GetObjectClass(thiz);
    g_onProgressMethod = env->GetMethodID(cls, "onScanProgress", "(I)V");
    g_onBatchMethod    = env->GetMethodID(cls, "onScanBatch", "([J[[B)V");
    g_onCountMethod    = env->GetMethodID(cls, "onScanCount", "(I)V");
    g_onCompleteMethod = env->GetMethodID(cls, "onScanComplete", "(IZ)V");
    g_onPointerBatchMethod =
        env->GetMethodID(cls, "onPointerBatch", "([J[I)V");
    g_onPointerCompleteMethod =
        env->GetMethodID(cls, "onPointerComplete", "(I)V");
    env->DeleteLocalRef(cls);

    if (!g_onProgressMethod || !g_onBatchMethod || !g_onCountMethod ||
        !g_onCompleteMethod || !g_onPointerBatchMethod ||
        !g_onPointerCompleteMethod) {
        LOGE("[API] Callbacks não encontrados");
        env->DeleteGlobalRef(ref);
        return false;
    }
    g_callbackObj = ref;
    LOGI("[API] Callbacks registrados");
    return true;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeStartScan(
    JNIEnv* env, jobject thiz, jlong value, jlong value2, jint type, jint condition) {
    LOGI("[API] nativeStartScan | %s %s v1=%lld v2=%lld",
         typeName(type), condName(condition), (long long)value, (long long)value2);

    bool expected = false;
    if (!g_scanRunning.compare_exchange_strong(expected, true)) {
        LOGW("[API] Scan já em execução");
        return;
    }
    ensurePaths();

    if (g_callbackObj == nullptr) {
        g_callbackObj = env->NewGlobalRef(thiz);
        jclass cls = env->GetObjectClass(thiz);
        g_onProgressMethod = env->GetMethodID(cls, "onScanProgress", "(I)V");
        g_onBatchMethod    = env->GetMethodID(cls, "onScanBatch", "([J[[B)V");
        g_onCountMethod    = env->GetMethodID(cls, "onScanCount", "(I)V");
        g_onCompleteMethod = env->GetMethodID(cls, "onScanComplete", "(IZ)V");
        g_onPointerBatchMethod =
            env->GetMethodID(cls, "onPointerBatch", "([J[I)V");
        g_onPointerCompleteMethod =
            env->GetMethodID(cls, "onPointerComplete", "(I)V");
        env->DeleteLocalRef(cls);
        if (!g_onProgressMethod || !g_onBatchMethod ||
            !g_onCountMethod    || !g_onCompleteMethod ||
            !g_onPointerBatchMethod || !g_onPointerCompleteMethod) {
            LOGE("[API] Callbacks não encontrados");
            env->DeleteGlobalRef(g_callbackObj); g_callbackObj = nullptr;
            g_scanRunning = false;
            return;
        }
    }

    g_lastScanType    = (int)type;
    g_scanCancelled   = false;
    g_memoryExhausted = false;
    g_displayFull     = false;

    if (g_scanThread.joinable()) g_scanThread.join();
    g_scanThread = std::thread(scanThread, g_callbackObj,
                               (long long)value, (long long)value2,
                               (int)type, (int)condition);
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeNextScan(
    JNIEnv*, jobject, jlong value, jlong value2, jint condition) {
    LOGI("[API] nativeNextScan | v1=%lld v2=%lld cond=%s",
         (long long)value, (long long)value2, condName(condition));

    bool expected = false;
    if (!g_scanRunning.compare_exchange_strong(expected, true)) {
        LOGW("[API] Scan já em execução");
        return;
    }
    if (g_scanCount.load() == 0) {
        g_scanRunning = false;
        return;
    }
    ensurePaths();

    int type = g_lastScanType.load();
    g_scanCancelled   = false;
    g_memoryExhausted = false;
    g_displayFull     = false;

    if (g_scanThread.joinable()) g_scanThread.join();
    g_scanThread = std::thread(nextScanThread, g_callbackObj,
                               (long long)value, (long long)value2,
                               type, (int)condition);
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeAoBScan(
    JNIEnv* env, jobject thiz, jstring jpattern, jint /*limit*/) {
    const char* p = env->GetStringUTFChars(jpattern, nullptr);
    if (!p) return;
    std::string patStr(p);
    env->ReleaseStringUTFChars(jpattern, p);

    AoBPattern pat = parseAoBPattern(patStr);
    LOGI("[API] nativeAoBScan '%s' → %zu bytes", patStr.c_str(), pat.size());
    if (pat.empty()) return;

    if (!ensureCallbacksRegistered(env, thiz)) return;

    bool expected = false;
    if (!g_scanRunning.compare_exchange_strong(expected, true)) {
        LOGW("[API] Scan já em execução");
        return;
    }
    ensurePaths();

    g_scanCancelled   = false;
    g_memoryExhausted = false;
    g_displayFull     = false;

    if (g_scanThread.joinable()) g_scanThread.join();
    g_scanThread = std::thread(aobScanThread, g_callbackObj, pat);
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativePointerScan(
    JNIEnv* env, jobject thiz, jlong target, jint maxDepth) {
    LOGI("[API] nativePointerScan target=0x%lx depth=%d",
         (unsigned long)target, (int)maxDepth);
    if (target == 0) return;

    if (!ensureCallbacksRegistered(env, thiz)) return;

    bool expected = false;
    if (!g_scanRunning.compare_exchange_strong(expected, true)) {
        LOGW("[API] Scan já em execução");
        return;
    }

    g_scanCancelled = false;
    if (g_scanThread.joinable()) g_scanThread.join();
    g_scanThread = std::thread(pointerScanThread, g_callbackObj,
                               (uintptr_t)target, (int)maxDepth);
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetDisplayFull(
    JNIEnv*, jobject) {
    LOGI("[API] nativeSetDisplayFull");
    g_displayFull = true;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeCancelScan(
    JNIEnv*, jobject) {
    LOGW("[API] nativeCancelScan");
    g_scanCancelled = true;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeClearResults(
    JNIEnv*, jobject) {
    LOGI("[API] nativeClearResults");

    // Ordem correta: nunca segurar g_frozenMutex e g_freezeCvMutex ao mesmo tempo
    {
        std::unique_lock<std::shared_mutex> l(g_frozenMutex);
        g_frozen.clear();
    }
    {
        std::unique_lock<std::mutex> l(g_freezeCvMutex);
        if (g_freezeRunning) { g_freezeRunning = false; g_freezeCv.notify_all(); }
    }
    if (g_freezeThread.joinable()) g_freezeThread.join();

    ensurePaths();
    unlink(g_pathA.c_str());
    unlink(g_pathB.c_str());
    g_scanCount = 0;
    g_currentFile = 0;
    g_displayFull = false;
    LOGI("[API] Limpeza concluída");
}

JNIEXPORT jlongArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetResults(
    JNIEnv* env, jobject) {
    ensurePaths();
    int idx = g_currentFile.load();
    const std::string& path = pathOf(idx);
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return env->NewLongArray(0);

    size_t count = g_scanCount.load();
    jlongArray arr = env->NewLongArray((jsize)count);
    if (!arr) { close(fd); return nullptr; }
    jlong* elems = env->GetLongArrayElements(arr, nullptr);
    if (!elems) { close(fd); return arr; }

    std::vector<uintptr_t> buf(4096);
    size_t out = 0;
    ssize_t got;
    while ((got = read(fd, buf.data(), buf.size() * sizeof(uintptr_t))) > 0 && out < count) {
        size_t n = (size_t)got / sizeof(uintptr_t);
        for (size_t i = 0; i < n && out < count; i++, out++)
            elems[out] = (jlong)buf[i];
    }
    env->ReleaseLongArrayElements(arr, elems, 0);
    close(fd);
    return arr;
}

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeWriteMemory(
    JNIEnv* env, jobject, jlong address, jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    jbyte* bytes = env->GetByteArrayElements(data, nullptr);
    bool ok = writeMemory((uintptr_t)address, bytes, (size_t)len);
    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeToggleFreeze(
    JNIEnv*, jobject, jlong address, jlong value, jint type, jboolean enable) {
    uintptr_t a = (uintptr_t)address;

    if (enable) {
        std::vector<uint8_t> b = intToBytes(value, type);
        if (b.empty()) return;
        bool needStart = false;
        {
            std::unique_lock<std::shared_mutex> l(g_frozenMutex);
            g_frozen[a] = {b, type};
            needStart = !g_freezeRunning.load(std::memory_order_relaxed);
        }
        if (needStart) {
            if (g_freezeThread.joinable()) g_freezeThread.join();
            g_freezeRunning = true;
            g_freezeThread = std::thread(freezeLoop);
        }
        g_freezeCv.notify_all();
    } else {
        bool empty = false;
        {
            std::unique_lock<std::shared_mutex> l(g_frozenMutex);
            g_frozen.erase(a);
            empty = g_frozen.empty();
        }
        if (empty) {
            std::unique_lock<std::mutex> cv(g_freezeCvMutex);
            if (g_freezeRunning) {
                g_freezeRunning = false;
                g_freezeCv.notify_all();
            }
        }
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeReadMemory(
    JNIEnv* env, jobject, jlong address, jint size) {
    if (size <= 0 || size > 64 * 1024) return nullptr;
    jbyteArray arr = env->NewByteArray(size);
    if (!arr) return nullptr;
    jbyte* bytes = env->GetByteArrayElements(arr, nullptr);
    bool ok = safeReadMemory((uintptr_t)address, bytes, (size_t)size);
    env->ReleaseByteArrayElements(arr, bytes, ok ? 0 : JNI_ABORT);
    return ok ? arr : nullptr;
}

JNIEXPORT jbyteArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeReadRegion(
    JNIEnv* env, jobject, jlong start, jint size) {
    if (size <= 0 || size > 64 * 1024) return nullptr;

    jbyteArray arr = env->NewByteArray(size);
    if (!arr) return nullptr;
    jbyte* bytes = env->GetByteArrayElements(arr, nullptr);
    if (!bytes) { env->DeleteLocalRef(arr); return nullptr; }

    const size_t PS = (size_t)sysconf(_SC_PAGE_SIZE);
    uintptr_t addr = (uintptr_t)start;
    size_t remaining = (size_t)size;
    size_t offset = 0;
    int okPages = 0, badPages = 0;

    while (remaining > 0) {
        size_t pageOff = addr & (PS - 1);
        size_t chunk = PS - pageOff;
        if (chunk > remaining) chunk = remaining;

        if (safeReadMemory(addr, bytes + offset, chunk)) okPages++;
        else { memset(bytes + offset, 0, chunk); badPages++; }

        addr      += chunk;
        offset    += chunk;
        remaining -= chunk;
    }

    env->ReleaseByteArrayElements(arr, bytes, 0);
    LOGD("[READREGION] 0x%lx size=%d ok=%d bad=%d",
         (unsigned long)start, (int)size, okPages, badPages);

    if (okPages == 0) { env->DeleteLocalRef(arr); return nullptr; }
    return arr;
}

// ============================================================
//  JNI_OnLoad
// ============================================================
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;

    LOGI("=========================================================");
    LOGI("[INIT] ███ MemScanner v3 (AoB + Pointer) ███");
    LOGI("[INIT]   PID: %d | Page: %ld | %s",
         getpid(), sysconf(_SC_PAGE_SIZE),
         sizeof(void*) == 4 ? "32-bit" : "64-bit");
    LOGI("[INIT]   Threads escolhidas: %d", pickThreadCount());

    {
        int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            uint8_t dummy = 0;
            errno = 0;
            ssize_t n = pread64(fd, &dummy, 1, (off64_t)(uintptr_t)&dummy);
            LOGI("[INIT] /proc/self/mem: %s", (n == 1) ? "SIM" : "NÃO");
            close(fd);
        }
    }
    installSigHandlers();
    LOGI("[INIT] SIGSEGV/SIGBUS handlers instalados");

    {
        JNIEnv* env = nullptr;
        if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) == JNI_OK && env) {
            jclass localB = env->FindClass("[B");
            if (localB) { g_byteArrayClass = (jclass)env->NewGlobalRef(localB); env->DeleteLocalRef(localB); }
            jclass localI = env->FindClass("[I");
            if (localI) { g_intArrayClass  = (jclass)env->NewGlobalRef(localI); env->DeleteLocalRef(localI); }
            LOGI("[INIT] [B=%s [I=%s",
                 g_byteArrayClass ? "OK" : "FALHOU",
                 g_intArrayClass ? "OK" : "FALHOU");
        }
    }

    LOGI("=========================================================");
    return JNI_VERSION_1_6;
}
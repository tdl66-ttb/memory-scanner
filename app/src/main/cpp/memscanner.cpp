// ============================================================
//  memscanner.cpp
//  Memory Scanner (JNI) — UNIVERSAL + STREAMING EM ARQUIVO
//  Android 11 Go / SELinux Enforcing: /proc/self/mem NÃO funciona.
//  Leitura primária = memcpy + recuperação de SIGSEGV.
//  Handlers reinstalados a cada scan (IL2CPP sobrescreve os nossos).
//
//  v5 (alvo: Android 11 Go, armv8l/32 bits, sem root): correções de corrida,
//  contadores 64 bits, callbacks por instância, freeze sem busy-loop, AoB estrito.
//  v4:
//   - AoB scan (padrão "FF ?? AA 12")
//   - Pointer scan (níveis múltiplos)
//   - Reporter dedicado de progresso (monotônico, sem race)
//   - Range scan, filtro opcional, vicinity
//   - Filtro "Só estáticos" no Pointer Scan
//   - Filtro por módulo (substring no path)
//   - String scan (UTF-8 / UTF-16LE)
//   - Snapshot + diff (Mudou / Igual / Aumentou / Diminuiu)
//   - Pointer path (resolver cadeia base + offsets)
//   - Listar módulos / obter base / achar módulo de um addr
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
#include <set>
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
#include <functional>
#include <system_error>

#define LOG_TAG "MemScanner"
// Logs verbosos (endereços/valores) só em build Debug (MS_DEBUG_LOG definido no CMake).
#ifdef MS_DEBUG_LOG
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGD(...) ((void)0)
#endif
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

static inline int typeSizeOf(int t) {
    switch (t) {
        case TYPE_BYTE:   return 1;
        case TYPE_SHORT:  return 2;
        case TYPE_INT:    return 4;
        case TYPE_LONG:   return 8;
        case TYPE_FLOAT:  return 4;
        case TYPE_DOUBLE: return 8;
        default:          return 4;
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
    uint8_t   data[32];   // bumpado 8→32 (suporta strings curtas)
    uint8_t   size;
    uint8_t   _pad[3];
};

struct AoBPattern {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;   // 0xFF = byte fixo | 0xF0/0x0F = nibble fixo | 0x00 = curinga
    size_t size() const { return bytes.size(); }
    bool empty()  const { return bytes.empty(); }
    // Primeiro byte totalmente fixo (âncora p/ memchr). size() se não existir.
    size_t anchorIndex() const {
        for (size_t i = 0; i < mask.size(); i++) if (mask[i] == 0xFF) return i;
        return mask.size();
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
static std::atomic<bool>   g_pointerStaticOnly{false};

static std::string g_moduleFilter;
static std::mutex  g_moduleFilterMutex;

// Snapshot
static std::atomic<int>    g_snapshotType{TYPE_INT};
static std::atomic<size_t> g_snapshotCount{0};

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
        [[maybe_unused]] uint64_t freeB = (uint64_t)st.f_bavail * st.f_frsize;
        LOGI("[INIT] Espaço livre: %llu MB", (unsigned long long)(freeB / 1048576));
    }
}
static inline const std::string& pathOf(int idx) { return (idx == 0) ? g_pathA : g_pathB; }

static std::string snapshotPath() {
    ensurePaths();
    return g_workDir + "/snapshot.bin";
}

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
static __thread volatile sig_atomic_t   t_chaining   = 0;

static struct sigaction g_origSegvAction;
static struct sigaction g_origBusAction;
static bool             g_haveOrigSegv = false;
static bool             g_haveOrigBus  = false;
static std::mutex       g_sigMutex;

static void memScannerFaultHandler(int sig, siginfo_t* info, void* ctx);

// Reinstalado a cada scan (a engine do jogo pode sobrescrever o nosso handler).
// Protegido por mutex: várias threads/chamadas JNI podem chamar ao mesmo tempo.
static void installSigHandlers() {
    std::lock_guard<std::mutex> lk(g_sigMutex);
    struct sigaction sa, prev;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = memScannerFaultHandler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    memset(&prev, 0, sizeof(prev));
    if (sigaction(SIGSEGV, &sa, &prev) == 0) {
        if (prev.sa_sigaction != memScannerFaultHandler) {
            g_origSegvAction = prev;
            g_haveOrigSegv = true;
        }
    } else {
        LOGE("[INIT] sigaction(SIGSEGV) falhou: %s", strerror(errno));
    }

    memset(&prev, 0, sizeof(prev));
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

    // t_chaining evita recursão infinita quando o handler anterior (ex.: da engine)
    // encadeia de volta para o nosso.
    if (orig && !t_chaining) {
        if (orig->sa_flags & SA_SIGINFO) {
            if (orig->sa_sigaction && orig->sa_sigaction != memScannerFaultHandler) {
                t_chaining = 1;
                orig->sa_sigaction(sig, info, ctx);
                t_chaining = 0;
                return;
            }
        } else if (orig->sa_handler != SIG_IGN && orig->sa_handler != SIG_DFL) {
            t_chaining = 1;
            orig->sa_handler(sig);
            t_chaining = 0;
            return;
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
// Teto de resultados por scan (4 bytes/entrada em 32 bits => ~32 MB em disco).
// Evita encher o armazenamento de aparelhos Go com scans do tipo "maior que 0".
static const size_t MAX_SCAN_RESULTS = 8u * 1024u * 1024u;

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
        if (m_stage.empty()) return;
        if (m_fd < 0) { m_stage.clear(); return; }
        std::lock_guard<std::mutex> lk(m_mtx);
        const uint8_t* p = (const uint8_t*)m_stage.data();
        const size_t bytes = m_stage.size() * sizeof(uintptr_t);
        size_t written = 0;
        while (written < bytes) {
            ssize_t n = ::write(m_fd, p + written, bytes - written);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) {
                LOGE("[SINK] write falhou: %s", strerror(errno));
                g_memoryExhausted.store(true);
                break;
            }
            written += (size_t)n;
        }
        // Conta só o que realmente foi gravado.
        const size_t entries = written / sizeof(uintptr_t);
        const size_t total = m_counter.fetch_add(entries) + entries;
        if (total >= MAX_SCAN_RESULTS) g_memoryExhausted.store(true);
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
        BatchEntry e; e.addr = a;
        e.size = (uint8_t)(s > 32 ? 32 : s);
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
//  parseMaps — Universal por padrão, filtros opcionais
// ============================================================
// Regiões de driver/GPU/dmabuf: ler pode travar ou derrubar o processo.
static inline bool isRiskyPath(const std::string& p) {
    static const char* const bad[] = {
        "/dev/kgsl", "/dev/mali", "/dev/dri", "/dev/binder", "/dev/hwbinder",
        "/dev/vndbinder", "/dev/ion", "/dev/dma_heap", "/dev/video", "/dev/graphics",
        "/dev/nvmap", "/dmabuf", "/sys/", "/proc/", nullptr
    };
    for (int i = 0; bad[i]; i++)
        if (p.compare(0, strlen(bad[i]), bad[i]) == 0) return true;
    return false;
}

// Regiões maiores que isso são fatiadas (em vez de ignoradas).
static const uintptr_t MAX_REGION_CHUNK = (uintptr_t)128 * 1024 * 1024;

// useUserFilters=false: ignora o filtro de região/módulo da UI (usado pelo Pointer Scan).
static std::vector<MemoryRegion> parseMaps(bool useUserFilters = true) {
    std::vector<MemoryRegion> regions;
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) { LOGE("[MAPS] Falha /proc/self/maps"); return regions; }

    const int filter = useUserFilters ? g_regionFilter.load(std::memory_order_relaxed) : RF_NONE;

    std::string modF;
    if (useUserFilters) {
        std::lock_guard<std::mutex> lk(g_moduleFilterMutex);
        modF = g_moduleFilter;
    }

    std::string line;
    int total = 0, accepted = 0, skippedSp = 0, skippedBad = 0, skippedFilt = 0;
    while (std::getline(maps, line)) {
        total++;
        std::istringstream iss(line);
        uintptr_t s = 0, e = 0; char dash = 0; std::string perms, path;
        iss >> std::hex >> s >> dash >> e >> perms;
        std::string tmp; iss >> tmp >> tmp >> tmp;
        std::getline(iss, path);
        size_t first = path.find_first_not_of(' ');
        path = (first == std::string::npos) ? std::string() : path.substr(first);

        if (path.find("[vsyscall]") != std::string::npos ||
            path.find("[vvar]")     != std::string::npos ||
            path.find("[vdso]")     != std::string::npos ||
            path.find("[vectors]")  != std::string::npos ||
            path.find("[sigpage]")  != std::string::npos ||
            path.find("libmemscanner.so") != std::string::npos ||
            isRiskyPath(path)) {
            skippedSp++; continue;
        }
        if (perms.size() < 3 || perms[0] != 'r' || e <= s) {
            skippedBad++; continue;
        }
        if (filter != RF_NONE) {
            if ((filter & RF_RW_ONLY)   && perms[1] != 'w') { skippedFilt++; continue; }
            if ((filter & RF_SKIP_EXEC) && perms[2] == 'x') { skippedFilt++; continue; }
            if ((filter & RF_ANON_ONLY) && !path.empty() && path[0] == '/') { skippedFilt++; continue; }
        }
        if (!modF.empty()) {
            if (path.find(modF) == std::string::npos) { skippedFilt++; continue; }
        }
        for (uintptr_t cs = s; cs < e; ) {
            uintptr_t ce = (e - cs > MAX_REGION_CHUNK) ? cs + MAX_REGION_CHUNK : e;
            MemoryRegion r; r.start = cs; r.end = ce;
            r.readable = true; r.writable = (perms[1] == 'w'); r.executable = (perms[2] == 'x');
            r.path = path; regions.push_back(r);
            cs = ce;
        }
        accepted++;
    }
    std::sort(regions.begin(), regions.end(),
              [](const MemoryRegion& a, const MemoryRegion& b) {
                  return (a.end - a.start) > (b.end - b.start);
              });
    LOGI("[MAPS] %d linhas | %d aceitas | %d puladas(esp) | %d inválidas | %d filtradas (mask=0x%X mod='%s')",
         total, accepted, skippedSp, skippedBad, skippedFilt, filter, modF.c_str());
    return regions;
}

// ============================================================
//  Leitura/escrita protegidas por sinal
// ============================================================
static bool safeReadMemory(uintptr_t address, void* buffer, size_t size) {
    if (sigsetjmp(t_jmpBuf, 1) == 0) {
        t_inSafeRead = 1;
        std::atomic_signal_fence(std::memory_order_seq_cst);   // memcpy não pode subir acima da flag
        memcpy(buffer, (const void*)address, size);
        std::atomic_signal_fence(std::memory_order_seq_cst);
        t_inSafeRead = 0;
        return true;
    }
    t_inSafeRead = 0;
    return false;
}
static bool safeWriteMemory(uintptr_t address, const void* buffer, size_t size) {
    if (sigsetjmp(t_jmpBuf, 1) == 0) {
        t_inSafeRead = 1;
        std::atomic_signal_fence(std::memory_order_seq_cst);
        memcpy((void*)address, buffer, size);
        std::atomic_signal_fence(std::memory_order_seq_cst);
        t_inSafeRead = 0;
        return true;
    }
    t_inSafeRead = 0;
    return false;
}

// jlong (Java) -> endereço nativo. Em 32 bits, rejeita valores que não cabem
// (senão o cast truncaria e acessaria outro endereço).
static inline bool toAddr(jlong a, uintptr_t* out) {
    if (a <= 0) return false;
#if UINTPTR_MAX == 0xFFFFFFFFu
    if ((unsigned long long)a > 0xFFFFFFFFULL) return false;
#endif
    *out = (uintptr_t)a;
    return true;
}

// Remove a tag do byte alto (TBI/heap tagging em arm64). No-op em 32 bits.
static inline uintptr_t untagPtr(uintptr_t v) {
#if UINTPTR_MAX > 0xFFFFFFFFu
    return v & (uintptr_t)0x00FFFFFFFFFFFFFFULL;
#else
    return v;
#endif
}

static inline size_t pageSize() {
    static const size_t ps = (size_t)sysconf(_SC_PAGE_SIZE);
    return ps ? ps : 4096;
}

// Permissões atuais (PROT_*) da página que contém 'a'; -1 se não mapeada.
static int protForAddr(uintptr_t a) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream iss(line);
        uintptr_t s = 0, e = 0; char dash = 0; std::string perms;
        iss >> std::hex >> s >> dash >> e >> perms;
        if (a >= s && a < e && perms.size() >= 3) {
            int p = 0;
            if (perms[0] == 'r') p |= PROT_READ;
            if (perms[1] == 'w') p |= PROT_WRITE;
            if (perms[2] == 'x') p |= PROT_EXEC;
            return p;
        }
    }
    return -1;
}

static std::atomic<bool> g_procMemBroken{false};

// /proc/self/mem costuma ser bloqueado pelo SELinux; se bloquear, não insistimos.
static bool writeViaProcMem(uintptr_t address, const void* buffer, size_t size) {
    if (g_procMemBroken.load(std::memory_order_relaxed)) return false;
    int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM || errno == ENOENT) g_procMemBroken.store(true);
        return false;
    }
    ssize_t n = pwrite64(fd, buffer, size, (off64_t)address);
    const int err = errno;
    close(fd);
    if (n == (ssize_t)size) return true;
    if (n < 0 && (err == EACCES || err == EPERM)) g_procMemBroken.store(true);
    return false;
}

static bool writeMemory(uintptr_t address, const void* buffer, size_t size) {
    if (size == 0) return true;
    if (writeViaProcMem(address, buffer, size)) return true;
    if (safeWriteMemory(address, buffer, size)) {
        __builtin___clear_cache((char*)address, (char*)address + size);
        return true;
    }

    // Página sem permissão de escrita: libera só o necessário e RESTAURA as
    // permissões originais (antes o mprotect(RW) removia o PROT_EXEC de código).
    const size_t ps = pageSize();
    const uintptr_t pS = address & ~(uintptr_t)(ps - 1);
    const uintptr_t pE = (address + size + ps - 1) & ~(uintptr_t)(ps - 1);
    std::vector<std::pair<uintptr_t, int>> saved;
    bool ok = true;
    for (uintptr_t p = pS; p < pE; p += ps) {
        int pr = protForAddr(p);
        if (pr < 0 || mprotect((void*)p, ps, pr | PROT_WRITE) != 0) { ok = false; break; }
        saved.emplace_back(p, pr);
    }
    if (ok) {
        ok = safeWriteMemory(address, buffer, size);
        if (ok) __builtin___clear_cache((char*)address, (char*)address + size);
    }
    for (const auto& s : saved) mprotect((void*)s.first, ps, s.second);
    if (!ok) LOGE("[WRITE] Falhou 0x%lx (errno=%d)", (unsigned long)address, errno);
    return ok;
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
static inline int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static inline bool isWildChar(char c) { return c == '?' || c == 'x' || c == 'X'; }

// Aceita: "FF ?? AA", "FF,??,AA", "0xFF", "A?" / "?A" (nibble curinga), "FFAA??" (sem espaços).
// Qualquer token inválido invalida o padrão inteiro (ok=false) — nada é descartado em silêncio.
static AoBPattern parseAoBPattern(const std::string& pattern, bool* okOut) {
    AoBPattern result;
    bool ok = true;
    std::string s = pattern;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (c == ',' || c == '-' || c == ':' || c == ';' || c == '\t' || c == '\n' || c == '\r')
            s[i] = ' ';
    }
    std::istringstream iss(s);
    std::string tok;
    while (ok && (iss >> tok)) {
        if (tok.size() > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) tok.erase(0, 2);
        if (tok.size() == 1 && isWildChar(tok[0])) {          // "?" = byte curinga
            result.bytes.push_back(0); result.mask.push_back(0x00);
            continue;
        }
        if (tok.empty() || (tok.size() % 2) != 0) { ok = false; break; }
        for (size_t i = 0; i + 1 < tok.size() + 0 && ok; i += 2) {
            const char hi = tok[i], lo = tok[i + 1];
            int hv = 0, lv = 0; uint8_t m = 0;
            if (!isWildChar(hi)) { hv = hexNibble(hi); if (hv < 0) { ok = false; break; } m |= 0xF0; }
            if (!isWildChar(lo)) { lv = hexNibble(lo); if (lv < 0) { ok = false; break; } m |= 0x0F; }
            result.bytes.push_back((uint8_t)(((hv << 4) | lv) & m));
            result.mask.push_back(m);
        }
    }
    if (result.size() > 4096) ok = false;
    // precisa de ao menos 1 byte totalmente fixo (âncora p/ busca rápida)
    if (ok && result.anchorIndex() >= result.size()) ok = false;
    if (!ok) { result.bytes.clear(); result.mask.clear(); }
    if (okOut) *okOut = ok;
    return result;
}

static inline bool matchAoB(const uint8_t* data, const AoBPattern& p) {
    for (size_t i = 0; i < p.bytes.size(); i++) {
        if ((data[i] & p.mask[i]) != (p.bytes[i] & p.mask[i])) return false;
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
    // Aparelhos Go (pouca RAM): no máximo 2 threads para não matar o app por memória.
    long pages = sysconf(_SC_PHYS_PAGES);
    long psz   = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && psz > 0) {
        unsigned long long ram = (unsigned long long)pages * (unsigned long long)psz;
        if (ram < 1536ULL * 1024ULL * 1024ULL && nThr > 2) nThr = 2;
    }
    if (nThr < 1) nThr = 1;
    return nThr;
}

static inline bool isStaticRegion(const MemoryRegion& r) {
    if (r.path.empty() || r.path[0] != '/') return false;
    if (r.path.compare(0, 5, "/dev/") == 0) return false;
    if (r.path.compare(0, 7, "/memfd:") == 0) return false;
    return true;
}

static inline std::string basenameOf(const std::string& p) {
    size_t slash = p.find_last_of('/');
    return (slash == std::string::npos) ? p : p.substr(slash + 1);
}

// Alinhamento da varredura: tipos de 2/4/8 bytes são procurados em endereços
// alinhados (até 4). Bytes/strings: passo 1. Reduz falsos positivos e o tempo de scan.
static inline size_t scanStep(int type, size_t tgtSz) {
    if (type == TYPE_BYTE) return 1;
    return tgtSz > 4 ? 4 : (tgtSz ? tgtSz : 1);
}

// ============================================================
//  scanBuffer — varredura de um buffer
//  (baseAddr é sempre múltiplo da página => offsets alinhados = endereços alinhados)
// ============================================================
template<typename Emit>
static void scanBuffer(const uint8_t* base, size_t len, uintptr_t baseAddr,
                       const std::vector<uint8_t>& tgt,
                       const std::vector<uint8_t>& tgt2,
                       size_t tgtSz, int type, int condition, Emit& emit) {
    if (len < tgtSz || tgtSz == 0) return;
    const size_t step  = scanStep(type, tgtSz);
    const size_t limit = len - tgtSz;

    if (condition == COND_EXACT) {
        const uint8_t first = tgt[0];
        size_t off = 0;
        while (off <= limit) {
            if (g_scanCancelled.load(std::memory_order_relaxed)) return;
            if (g_memoryExhausted.load(std::memory_order_relaxed)) return;
            const uint8_t* p = (const uint8_t*)memchr(base + off, first, limit - off + 1);
            if (!p) break;
            size_t o = (size_t)(p - base);
            if ((o % step) == 0 && (tgtSz == 1 || memcmp(p, tgt.data(), tgtSz) == 0))
                emit(baseAddr + o, p, tgtSz);
            off = o + 1;
        }
    } else {
        const void* t2 = tgt2.empty() ? tgt.data() : tgt2.data();
        unsigned iter = 0;
        for (size_t o = 0; o <= limit; o += step) {
            if (((++iter) & 0x3FF) == 0) {
                if (g_scanCancelled.load(std::memory_order_relaxed)) return;
                if (g_memoryExhausted.load(std::memory_order_relaxed)) return;
            }
            size_t sz = 0;
            if (compareValue(base + o, tgt.data(), t2, type, condition, sz))
                emit(baseAddr + o, base + o, sz);
        }
    }
}

// ============================================================
//  scanAoBBuffer
// ============================================================
template<typename Emit>
static void scanAoBBuffer(const uint8_t* base, size_t len, uintptr_t baseAddr,
                          const AoBPattern& pat, Emit& emit) {
    const size_t psz = pat.size();
    if (psz == 0 || len < psz) return;
    const size_t anchorIdx = pat.anchorIndex();
    if (anchorIdx >= psz) return;
    const uint8_t anchorByte = pat.bytes[anchorIdx];
    const size_t limit = len - psz;

    size_t off = 0;
    while (off <= limit) {
        if (g_scanCancelled.load(std::memory_order_relaxed)) return;
        if (g_memoryExhausted.load(std::memory_order_relaxed)) return;
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
//  Buffers thread-local
// ============================================================
static thread_local std::vector<uint8_t> t_scanBuf;

// Lê [addr, addr+want) ; se falhar e 'want' passa da página, tenta só a página atual
// (assim uma página vizinha ilegível não faz perder a página boa).
static inline size_t readWindow(uintptr_t addr, size_t want, size_t PS, uint8_t* buf) {
    if (safeReadMemory(addr, buf, want)) return want;
    if (want > PS && safeReadMemory(addr, buf, PS)) return PS;
    return 0;
}

// ============================================================
//  scanRegion / scanAoBRegion
// ============================================================
template<typename Emit>
static void scanRegion(const MemoryRegion& reg,
                       const std::vector<uint8_t>& tgt,
                       const std::vector<uint8_t>& tgt2,
                       size_t tgtSz, int type, int condition, Emit& emit,
                       std::atomic<uint64_t>& bytesOut,
                       std::atomic<uint64_t>& scannedOut,
                       std::atomic<uint64_t>& readsOut,
                       std::atomic<uint64_t>& failOut) {
    if (!reg.readable || reg.start >= reg.end) return;

    const size_t PS = pageSize();
    const size_t BUF_SIZE = PS + tgtSz + 16;
    if (t_scanBuf.size() < BUF_SIZE) t_scanBuf.resize(BUF_SIZE);

    uintptr_t addr = reg.start;
    while (addr < reg.end
           && !g_scanCancelled.load(std::memory_order_relaxed)
           && !g_memoryExhausted.load(std::memory_order_relaxed)) {

        const size_t rem = reg.end - addr;
        const size_t adv = rem < PS ? rem : PS;
        size_t rd = PS + tgtSz - 1;
        if (rd > rem) rd = rem;

        scannedOut.fetch_add(adv, std::memory_order_relaxed);
        if (rd >= tgtSz) {
            readsOut.fetch_add(1, std::memory_order_relaxed);
            size_t got = readWindow(addr, rd, PS, t_scanBuf.data());
            if (got >= tgtSz) {
                bytesOut.fetch_add(got, std::memory_order_relaxed);
                scanBuffer(t_scanBuf.data(), got, addr, tgt, tgt2, tgtSz, type, condition, emit);
            } else {
                failOut.fetch_add(1, std::memory_order_relaxed);
            }
        }
        uintptr_t next = addr + PS;
        if (next <= addr) break;
        addr = next;
    }
}

template<typename Emit>
static void scanAoBRegion(const MemoryRegion& reg,
                          const AoBPattern& pat,
                          Emit& emit,
                          std::atomic<uint64_t>& bytesOut,
                          std::atomic<uint64_t>& scannedOut,
                          std::atomic<uint64_t>& readsOut,
                          std::atomic<uint64_t>& failOut) {
    if (!reg.readable || reg.start >= reg.end) return;
    const size_t psz = pat.size();
    if (psz == 0) return;

    const size_t PS = pageSize();
    const size_t BUF_SIZE = PS + psz + 16;
    if (t_scanBuf.size() < BUF_SIZE) t_scanBuf.resize(BUF_SIZE);

    uintptr_t addr = reg.start;
    while (addr < reg.end
           && !g_scanCancelled.load(std::memory_order_relaxed)
           && !g_memoryExhausted.load(std::memory_order_relaxed)) {

        const size_t rem = reg.end - addr;
        const size_t adv = rem < PS ? rem : PS;
        size_t rd = PS + psz - 1;
        if (rd > rem) rd = rem;

        scannedOut.fetch_add(adv, std::memory_order_relaxed);
        if (rd >= psz) {
            readsOut.fetch_add(1, std::memory_order_relaxed);
            size_t got = readWindow(addr, rd, PS, t_scanBuf.data());
            if (got >= psz) {
                bytesOut.fetch_add(got, std::memory_order_relaxed);
                scanAoBBuffer(t_scanBuf.data(), got, addr, pat, emit);
            } else {
                failOut.fetch_add(1, std::memory_order_relaxed);
            }
        }
        uintptr_t next = addr + PS;
        if (next <= addr) break;
        addr = next;
    }
}

// ============================================================
//  Finalização / progresso / workers (comuns a todos os scans)
// ============================================================
// Sempre reseta as flags e SEMPRE avisa a UI (evita "Scanneando..." eterno).
static void finishScan(JNIEnv* env, jobject cb, size_t count, bool exhausted) {
    g_scanRunning = false;
    g_scanCancelled = false;
    g_memoryExhausted = false;
    if (env && cb && g_onCompleteMethod) {
        env->CallVoidMethod(cb, g_onCompleteMethod,
                            (jint)count, exhausted ? JNI_TRUE : JNI_FALSE);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
}

static std::thread startProgressReporter(jobject cb, const std::atomic<uint64_t>& done,
                                         uint64_t total, const std::atomic<bool>& running) {
    if (!cb || !g_onProgressMethod) return std::thread();
    return std::thread([cb, &done, total, &running]() {
        JniThreadAttacher a(g_jvm);
        JNIEnv* e = a.getEnv();
        if (!e) return;
        int lastPct = -1;
        while (running.load(std::memory_order_relaxed)) {
            uint64_t d = done.load(std::memory_order_relaxed);
            int p = total ? (int)((d * 100ULL) / total) : 0;   // 64 bits: em 32 bits size_t*100 estourava
            if (p > 99) p = 99;
            if (p > lastPct) {
                lastPct = p;
                e->CallVoidMethod(cb, g_onProgressMethod, p);
                if (e->ExceptionCheck()) e->ExceptionClear();
            }
            for (int i = 0; i < 3 && running.load(std::memory_order_relaxed); i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        e->CallVoidMethod(cb, g_onProgressMethod, 100);
        if (e->ExceptionCheck()) e->ExceptionClear();
    });
}

template<typename W>
static void runWorkers(int nThr, W& worker) {
    std::vector<std::thread> ws;
    ws.reserve((size_t)nThr);
    for (int i = 0; i < nThr; i++) {
        try { ws.emplace_back(std::ref(worker)); }
        catch (const std::system_error& ex) { LOGE("[THR] falha ao criar thread: %s", ex.what()); break; }
    }
    if (ws.empty()) worker();           // sem threads: roda na própria thread
    for (auto& w : ws) w.join();
}

template<typename RegionFn>
static void runRegionScan(jobject cb, const char* tag, RegionFn regionFn) {
    auto t0 = std::chrono::steady_clock::now();

    installSigHandlers();
    ensurePaths();

    JniThreadAttacher att(g_jvm);
    JNIEnv* env = att.getEnv();
    if (!env) { finishScan(nullptr, nullptr, 0, false); return; }

    auto regions = parseMaps(true);
    if (regions.empty()) { finishScan(env, cb, 0, false); return; }

    const int outIdx = 1 - g_currentFile.load();
    int outFd = open(pathOf(outIdx).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (outFd < 0) {
        LOGE("%s open falhou: %s", tag, strerror(errno));
        finishScan(env, cb, 0, true);
        return;
    }

    g_liveCount = 0;
    g_recoveredFaults.store(0);

    const int nReg = (int)regions.size();
    const int nThr = pickThreadCount();

    uint64_t totalRegionBytes = 0;
    for (const auto& r : regions) totalRegionBytes += (uint64_t)(r.end - r.start);
    LOGI("%s %d regiões | %d threads | %.2f MB",
         tag, nReg, nThr, totalRegionBytes / 1048576.0);

    std::atomic<int>      nextReg{0};
    std::atomic<uint64_t> bytesAt{0}, scannedAt{0}, readsAt{0}, failAt{0};
    std::mutex writeMutex;

    std::atomic<bool> reporterRunning{true};
    std::thread reporter = startProgressReporter(cb, scannedAt, totalRegionBytes, reporterRunning);

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
            if (g_scanCancelled.load() || g_memoryExhausted.load()) break;
            int idx = nextReg.fetch_add(1);
            if (idx >= nReg) break;
            regionFn(regions[idx], emit, bytesAt, scannedAt, readsAt, failAt);
        }
        flusher.flush();
        sink.flush();
    };
    runWorkers(nThr, worker);

    reporterRunning = false;
    if (reporter.joinable()) reporter.join();

    close(outFd);      // sem fsync: é arquivo temporário (fsync só deixa o eMMC lento)

    const size_t finalCount = g_liveCount.load();
    g_currentFile.store(outIdx);
    g_scanCount.store(finalCount);

    [[maybe_unused]] auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - t0).count();
    LOGI("%s FIM em %lld ms | Endereços: %zu | Bytes: %.2f MB",
         tag, (long long)ms, finalCount, bytesAt.load() / 1048576.0);
    LOGI("%s   Leituras: %llu | Páginas ruins: %llu | Faults: %zu",
         tag, (unsigned long long)readsAt.load(), (unsigned long long)failAt.load(),
         g_recoveredFaults.load());

    finishScan(env, cb, finalCount, g_memoryExhausted.load());
}

// ============================================================
//  Threads de scan
// ============================================================
static void scanThread(jobject cb, long long value, long long value2,
                       int type, int condition) {
    LOGI("[SCAN] Primeira varredura | %s %s v1=%lld v2=%lld",
         typeName(type), condName(condition), value, value2);

    std::vector<uint8_t> tgt  = intToBytes(value,  type);
    std::vector<uint8_t> tgt2 = intToBytes(value2, type);
    if (tgt.empty()) {
        JniThreadAttacher att(g_jvm);
        finishScan(att.getEnv(), cb, 0, false);
        return;
    }
    const size_t tgtSz = tgt.size();

    runRegionScan(cb, "[SCAN]",
        [&](const MemoryRegion& r, auto& emit, auto& b, auto& s, auto& rd, auto& f) {
            scanRegion(r, tgt, tgt2, tgtSz, type, condition, emit, b, s, rd, f);
        });
}

static void stringScanThread(jobject cb, std::vector<uint8_t> pattern) {
    LOGI("[STR] String scan | padrão %zu bytes", pattern.size());
    if (pattern.empty()) {
        JniThreadAttacher att(g_jvm);
        finishScan(att.getEnv(), cb, 0, false);
        return;
    }
    // Byte exact match — reaproveita o pipeline de value scan.
    const size_t sz = pattern.size();
    runRegionScan(cb, "[STR]",
        [&](const MemoryRegion& r, auto& emit, auto& b, auto& s, auto& rd, auto& f) {
            scanRegion(r, pattern, pattern, sz, TYPE_BYTE, COND_EXACT, emit, b, s, rd, f);
        });
}

static void aobScanThread(jobject cb, AoBPattern pat) {
    LOGI("[AOB] Padrão com %zu bytes", pat.size());
    if (pat.empty() || pat.anchorIndex() >= pat.size()) {
        JniThreadAttacher att(g_jvm);
        finishScan(att.getEnv(), cb, 0, false);
        return;
    }
    runRegionScan(cb, "[AOB]",
        [&](const MemoryRegion& r, auto& emit, auto& b, auto& s, auto& rd, auto& f) {
            scanAoBRegion(r, pat, emit, b, s, rd, f);
        });
}

// ============================================================
//  nextScan (refino)
// ============================================================
static void nextScanWorker(int inFd, off64_t startByte, size_t entries,
                           jobject cb,
                           const std::vector<uint8_t>& tgt,
                           const std::vector<uint8_t>& tgt2,
                           size_t tgtSz, int type, int condition,
                           int outFd, std::mutex& writeMutex,
                           std::atomic<uint64_t>& processedOut,
                           std::atomic<uint64_t>& failedOut) {
    JniThreadAttacher a(g_jvm);
    JNIEnv* e = a.getEnv();
    // Um FileSink POR THREAD (o original compartilhava um único sink entre as
    // threads => corrida em m_stage => corrupção/crash).
    FileSink sink(outFd, writeMutex, g_liveCount);
    BatchFlusher flusher(e, cb, g_onBatchMethod);

    const size_t CHUNK = 4096;
    std::vector<uintptr_t> buf(CHUNK);
    const void* t2 = tgt2.empty() ? tgt.data() : tgt2.data();

    off64_t off = startByte;
    size_t remaining = entries;

    while (remaining > 0
           && !g_scanCancelled.load()
           && !g_memoryExhausted.load()) {
        size_t want = remaining > CHUNK ? CHUNK : remaining;
        ssize_t got = pread64(inFd, buf.data(), want * sizeof(uintptr_t), off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        size_t cnt = (size_t)got / sizeof(uintptr_t);
        if (cnt == 0) break;

        for (size_t i = 0; i < cnt; i++) {
            if (g_scanCancelled.load() || g_memoryExhausted.load()) break;
            uintptr_t addr = buf[i];
            uint8_t v[8];
            if (!safeReadMemory(addr, v, tgtSz)) { failedOut.fetch_add(1); continue; }
            size_t sz = 0;
            if (compareValue(v, tgt.data(), t2, type, condition, sz)) {
                sink.add(addr);
                flusher.add(addr, v, sz);
                if (flusher.full()) flusher.flush();
            }
        }
        off += (off64_t)cnt * (off64_t)sizeof(uintptr_t);
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
    if (!env) { finishScan(nullptr, nullptr, 0, false); return; }

    std::vector<uint8_t> tgt  = intToBytes(value,  type);
    std::vector<uint8_t> tgt2 = intToBytes(value2, type);
    if (tgt.empty()) { finishScan(env, cb, g_scanCount.load(), false); return; }
    const size_t tgtSz = tgt.size();

    const int inIdx  = g_currentFile.load();
    const int outIdx = 1 - inIdx;

    int inFd  = open(pathOf(inIdx).c_str(),  O_RDONLY | O_CLOEXEC);
    int outFd = open(pathOf(outIdx).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (inFd < 0 || outFd < 0) {
        LOGE("[SCAN] open falhou");
        if (inFd  >= 0) close(inFd);
        if (outFd >= 0) close(outFd);
        finishScan(env, cb, 0, true);
        return;
    }

    off64_t fileSize = lseek64(inFd, 0, SEEK_END);
    const size_t totalEntries = (fileSize > 0) ? (size_t)(fileSize / (off64_t)sizeof(uintptr_t)) : 0;
    LOGI("[SCAN] Refinando %zu endereços", totalEntries);

    if (totalEntries == 0) {
        close(inFd); close(outFd);
        finishScan(env, cb, 0, false);
        return;
    }

    std::mutex writeMutex;
    g_liveCount = 0;
    g_recoveredFaults.store(0);

    const int nThr = pickThreadCount();
    size_t perThread = (totalEntries + (size_t)nThr - 1) / (size_t)nThr;
    if (perThread == 0) perThread = 1;

    std::atomic<uint64_t> processedAt{0}, failedAt{0};
    std::atomic<bool> reporterRunning{true};
    std::thread reporter = startProgressReporter(cb, processedAt, (uint64_t)totalEntries, reporterRunning);

    std::atomic<int> nextTid{0};
    auto worker = [&]() {
        setpriority(PRIO_PROCESS, 0, 10);
        const int tid = nextTid.fetch_add(1);
        const size_t startIdx = (size_t)tid * perThread;
        if (startIdx >= totalEntries) return;
        const size_t myEntries = std::min(perThread, totalEntries - startIdx);
        const off64_t startByte = (off64_t)startIdx * (off64_t)sizeof(uintptr_t);
        nextScanWorker(inFd, startByte, myEntries, cb, tgt, tgt2, tgtSz,
                       type, condition, outFd, writeMutex, processedAt, failedAt);
    };
    runWorkers(nThr, worker);

    reporterRunning = false;
    if (reporter.joinable()) reporter.join();

    close(inFd);
    close(outFd);

    const size_t finalCount = g_liveCount.load();
    g_currentFile.store(outIdx);
    g_scanCount.store(finalCount);

    [[maybe_unused]] auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - t0).count();
    LOGI("[SCAN] Refino FIM em %lld ms | %zu endereços | %llu falhas",
         (long long)ms, finalCount, (unsigned long long)failedAt.load());

    finishScan(env, cb, finalCount, g_memoryExhausted.load());
}

// ============================================================
//  Pointer scan
// ============================================================
struct PointerHit {
    uintptr_t addr;
    int level;
};

static void pointerScanThread(jobject cb, uintptr_t targetAddr, int maxDepth) {
    auto t0 = std::chrono::steady_clock::now();
    if (maxDepth < 1) maxDepth = 1;
    if (maxDepth > 4) maxDepth = 4;

    const bool staticOnly = g_pointerStaticOnly.load(std::memory_order_relaxed);

    LOGI("[PTR] Pointer scan → 0x%lx | maxDepth=%d | filtro=%s",
         (unsigned long)targetAddr, maxDepth, staticOnly ? "SÓ ESTÁTICOS" : "Universal");

    installSigHandlers();
    JniThreadAttacher att(g_jvm);
    JNIEnv* env = att.getEnv();
    if (!env) { g_scanRunning = false; g_scanCancelled = false; return; }

    const size_t PSIZE = sizeof(void*);
    const size_t MAX_RESULTS_PER_LEVEL = 200000;
    const size_t MAX_TOTAL_RESULTS     = 500000;

    std::unordered_set<uintptr_t> targets;
    targets.insert(targetAddr);

    std::vector<PointerHit> allHits;

    for (int level = 1; level <= maxDepth; level++) {
        if (g_scanCancelled.load()) break;
        if (targets.empty()) break;
        if (allHits.size() >= MAX_TOTAL_RESULTS) break;

        LOGI("[PTR] Nível %d: procurando pointers para %zu alvo(s)...", level, targets.size());

        // O pointer scan ignora o filtro de região/módulo do scan de valor.
        auto regions = parseMaps(false);
        if (regions.empty()) break;

        if (staticOnly) {
            std::vector<MemoryRegion> filtered;
            filtered.reserve(regions.size());
            for (auto& r : regions) if (isStaticRegion(r)) filtered.push_back(r);
            regions = std::move(filtered);
            if (regions.empty()) { LOGW("[PTR] Nenhuma região estática"); break; }
        }

        uint64_t totalBytes = 0;
        for (const auto& r : regions) totalBytes += (uint64_t)(r.end - r.start);

        std::atomic<int>      nextReg{0};
        std::atomic<uint64_t> scannedAt{0};
        std::atomic<size_t>   foundAt{0};
        std::mutex            hitsMutex;
        std::vector<PointerHit> levelHits;
        const size_t alreadyFound = allHits.size();

        std::atomic<bool> reporterRunning{true};
        std::thread reporter = startProgressReporter(cb, scannedAt, totalBytes, reporterRunning);

        auto worker = [&]() {
            setpriority(PRIO_PROCESS, 0, 10);
            const size_t PS = pageSize();
            std::vector<uint8_t> buf(PS + 16);
            std::vector<PointerHit> localHits;

            while (true) {
                if (g_scanCancelled.load()) break;
                if (alreadyFound + foundAt.load() >= MAX_TOTAL_RESULTS) break;
                int idx = nextReg.fetch_add(1);
                if (idx >= (int)regions.size()) break;
                const auto& r = regions[idx];
                if (!r.readable || r.start >= r.end) continue;

                uintptr_t addr = r.start;
                while (addr < r.end && !g_scanCancelled.load()) {
                    const size_t rem = r.end - addr;
                    const size_t rd = rem < PS ? rem : PS;       // ponteiros alinhados não cruzam página
                    if (rd < PSIZE) break;
                    scannedAt.fetch_add(rd, std::memory_order_relaxed);

                    if (safeReadMemory(addr, buf.data(), rd)) {
                        for (size_t off = 0; off + PSIZE <= rd; off += PSIZE) {
                            uintptr_t val = 0;
                            memcpy(&val, buf.data() + off, PSIZE);
                            val = untagPtr(val);
                            if (targets.count(val)) {
                                PointerHit h{(uintptr_t)(addr + off), level};
                                localHits.push_back(h);
                                if (alreadyFound + foundAt.fetch_add(1) + 1 >= MAX_TOTAL_RESULTS) break;
                            }
                        }
                    }
                    uintptr_t next = addr + PS;
                    if (next <= addr) break;
                    addr = next;
                    if (alreadyFound + foundAt.load() >= MAX_TOTAL_RESULTS) break;
                }
            }

            if (!localHits.empty()) {
                std::lock_guard<std::mutex> lk(hitsMutex);
                size_t room = MAX_RESULTS_PER_LEVEL > levelHits.size()
                              ? MAX_RESULTS_PER_LEVEL - levelHits.size() : 0;
                size_t take = std::min(room, localHits.size());
                levelHits.insert(levelHits.end(), localHits.begin(), localHits.begin() + take);
            }
        };
        runWorkers(pickThreadCount(), worker);

        reporterRunning = false;
        if (reporter.joinable()) reporter.join();

        LOGI("[PTR] Nível %d: %zu hits", level, levelHits.size());

        if (!levelHits.empty() && cb && g_onPointerBatchMethod) {
            const size_t CHUNK = 1024;
            for (size_t base = 0; base < levelHits.size(); base += CHUNK) {
                size_t n = std::min(CHUNK, levelHits.size() - base);
                jlongArray arr = env->NewLongArray((jsize)n);
                jintArray  lvl = env->NewIntArray((jsize)n);
                if (!arr || !lvl) {
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (arr) env->DeleteLocalRef(arr);
                    if (lvl) env->DeleteLocalRef(lvl);
                    break;
                }
                std::vector<jlong> a(n);
                std::vector<jint>  l(n);
                for (size_t i = 0; i < n; i++) {
                    a[i] = (jlong)levelHits[base + i].addr;
                    l[i] = (jint)levelHits[base + i].level;
                }
                env->SetLongArrayRegion(arr, 0, (jsize)n, a.data());
                env->SetIntArrayRegion(lvl, 0, (jsize)n, l.data());
                env->CallVoidMethod(cb, g_onPointerBatchMethod, arr, lvl);
                if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
                env->DeleteLocalRef(arr);
                env->DeleteLocalRef(lvl);
            }
        }

        allHits.insert(allHits.end(), levelHits.begin(), levelHits.end());
        targets.clear();
        for (const auto& h : levelHits) targets.insert(h.addr);
    }

    [[maybe_unused]] auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - t0).count();
    LOGI("[PTR] FIM em %lld ms | total %zu hits", (long long)ms, allHits.size());

    g_scanRunning = false;
    g_scanCancelled = false;

    if (cb && g_onPointerCompleteMethod) {
        env->CallVoidMethod(cb, g_onPointerCompleteMethod, (jint)allHits.size());
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
}

// ============================================================
//  freezeLoop
// ============================================================
static std::mutex g_freezeCtlMutex;     // serializa start/stop da thread de freeze

static void freezeLoop() {
    LOGI("[FREEZE] Thread iniciada");
    std::vector<uint8_t> cur;
    while (g_freezeRunning.load()) {
        installSigHandlers();

        std::vector<std::pair<uintptr_t, std::vector<uint8_t>>> cp;
        {
            std::shared_lock<std::shared_mutex> fl(g_frozenMutex);
            cp.reserve(g_frozen.size());
            for (const auto& e : g_frozen) cp.emplace_back(e.first, e.second.first);
        }

        int fail = 0;
        for (const auto& e : cp) {
            const size_t n = e.second.size();
            cur.resize(n);
            // Só escreve se o valor mudou (menos syscalls e menos páginas sujas).
            if (safeReadMemory(e.first, cur.data(), n) &&
                memcmp(cur.data(), e.second.data(), n) == 0) continue;
            if (!writeMemory(e.first, e.second.data(), n)) fail++;
        }
        if (fail) LOGW("[FREEZE] %d falhas", fail);

        // Espera SEMPRE (o original usava um predicado que já nascia verdadeiro
        // e girava em loop apertado a 100% de CPU).
        std::unique_lock<std::mutex> lk(g_freezeCvMutex);
        g_freezeCv.wait_for(lk, std::chrono::milliseconds(50),
                            [] { return !g_freezeRunning.load(); });
    }
    LOGI("[FREEZE] Thread encerrada");
}

static void stopFreezeThread(bool clearAll) {
    std::lock_guard<std::mutex> ctl(g_freezeCtlMutex);
    if (clearAll) {
        std::unique_lock<std::shared_mutex> l(g_frozenMutex);
        g_frozen.clear();
    }
    g_freezeRunning = false;
    g_freezeCv.notify_all();
    if (g_freezeThread.joinable()) g_freezeThread.join();
}

// ============================================================
//  JNI IMPLEMENTATIONS
// ============================================================
static std::mutex g_cbMutex;

// Registra (ou RE-registra) o Service que recebe os callbacks. Se o Service foi
// recriado, troca a referência global (antes ficava presa na instância morta).
static bool registerCallbacks(JNIEnv* env, jobject thiz) {
    std::lock_guard<std::mutex> lk(g_cbMutex);
    if (g_callbackObj && env->IsSameObject(g_callbackObj, thiz)) return true;

    jclass cls = env->GetObjectClass(thiz);
    if (!cls) return false;
    jmethodID mProg  = env->GetMethodID(cls, "onScanProgress",   "(I)V");
    jmethodID mBatch = env->GetMethodID(cls, "onScanBatch",      "([J[[B)V");
    jmethodID mCount = env->GetMethodID(cls, "onScanCount",      "(I)V");
    jmethodID mDone  = env->GetMethodID(cls, "onScanComplete",   "(IZ)V");
    jmethodID mPBat  = env->GetMethodID(cls, "onPointerBatch",   "([J[I)V");
    jmethodID mPDone = env->GetMethodID(cls, "onPointerComplete","(I)V");
    env->DeleteLocalRef(cls);

    if (!mProg || !mBatch || !mCount || !mDone || !mPBat || !mPDone) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("[API] Callbacks não encontrados (R8/ProGuard removeu os métodos?)");
        return false;
    }
    jobject ref = env->NewGlobalRef(thiz);
    if (!ref) return false;
    if (g_callbackObj) env->DeleteGlobalRef(g_callbackObj);
    g_callbackObj = ref;
    g_onProgressMethod = mProg;  g_onBatchMethod = mBatch;  g_onCountMethod = mCount;
    g_onCompleteMethod = mDone;  g_onPointerBatchMethod = mPBat;
    g_onPointerCompleteMethod = mPDone;
    LOGI("[API] Callbacks registrados");
    return true;
}

// Reserva o "slot" de scan (só um por vez), junta a thread anterior e prepara o estado.
static bool beginScan(JNIEnv* env, jobject thiz) {
    bool expected = false;
    if (!g_scanRunning.compare_exchange_strong(expected, true)) {
        LOGW("[API] Scan já em execução");
        return false;
    }
    if (g_scanThread.joinable() && g_scanThread.get_id() != std::this_thread::get_id())
        g_scanThread.join();
    if (!registerCallbacks(env, thiz)) { g_scanRunning = false; return false; }
    ensurePaths();
    g_scanCancelled   = false;
    g_memoryExhausted = false;
    g_displayFull     = false;
    return true;
}

template<typename Fn, typename... Args>
static bool launchScan(Fn fn, Args... args) {
    try {
        g_scanThread = std::thread(fn, g_callbackObj, args...);
    } catch (const std::system_error& e) {
        LOGE("[API] não foi possível criar a thread de scan: %s", e.what());
        g_scanRunning = false;
        return false;
    }
    return true;
}

// Libera o slot de scan ao sair do escopo (snapshot usa isso).
struct ScanSlot {
    bool held;
    ScanSlot() : held(false) {
        bool expected = false;
        held = g_scanRunning.compare_exchange_strong(expected, true);
    }
    ~ScanSlot() { if (held) g_scanRunning = false; }
};

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetWorkDir(
    JNIEnv* env, jobject, jstring jpath) {
    if (!jpath || g_scanRunning.load()) return;
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

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetPointerStaticFilter(
    JNIEnv*, jobject, jboolean enabled) {
    bool v = (enabled == JNI_TRUE);
    g_pointerStaticOnly.store(v, std::memory_order_relaxed);
    LOGI("[API] nativeSetPointerStaticFilter = %s", v ? "ON" : "OFF");
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetModuleFilter(
    JNIEnv* env, jobject, jstring jpat) {
    std::string s;
    if (jpat) {
        const char* c = env->GetStringUTFChars(jpat, nullptr);
        if (c) { s = c; env->ReleaseStringUTFChars(jpat, c); }
    }
    {
        std::lock_guard<std::mutex> lk(g_moduleFilterMutex);
        g_moduleFilter = s;
    }
    LOGI("[API] nativeSetModuleFilter = '%s'", s.empty() ? "(off)" : s.c_str());
}

// Lê uma linha de /proc/self/maps; devolve false se não parseável.
static bool parseMapsLine(const std::string& line, uintptr_t& s, uintptr_t& e, std::string& path) {
    std::istringstream iss(line);
    char dash = 0; std::string perms;
    s = 0; e = 0;
    if (!(iss >> std::hex >> s >> dash >> e >> perms)) return false;
    std::string tmp; iss >> tmp >> tmp >> tmp;
    std::getline(iss, path);
    size_t first = path.find_first_not_of(' ');
    path = (first == std::string::npos) ? std::string() : path.substr(first);
    return true;
}

JNIEXPORT jobjectArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeListModules(
    JNIEnv* env, jobject) {
    std::set<std::string> names;
    std::ifstream maps("/proc/self/maps");
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line)) {
            uintptr_t s, e; std::string path;
            if (!parseMapsLine(line, s, e, path)) continue;
            if (path.empty() || path[0] != '/') continue;
            if (path.compare(0, 5, "/dev/") == 0) continue;
            if (path.compare(0, 7, "/memfd:") == 0) continue;
            if (path.find("libmemscanner.so") != std::string::npos) continue;
            names.insert(basenameOf(path));
        }
    }

    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray arr = env->NewObjectArray((jsize)names.size(), strCls, nullptr);
    env->DeleteLocalRef(strCls);
    if (!arr) return nullptr;
    jsize i = 0;
    for (const auto& n : names) {
        jstring js = env->NewStringUTF(n.c_str());
        if (!js) { if (env->ExceptionCheck()) env->ExceptionClear(); continue; }
        env->SetObjectArrayElement(arr, i++, js);
        env->DeleteLocalRef(js);
    }
    LOGI("[API] nativeListModules → %zu módulos", names.size());
    return arr;
}

JNIEXPORT jlong JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetModuleBase(
    JNIEnv* env, jobject, jstring jname) {
    if (!jname) return 0;
    const char* c = env->GetStringUTFChars(jname, nullptr);
    if (!c) return 0;
    std::string name(c);
    env->ReleaseStringUTFChars(jname, c);
    if (name.empty()) return 0;

    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return 0;
    std::string line;
    uintptr_t lowest = 0;
    const size_t nameLen = name.size();
    while (std::getline(maps, line)) {
        uintptr_t s, e; std::string path;
        if (!parseMapsLine(line, s, e, path)) continue;
        if (path.size() < nameLen) continue;
        if (path.compare(path.size() - nameLen, nameLen, name) != 0) continue;
        if (path.size() != nameLen && path[path.size() - nameLen - 1] != '/') continue;
        if (lowest == 0 || s < lowest) lowest = s;
    }
    LOGI("[API] nativeGetModuleBase('%s') = 0x%lx", name.c_str(), (unsigned long)lowest);
    return (jlong)lowest;
}

JNIEXPORT jstring JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeFindModuleForAddr(
    JNIEnv* env, jobject, jlong jaddr) {
    uintptr_t addr = 0;
    std::string result;
    if (toAddr(jaddr, &addr)) {
        uintptr_t lowest = 0;
        std::ifstream maps("/proc/self/maps");
        std::string line;
        while (maps.is_open() && std::getline(maps, line)) {
            uintptr_t s, e; std::string path;
            if (!parseMapsLine(line, s, e, path)) continue;
            if (path.empty() || path[0] != '/') continue;
            if (addr < s || addr >= e) continue;
            if (lowest == 0 || s < lowest) { lowest = s; result = basenameOf(path); }
        }
    }
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jlong JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeResolvePointerPath(
    JNIEnv* env, jobject, jlong baseAddr, jintArray joffs) {
    uintptr_t addr = 0;
    if (!joffs || !toAddr(baseAddr, &addr)) return 0;
    jsize n = env->GetArrayLength(joffs);
    if (n == 0) return (jlong)addr;

    std::vector<jint> offs((size_t)n);
    env->GetIntArrayRegion(joffs, 0, n, offs.data());
    if (env->ExceptionCheck()) { env->ExceptionClear(); return 0; }

    installSigHandlers();
    const size_t PSIZE = sizeof(void*);
    for (jsize i = 0; i < n; i++) {
        uintptr_t p = 0;
        if (!safeReadMemory(addr, &p, PSIZE)) return 0;
        p = untagPtr(p);
        if (p == 0) return 0;                                   // ponteiro nulo no meio da cadeia
        addr = p + (uintptr_t)(intptr_t)offs[(size_t)i];        // offset COM SINAL (antes era uint32)
    }
    return (jlong)addr;
}

static bool validType(int t)  { return t >= TYPE_BYTE && t <= TYPE_DOUBLE; }
static bool validCond(int c)  { return c >= COND_EXACT && c <= COND_RANGE; }

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeStartScan(
    JNIEnv* env, jobject thiz, jlong value, jlong value2, jint type, jint condition) {
    LOGI("[API] nativeStartScan | %s %s v1=%lld v2=%lld",
         typeName(type), condName(condition), (long long)value, (long long)value2);
    if (!validType((int)type) || !validCond((int)condition)) return JNI_FALSE;
    if (!beginScan(env, thiz)) return JNI_FALSE;
    g_lastScanType = (int)type;
    return launchScan(scanThread, (long long)value, (long long)value2,
                      (int)type, (int)condition) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeNextScan(
    JNIEnv* env, jobject thiz, jlong value, jlong value2, jint condition) {
    LOGI("[API] nativeNextScan | v1=%lld v2=%lld cond=%s",
         (long long)value, (long long)value2, condName(condition));
    if (!validCond((int)condition)) return JNI_FALSE;
    if (g_scanCount.load() == 0) return JNI_FALSE;
    if (!beginScan(env, thiz)) return JNI_FALSE;
    return launchScan(nextScanThread, (long long)value, (long long)value2,
                      g_lastScanType.load(), (int)condition) ? JNI_TRUE : JNI_FALSE;
}

// UTF-16 (jchar) -> UTF-8 de verdade (GetStringUTFChars devolve "modified UTF-8":
// emojis/caracteres fora do BMP sairiam como pares substitutos e nunca casariam).
static std::vector<uint8_t> utf16ToUtf8(const jchar* s, jsize len) {
    std::vector<uint8_t> out;
    out.reserve((size_t)len * 3);
    for (jsize i = 0; i < len; i++) {
        uint32_t c = s[i];
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < len && s[i + 1] >= 0xDC00 && s[i + 1] <= 0xDFFF) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00);
            i++;
        }
        if (c < 0x80) out.push_back((uint8_t)c);
        else if (c < 0x800) { out.push_back((uint8_t)(0xC0 | (c >> 6))); out.push_back((uint8_t)(0x80 | (c & 0x3F))); }
        else if (c < 0x10000) { out.push_back((uint8_t)(0xE0 | (c >> 12))); out.push_back((uint8_t)(0x80 | ((c >> 6) & 0x3F))); out.push_back((uint8_t)(0x80 | (c & 0x3F))); }
        else { out.push_back((uint8_t)(0xF0 | (c >> 18))); out.push_back((uint8_t)(0x80 | ((c >> 12) & 0x3F))); out.push_back((uint8_t)(0x80 | ((c >> 6) & 0x3F))); out.push_back((uint8_t)(0x80 | (c & 0x3F))); }
    }
    return out;
}

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeStringScan(
    JNIEnv* env, jobject thiz, jstring jtext, jint encoding) {
    if (!jtext) return JNI_FALSE;
    const jsize len = env->GetStringLength(jtext);
    if (len <= 0) return JNI_FALSE;
    const jchar* chars = env->GetStringChars(jtext, nullptr);
    if (!chars) return JNI_FALSE;

    std::vector<uint8_t> pattern;
    if (encoding == 1) {
        pattern.reserve((size_t)len * 2);
        for (jsize i = 0; i < len; i++) {
            uint16_t u = (uint16_t)chars[i];
            pattern.push_back((uint8_t)(u & 0xFF));
            pattern.push_back((uint8_t)(u >> 8));
        }
    } else {
        pattern = utf16ToUtf8(chars, len);
    }
    env->ReleaseStringChars(jtext, chars);

    LOGI("[API] nativeStringScan enc=%d len=%zu", (int)encoding, pattern.size());
    if (pattern.empty()) return JNI_FALSE;
    if (!beginScan(env, thiz)) return JNI_FALSE;
    g_lastScanType = TYPE_BYTE;
    return launchScan(stringScanThread, pattern) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeAoBScan(
    JNIEnv* env, jobject thiz, jstring jpattern, jint /*limit*/) {
    if (!jpattern) return JNI_FALSE;
    const char* p = env->GetStringUTFChars(jpattern, nullptr);
    if (!p) return JNI_FALSE;
    std::string patStr(p);
    env->ReleaseStringUTFChars(jpattern, p);

    bool ok = false;
    AoBPattern pat = parseAoBPattern(patStr, &ok);
    LOGI("[API] nativeAoBScan '%s' → %zu bytes (ok=%d)", patStr.c_str(), pat.size(), (int)ok);
    if (!ok || pat.empty()) return JNI_FALSE;
    if (!beginScan(env, thiz)) return JNI_FALSE;
    g_lastScanType = TYPE_BYTE;
    return launchScan(aobScanThread, pat) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativePointerScan(
    JNIEnv* env, jobject thiz, jlong target, jint maxDepth) {
    uintptr_t t = 0;
    if (!toAddr(target, &t)) return JNI_FALSE;
    LOGI("[API] nativePointerScan target=0x%lx depth=%d", (unsigned long)t, (int)maxDepth);
    if (!beginScan(env, thiz)) return JNI_FALSE;
    return launchScan(pointerScanThread, t, (int)maxDepth) ? JNI_TRUE : JNI_FALSE;
}

// ============================================================
//  Snapshot
// ============================================================
struct SnapEnt { uintptr_t addr; uint8_t val[8]; };

static ssize_t readLoop(int fd, void* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = ::read(fd, (uint8_t*)buf + total, n - total);
        if (r < 0) { if (errno == EINTR) continue; return total ? (ssize_t)total : -1; }
        if (r == 0) break;
        total += (size_t)r;
    }
    return (ssize_t)total;
}
static bool writeLoop(int fd, const void* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = ::write(fd, (const uint8_t*)buf + total, n - total);
        if (w < 0) { if (errno == EINTR) continue; return false; }
        if (w == 0) return false;
        total += (size_t)w;
    }
    return true;
}

template<typename T>
static int cmpT(const uint8_t* a, const uint8_t* b) {
    T x, y; memcpy(&x, a, sizeof(T)); memcpy(&y, b, sizeof(T));
    return x < y ? -1 : (x > y ? 1 : 0);
}
// Comparação NUMÉRICA conforme o tipo (antes era uint64 cru: errado p/ negativos e float).
static int cmpTyped(const uint8_t* a, const uint8_t* b, int type) {
    switch (type) {
        case TYPE_BYTE:   return cmpT<uint8_t>(a, b);
        case TYPE_SHORT:  return cmpT<int16_t>(a, b);
        case TYPE_INT:    return cmpT<int32_t>(a, b);
        case TYPE_LONG:   return cmpT<int64_t>(a, b);
        case TYPE_FLOAT:  return cmpT<float>(a, b);
        case TYPE_DOUBLE: return cmpT<double>(a, b);
        default:          return 0;
    }
}

// Retorna: >=0 qtd salva | -1 scan em andamento | -2 erro de arquivo
JNIEXPORT jint JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSnapshotSave(
    JNIEnv*, jobject) {
    ScanSlot slot;
    if (!slot.held) return -1;
    installSigHandlers();
    ensurePaths();
    const int type = g_lastScanType.load();
    const size_t sz = (size_t)typeSizeOf(type);
    g_snapshotType = type;

    int snapFd = open(snapshotPath().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (snapFd < 0) { LOGW("[SNAP] open falhou: %s", strerror(errno)); return -2; }
    int inFd = open(pathOf(g_currentFile.load()).c_str(), O_RDONLY | O_CLOEXEC);
    if (inFd < 0) { close(snapFd); return -2; }

    std::vector<uintptr_t> addrs(4096);
    std::vector<SnapEnt> outBuf;
    outBuf.reserve(4096);
    size_t saved = 0;
    bool ioOk = true;

    while (ioOk) {
        ssize_t got = readLoop(inFd, addrs.data(), addrs.size() * sizeof(uintptr_t));
        if (got <= 0) break;
        size_t n = (size_t)got / sizeof(uintptr_t);
        for (size_t i = 0; i < n && ioOk; i++) {
            SnapEnt e;
            memset(&e, 0, sizeof(e));
            e.addr = addrs[i];
            if (!safeReadMemory(e.addr, e.val, sz)) continue;
            outBuf.push_back(e);
            if (outBuf.size() >= 4096) {
                ioOk = writeLoop(snapFd, outBuf.data(), outBuf.size() * sizeof(SnapEnt));
                if (ioOk) saved += outBuf.size();
                outBuf.clear();
            }
        }
    }
    if (ioOk && !outBuf.empty()) {
        ioOk = writeLoop(snapFd, outBuf.data(), outBuf.size() * sizeof(SnapEnt));
        if (ioOk) saved += outBuf.size();
    }
    close(snapFd); close(inFd);
    g_snapshotCount.store(saved);
    LOGI("[SNAP] Snapshot com %zu entradas (type=%d)", saved, type);
    return ioOk ? (jint)saved : -2;
}

// Retorna: >=0 qtd de resultados | -1 scan em andamento | -2 sem snapshot / erro
JNIEXPORT jint JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSnapshotDiff(
    JNIEnv*, jobject, jint mode) {
    ScanSlot slot;
    if (!slot.held) return -1;
    installSigHandlers();
    ensurePaths();
    const int type = g_snapshotType.load();
    const size_t sz = (size_t)typeSizeOf(type);

    int snapFd = open(snapshotPath().c_str(), O_RDONLY | O_CLOEXEC);
    if (snapFd < 0) { LOGW("[SNAP] sem snapshot"); return -2; }

    const int outIdx = 1 - g_currentFile.load();
    int outFd = open(pathOf(outIdx).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (outFd < 0) { close(snapFd); return -2; }

    std::vector<SnapEnt> buf(4096);
    std::vector<uintptr_t> outStage;
    outStage.reserve(4096);
    size_t outCount = 0;
    bool ioOk = true;

    while (ioOk) {
        ssize_t got = readLoop(snapFd, buf.data(), buf.size() * sizeof(SnapEnt));
        if (got <= 0) break;
        size_t n = (size_t)got / sizeof(SnapEnt);
        for (size_t i = 0; i < n && ioOk; i++) {
            uint8_t cur[8];
            memset(cur, 0, sizeof(cur));
            if (!safeReadMemory(buf[i].addr, cur, sz)) continue;
            bool match = false;
            switch ((int)mode) {
                case 0: match = memcmp(cur, buf[i].val, sz) != 0; break;
                case 1: match = memcmp(cur, buf[i].val, sz) == 0; break;
                case 2: match = cmpTyped(cur, buf[i].val, type) > 0; break;
                case 3: match = cmpTyped(cur, buf[i].val, type) < 0; break;
                default: match = false;
            }
            if (match) {
                outStage.push_back(buf[i].addr);
                outCount++;
                if (outStage.size() >= 4096) {
                    ioOk = writeLoop(outFd, outStage.data(), outStage.size() * sizeof(uintptr_t));
                    outStage.clear();
                }
            }
        }
    }
    if (ioOk && !outStage.empty())
        ioOk = writeLoop(outFd, outStage.data(), outStage.size() * sizeof(uintptr_t));
    close(outFd); close(snapFd);
    if (!ioOk) return -2;

    g_currentFile.store(outIdx);
    g_scanCount.store(outCount);
    g_liveCount.store(outCount);
    LOGI("[SNAP] Diff mode=%d → %zu resultados", (int)mode, outCount);
    return (jint)outCount;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSnapshotClear(
    JNIEnv*, jobject) {
    ensurePaths();
    unlink(snapshotPath().c_str());
    g_snapshotCount.store(0);
    LOGI("[SNAP] Snapshot apagado");
}

// ============================================================
//  Controle
// ============================================================
JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeSetDisplayFull(
    JNIEnv*, jobject) {
    g_displayFull = true;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeCancelScan(
    JNIEnv*, jobject) {
    LOGW("[API] nativeCancelScan");
    g_scanCancelled = true;
}

JNIEXPORT jint JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetLastScanType(
    JNIEnv*, jobject) {
    return (jint)g_lastScanType.load();
}

// Chamado no onDestroy do Service: para scan e freeze e solta a referência global
// (senão ela prenderia o Service morto e os callbacks iriam para a instância errada).
JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeShutdown(
    JNIEnv* env, jobject) {
    g_scanCancelled = true;
    if (g_scanThread.joinable() && g_scanThread.get_id() != std::this_thread::get_id())
        g_scanThread.join();
    g_scanCancelled = false;
    g_scanRunning   = false;

    stopFreezeThread(true);

    std::lock_guard<std::mutex> lk(g_cbMutex);
    if (g_callbackObj) { env->DeleteGlobalRef(g_callbackObj); g_callbackObj = nullptr; }
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeClearResults(
    JNIEnv*, jobject) {
    LOGI("[API] nativeClearResults");
    // Se houver scan rodando, cancela e espera antes de apagar os arquivos que ele usa.
    if (g_scanRunning.load()) {
        g_scanCancelled = true;
        if (g_scanThread.joinable() && g_scanThread.get_id() != std::this_thread::get_id())
            g_scanThread.join();
        g_scanCancelled = false;
        g_scanRunning   = false;
    }
    stopFreezeThread(true);

    ensurePaths();
    unlink(g_pathA.c_str());
    unlink(g_pathB.c_str());
    unlink(snapshotPath().c_str());
    g_scanCount = 0;
    g_liveCount = 0;
    g_snapshotCount = 0;
    g_currentFile = 0;
    g_displayFull = false;
}

// ============================================================
//  Resultados
// ============================================================
JNIEXPORT jlongArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeGetResults(
    JNIEnv* env, jobject, jint maxCount) {
    ensurePaths();
    int fd = open(pathOf(g_currentFile.load()).c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return env->NewLongArray(0);

    off64_t fsz = lseek64(fd, 0, SEEK_END);
    lseek64(fd, 0, SEEK_SET);
    size_t count = g_scanCount.load();
    const size_t inFile = (fsz > 0) ? (size_t)(fsz / (off64_t)sizeof(uintptr_t)) : 0;
    if (count > inFile) count = inFile;
    if (maxCount > 0 && count > (size_t)maxCount) count = (size_t)maxCount;

    jlongArray arr = env->NewLongArray((jsize)count);
    if (!arr) { close(fd); return nullptr; }

    std::vector<uintptr_t> buf(4096);
    std::vector<jlong> jb(4096);
    size_t out = 0;
    while (out < count) {
        size_t want = std::min((size_t)4096, count - out);
        ssize_t got = readLoop(fd, buf.data(), want * sizeof(uintptr_t));
        if (got <= 0) break;
        size_t n = (size_t)got / sizeof(uintptr_t);
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) jb[i] = (jlong)buf[i];
        env->SetLongArrayRegion(arr, (jsize)out, (jsize)n, jb.data());
        out += n;
    }
    close(fd);
    return arr;
}

// ============================================================
//  Acesso à memória
// ============================================================
JNIEXPORT jboolean JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeWriteMemory(
    JNIEnv* env, jobject, jlong address, jbyteArray data) {
    uintptr_t a = 0;
    if (!data || !toAddr(address, &a)) return JNI_FALSE;
    jsize len = env->GetArrayLength(data);
    if (len <= 0) return JNI_FALSE;
    std::vector<jbyte> tmp((size_t)len);
    env->GetByteArrayRegion(data, 0, len, tmp.data());
    if (env->ExceptionCheck()) { env->ExceptionClear(); return JNI_FALSE; }
    installSigHandlers();
    return writeMemory(a, tmp.data(), (size_t)len) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeToggleFreeze(
    JNIEnv*, jobject, jlong address, jlong value, jint type, jboolean enable) {
    uintptr_t a = 0;
    if (!toAddr(address, &a)) return;

    if (enable) {
        if (!validType((int)type)) return;
        std::vector<uint8_t> b = intToBytes(value, (int)type);
        if (b.empty()) return;
        {
            std::unique_lock<std::shared_mutex> l(g_frozenMutex);
            g_frozen[a] = std::make_pair(b, (int)type);
        }
        {
            std::lock_guard<std::mutex> ctl(g_freezeCtlMutex);
            if (!g_freezeRunning.load()) {
                if (g_freezeThread.joinable()) g_freezeThread.join();
                g_freezeRunning = true;
                try { g_freezeThread = std::thread(freezeLoop); }
                catch (const std::system_error&) { g_freezeRunning = false; }
            }
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
            std::lock_guard<std::mutex> ctl(g_freezeCtlMutex);
            g_freezeRunning = false;
            g_freezeCv.notify_all();
        }
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeReadMemory(
    JNIEnv* env, jobject, jlong address, jint size) {
    uintptr_t a = 0;
    if (size <= 0 || size > 64 * 1024 || !toAddr(address, &a)) return nullptr;
    installSigHandlers();
    std::vector<uint8_t> tmp((size_t)size);
    if (!safeReadMemory(a, tmp.data(), (size_t)size)) return nullptr;
    jbyteArray arr = env->NewByteArray(size);
    if (!arr) return nullptr;
    env->SetByteArrayRegion(arr, 0, size, (const jbyte*)tmp.data());
    return arr;
}

JNIEXPORT jbyteArray JNICALL Java_com_exemplo_scanner_MemoryScannerService_nativeReadRegion(
    JNIEnv* env, jobject, jlong start, jint size) {
    uintptr_t addr = 0;
    if (size <= 0 || size > 64 * 1024 || !toAddr(start, &addr)) return nullptr;
    installSigHandlers();

    std::vector<uint8_t> tmp((size_t)size, 0);
    const size_t PS = pageSize();
    size_t remaining = (size_t)size, offset = 0;
    int okPages = 0, badPages = 0;

    while (remaining > 0) {
        size_t pageOff = addr & (PS - 1);
        size_t chunk = PS - pageOff;
        if (chunk > remaining) chunk = remaining;
        if (safeReadMemory(addr, tmp.data() + offset, chunk)) okPages++;
        else { memset(tmp.data() + offset, 0, chunk); badPages++; }
        addr += chunk; offset += chunk; remaining -= chunk;
    }
    LOGD("[READREGION] size=%d ok=%d bad=%d", (int)size, okPages, badPages);
    if (okPages == 0) return nullptr;

    jbyteArray arr = env->NewByteArray(size);
    if (!arr) return nullptr;
    env->SetByteArrayRegion(arr, 0, size, (const jbyte*)tmp.data());
    return arr;
}

// ============================================================
//  JNI_OnLoad
// ============================================================
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;

    LOGI("[INIT] MemScanner v5 | PID: %d | Page: %ld | %s",
         getpid(), sysconf(_SC_PAGE_SIZE), sizeof(void*) == 4 ? "32-bit" : "64-bit");
    LOGI("[INIT] Threads escolhidas: %d", pickThreadCount());

    installSigHandlers();

    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) == JNI_OK && env) {
        jclass localB = env->FindClass("[B");
        if (localB) { g_byteArrayClass = (jclass)env->NewGlobalRef(localB); env->DeleteLocalRef(localB); }
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    return JNI_VERSION_1_6;
}

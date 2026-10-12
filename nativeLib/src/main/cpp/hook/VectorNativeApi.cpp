//
// Created by Zhenxi on 2023/4/2.
//
// Vector NativeAPIEntries 的封装实现。
//
// 注意:这里不做任何 inline hook 的移植工作 —— wxshadow 由框架提供,
// 我们只是调用它,并且严格遵守"replacement 签名必须与目标一致、原函数走 backup trampoline"。
//
#include "vector_native_api.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>

#include <cstring>
#include <map>
#include <mutex>

#include "ZhenxiLog.h"
#include "logging.h"

namespace {

    /**
     * ARMv8.3 指针认证:高 8 位是 PAC 签名,交给 hook 引擎前必须先剥掉。
     * 对齐 Vector 示例 examples/native-hook-demo 的 StripPac。
     */
    constexpr uintptr_t kPacStripMask = 0x00FFFFFFFFFFFFFFULL;

    uintptr_t StripPac(uintptr_t value) {
        if (value & 0xFF00000000000000ULL) {
            value &= kPacStripMask;
        }
        return value;
    }

    NativeAPIEntries g_entries{};
    bool g_entriesReady = false;

    /**
     * 已经 hook 过的地址 -> backup。
     *
     * wxshadow 的 hook_install 对同一个 target 是拒绝重复安装的(hook_install 返回 NULL),
     * 而模块里可能出现同一个函数被两条路径各 hook 一次的情况(JNIEnv 表在多个 env 上是同一份)。
     * 这里做一层去重:重复 hook 时直接复用已有的 backup。
     */
    std::mutex g_hookMutex;
    std::map<void *, void *> g_hookedTargets;

    // libart .dynsym 定位结果
    struct LibartElfInfo {
        uintptr_t base = 0;
        const ElfW(Dyn) *dynamic = nullptr;
        size_t dynamicCount = 0;
    };

    int FindLibartCallback(struct dl_phdr_info *info, size_t /*size*/, void *data) {
        auto *out = static_cast<LibartElfInfo *>(data);
        if (out->base != 0) {
            return 0;
        }
        const char *name = info->dlpi_name ? info->dlpi_name : "";
        if (strstr(name, "libart.so") == nullptr) {
            return 0;
        }
        out->base = static_cast<uintptr_t>(info->dlpi_addr);
        for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
            const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
            if (phdr->p_type == PT_DYNAMIC) {
                // PT_DYNAMIC 的 p_vaddr 是 load bias 相对值,dlpi_addr 就是 load bias
                out->dynamic = reinterpret_cast<const ElfW(Dyn) *>(out->base + phdr->p_vaddr);
                out->dynamicCount = phdr->p_memsz / sizeof(ElfW(Dyn));
                break;
            }
        }
        return 0;
    }

    JavaVM *g_vm = nullptr;
    std::mutex g_vmMutex;

}  // namespace

namespace VectorApi {

    void Init(const NativeAPIEntries *entries) {
        if (entries == nullptr) {
            LOGE("VectorApi::Init entries == null");
            return;
        }
        if (entries->version < 2) {
            LOGW("VectorApi::Init unexpected version %u (expect >= 2)", entries->version);
        }
        g_entries = *entries;
        g_entriesReady = (entries->hookFunc != nullptr && entries->unhookFunc != nullptr);
        LOGI("VectorApi::Init version=%u hookFunc=%p unhookFunc=%p",
             entries->version,
             reinterpret_cast<void *>(entries->hookFunc),
             reinterpret_cast<void *>(entries->unhookFunc));
    }

    bool IsReady() {
        return g_entriesReady;
    }

    uint32_t Version() {
        return g_entries.version;
    }

    bool Hook(void *target, void *replace, void **backup) {
        if (backup == nullptr) {
            LOGE("VectorApi::Hook backup == null");
            return false;
        }
        *backup = nullptr;
        if (target == nullptr || replace == nullptr) {
            LOGE("VectorApi::Hook invalid param target=%p replace=%p", target, replace);
            return false;
        }
        if (!g_entriesReady) {
            LOGE("VectorApi::Hook called before native_init / entries unavailable");
            return false;
        }

        void *stripped = reinterpret_cast<void *>(StripPac(reinterpret_cast<uintptr_t>(target)));

        std::lock_guard<std::mutex> lock(g_hookMutex);
        auto iter = g_hookedTargets.find(stripped);
        if (iter != g_hookedTargets.end()) {
            // 已经 hook 过,直接复用 backup
            *backup = iter->second;
            return true;
        }

        void *trampoline = nullptr;
        int ret = g_entries.hookFunc(stripped, replace, &trampoline);
        if (ret != 0 || trampoline == nullptr) {
            // 框架层把所有失败原因都压成同一个错误码,wxshadow 未就绪 / 页属性不支持 / 分配失败都走这里
            LOGE("VectorApi::Hook failed target=%p replace=%p ret=%d trampoline=%p",
                 stripped, replace, ret, trampoline);
            return false;
        }
        g_hookedTargets[stripped] = trampoline;
        *backup = trampoline;
        LOGI("VectorApi::Hook ok target=%p replace=%p trampoline=%p", stripped, replace, trampoline);
        return true;
    }

    bool Unhook(void *target) {
        if (target == nullptr) {
            return false;
        }
        if (!g_entriesReady) {
            return false;
        }
        void *stripped = reinterpret_cast<void *>(StripPac(reinterpret_cast<uintptr_t>(target)));
        std::lock_guard<std::mutex> lock(g_hookMutex);
        g_hookedTargets.erase(stripped);
        return g_entries.unhookFunc(stripped) == 0;
    }

    uintptr_t DlsymLibart(const char *name) {
        if (name == nullptr) {
            return 0;
        }
        LibartElfInfo info;
        dl_iterate_phdr(&FindLibartCallback, &info);
        if (info.base == 0 || info.dynamic == nullptr) {
            LOGE("VectorApi: cannot locate libart.so via dl_iterate_phdr");
            return 0;
        }

        const ElfW(Sym) *symtab = nullptr;
        const char *strtab = nullptr;
        size_t strsz = 0;
        // PT_DYNAMIC 里 DT_SYMTAB/DT_STRTAB 的 d_ptr 可能是 load bias 相对值,也可能是绝对地址
        auto dynamicPtr = [&info](uint64_t value) -> uintptr_t {
            return value >= info.base ? static_cast<uintptr_t>(value)
                                      : static_cast<uintptr_t>(info.base + value);
        };
        for (size_t i = 0; i < info.dynamicCount; ++i) {
            const ElfW(Dyn) *d = &info.dynamic[i];
            if (d->d_tag == DT_NULL) {
                break;
            }
            if (d->d_tag == DT_SYMTAB) {
                symtab = reinterpret_cast<const ElfW(Sym) *>(dynamicPtr(d->d_un.d_ptr));
            } else if (d->d_tag == DT_STRTAB) {
                strtab = reinterpret_cast<const char *>(dynamicPtr(d->d_un.d_ptr));
            } else if (d->d_tag == DT_STRSZ) {
                strsz = static_cast<size_t>(d->d_un.d_val);
            }
        }
        if (symtab == nullptr || strtab == nullptr || strsz == 0) {
            LOGE("VectorApi: libart dynamic symbol table incomplete");
            return 0;
        }

        // PT_DYNAMIC 不给 nsyms,但 .dynsym 紧邻 .dynstr,用两者距离作为上界
        size_t maxSyms = (reinterpret_cast<uintptr_t>(strtab) > reinterpret_cast<uintptr_t>(symtab))
                             ? (reinterpret_cast<uintptr_t>(strtab) -
                                reinterpret_cast<uintptr_t>(symtab)) / sizeof(ElfW(Sym))
                             : 65536;
        for (size_t i = 0; i < maxSyms; ++i) {
            const ElfW(Sym) *sym = &symtab[i];
            if (sym->st_name == 0) {
                continue;
            }
            if (sym->st_name >= strsz) {
                break;
            }
            if (strcmp(strtab + sym->st_name, name) == 0) {
                return info.base + sym->st_value;
            }
        }
        LOGE("VectorApi: symbol '%s' not found in libart .dynsym", name);
        return 0;
    }

    void SetJavaVm(JavaVM *vm) {
        if (vm == nullptr) {
            return;
        }
        std::lock_guard<std::mutex> lock(g_vmMutex);
        g_vm = vm;
    }

    JavaVM *GetJavaVm() {
        {
            std::lock_guard<std::mutex> lock(g_vmMutex);
            if (g_vm != nullptr) {
                return g_vm;
            }
        }

        // 对齐 rustFrida get_or_init_vm:APEX 里的 libart 不进 app namespace,
        // dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs") 拿不到,必须自己解析 .dynsym
        using JniGetCreatedJavaVMs = jint (*)(JavaVM **, jsize, jsize *);
        uintptr_t addr = DlsymLibart("JNI_GetCreatedJavaVMs");
        if (addr == 0) {
            return nullptr;
        }
        auto getVms = reinterpret_cast<JniGetCreatedJavaVMs>(addr);
        JavaVM *vm = nullptr;
        jsize count = 0;
        if (getVms(&vm, 1, &count) != JNI_OK || count == 0 || vm == nullptr) {
            LOGE("VectorApi: JNI_GetCreatedJavaVMs failed count=%d", static_cast<int>(count));
            return nullptr;
        }
        std::lock_guard<std::mutex> lock(g_vmMutex);
        g_vm = vm;
        return vm;
    }

    JNIEnv *GetEnv() {
        JavaVM *vm = GetJavaVm();
        if (vm == nullptr) {
            return nullptr;
        }
        JNIEnv *env = nullptr;
        jint ret = vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
        if (ret == JNI_OK && env != nullptr) {
            return env;
        }
        if (ret == JNI_EDETACHED) {
            if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK && env != nullptr) {
                return env;
            }
            LOGE("VectorApi: AttachCurrentThread failed");
        }
        return nullptr;
    }

}  // namespace VectorApi

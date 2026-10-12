//
// Created by zhenxi on 2021/5/16.
//
// inline hook 统一入口 —— 现在完全走 Vector 框架下发的 wxshadow 引擎。
// 这里不再包含任何 hook 引擎实现(原 Dobby / sandhook 已移除)。
//
#include "HookUtils.h"
#include "vector_native_api.h"

#include "ZhenxiLog.h"
#include "logging.h"

/**
 * hook 一个已知地址的函数
 */
bool HookUtils::Hooker(void *dysym, void *repl, void **org) {
    if (dysym == nullptr) {
        LOG(ERROR) << "HookUtils::Hooker target == null";
        return false;
    }
    return VectorApi::Hook(dysym, repl, org);
}

/**
 * hook 一个 handle 里的符号
 */
bool HookUtils::Hooker(void *handler, const char *dysym, void *repl, void **org) {
    if (handler == nullptr || dysym == nullptr) {
        LOG(ERROR) << "HookUtils::Hooker invalid param handler=" << handler << " sym=" << dysym;
        return false;
    }
    void *sym = dlsym_compat(handler, dysym);
    if (sym == nullptr) {
        LOG(ERROR) << "HookUtils::Hooker dlsym == null : " << dysym;
        return false;
    }
    bool ret = Hooker(sym, repl, org);
    if (!ret) {
        LOG(ERROR) << "HookUtils::Hooker hook failed : " << dysym;
    }
    return ret;
}

/**
 * 带函数名(仅用于日志可读性)
 */
bool HookUtils::Hooker(void *dysym, void *repl, void **org, const char *dynSymName) {
    bool ret = Hooker(dysym, repl, org);
    if (!ret) {
        LOG(ERROR) << "HookUtils::Hooker failed : " << (dynSymName == nullptr ? "?" : dynSymName);
    }
    return ret;
}

/**
 * 按 so 路径 + 符号名 hook
 */
bool HookUtils::Hooker(const char *libName, const char *dysym, void *repl, void **org) {
    if (libName == nullptr || dysym == nullptr) {
        return false;
    }
    void *sym = getSymCompat(libName, dysym);
    if (sym == nullptr) {
        LOG(ERROR) << "HookUtils::Hooker getSymCompat == null : " << libName << " " << dysym;
        return false;
    }
    bool ret = Hooker(sym, repl, org);
    if (!ret) {
        LOG(ERROR) << "HookUtils::Hooker hook failed : " << libName << " " << dysym;
    }
    return ret;
}

bool HookUtils::unHook(void *sym) {
    return VectorApi::Unhook(sym);
}

/**
 * libc 函数 hook 的常用封装
 */
void hook_libc_function(void *handle, const char *symbol, void *new_func, void **old_func) {
    if (handle == nullptr || symbol == nullptr) {
        LOGE("hook_libc_function invalid param handle=%p symbol=%s", handle, symbol)
        return;
    }
    void *addr = dlsym(handle, symbol);
    if (addr == nullptr) {
        LOGE("hook_function_libc not found symbol : %s", symbol)
        return;
    }
    if (!HookUtils::Hooker(addr, new_func, old_func)) {
        LOGE(">>>>>>>>>>> libc hook %s fail !", symbol)
    }
}

//
// Created by zhenxi on 2021/5/16.
//
// inline hook 的统一入口。
//
// 历史:这个类原来封装的是 Dobby + sandhook 三级降级。
// 在 Vector(soLoader 基线)下,模块**不允许**自带第二套 inline hook,
// 必须使用框架通过 native_init 下发的 NativeAPIEntries.hookFunc(wxshadow 引擎),
// 所以这里现在只是 VectorApi 的一层薄封装,对外保持原来的函数签名不变。
//

#include "logging.h"
#include "dlfcn_compat.h"

#ifndef VMP_HOOKUTILS_H
#define VMP_HOOKUTILS_H

#define HOOK_DEF(ret, func, ...) \
  ret (*orig_##func)(__VA_ARGS__)=nullptr; \
  ret new_##func(__VA_ARGS__)

class HookUtils {
public:

    /**
     * hook 一个已经知道地址的函数
     *
     * @param dysym  目标函数地址
     * @param repl   replacement(签名必须与目标一致,裸露换语义)
     * @param org    成功后写入 backup trampoline,调原函数走它
     */
    static bool Hooker(void *dysym, void *repl, void **org);

    /**
     * hook dlopen 出来的 handle 里的符号
     */
    static bool Hooker(void *handler, const char *dysym, void *repl, void **org);

    /**
     * 带函数名版本,只是为了失败时日志更清楚
     */
    static bool Hooker(void *dysym, void *repl, void **org, const char *dynSymName);

    /**
     * 从 so 路径里找符号再 hook
     */
    static bool Hooker(const char *libName, const char *dysym, void *repl, void **org);

    /**
     * 取消 hook
     */
    static bool unHook(void *sym);

};

/**
 * libc 函数 hook 的常用封装:dlsym 找符号 + Hooker
 */
void hook_libc_function(void *handle, const char *symbol, void *new_func, void **old_func);

#endif //VMP_HOOKUTILS_H

//
// Created by Zhenxi on 2023/4/2.
//
// Vector 框架的 native 模块 API 对接层。
//
// Vector 的硬性约束(见 Vector/docs/native-module-guide.md 与 AGENTS.md《编写 native 模块的硬约束》):
//   1. 禁止 System.loadLibrary / System.load,模块 so 只能由 soLoader 匿名装载;
//   2. 模块 so 必须导出 native_init(NativeAPIEntries*),JNI_OnLoad 不会被调用;
//   3. JavaVM* 只能从 libart 的 .dynsym 解析 JNI_GetCreatedJavaVMs 自举;
//   4. inline hook 只能用 entries->hookFunc / unhookFunc(wxshadow 引擎),
//      不得引入 Dobby、mprotect fallback 或任何第二套 inline hook。
//
// 本文件只做 ABI 镜像与薄封装,不含任何 hook 引擎实现。
//
#ifndef ZHENXIRUNTIME_VECTOR_NATIVE_API_H
#define ZHENXIRUNTIME_VECTOR_NATIVE_API_H

#include <cstdint>
#include <jni.h>

// ---------------------------------------------------------------------------
// Vector native/include/core/native_api.h 的 ABI 镜像(当前 version = 2)
// ---------------------------------------------------------------------------
struct NativeAPIEntries {
    uint32_t version;
    /** 返回 0 且 *backup != nullptr 才算成功;语义是裸替换,replacement 签名必须与目标一致 */
    int (*hookFunc)(void *func, void *replace, void **backup);
    int (*unhookFunc)(void *func);
};

using NativeOnModuleLoaded = void (*)(const char *name, void *handle);
using NativeInit = NativeOnModuleLoaded (*)(const NativeAPIEntries *entries);

namespace VectorApi {

    /**
     * 由 native_init 调用一次,保存框架下发的 API 表
     */
    void Init(const NativeAPIEntries *entries);

    bool IsReady();

    uint32_t Version();

    /**
     * inline hook(走 wxshadow)。
     *
     * @param target  被 hook 的函数地址(内部会做 PAC strip)
     * @param replace replacement 函数地址,ABI 必须与 target 一致
     * @param backup  成功时写入可调原函数的 trampoline
     * @return 是否成功
     */
    bool Hook(void *target, void *replace, void **backup);

    /**
     * 取消 hook(目前模块内没有调用点,保留给调试用)
     */
    bool Unhook(void *target);

    /**
     * 从 libart 的 .dynsym 解析符号(APEX 模块的符号拿不到 dlsym(RTLD_DEFAULT))
     */
    uintptr_t DlsymLibart(const char *name);

    /**
     * JavaVM 自举:优先用框架下发的 vm,其次从 libart 解析 JNI_GetCreatedJavaVMs 自己拿
     */
    JavaVM *GetJavaVm();

    /**
     * 取当前线程的 JNIEnv,未 attach 则 attach
     */
    JNIEnv *GetEnv();

    /**
     * 首次 native_init 时把 JavaVM 记下来(框架会在调用 native_init 前准备好 VM)
     */
    void SetJavaVm(JavaVM *vm);

}  // namespace VectorApi

#endif  // ZHENXIRUNTIME_VECTOR_NATIVE_API_H

//
// Created by zhenxi on 2022/2/6.
//
// Two 个 ART 层 hook:
//   - art::ArtMethod::Invoke        打印所有 Java 方法调用(function id "4")
//   - art::ArtMethod::RegisterNative 打印静态注册的 native 方法与实现地址(function id "2")
//
// 注意:
//   1. hook 走 Vector 下发的 wxshadow(见 HookUtils / VectorNativeApi),不再用 Dobby;
//   2. replacement 是裸替换语义,签名必须与目标成员函数一致(第一个参数是 this);
//   3. ArtMethod::Invoke 是**极热**路径 —— 每一条 Java 方法调用都会进来。
//      实测同类日志(demo 的 RegisterNatives 高频去重)曾导致 3 次 blocking GC 并把宿主
//      bindApplication 拖到 15s,所以这里:
//        - 用 atomic 控制开关;
//        - 只有真的要输出时才调用 PrettyMethod(它本身有分配);
//   4. 文件写入统一走 TraceLog 的锁(和 Jnitrace / stringHandler 共用同一把锁)。
//
#include <atomic>

#include "../includes/invokePrintf.h"

#include "HookUtils.h"
#include "AllInclude.h"
#include "ZhenxiLog.h"
#include "logging.h"
#include "traceLog.h"
#include "dlfcn_nougat.h"
#include "dlfcn_compat.h"
#include "libpath.h"

static std::atomic<std::ofstream *> invokeOs{nullptr};
static std::atomic<bool> isSave{false};

std::string (*invokePrintf_org_PrettyMethodSym)(void *thiz, bool b) = nullptr;

static void writeInvokeLog(const std::string &msg) {
    if (msg.empty()) {
        return;
    }
    std::ofstream *os = invokeOs.load();
    if (os != nullptr && isSave.load()) {
        // TraceLog 在 ZhenxiRunTime 命名空间下,而这里是全局作用域,需要写全名
        ZhenxiRunTime::TraceLog::writeLine(os, msg);
    }
}

HOOK_DEF(void*, invoke, void *thiz, void *self, uint32_t *args, uint32_t args_size, void *result,
         const char *shorty) {

    if (invokePrintf_org_PrettyMethodSym != nullptr) {
        std::string basicString = invokePrintf_org_PrettyMethodSym(thiz, true);
        if (!basicString.empty()) {
            LOG(INFO) << "invoke method info -> " << basicString;
            writeInvokeLog(basicString.append("\n"));
        }
    }
    return orig_invoke(thiz, self, args, args_size, result, shorty);
}

__always_inline
static string getFileNameForPath(const char *path) {
    if (path == nullptr) {
        return {};
    }
    std::string pathStr = path;
    size_t pos = pathStr.rfind('/');
    if (pos != std::string::npos) {
        return pathStr.substr(pos + 1);
    }
    return pathStr;
}

void invokePrintf::HookJNIInvoke(JNIEnv *env,
                                 [[maybe_unused]] std::ofstream *os,
                                 std::string(*prettyMethodSym)(void *, bool)) {
    if (os != nullptr) {
        invokeOs.store(os);
        isSave.store(true);
    }
    if (invokePrintf_org_PrettyMethodSym == nullptr) {
        invokePrintf_org_PrettyMethodSym = prettyMethodSym;
    }
    //artmethod->invoke
    void *invokeSym = getSymCompat(getlibArtPath(),
                                  "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc");
    if (invokeSym == nullptr) {
        LOGE(">>>>>>>>> hook art method invoke fail ")
        return;
    }
    bool isSuccess = HookUtils::Hooker(invokeSym,
                                       (void *) new_invoke,
                                       (void **) &orig_invoke);
    LOGE(">>>>>>>>> hook art method invoke success ! %s ", isSuccess ? "true" : "false")
}

HOOK_DEF(void*, RegisterNative, void *thiz, void *native_method) {
    string basicString = invokePrintf_org_PrettyMethodSym != nullptr
                         ? invokePrintf_org_PrettyMethodSym(thiz, true)
                         : string();
    if (isSave.load()) {
        writeInvokeLog(basicString.append("\n"));
    }
    Dl_info info{nullptr};
    const char *libName = nullptr;
    size_t relative_offset = 0;
    if (native_method != nullptr && dladdr(native_method, &info) != 0) {
        relative_offset = reinterpret_cast<size_t>(native_method) -
                          reinterpret_cast<size_t>(info.dli_fbase);
        libName = info.dli_fname;
    }
    LOG(INFO) << "REGISTER_NATIVE " << basicString.c_str()
              << " absolute address(内存地址) -> " << native_method
              << "  relative offset(相对地址) " << (void *) relative_offset
              << " 所属ELF文件 [" << getFileNameForPath(libName) << "]";

    return orig_RegisterNative(thiz, native_method);
}

void invokePrintf::HookJNIRegisterNative(JNIEnv *env,
                                         std::ofstream *os,
                                         std::string(*prettyMethodSym)(void *, bool)) {
    if (os != nullptr) {
        invokeOs.store(os);
        isSave.store(true);
    }
    if (invokePrintf_org_PrettyMethodSym == nullptr) {
        invokePrintf_org_PrettyMethodSym = prettyMethodSym;
    }
    //artmethod->RegisterNative
    void *registerNativeSym =
            getSymCompat(getlibArtPath(),
                         "_ZN3art9ArtMethod14RegisterNativeEPKv");
    if (registerNativeSym == nullptr) {
        LOGE(">>>>>>>>> hook art method RegisterNative fail ")
        return;
    }
    bool isSuccess = HookUtils::Hooker(registerNativeSym,
                                       (void *) new_RegisterNative,
                                       (void **) &orig_RegisterNative);
    LOGE(">>>>>>>>> hook art method register native success ! %s ", isSuccess ? "true" : "false")
}

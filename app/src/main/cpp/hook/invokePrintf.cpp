//
// Created by zhenxi on 2022/2/6.
//
// Two 个 ART 层 hook:
//   - art::ArtMethod::Invoke         打印所有 Java 方法调用(function id "4")
//   - native 注册入口(见 HookJNIRegisterNative) 打印 native 方法的注册信息(function id "2")
//
// 关于 function id "2" 的一个常见误解(原注释写的是"静态注册",正好说反了):
//   它只能看到**显式注册**——Java 层调 env->RegisterNatives() 的那种;
//   看不到"静态注册"(so 里导出 Java_pkg_Class_method,靠命名约定匹配):
//   后者在 ART 里走 ClassLinker::LinkCode 里设置的 dlsym lookup stub 懒解析,
//   根本不经过 RegisterNative。
//   所以对纯静态注册的 so 这个功能没有输出,要观察它们请用 function id "0"/"3"。
//
// 另外 RegisterNative 的符号位置在 ART 里搬过家(ArtMethod -> ClassLinker),
// 改动前只认老符号,在新系统上会"符号找不到、功能静默失效"。
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
#include <sstream>

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

/**
 * 打印一次 native 方法注册。
 *
 * @param art_method    ArtMethod*(PrettyMethod 需要它拿方法签名)
 * @param native_method native 实现地址
 */
static void printRegisterNative(void *art_method, const void *native_method) {
    string basicString =
            (invokePrintf_org_PrettyMethodSym != nullptr && art_method != nullptr)
            ? invokePrintf_org_PrettyMethodSym(art_method, true)
            : string();
    Dl_info info{nullptr};
    const char *libName = nullptr;
    size_t relative_offset = 0;
    if (native_method != nullptr && dladdr(native_method, &info) != 0) {
        relative_offset = reinterpret_cast<size_t>(native_method) -
                          reinterpret_cast<size_t>(info.dli_fbase);
        libName = info.dli_fname;
    }
    //地址也必须进文件:显式注册的方法在 so 里没有静态符号,
    //错过这次输出(比如 logcat 被 hunter 那种日志洪水冲掉)就再也拿不到地址了。
    //实测:124 条 libhunter.so 注册记录里,只靠 logcat 能读到 0 条。
    if (isSave.load()) {
        std::ostringstream line;
        line << "REGISTER_NATIVE " << basicString
             << " absolute address(内存地址) -> " << native_method
             << "  relative offset(相对地址) " << (void *) relative_offset
             << " 所属ELF文件 [" << getFileNameForPath(libName) << "]\n";
        writeInvokeLog(line.str());
    }
    LOG(INFO) << "REGISTER_NATIVE " << basicString.c_str()
              << " absolute address(内存地址) -> " << native_method
              << "  relative offset(相对地址) " << (void *) relative_offset
              << " 所属ELF文件 [" << getFileNameForPath(libName) << "]";
}

/**
 * Android 5-7: art::ArtMethod::RegisterNative(const void* native_method)
 * this 是 ArtMethod*,实现地址就是第一个显式参数。
 */
HOOK_DEF(void, RegisterNativeArtMethod, void *thiz, void *native_method) {
    printRegisterNative(thiz, native_method);
    if (orig_RegisterNativeArtMethod != nullptr) {
        orig_RegisterNativeArtMethod(thiz, native_method);
    }
}

/**
 * Android 8+: art::ClassLinker::RegisterNative(Thread* self,
 *                                              ArtMethod* method,
 *                                              const void* native_method)
 * this 是 ClassLinker*,ArtMethod 和实现地址都是显式参数。
 */
HOOK_DEF(void, RegisterNativeClassLinker, void *thiz, void *self, void *method,
         void *native_method) {
    printRegisterNative(method, native_method);
    if (orig_RegisterNativeClassLinker != nullptr) {
        orig_RegisterNativeClassLinker(thiz, self, method, native_method);
    }
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
    const char *artPath = getlibArtPath();
    if (artPath == nullptr) {
        LOGE(">>>>>>>>> hook RegisterNative fail : cannot locate libart")
        return;
    }
    //RegisterNative 的符号在不同 ART 版本里位置不同,按新->旧顺序尝试:
    //  Android 8+ : art::ClassLinker::RegisterNative(Thread*, ArtMethod*, const void*)
    //  Android 5-7: art::ArtMethod::RegisterNative(const void*)
    struct Candidate {
        const char *symbol;
        void *replacement;
        void **backup;
    };
    const Candidate candidates[] = {
            {"_ZN3art11ClassLinker14RegisterNativeEPNS_6ThreadEPNS_9ArtMethodEPKv",
             reinterpret_cast<void *>(new_RegisterNativeClassLinker),
             reinterpret_cast<void **>(&orig_RegisterNativeClassLinker)},
            {"_ZN3art9ArtMethod14RegisterNativeEPKv",
             reinterpret_cast<void *>(new_RegisterNativeArtMethod),
             reinterpret_cast<void **>(&orig_RegisterNativeArtMethod)},
    };
    for (const Candidate &candidate: candidates) {
        void *registerNativeSym = getSymCompat(artPath, candidate.symbol);
        if (registerNativeSym == nullptr) {
            LOG(INFO) << "RegisterNative symbol not found, try next -> " << candidate.symbol;
            continue;
        }
        if (HookUtils::Hooker(registerNativeSym, candidate.replacement, candidate.backup)) {
            LOG(INFO) << ">>>>>>>>> hook RegisterNative success -> " << candidate.symbol;
            return;
        }
        LOGE(">>>>>>>>> hook RegisterNative failed -> %s", candidate.symbol)
    }
    LOGE(">>>>>>>>> hook RegisterNative fail : no usable symbol in libart")
}

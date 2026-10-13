//
// Vector native 模块入口。
//
// 与老版本(Xposed + Runtime.nativeLoad 注入)的区别:
//   1. 不再有 JNI_OnLoad —— Vector 的 soLoader 只跑 DT_INIT/init_array,JNI_OnLoad 不会被调用;
//   2. 唯一入口是导出的 native_init(NativeAPIEntries*),必须返回非 null 的库加载回调;
//   3. JavaVM* 通过 VectorApi(从 libart .dynsym 解析 JNI_GetCreatedJavaVMs)自举;
//   4. Java 侧声明的 native 方法没有自动绑定来源,必须在 native_init 里手动 RegisterNatives;
//   5. 模块 so 不能再用 System.loadLibrary 装载,也不需要自己解压注入。
//
#include <libgen.h>
#include <jni.h>
#include <logging.h>

#include <list>
#include <map>
#include <memory>
#include <string>
#include <fstream>

#include "adapter.h"
#include "libpath.h"
#include "parse.h"
#include "JnitraceForC.h"
#include "stringHandler.h"
#include "invokePrintf.h"
#include "linkerHandler.h"
#include "traceLog.h"
#include "vector_native_api.h"
#include "ZhenxiLog.h"
#include "dlfcn_nougat.h"

/**
 * 日志文件的生命周期由这里统一持有。
 *
 * 原来是用 new 出来的裸指针同时交给 4 个模块,它们的 stopjnitrace() 各自 delete 一次,
 * 是 double free;现在各模块只持有指针,不负责释放。
 */
static std::unique_ptr<std::ofstream> gTraceOs;

static void printList(const char *tag, const std::list<std::string> &list) {
    std::string all;
    for (const auto &item: list) {
        all.append(item).append(" ");
    }
    LOGI("startHookJni %s -> [ %s]", tag, all.c_str());
}

static bool hasFunction(const std::list<std::string> &functionList, const char *target) {
    for (const auto &item: functionList) {
        if (item == target) {
            return true;
        }
    }
    return false;
}

/**
 * java.util.List<String> -> std::list<std::string>
 *
 * 逐项做了判空与局部引用释放(原实现每项都不分别释放,长列表会顶到局部引用表上限)
 */
static std::list<std::string> jlist2clist(JNIEnv *env, jobject jList) {
    std::list<std::string> result;
    if (env == nullptr || jList == nullptr) {
        return result;
    }
    jclass listClazz = env->FindClass("java/util/ArrayList");
    if (listClazz == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return result;
    }
    jmethodID sizeMid = env->GetMethodID(listClazz, "size", "()I");
    jmethodID getMid = env->GetMethodID(listClazz, "get", "(I)Ljava/lang/Object;");
    if (sizeMid == nullptr || getMid == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(listClazz);
        return result;
    }
    jint size = env->CallIntMethod(jList, sizeMid);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(listClazz);
        return result;
    }
    for (jint i = 0; i < size; ++i) {
        auto item = env->CallObjectMethod(jList, getMid, i);
        if (item == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            continue;
        }
        const std::string str = parse::jstring2str(env, reinterpret_cast<jstring>(item));
        if (!str.empty()) {
            result.push_back(str);
        }
        env->DeleteLocalRef(item);
    }
    env->DeleteLocalRef(listClazz);
    return result;
}

/**
 * Java 层入口:LHook.startHookJni(isHookAll, filterList, functionList, savePath)
 *
 * 由 native_init 里的 RegisterNatives 绑定。
 */
extern "C" void startHookJni(JNIEnv *env,
                             [[maybe_unused]] jclass clazz,
                             jboolean isListenerAll,
                             jobject jFilterList,
                             jobject jFunctionList,
                             jstring filepath) {

    LOGI("<<<<<<<<< startHookJni start init >>>>>>>>>>");

    std::list<std::string> filterList{};
    if (jFilterList != nullptr) {
        filterList = jlist2clist(env, jFilterList);
    }
    printList("filterList", filterList);

    std::list<std::string> functionList{};
    if (jFunctionList != nullptr) {
        functionList = jlist2clist(env, jFunctionList);
    }
    printList("functionList", functionList);

    if (functionList.empty()) {
        LOGE("startHookJni function list is empty, nothing will be hooked!")
        return;
    }

    const bool listenerAll = (isListenerAll == JNI_TRUE);

    // 文件打不开时只输出 logcat,而不是直接 return ——
    // 原来的写法会让 5 个 hook 一个都不装,却是静默失败
    std::ofstream *saveOs = nullptr;
    if (filepath != nullptr) {
        const std::string path = parse::jstring2str(env, filepath);
        if (!path.empty()) {
            gTraceOs = std::make_unique<std::ofstream>();
            gTraceOs->open(path, std::ios::app);
            if (gTraceOs->is_open()) {
                saveOs = gTraceOs.get();
            } else {
                LOGE("startHookJni open save file error : %s (只输出 logcat)", path.c_str())
                gTraceOs.reset();
            }
        }
    } else {
        LOGI("startHookJni save path is null, 只输出 logcat");
    }

    // art::ArtMethod::PrettyMethod,给 RegisterNative / ArtMethod::Invoke 用
    std::string (*prettyMethodSym)(void *, bool) = nullptr;
    void *artHandle = fake_dlopen(getlibArtPath(), RTLD_NOW);
    if (artHandle != nullptr) {
        prettyMethodSym = reinterpret_cast<std::string (*)(void *, bool)>(
                fake_dlsym(artHandle, "_ZN3art9ArtMethod12PrettyMethodEb"));
    }
    if (prettyMethodSym == nullptr) {
        LOGE("startHookJni resolve PrettyMethod failed, function 2/4 不可用")
    }

    // 排除我们自己的 SO,防止自己 hook 自己造成无限递归
    const std::list<std::string> forbidList{CORE_SO_NAME};

    if (hasFunction(functionList, "0")) {
        // JNIEnv 函数表 hook
        LOGI("startHookJni -> [0] JNIEnv hook")
        Jnitrace::startjnitrace(env, listenerAll, forbidList, filterList, saveOs);
    }
    if (hasFunction(functionList, "1")) {
        // libc 字符串函数 hook(热点函数,风险见 stringHandler.cpp 文件头)
        LOGI("startHookJni -> [1] libc string hook")
        stringHandler::hookStrHandler(listenerAll, forbidList, filterList, saveOs);
    }
    if (hasFunction(functionList, "2") && prettyMethodSym != nullptr) {
        // RegisterNatives: 打印静态注册的 native 方法与实现地址
        LOGI("startHookJni -> [2] RegisterNative hook")
        invokePrintf::HookJNIRegisterNative(env, saveOs, prettyMethodSym);
    }
    if (hasFunction(functionList, "3")) {
        // linker dlopen 回调
        LOGI("startHookJni -> [3] linker hook")
        linkerHandler::linkerCallBack(saveOs);
    }
    if (hasFunction(functionList, "4") && prettyMethodSym != nullptr) {
        // art::ArtMethod::Invoke: 打印所有 Java 方法调用(极热,谨慎开启)
        LOGI("startHookJni -> [4] ArtMethod::Invoke hook")
        invokePrintf::HookJNIInvoke(env, saveOs, prettyMethodSym);
    }

    LOGI(">>>>>>>>>>>>> jni hook finish !");
}

static JNINativeMethod gMethods[] = {
        {"startHookJni", "(ZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/lang/String;)V",
         (void *) startHookJni},
};

/**
 * Vector 模块唯一入口。
 *
 * 返回值必须是**非 null** 的库加载回调,否则框架日志只会打
 * "native_init for '...' completed without library-load callback",
 * 这里返回的回调转发给 linkerHandler(function id "3" 的 so 加载监视),不需要该功能时它自己会忽略。
 */
extern "C" NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    if (entries == nullptr) {
        LOGE("native_init: entries == null");
        return nullptr;
    }

    // 1. 保存框架下发的 hook API(wxshadow),后续所有 hook 都走它
    VectorApi::Init(entries);

    // 2. JavaVM 自举(首次 native_init 时 env->GetJavaVM() 不可靠)
    JavaVM *vm = VectorApi::GetJavaVm();
    if (vm == nullptr) {
        LOGE("native_init: cannot obtain JavaVM*");
    } else {
        mVm = vm;
        VectorApi::SetJavaVm(vm);
    }

    JNIEnv *env = VectorApi::GetEnv();
    if (env == nullptr) {
        LOGE("native_init: cannot obtain JNIEnv*");
        return nullptr;
    }

    // 3. 绑定 Java 侧声明的 native 方法。
    //    soLoader 装载的 so 不在系统 dl 链里,JNI 符号不会被自动查找,必须手动 RegisterNatives。
    //    FindClass 在这里是可靠的:框架是通过载体类(org.matrix.vector.nativeload.NativeInitFire)
    //    的 native trampoline 触发 native_init 的,此时"当前方法的声明类"属于模块 ClassLoader。
    jclass mainClass = env->FindClass("com/zhenxi/jnitrace/LHook");
    if (mainClass == nullptr) {
        LOGE("native_init: FindClass LHook failed");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return nullptr;
    }
    jint regRet = env->RegisterNatives(mainClass, gMethods,
                                       sizeof(gMethods) / sizeof(gMethods[0]));
    if (regRet < 0) {
        LOGE("native_init: RegisterNatives failed ret=%d", static_cast<int>(regRet));
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    } else {
        LOGI("native_init: RegisterNatives startHookJni ok");
    }

    LOGI("native_init: FunJni native api ready (version=%u hookAllSo=%s)",
         VectorApi::Version(), (VectorApi::IsReady() ? "true" : "false"));

    // 4. 必须返回非 null 回调。
    //    框架每次 dlopen 成功(handle != null)都会调它,这是 function id "3" 的数据来源。
    //    功能未启用时内部会立即返回(见 linkerHandler::recordLoadedSo)。
    return [](const char *name, void *handle) {
        LOGD("[module-load] name='%s' handle=%p", name == nullptr ? "(null)" : name, handle);
        linkerHandler::onModuleLoaded(name, handle);
    };
}

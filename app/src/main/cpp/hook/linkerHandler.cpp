//
// Created by zhenxi on 2022/1/21.
//
// so 加载监视(function id "3")。
//
// 以前是自己解析 linker64 的 ELF 静态符号表找 __dl__Z9do_dlopenPKciPK17android_dlextinfoPKv,
// 算出地址再用 inline hook 挂上去 —— 在 Vector 上这条路走不通,而且是必然走不通:
//
//   Vector 框架自己的 InstallNativeLibraryLoadMonitor() 就是用 wxshadow 挂同一个
//   do_dlopen 的(用来给模块分发 so 加载通知),wxshadow 对同一地址二次 hook 会失败。
//   真机日志: VectorApi::Hook failed target=0x7d39b9d52c ret=-8 trampoline=0x0
//
// 而且框架那次 hook 干的正是我们要干的事 —— 它的 DoDlopenHook 先执行真实 dlopen,
// 再无条件调 NotifyNativeModuleCallbacks(name, handle),把 (name, handle) 发给
// 每个模块在 native_init 里返回的回调。
//
// 所以这里改成纯记录端:不再自己装 hook,直接吃框架送来的通知。
// 好处:
//   - 彻底不和框架抢 do_dlopen,不存在 hook 失败;
//   - 时机语义完全一致(都是 dlopen 成功之后);
//   - 省掉手写 ELF 解析(symtab/strtab/节遍历)+ 9 个符号候选的猜测,几百行变几十行。
//
#include <cstdio>
#include <fstream>
#include <string>
#include <atomic>
#include <climits>

#include "linkerHandler.h"
#include "logging.h"
#include "traceLog.h"
#include "appUtils.h"
#include "ZhenxiLog.h"

namespace ZhenxiRunTime::linkerHandler {
    static std::atomic<std::ofstream *> linkerOs{nullptr};
    static std::atomic<bool> isSave{false};

    void setOutput(std::ofstream *os) {
        if (os != nullptr) {
            linkerOs.store(os);
            isSave.store(true);
            LOG(INFO) << ">>>>>>>>> linker handler ready (由 Vector 的 so 加载通知驱动)";
        } else {
            LOG(ERROR) << ">>>>>>>>>>>>> linker handler os == null,只输出logcat  ";
        }
    }

    void clearOutput() {
        // 文件流由 main.cpp 持有,这里只放弃引用(原来这里 delete 会造成 double free)
        linkerOs.store(nullptr);
        isSave.store(false);
    }

    /**
     * 记录一次 so 加载。由 Vector 的 so 加载通知回调直接驱动。
     *
     * 注意:框架的回调是**无条件**调用的(每次 dlopen 都会进来),
     * 而本功能( id "3")可能没被启用,所以必须先判开关再干活,
     * 否则未启用时也会跟着每次 dlopen 去读 /proc/self/maps。
     *
     * @param filename dlopen 进来的 so 路径(框架传的是路径,不是 soname)
     * @param handle   dlopen 返回的 handle
     */
    void recordLoadedSo(const char *filename, void *handle) {
        if (filename == nullptr || !isSave.load()) {
            return;
        }
        auto mapInfo = getSoBaseAddress(filename);
        char addrBuf[160] = {};
        if (mapInfo.start != 0) {
            snprintf(addrBuf, sizeof(addrBuf),
                     "start-> 0x%zx  end-> 0x%zx  size -> %zu",
                     mapInfo.start, mapInfo.end, mapInfo.end - mapInfo.start);
        } else {
            //APK 内加载的 so(/path/base.apk!/lib/arm64-v8a/libx.so)在 maps 里只有
            //apk 自身的映射、不含 so 名,地址本质上取不到 —— 明确标注,
            //不要输出 0x0 那种看着像真实地址的值。
            snprintf(addrBuf, sizeof(addrBuf), "start-> (未知:zip内加载或匿名映射)");
        }
        char buffer[PATH_MAX + 256] = {};
        snprintf(buffer, sizeof(buffer), "linker load %s  %s  handle -> %p\n",
                 filename, addrBuf, handle);
        std::ofstream *os = linkerOs.load();
        if (isSave.load() && os != nullptr) {
            // 和 jnitrace / stringHandler / invokePrintf 共用同一把文件锁
            TraceLog::writeLine(os, buffer);
        }
        LOGI("%s ", buffer);
    }
}

void linkerHandler::onModuleLoaded(const char *filename, void *handle) {
    ZhenxiRunTime::linkerHandler::recordLoadedSo(filename, handle);
}

void linkerHandler::linkerCallBack(std::ofstream *os) {
    ZhenxiRunTime::linkerHandler::setOutput(os);
}

[[maybe_unused]]
void linkerHandler::stopjnitrace() {
    ZhenxiRunTime::linkerHandler::clearOutput();
}

cmake_minimum_required(VERSION 3.4.1)
enable_language(C ASM)

# 说明:这里原来会引入 Dobby 与 sandhook(signhook)两套 inline hook 引擎。
# Vector(soLoader 基线)不允许模块自带第二套 inline hook,
# 模块只能使用框架通过 native_init 下发的 NativeAPIEntries.hookFunc(wxshadow),
# 因此 Dobby / signhook 目录已从本仓库删除。

include_directories(
        ${HomePath}/nativeLib/src/main/cpp/
        ${HomePath}/nativeLib/src/main/cpp/includes/
)

add_library(
        runtimehook

        STATIC

        HookUtils.cpp
        VectorNativeApi.cpp
)

target_link_libraries(
        runtimehook
        dlfc
        ${log-lib}
)

find_library(
        log-lib
        log
)

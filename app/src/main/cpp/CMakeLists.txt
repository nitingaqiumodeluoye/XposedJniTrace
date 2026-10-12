cmake_minimum_required(VERSION 3.22.1)
project(XposedJniTrace)

enable_language(C ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# app/src/main/cpp -> HomePath 是仓库根
string(REGEX REPLACE "(.*)/app/src.*" "\\1" HomePath ${PROJECT_SOURCE_DIR})
message(STATUS ">>>>>>>> home path -> ${HomePath}")

# 排除自己,防止 hook 到自己造成无限递归
add_definitions(-DCORE_SO_NAME="libFunJni.so")

find_library(
        log-lib
        log
)

# native 基础库(adapter / dlfc / hook / libpath / raw_syscall / utils)
add_subdirectory(${HomePath}/nativeLib/src/main/cpp/ nativeLib.out)

# 反盗版(独立成 libsecure.so,由模块 App 进程自己加载)
add_subdirectory(sec)

include_directories(
        ./
        ./includes/
        ${HomePath}/nativeLib/src/main/cpp/
        ${HomePath}/nativeLib/src/main/cpp/includes/
)

aux_source_directory(hook hook_src_list)

add_library(
        FunJni

        SHARED

        main.cpp

        ${hook_src_list}
)

target_compile_features(FunJni PRIVATE cxx_std_20)

target_link_libraries(
        FunJni

        adapter
        dlfc
        runtimehook
        libpath
        utils
        raw_syscall

        ${log-lib}
)

# Android 15+ 的 16KB page size 兼容
target_link_options(FunJni PRIVATE "-Wl,-z,max-page-size=16384")

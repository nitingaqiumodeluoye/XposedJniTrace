//
// Created by Zhenxi on 2022/10/17.
//
// JNI 环境适配层。
//
// 注意:在 Vector(soLoader 基线)下 JNI_OnLoad 不会被调用,
// JavaVM* 由 native_init 自举后写入本文件(见 app/src/main/cpp/main.cpp)。
//
#include "adapter.h"
#include "vector_native_api.h"

JavaVM *mVm = nullptr;
JNIEnv *mEnv = nullptr;

static int SDK_INT = -1;

int get_sdk_level() {
    if (SDK_INT > 0) {
        return SDK_INT;
    }
    char sdk[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.sdk", sdk);
    SDK_INT = atoi(sdk);
    return SDK_INT;
}

ScopeUtfString::ScopeUtfString(jstring j_str) {
    _j_str = j_str;
    // JNIEnv 是"每线程一个"的,不能跨线程复用,所以这里取当前线程的 env 记下来,
    // 析构时用同一个 env 释放(原实现用全局 mEnv,多线程下会拿错线程的 env)
    _env = VectorApi::GetEnv();
    _c_str = (_env == nullptr) ? nullptr : _env->GetStringUTFChars(j_str, nullptr);
}

ScopeUtfString::~ScopeUtfString() {
    if (_env != nullptr && _c_str != nullptr) {
        _env->ReleaseStringUTFChars(_j_str, _c_str);
    }
}

JNIEnv *getRunTimeEnv() {
    // 原实现在这里缓存全局 mEnv,而 env 是线程相关的,缓存值跨线程使用是错的。
    // 改为每次向 VM 查询当前线程的 env。
    return VectorApi::GetEnv();
}

JNIEnv *ensureEnvCreated() {
    return VectorApi::GetEnv();
}

void DetachCurrentThread() {
    if (mVm != nullptr) {
        mVm->DetachCurrentThread();
    }
}

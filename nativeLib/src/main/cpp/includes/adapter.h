//
// Created by Zhenxi on 2022/10/17.
//
#include <sys/system_properties.h>
#include <cstdlib>
#include <jni.h>

#ifndef ZHENXIRUNTIME_ADAPTER_H
#define ZHENXIRUNTIME_ADAPTER_H

extern JavaVM *mVm;
extern JNIEnv *mEnv;

JNIEnv *getRunTimeEnv();
JNIEnv *ensureEnvCreated();
void DetachCurrentThread();

int get_sdk_level();




class ScopeUtfString {
public:
    ScopeUtfString(jstring j_str);


    const char *c_str() {
        return _c_str;
    }

    ~ScopeUtfString();

private:
    jstring _j_str;
    // 记录取字符时那个线程的 JNIEnv,析构必须用同一个(env 是线程相关的)
    JNIEnv *_env = nullptr;
    const char *_c_str = nullptr;
};


#endif //ZHENXIRUNTIME_ADAPTER_H

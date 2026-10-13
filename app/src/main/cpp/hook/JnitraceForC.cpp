

#include "JnitraceForC.h"

#include "mylibc.h"
#include "HookUtils.h"
#include "ZhenxiLog.h"
#include "traceLog.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <sstream>

namespace ZhenxiRunTime::JniTrace {

    /**
     * 匹配到的so文件名缓冲区大小
     */
    static constexpr size_t MATCH_SO_NAME_SIZE = 128;

    /**
     * 单条日志的最大长度,超过则截断,避免目标程序打印大数组时把日志撑爆
     */
    static constexpr size_t MAX_PRINT_SIZE = 1024;

    static void
    getArgsInfo(JNIEnv *env, jobject obj, jmethodID jmethodId, va_list args, bool isStatic);

    static void getJObjectInfo(JNIEnv *env, jobject obj, const string &methodname);

    static string getJObjectToString(JNIEnv *env, jobject obj);

    static void
    getJObjectInfoInternal(JNIEnv *env, jobject obj, const string &message,
                           bool isPrintClassinfo, const string &classInfo);

    static string getJObjectClassInfo(JNIEnv *env, jobject classObj);

    //__always_inline
    static bool isAppFile(const char *path) {
        if (my_strstr(path, "/data/") != nullptr) {
            return true;
        }
        return false;
    }

    //__always_inline
    static string getFileNameForPath(const char *path) {
        if (path == nullptr) {
            return {};
        }
        std::string pathStr{path};
        size_t pos = pathStr.rfind('/');
        if (pos != std::string::npos) {
            return pathStr.substr(pos + 1);
        }
        return pathStr;
    }

    //__always_inline
    static std::string getAddressHex(void *ptr) {
        if (ptr == nullptr) {
            return {};
        }
        std::stringstream stream;
        stream << "0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(ptr);
        return stream.str();
    }

#define HOOK_JNITRACE(env, func) \
    bool func##hook_success = HookUtils::Hooker(    \
      (void*)(env)->functions->func,\
      (void*)new_##func,\
      (void**)&orig_##func );    \
      if(!func##hook_success) {  \
         LOG(INFO) <<"jnitrace hook error "<<#func; \
      } \
                                 \

//#define GET_TOSTRING_METHOD(type) env->GetStaticMethodID(ArrayClazz,"toString", "("##type##")Ljava/lang/String;");

#define JNITRACE_HOOK_DEF(ret, func, ...) \
  ret (*orig_##func)(__VA_ARGS__); \
  ret new_##func(__VA_ARGS__)

#define JNI_HOOK_DEF(ret, func, ...)    \
  ret (*orig_##func)(JNIEnv *env, jobject obj, jmethodID jmethodId,...) = nullptr;  \
  ret new_##func(__VA_ARGS__) {         \
  //if(orig_##func == nullptr){LOG(INFO) <<"jnitrace hook error ,org sym == null "<<#func;}  \
  //LOG(INFO) << #func<<"("#__VA_ARGS__")" ;\

#define GET_ADDRESS \
 auto address = getAddressHex((void*)((char *) \
            __builtin_return_address(0) - ((size_t) info.dli_fbase))); \


#define GET_JOBJECT_INFO(env, obj, methodname) \
            GET_ADDRESS                                   \
            getJObjectInfo(env,obj,"("+getFileNameForPath(info.dli_fname)+")"+ methodname+"<"+address+">"+"("+getprogname()+")");\



/**
 * 打印参数。
 * args 必须传 TRACE_ARGS_SNAPSHOT 复制出来的副本,原因见 TRACE_ARGS_SNAPSHOT 的注释。
 */
#define GET_METHOD_INFO_ARGS(env, obj, methodid, args, isStatic) \
    getArgsInfo(env,obj,methodid,args,isStatic); \
    va_end(args);

/**
 * 每个hook在调用orig_xxx之前,先把va_list复制一份出来专门用于打印。
 *
 * orig_xxx(CallObjectMethodV等)内部会按方法签名把va_list消费掉
 * (见 art/runtime/reflection.cc 的 ArgArray::BuildArgArrayFromVarArgs),
 * 之后再读同一个va_list,读到的是错位的数据,属于未定义行为。
 *
 * 用副本打印还有一个好处:即使打印时类型推断出错,也只影响日志,不会破坏目标程序真正的调用。
 */
#define TRACE_ARGS_SNAPSHOT \
    va_list traceArgs; \
    va_copy(traceArgs, args);


    static bool isHookAll = false;
    static std::atomic<std::ofstream *> jnitraceOs{nullptr};
    static std::list<string> filterSoList;
    static std::list<string> forbidSoList;
    static std::atomic<bool> isSave{false};

    /**
     * 当前线程命中的so文件名。
     *
     * 用thread_local而不是全局变量:isLister()写入,write()读取,两者在同一个线程内成对出现,
     * 多线程同时调用jni时不会互相覆盖(原来是全局std::string,多线程下是数据竞争,可能读到半写入状态)。
     */
    static thread_local char match_so_name[MATCH_SO_NAME_SIZE] = {};

# define DL_INFO \
    Dl_info info={nullptr}; \
    int addr_ret_0= dladdr((void *) __builtin_return_address(0), &info); \

# define IS_MATCH \
        if(isLister(addr_ret_0,&info)){\


    static void setMatchSoName(const char *path) {
        if (path == nullptr) {
            match_so_name[0] = '\0';
            return;
        }
        const char *fileName = path;
        const char *pos = strrchr(path, '/');
        if (pos != nullptr) {
            fileName = pos + 1;
        }
        my_strlcpy(match_so_name, fileName, MATCH_SO_NAME_SIZE);
    }

    static bool isLister(int dladd_ret, Dl_info *info) {
        if (dladd_ret == 0) {
            return false;
        }
        if (info == nullptr) {
            return false;
        }
        const char *name = info->dli_fname;

        if (name == nullptr) {
            return false;
        }
        //系统apk暂不处理,只监听当前apk包下的
        if (!isAppFile(name)) {
            return false;
        }
        //如果是已经过滤的apk也暂不处理
        //比如我们注入的SO文件(否则会自己打印自己,造成无限递归)
        for (const string &forbid: forbidSoList) {
            if (my_strstr(name, forbid.c_str()) != nullptr) {
                //找到了则不进行处理
                return false;
            }
        }
        if (isHookAll) {
            setMatchSoName(name);
            return true;
        } else {
            for (const string &filter: filterSoList) {
                //默认监听一级
                if (my_strstr(name, filter.c_str()) != nullptr) {
                    setMatchSoName(name);
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * 统一日志出口。
     *
     * 文件写入必须加锁(std::ofstream多线程并发写入是未定义行为),
     * 而且stringHandler那边用的是同一把锁(见traceLog.h),否则两个模块会互相踩。
     */
    static void write(const std::string &msg) {
        if (msg.empty()) {
            return;
        }
        std::ofstream *os = jnitraceOs.load();
        if (os != nullptr && isSave.load()) {
            std::lock_guard<std::mutex> lock(TraceLog::fileMutex());
            (*os) << "[" << match_so_name << "] " << msg;
            os->flush();
        }
        LOG(INFO) << "[" << match_so_name << "] " << msg.c_str();
    }

    //jobject CallObjectMethod(JNIEnv*, jobject, jmethodID, va_list args);
    JNI_HOOK_DEF(jobject, CallObjectMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jobject ret = orig_CallObjectMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallObjectMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            getJObjectInfoInternal(env, ret, "result object :", true, "");
            return ret;
        }
        return orig_CallObjectMethodV(env, obj, jmethodId, args);
    }

    //void CallVoidMethod(jobject obj, jmethodID methodID, va_list args)
    JNI_HOOK_DEF(void, CallVoidMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            GET_JOBJECT_INFO(env, obj, "CallVoidMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)

        }
        return orig_CallVoidMethodV(env, obj, jmethodId, args);
    }

    JNI_HOOK_DEF(jboolean, CallBooleanMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)

        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jboolean ret = orig_CallBooleanMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallBooleanMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            write(string("invoke method result Boolean : ").append(
                    (ret == JNI_TRUE ? "true" : "false")).append("\n"));
            return ret;
        }
        return orig_CallBooleanMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jbyte, CallByteMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jbyte ret = orig_CallByteMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallByteMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            write(string("result Byte : ").append(to_string(ret)).append("\n"));
            return ret;
        }

        return orig_CallByteMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jchar, CallCharMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jchar ret = orig_CallCharMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallCharMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            write(string("result Char : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallCharMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jshort, CallShortMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jshort ret = orig_CallShortMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallShortMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            write(string("result Short : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallShortMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jint, CallIntMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jint ret = orig_CallIntMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallIntMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            write(string("result Int : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallIntMethodV(env, obj, jmethodId, args);

    }


    JNI_HOOK_DEF(jlong, CallLongMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jlong ret = orig_CallLongMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallLongMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            write(string("result Long : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallLongMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jfloat, CallFloatMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jfloat ret = orig_CallFloatMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallFloatMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            write(string("result Float : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallFloatMethodV(env, obj, jmethodId, args);

    }

    JNI_HOOK_DEF(jdouble, CallDoubleMethodV, JNIEnv *env, jobject obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jdouble ret = orig_CallDoubleMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallDoubleMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            write(string("result Double : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallDoubleMethodV(env, obj, jmethodId, args);
    }



    //------------------ static ------------------------------------------------------------

    JNI_HOOK_DEF(jobject, CallStaticObjectMethodV, JNIEnv *env, jclass obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jobject ret = orig_CallStaticObjectMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallStaticObjectMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)
            getJObjectInfoInternal(env, ret, "result object :", true, "");
            return ret;
        }
        return orig_CallStaticObjectMethodV(env, obj, jmethodId, args);
    }

    //void CallVoidMethod(jobject obj, jmethodID methodID, va_list args)
    JNI_HOOK_DEF(void, CallStaticVoidMethodV, JNIEnv *env, jclass obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            GET_JOBJECT_INFO(env, obj, "CallStaticVoidMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)

        }
        return orig_CallStaticVoidMethodV(env, obj, jmethodId, args);
    }

    JNI_HOOK_DEF(jboolean, CallStaticBooleanMethodV, JNIEnv *env, jclass obj,
                 jmethodID jmethodId,
                 va_list args)

        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT

            jboolean ret = orig_CallStaticBooleanMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallStaticBooleanMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)
            write(string("result Boolean : ").append(
                    (ret == JNI_TRUE ? "true" : "false")).append(
                    "\n"));
            return ret;
        }

        return orig_CallStaticBooleanMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jbyte, CallStaticByteMethodV, JNIEnv *env, jclass obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jbyte ret = orig_CallStaticByteMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallStaticByteMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)
            write(string("result Byte : ").append(to_string(ret)).append("\n"));
            return ret;
        }


        return orig_CallStaticByteMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jchar, CallStaticCharMethodV, JNIEnv *env, jclass obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jchar ret = orig_CallStaticCharMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallStaticCharMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)
            write(string("result Char : ").append(to_string(ret)).append("\n"));
            return ret;

        }
        return orig_CallStaticCharMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jshort, CallStaticShortMethodV, JNIEnv *env, jclass obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jshort ret = orig_CallStaticShortMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallStaticShortMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)
            write(string("result Short : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallStaticShortMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jint, CallStaticIntMethodV, JNIEnv *env, jclass obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jint ret = orig_CallStaticIntMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallStaticIntMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)
            write(string("result Int : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallStaticIntMethodV(env, obj, jmethodId, args);

    }


    JNI_HOOK_DEF(jlong, CallStaticLongMethodV, JNIEnv *env, jclass obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jlong ret = orig_CallStaticLongMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallStaticLongMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)
            write(string("result Long : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallStaticLongMethodV(env, obj, jmethodId, args);
    }


    JNI_HOOK_DEF(jfloat, CallStaticFloatMethodV, JNIEnv *env, jclass obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jfloat ret = orig_CallStaticFloatMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallStaticFloatMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)
            write(string("result Float : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallStaticFloatMethodV(env, obj, jmethodId, args);

    }


    JNI_HOOK_DEF(jdouble, CallStaticDoubleMethodV, JNIEnv *env, jclass obj, jmethodID jmethodId,
                 va_list args)
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            jdouble ret = orig_CallStaticDoubleMethodV(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallStaticDoubleMethodV")
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, true)
            write(string("result Double : ").append(to_string(ret)).append("\n"));
            return ret;
        }
        return orig_CallStaticDoubleMethodV(env, obj, jmethodId, args);
    }


    /**
     * jstring -> std::string,并正确释放JNI资源
     */
    static string jstringToStdString(JNIEnv *env, jstring jstr) {
        string ret{};
        if (env == nullptr || jstr == nullptr) {
            return ret;
        }
        const char *cstr = env->GetStringUTFChars(jstr, nullptr);
        if (cstr != nullptr) {
            ret.assign(cstr);
            env->ReleaseStringUTFChars(jstr, cstr);
        }
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return ret;
    }

    /**
     * 过长的内容截断,避免目标程序打印大数组/长字符串时把日志打爆
     */
    static string limitLength(const string &content) {
        if (content.size() <= MAX_PRINT_SIZE) {
            return content;
        }
        return content.substr(0, MAX_PRINT_SIZE) + "...(total len=" +
               to_string(content.size()) + ")";
    }

    /**
     * 对一个Class实例调用getName(),即取这个Class所代表的类型名。
     *
     * 原实现把GetStringUTFChars的结果Release掉之后又把该指针返回给调用者(释放后使用),
     * 而且调用者拿到之后也不再释放,既可能崩也会稳定泄漏。这里改成返回std::string。
     */
    static string getJObjectClassInfo(JNIEnv *env, jobject classObj) {
        string ret{};
        if (env == nullptr || classObj == nullptr) {
            return ret;
        }
        jclass classClazz = env->FindClass("java/lang/Class");
        if (classClazz == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            return ret;
        }
        jmethodID getNameId = env->GetMethodID(classClazz, "getName", "()Ljava/lang/String;");
        if (getNameId == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            env->DeleteLocalRef(classClazz);
            return ret;
        }
        auto nameStr = (jstring) env->CallObjectMethod(classObj, getNameId);
        env->DeleteLocalRef(classClazz);
        if (nameStr == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            return ret;
        }
        ret = jstringToStdString(env, nameStr);
        env->DeleteLocalRef(nameStr);
        return ret;
    }

    /**
     * 取一个对象所属的类名,失败返回空串
     */
    static string getObjectClassName(JNIEnv *env, jobject obj) {
        if (env == nullptr || obj == nullptr) {
            return {};
        }
        jclass clazz = env->GetObjectClass(obj);
        if (clazz == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            return {};
        }
        string name = getJObjectClassInfo(env, clazz);
        env->DeleteLocalRef(clazz);
        return name;
    }

    /**
     * 调用obj.toString()并取回UTF8内容
     */
    static string getJObjectToString(JNIEnv *env, jobject obj) {
        if (env == nullptr || obj == nullptr) {
            return "null";
        }
        jclass objectClazz = env->FindClass("java/lang/Object");
        if (objectClazz == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            return {};
        }
        jmethodID toStringId = env->GetMethodID(objectClazz, "toString", "()Ljava/lang/String;");
        if (toStringId == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            env->DeleteLocalRef(objectClazz);
            return {};
        }
        auto str = (jstring) env->CallObjectMethod(obj, toStringId);
        env->DeleteLocalRef(objectClazz);
        if (str == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            return {};
        }
        string ret = jstringToStdString(env, str);
        env->DeleteLocalRef(str);
        return ret;
    }

    /**
     * 取java数组的文本表示。
     * byte[]走 new String(bytes, "UTF-8")(顺便能看出明文),其余类型走 java.util.Arrays.toString
     */
    static string getJavaArrayString(JNIEnv *env, jobject array, const string &classInfo) {
        if (env == nullptr || array == nullptr) {
            return "null";
        }
        if (classInfo == "[B") {
            jclass stringClazz = env->FindClass("java/lang/String");
            if (stringClazz == nullptr) {
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
                return {};
            }
            jmethodID initId = env->GetMethodID(stringClazz, "<init>", "([BLjava/lang/String;)V");
            jstring charsetName = env->NewStringUTF("UTF-8");
            jstring strRet = nullptr;
            if (initId != nullptr && charsetName != nullptr) {
                strRet = (jstring) env->NewObject(stringClazz, initId, array, charsetName);
            }
            if (charsetName != nullptr) {
                env->DeleteLocalRef(charsetName);
            }
            env->DeleteLocalRef(stringClazz);
            if (strRet == nullptr) {
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
                return {};
            }
            string ret = jstringToStdString(env, strRet);
            env->DeleteLocalRef(strRet);
            return ret;
        }

        jclass arraysClazz = env->FindClass("java/util/Arrays");
        if (arraysClazz == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            return {};
        }
        const char *sign = "([Ljava/lang/Object;)Ljava/lang/String;";
        if (classInfo == "[Z") {
            sign = "([Z)Ljava/lang/String;";
        } else if (classInfo == "[C") {
            sign = "([C)Ljava/lang/String;";
        } else if (classInfo == "[S") {
            sign = "([S)Ljava/lang/String;";
        } else if (classInfo == "[I") {
            sign = "([I)Ljava/lang/String;";
        } else if (classInfo == "[J") {
            sign = "([J)Ljava/lang/String;";
        } else if (classInfo == "[F") {
            sign = "([F)Ljava/lang/String;";
        } else if (classInfo == "[D") {
            sign = "([D)Ljava/lang/String;";
        }
        jmethodID toStringId = env->GetStaticMethodID(arraysClazz, "toString", sign);
        if (toStringId == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            env->DeleteLocalRef(arraysClazz);
            return {};
        }
        auto strRet = (jstring) env->CallStaticObjectMethod(arraysClazz, toStringId, array);
        env->DeleteLocalRef(arraysClazz);
        if (strRet == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            return {};
        }
        string ret = jstringToStdString(env, strRet);
        env->DeleteLocalRef(strRet);
        return ret;
    }

    /**
     * 取一个对象的文本表示
     *
     * @param classInfo 该对象的类名,传空则内部自己查询
     */
    static string describeJObject(JNIEnv *env, jobject obj, const string &classInfo) {
        if (obj == nullptr) {
            return "null";
        }
        string info = classInfo;
        if (info.empty()) {
            info = getObjectClassName(env, obj);
        }
        if (!info.empty() && info[0] == '[') {
            return limitLength(getJavaArrayString(env, obj, info));
        }
        return limitLength(getJObjectToString(env, obj));
    }

    /**
     * 打印一个obj的信息(类名 + toString)
     *
     * @param message 日志前缀
     * @param isPrintClassinfo 是否输出类名
     * @param classInfo 已知的类名,传空则内部自己查
     */
    static void getJObjectInfoInternal(JNIEnv *env, jobject obj, const string &message,
                                       bool isPrintClassinfo, const string &classInfo) {
        if (env == nullptr || obj == nullptr) {
            return;
        }
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            return;
        }
        //原实现把临时std::string的c_str()存了下来,出作用域后就是悬垂指针,这里按值传递
        string info = classInfo.empty() ? getObjectClassName(env, obj) : classInfo;
        string text = describeJObject(env, obj, info);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        if (text.empty()) {
            text = "<toString failed>";
        }
        if (isPrintClassinfo && !info.empty()) {
            write(message + "  [" + info + "]  " + text + "\n");
        } else {
            write(message + "  " + text + "\n");
        }
    }

    static void getJObjectInfo(JNIEnv *env, jobject obj, const string &methodname) {
        if (env == nullptr || obj == nullptr) {
            return;
        }
        if (env->ExceptionCheck()) {
            //exception return
            return;
        }
        write("<<<<<------------------" + methodname + " --------------------->>>>>");
        getJObjectInfoInternal(env, obj, "invoke this object", true, "");
    }

    /**
     * 把参数值格式化成字符串。
     *
     * 基础类型直接格式化(不往Java层绕一圈,既快又不会因为打印自己的调用再触发hook),
     * 引用类型才调toString。
     */
    static string formatArgValue(JNIEnv *env, const string &typeName, const jvalue &value) {
        if (typeName == "boolean") {
            return value.z == JNI_TRUE ? "true" : "false";
        }
        if (typeName == "byte") {
            return to_string(static_cast<int>(value.b));
        }
        if (typeName == "char") {
            char buf[64] = {};
            auto c = static_cast<unsigned int>(value.c);
            if (c >= 0x20 && c < 0x7F) {
                snprintf(buf, sizeof(buf), "'%c' (U+%04X)", static_cast<char>(c), c);
            } else {
                snprintf(buf, sizeof(buf), "(U+%04X)", c);
            }
            return buf;
        }
        if (typeName == "short") {
            return to_string(static_cast<int>(value.s));
        }
        if (typeName == "int") {
            return to_string(value.i);
        }
        if (typeName == "long") {
            return to_string(value.j);
        }
        if (typeName == "float") {
            ostringstream stream;
            stream << value.f;
            return stream.str();
        }
        if (typeName == "double") {
            ostringstream stream;
            stream << value.d;
            return stream.str();
        }
        //剩下的都是引用类型(数组/对象/包装类)
        if (value.l == nullptr) {
            return "null";
        }
        return describeJObject(env, value.l, typeName);
    }

    /**
     * 按Java参数类型从va_list里取值。
     *
     * args 必须传引用:AArch64 的 va_list 是32字节结构体(struct __va_list),
     * 按值传参会在每个调用点把描述符重新复制一份(编译后就是 ldp q0,q1,[原];
     * stp q0,q1,[sp]; bl ...),被调函数里的 va_arg 推进只写回那份副本,
     * 于是"每读一个参数都从第一个槽位重新开始"——所有参数全部重复成第一个值,
     * 引用类型还会把整数当 jobject 交给 ART 解引用,直接 SIGSEGV。
     * 这是实测过的:同一个va_list连续读4个参数,按值传时4次全返回slot0。
     *
     * 取值规则必须和ART的行为完全一致,见 art/runtime/reflection.cc 的
     * ArgArray::BuildArgArrayFromVarArgs:
     *   'Z'/'B'/'C'/'S'/'I' -> va_arg(jint)
     *   'F'                 -> va_arg(jdouble)   注意:C可变参数的默认实参提升会把float提升成double
     *   'D'                 -> va_arg(jdouble)
     *   'J'                 -> va_arg(jlong)
     *   'L'/'['             -> va_arg(jobject)
     *
     * 原来是不管什么类型都 va_arg(jobject):arm32上long/double会读错位,
     * float参数会被当成double/指针,打印出来的全是垃圾甚至崩溃。
     */
    static void fetchArgValue(va_list &args, const string &typeName, jvalue &value) {
        if (typeName == "boolean") {
            value.z = (va_arg(args, jint) != 0) ? JNI_TRUE : JNI_FALSE;
        } else if (typeName == "byte") {
            value.b = (jbyte) va_arg(args, jint);
        } else if (typeName == "char") {
            value.c = (jchar) va_arg(args, jint);
        } else if (typeName == "short") {
            value.s = (jshort) va_arg(args, jint);
        } else if (typeName == "int") {
            value.i = va_arg(args, jint);
        } else if (typeName == "long") {
            value.j = va_arg(args, jlong);
        } else if (typeName == "float") {
            value.f = (jfloat) va_arg(args, jdouble);
        } else if (typeName == "double") {
            value.d = va_arg(args, jdouble);
        } else {
            //引用类型(也包括类型名查询失败的情况)
            value.l = va_arg(args, jobject);
        }
    }

    static void printArgValue(JNIEnv *env, const string &typeName, const jvalue &value,
                              const string &message) {
        string text = formatArgValue(env, typeName, value);
        if (text.empty()) {
            text = "<unknown>";
        }
        if (typeName.empty()) {
            write(message + "  " + text + "\n");
        } else {
            write(message + "  [" + typeName + "]  " + text + "\n");
        }
    }

    /**
     * 打印被调用的方法信息和全部参数
     *
     * @param args 必须是va_copy出来的副本,因为orig_xxx会把原始的va_list消费掉
     */
    static void getArgsInfo(JNIEnv *env, jobject obj, jmethodID jmethodId, va_list args,
                            bool isStatic) {
        if (env == nullptr || obj == nullptr || jmethodId == nullptr) {
            return;
        }
        if (env->ExceptionCheck()) {
            //有未处理异常时不打印,避免破坏目标程序的状态
            return;
        }
        //静态方法传进来的obj本身就是jclass,非静态的是实例对象
        jclass declaringClass = nullptr;
        if (isStatic) {
            declaringClass = reinterpret_cast<jclass>(obj);
        } else {
            declaringClass = env->GetObjectClass(obj);
            if (declaringClass == nullptr) {
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
                return;
            }
        }

        jobject invokeMethod = env->ToReflectedMethod(declaringClass, jmethodId,
                                                     isStatic ? JNI_TRUE : JNI_FALSE);
        if (!isStatic) {
            //非静态时declaringClass是我们自己申请的局部引用,需要释放;
            //静态时它是调用者传进来的,不能在这里释放
            env->DeleteLocalRef(declaringClass);
        }
        if (invokeMethod == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            return;
        }
        //打印被调用的方法本身(Method.toString能拿到完整的方法签名)
        getJObjectInfoInternal(env, invokeMethod, "invoke method", false, "");

        jclass methodClazz = env->GetObjectClass(invokeMethod);
        if (methodClazz == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            env->DeleteLocalRef(invokeMethod);
            return;
        }
        jmethodID countId = env->GetMethodID(methodClazz, "getParameterCount", "()I");
        jmethodID typesId = env->GetMethodID(methodClazz, "getParameterTypes",
                                             "()[Ljava/lang/Class;");
        if (countId == nullptr || typesId == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            env->DeleteLocalRef(methodClazz);
            env->DeleteLocalRef(invokeMethod);
            return;
        }
        jint paramCount = env->CallIntMethod(invokeMethod, countId);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        if (paramCount <= 0) {
            env->DeleteLocalRef(methodClazz);
            env->DeleteLocalRef(invokeMethod);
            return;
        }
        auto types = (jobjectArray) env->CallObjectMethod(invokeMethod, typesId);
        env->DeleteLocalRef(methodClazz);
        env->DeleteLocalRef(invokeMethod);
        if (types == nullptr) {
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            return;
        }
        //走查用的副本:必须自己用局部对象,且以引用方式往下传,
        //否则每个参数都会从这个副本的起点重新开始读(见 fetchArgValue 注释)
        va_list walk;
        va_copy(walk, args);
        for (jint i = 0; i < paramCount; i++) {
            auto typeClassObj = env->GetObjectArrayElement(types, i);
            if (typeClassObj == nullptr) {
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
                continue;
            }
            string typeName = getJObjectClassInfo(env, typeClassObj);
            env->DeleteLocalRef(typeClassObj);
            jvalue value{};
            fetchArgValue(walk, typeName, value);
            char indexBuf[48] = {};
            snprintf(indexBuf, sizeof(indexBuf), "args index [%d] ", static_cast<int>(i));
            printArgValue(env, typeName, value, indexBuf);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
        }
        env->DeleteLocalRef(types);
        va_end(walk);
    }
    //jstring NewStringUTF(const char* bytes)
    JNITRACE_HOOK_DEF(jstring, NewStringUTF, JNIEnv *env, const char *bytes) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            write(string("<" + address + ">NewStringUTF : ").append(
                    bytes == nullptr ? "" : bytes).append("\n"));
            return orig_NewStringUTF(env, bytes);

        }
        return orig_NewStringUTF(env, bytes);
    }

    //const char* GetStringUTFChars(jstring string, jboolean* isCopy)
    JNITRACE_HOOK_DEF(const char*, GetStringUTFChars, JNIEnv *env, jstring argstring,
                      [[maybe_unused]] jboolean * isCopy) {
        DL_INFO
        IS_MATCH
            if (argstring == nullptr) {
                return nullptr;
            }
            const char *chars = orig_GetStringUTFChars(env, argstring, isCopy);
            if (chars == nullptr || strlen(chars) == 0) {
                return chars;
            }
            GET_ADDRESS
            write(string("<" + address + ">GetStringUTFChars : ").append(chars).append("\n"));
            return chars;

        }
        return orig_GetStringUTFChars(env, argstring, isCopy);
    }

    //jclass FindClass(const char* name)
    JNITRACE_HOOK_DEF(jclass, FindClass, JNIEnv *env, const char *name) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            write(string("<" + address + ">find class : ").append(
                    name == nullptr ? "" : name).append("\n"));
            return orig_FindClass(env, name);

        }
        return orig_FindClass(env, name);
    }



    //jobject     (*NewObjectV)(JNIEnv*, jclass, jmethodID, va_list);
    JNITRACE_HOOK_DEF(jobject, NewObjectV, JNIEnv *env, jclass clazz, jmethodID jmethodId,
                      va_list args) {
        DL_INFO
        IS_MATCH
            TRACE_ARGS_SNAPSHOT
            //当method id 错误时候可能null
            jobject obj = orig_NewObjectV(env, clazz, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "NewObjectV")
            //打印构造方法参数信息
            GET_METHOD_INFO_ARGS(env, obj, jmethodId, traceArgs, false)
            return obj;

        }
        return orig_NewObjectV(env, clazz, jmethodId, args);
    }

    //void SetByteArrayRegion(jbyteArray array, jsize start, jsize len,const jbyte* buf)
    JNITRACE_HOOK_DEF(void, SetByteArrayRegion, JNIEnv *env,
                      jbyteArray array, jsize start, jsize len,
                      const jbyte *buf) {
        DL_INFO
        IS_MATCH
            orig_SetByteArrayRegion(env, array, start, len, buf);
            GET_ADDRESS
            getJObjectInfoInternal(env, array,
                                   "<" + address + ">SetByteArrayRegion java array, start->" +
                                   to_string(start) + " len -> " +
                                   to_string(len), false, "");
            return;
        }
        orig_SetByteArrayRegion(env, array, start, len, buf);
    }

    JNITRACE_HOOK_DEF(void, GetByteArrayRegion, JNIEnv *env,
                      jbyteArray array, jsize start, jsize len,
                      jbyte *buf) {
        DL_INFO
        IS_MATCH
            orig_GetByteArrayRegion(env, array, start, len, buf);
            GET_ADDRESS
            getJObjectInfoInternal(env, array,
                                   "<" + address + ">GetByteArrayRegion java array, start->" +
                                   to_string(start) + " len -> " +
                                   to_string(len), false, "");
            return;
        }
        orig_GetByteArrayRegion(env, array, start, len, buf);
    }
    //void  (*GetStringRegion)(JNIEnv*, jstring, jsize, jsize, jchar*);
    JNITRACE_HOOK_DEF(void, GetStringRegion,
                      JNIEnv *env, jstring str, jsize start, jsize len, jchar *buf) {
        DL_INFO
        IS_MATCH
            orig_GetStringRegion(env, str, start, len, buf);
            GET_ADDRESS
            getJObjectInfoInternal(env, str,
                                   "<" + address + ">GetStringRegion java str, start->" +
                                   to_string(start) + " len -> " +
                                   to_string(len), false, "");
            return;
        }
        orig_GetStringRegion(env, str, start, len, buf);
    }

    JNITRACE_HOOK_DEF(void, GetStringUTFRegion,
                      JNIEnv *env, jstring str, jsize start, jsize len, char *buf) {
        DL_INFO
        IS_MATCH
            orig_GetStringUTFRegion(env, str, start, len, buf);
            GET_ADDRESS
            getJObjectInfoInternal(env, str,
                                   "<" + address + ">GetStringUTFRegion java str, start->" +
                                   to_string(start) + " len -> " +
                                   to_string(len), false, "");
            return;
        }
        orig_GetStringUTFRegion(env, str, start, len, buf);
    }

    //jobject     (*ToReflectedMethod)(JNIEnv*, jclass, jmethodID, jboolean);
    JNITRACE_HOOK_DEF(jobject, ToReflectedMethod, JNIEnv *env, jclass clazz,
                      jmethodID jmethodId,
                      jboolean isStatic) {
        DL_INFO
        IS_MATCH
            jobject obj = orig_ToReflectedMethod(env, clazz, jmethodId, isStatic);
            if (obj != nullptr) {
                GET_ADDRESS
                getJObjectInfoInternal(env, obj, "<" + address + ">ToReflectedMethod result ",
                                       false, "");
            }
            return obj;

        }
        return orig_ToReflectedMethod(env, clazz, jmethodId, isStatic);
    }

    //jmethodID FromReflectedMethod(jobject method)
    JNITRACE_HOOK_DEF(jobject, FromReflectedMethod, JNIEnv *env, jobject method) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            getJObjectInfoInternal(env, method, "<" + address + ">FromReflectedMethod arg ", false, "");
            return orig_FromReflectedMethod(env, method);

        }
        return orig_FromReflectedMethod(env, method);
    }


    //jfieldID  (*GetFieldID)(JNIEnv*, jclass, const char*, const char*);
    JNITRACE_HOOK_DEF(jfieldID, GetFieldID, JNIEnv *env, jclass clazz, const char *name,
                      const char *sig) {
        DL_INFO
        IS_MATCH
            //clazz的toString(即clazz.toString(),能拿到class java.xxx.Yyy这样的完整类名)
            string classInfo = getJObjectToString(env, clazz);
            GET_ADDRESS
            write(string("<" + address + ">get field info  : ").append(classInfo)
                          .append(" name-> ").append(name == nullptr ? "" : name)
                          .append(" sign -> ").append(sig == nullptr ? "" : sig).append("\n"));
            return orig_GetFieldID(env, clazz, name, sig);

        }
        return orig_GetFieldID(env, clazz, name, sig);
    }

    //jfieldID    (*GetStaticFieldID)(JNIEnv*, jclass, const char*,const char*);
    JNITRACE_HOOK_DEF(jfieldID, GetStaticFieldID, JNIEnv *env, jclass clazz, const char *name,
                      const char *sig) {
        DL_INFO
        IS_MATCH
            string classInfo = getJObjectToString(env, clazz);
            GET_ADDRESS
            write(string("<" + address + ">get static field info  : ").append(classInfo)
                          .append(" name-> ").append(name == nullptr ? "" : name)
                          .append(" sign -> ").append(sig == nullptr ? "" : sig).append("\n"));
            return orig_GetStaticFieldID(env, clazz, name, sig);

        }
        return orig_GetStaticFieldID(env, clazz, name, sig);
    }

    //--------------------------getField----------------------------
    //jobject     (*GetObjectField)(JNIEnv*, jobject, jfieldID);
    JNITRACE_HOOK_DEF(jobject, GetObjectField, JNIEnv *env, [[maybe_unused]] jobject argObj,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            //GET_JOBJECT_INFO(env, argObj,"GetObjectField")
            jobject ret = orig_GetObjectField(env, argObj, jfieldId);
            if (ret != nullptr) {
                GET_ADDRESS
                getJObjectInfoInternal(env, ret, "<" + address + ">GetObjectField result object :",
                                       true, "");
            }
            return ret;
        }
        return orig_GetObjectField(env, argObj, jfieldId);
    }

    //jboolean    (*GetBooleanField)(JNIEnv*, jobject, jfieldID);
    JNITRACE_HOOK_DEF(jboolean, GetBooleanField, JNIEnv *env, [[maybe_unused]] jobject argObj,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            //GET_JOBJECT_INFO(env, argObj,"GetBooleanField")
            jboolean ret = orig_GetBooleanField(env, argObj, jfieldId);
            //LOG(INFO) << "GetBooleanField result jboolean : " << (ret == JNI_TRUE?"true":"false");
            //os << "GetBooleanField result jboolean :  " << (ret == JNI_TRUE?"true":"false") << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetBooleanField result jboolean : ").append(
                    (ret == JNI_TRUE ? "true" : "false")).append("\n"));
            return ret;
        }
        return orig_GetBooleanField(env, argObj, jfieldId);
    }
    //jbyte       (*GetByteField)(JNIEnv*, jobject, jfieldID);
    JNITRACE_HOOK_DEF(jbyte, GetByteField, JNIEnv *env, [[maybe_unused]] jobject argObj,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            //GET_JOBJECT_INFO(env, argObj,"GetByteField")
            jbyte ret = orig_GetByteField(env, argObj, jfieldId);
            //LOG(INFO) << "GetByteField result jbyte : " << ret;
            //            os << "GetByteField result jbyte :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetByteField result jbyte : ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetByteField(env, argObj, jfieldId);
    }
    //jchar       (*GetCharField)(JNIEnv*, jobject, jfieldID);
    JNITRACE_HOOK_DEF(jchar, GetCharField, JNIEnv *env, [[maybe_unused]] jobject argObj,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            //GET_JOBJECT_INFO(env, argObj,"GetCharField")
            jchar ret = orig_GetCharField(env, argObj, jfieldId);
            //LOG(INFO) << "GetCharField result jbyte : " << ret;
            //os << "GetCharField result jbyte :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetCharField result jbyte : ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetCharField(env, argObj, jfieldId);
    }
    //jshort      (*GetShortField)(JNIEnv*, jobject, jfieldID);
    JNITRACE_HOOK_DEF(jshort, GetShortField, JNIEnv *env, [[maybe_unused]] jobject argObj,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            //GET_JOBJECT_INFO(env, argObj,"GetShortField")
            jshort ret = orig_GetShortField(env, argObj, jfieldId);
            //LOG(INFO) << "GetShortField result jshort : " << ret;
            //os << "GetShortField result jshort :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetShortField result jshort : ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetShortField(env, argObj, jfieldId);
    }
    //jint        (*GetIntField)(JNIEnv*, jobject, jfieldID);
    JNITRACE_HOOK_DEF(jint, GetIntField, JNIEnv *env, [[maybe_unused]] jobject argObj,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            //GET_JOBJECT_INFO(env, argObj,"GetIntField")
            jint ret = orig_GetIntField(env, argObj, jfieldId);
            //LOG(INFO) << "GetIntField result jint : " << ret;
            //os << "GetIntField result jint :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetIntField result jint : ").append(
                    to_string(ret)).append("\n"));
            return ret;
        }
        return orig_GetIntField(env, argObj, jfieldId);
    }
    //jlong       (*GetLongField)(JNIEnv*, jobject, jfieldID);
    JNITRACE_HOOK_DEF(jlong, GetLongField, JNIEnv *env, [[maybe_unused]] jobject argObj,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            //GET_JOBJECT_INFO(env, argObj,"GetLongField")
            jlong ret = orig_GetLongField(env, argObj, jfieldId);
            //LOG(INFO) << "GetLongField result jlong : " << ret;
            //os << "GetLongField result jlong :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetLongField result jlong : ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetLongField(env, argObj, jfieldId);
    }
    //jfloat      (*GetFloatField)(JNIEnv*, jobject, jfieldID);
    JNITRACE_HOOK_DEF(jfloat, GetFloatField, JNIEnv *env, [[maybe_unused]] jobject argObj,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            //GET_JOBJECT_INFO(env, argObj,"GetFloatField")
            jfloat ret = orig_GetFloatField(env, argObj, jfieldId);
            //LOG(INFO) << "GetFloatField result jfloat : " << ret;
            //os << "GetFloatField result jfloat :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetFloatField result jfloat : ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetFloatField(env, argObj, jfieldId);
    }
    //jdouble     (*GetDoubleField)(JNIEnv*, jobject, jfieldID);
    JNITRACE_HOOK_DEF(jdouble, GetDoubleField, JNIEnv *env, [[maybe_unused]] jobject argObj,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            //GET_JOBJECT_INFO(env, argObj,"GetDoubleField")
            jdouble ret = orig_GetDoubleField(env, argObj, jfieldId);
            //LOG(INFO) << "GetDoubleField result jdouble : " << ret;
            //os << "GetDoubleField result jdouble :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetDoubleField result jdouble : ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetDoubleField(env, argObj, jfieldId);
    }
    //--------------------------getStaticField----------------------------
    //jobject     (*GetStaticObjectField)(JNIEnv*, jclass, jfieldID);
    JNITRACE_HOOK_DEF(jobject, GetStaticObjectField, JNIEnv *env, jclass clazz,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            jobject ret = orig_GetStaticObjectField(env, clazz, jfieldId);
            if (ret != nullptr) {
                GET_ADDRESS
                getJObjectInfoInternal(env, ret,
                                       "<" + address + ">GetStaticObjectField result object :",
                                       true, "");
            }
            return ret;
        }
        return orig_GetStaticObjectField(env, clazz, jfieldId);
    }

    //jboolean    (*GetStaticBooleanField)(JNIEnv*, jclass, jfieldID);
    JNITRACE_HOOK_DEF(jboolean, GetStaticBooleanField, JNIEnv *env, jclass clazz,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            jboolean ret = orig_GetStaticBooleanField(env, clazz, jfieldId);
            //LOG(INFO) << "GetStaticBooleanField result jboolean : " << (ret == JNI_TRUE?"true":"false");
            //os << "GetStaticBooleanField result jboolean :  " << (ret == JNI_TRUE?"true":"false") << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetStaticBooleanField result jboolean : ").append(
                    (ret == JNI_TRUE ? "true" : "false")).append("\n"));
            return ret;
        }
        return orig_GetStaticBooleanField(env, clazz, jfieldId);
    }
    //jbyte       (*GetStaticByteField)(JNIEnv*, jclass, jfieldID);
    JNITRACE_HOOK_DEF(jbyte, GetStaticByteField, JNIEnv *env, jclass clazz,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            jbyte ret = orig_GetStaticByteField(env, clazz, jfieldId);
            //LOG(INFO) << "GetStaticByteField result jbyte : " << ret;
            //            os << "GetStaticByteField result jbyte :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetStaticByteField result jbyte : ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetStaticByteField(env, clazz, jfieldId);
    }
    //jchar       (*GetStaticCharField)(JNIEnv*, jclass, jfieldID);
    JNITRACE_HOOK_DEF(jchar, GetStaticCharField, JNIEnv *env, jclass clazz,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            jchar ret = orig_GetStaticCharField(env, clazz, jfieldId);
            //LOG(INFO) << "GetStaticCharField result jchar : " << ret;
            //os << "GetStaticCharField result jchar :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetStaticCharField result jchar : ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetStaticCharField(env, clazz, jfieldId);
    }
    //jshort      (*GetStaticShortField)(JNIEnv*, jclass, jfieldID);
    JNITRACE_HOOK_DEF(jshort, GetStaticShortField, JNIEnv *env, jclass clazz,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            jshort ret = orig_GetStaticShortField(env, clazz, jfieldId);
            //LOG(INFO) << "GetStaticShortField result jshort : " << ret;
            //os << "GetStaticShortField result jshort :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetStaticShortField result jshort : ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetStaticShortField(env, clazz, jfieldId);
    }
    //jint        (*GetStaticIntField)(JNIEnv*, jclass, jfieldID);
    JNITRACE_HOOK_DEF(jint, GetStaticIntField, JNIEnv *env, jclass clazz,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            jint ret = orig_GetStaticIntField(env, clazz, jfieldId);
            //LOG(INFO) << "GetStaticIntField result jint : " << ret;
            //            os << "GetStaticIntField result jint :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetStaticIntField result jint :  ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetStaticIntField(env, clazz, jfieldId);
    }
    //jlong       (*GetStaticLongField)(JNIEnv*, jclass, jfieldID);
    JNITRACE_HOOK_DEF(jlong, GetStaticLongField, JNIEnv *env, jclass clazz,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            jlong ret = orig_GetStaticLongField(env, clazz, jfieldId);
            //LOG(INFO) << "GetStaticLongField result jlong : " << ret;
            //os << "GetStaticLongField result jlong :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetStaticLongField result jlong :  ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetStaticLongField(env, clazz, jfieldId);
    }
    //jfloat      (*GetStaticFloatField)(JNIEnv*, jclass, jfieldID);
    JNITRACE_HOOK_DEF(jfloat, GetStaticFloatField, JNIEnv *env, jclass clazz,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            jfloat ret = orig_GetStaticFloatField(env, clazz, jfieldId);
            //LOG(INFO) << "GetStaticFloatField result jfloat : " << ret;
            //os << "GetStaticFloatField result jfloat :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetStaticFloatField result jfloat :  ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetStaticFloatField(env, clazz, jfieldId);
    }
    //jdouble     (*GetStaticDoubleField)(JNIEnv*, jclass, jfieldID);
    JNITRACE_HOOK_DEF(jdouble, GetStaticDoubleField, JNIEnv *env, jclass clazz,
                      [[maybe_unused]] jfieldID jfieldId) {
        DL_INFO
        IS_MATCH
            jdouble ret = orig_GetStaticDoubleField(env, clazz, jfieldId);
            //LOG(INFO) << "GetStaticDoubleField result jdouble : " << ret;
            //os << "GetStaticDoubleField result jdouble :  " << ret << "\n";;
            GET_ADDRESS
            write(string("<" + address + ">GetStaticDoubleField result jdouble :  ").append(
                    to_string(ret)).append(
                    "\n"));
            return ret;
        }
        return orig_GetStaticDoubleField(env, clazz, jfieldId);
    }
    //jclass DefineClass(const char *name, jobject loader, const jbyte* buf,jsize bufLen)
    JNITRACE_HOOK_DEF(jclass, DefineClass, JNIEnv *env, const char *name, jobject loader,
                      const jbyte *buf, jsize bufLen) {
        DL_INFO
        IS_MATCH
            auto ret = orig_DefineClass(env, name, loader, buf, bufLen);
            if (ret != nullptr) {
                //LOG(INFO) << "GetStaticDoubleField result jdouble : " << ret;
                //os << "GetStaticDoubleField result jdouble :  " << ret << "\n";;
                GET_ADDRESS
                write(string("<" + address + ">DefineClass   ").append(name).append("\n"));
            }
            return ret;
        }
        return orig_DefineClass(env, name, loader, buf, bufLen);
    }
}

using namespace ZhenxiRunTime::JniTrace;

void Jnitrace::init(JNIEnv *env) {

    HOOK_JNITRACE(env, CallObjectMethodV)
    HOOK_JNITRACE(env, CallBooleanMethodV)
    HOOK_JNITRACE(env, CallByteMethodV)
    HOOK_JNITRACE(env, CallCharMethodV)
    HOOK_JNITRACE(env, CallShortMethodV)
    HOOK_JNITRACE(env, CallIntMethodV)
    HOOK_JNITRACE(env, CallLongMethodV)
    HOOK_JNITRACE(env, CallFloatMethodV)
    HOOK_JNITRACE(env, CallDoubleMethodV)
    HOOK_JNITRACE(env, CallVoidMethodV)

    HOOK_JNITRACE(env, CallStaticObjectMethodV)
    HOOK_JNITRACE(env, CallStaticBooleanMethodV)
    HOOK_JNITRACE(env, CallStaticByteMethodV)
    HOOK_JNITRACE(env, CallStaticCharMethodV)
    HOOK_JNITRACE(env, CallStaticShortMethodV)
    HOOK_JNITRACE(env, CallStaticIntMethodV)
    HOOK_JNITRACE(env, CallStaticLongMethodV)
    HOOK_JNITRACE(env, CallStaticFloatMethodV)
    HOOK_JNITRACE(env, CallStaticDoubleMethodV)
    HOOK_JNITRACE(env, CallStaticVoidMethodV)


    HOOK_JNITRACE(env, GetObjectField)
    HOOK_JNITRACE(env, GetBooleanField)
    HOOK_JNITRACE(env, GetByteField)
    HOOK_JNITRACE(env, GetCharField)
    HOOK_JNITRACE(env, GetShortField)
    HOOK_JNITRACE(env, GetIntField)
    HOOK_JNITRACE(env, GetLongField)
    HOOK_JNITRACE(env, GetFloatField)
    HOOK_JNITRACE(env, GetDoubleField)

    HOOK_JNITRACE(env, GetStaticObjectField)
    HOOK_JNITRACE(env, GetStaticBooleanField)
    HOOK_JNITRACE(env, GetStaticByteField)
    HOOK_JNITRACE(env, GetStaticCharField)
    HOOK_JNITRACE(env, GetStaticShortField)
    HOOK_JNITRACE(env, GetStaticIntField)
    HOOK_JNITRACE(env, GetStaticLongField)
    HOOK_JNITRACE(env, GetStaticFloatField)
    HOOK_JNITRACE(env, GetStaticDoubleField)

    //常用的字符串操作函数
    HOOK_JNITRACE(env, NewStringUTF)
    HOOK_JNITRACE(env, GetStringUTFChars)

    HOOK_JNITRACE(env, FindClass)
    HOOK_JNITRACE(env, DefineClass)
    HOOK_JNITRACE(env, ToReflectedMethod)
    HOOK_JNITRACE(env, FromReflectedMethod)


    HOOK_JNITRACE(env, GetFieldID)
    HOOK_JNITRACE(env, GetStaticFieldID)

    HOOK_JNITRACE(env, NewObjectV)

    //将C数组中的数据复制到Java字节数组
    HOOK_JNITRACE(env, SetByteArrayRegion)
    HOOK_JNITRACE(env, GetByteArrayRegion)

    //从Java字符串中获取指定范围的字符
    HOOK_JNITRACE(env, GetStringRegion)
    HOOK_JNITRACE(env, GetStringUTFRegion)


    LOG(INFO) << ">>>>>>>>> Jnitrace hook success! ";
}


void Jnitrace::startjnitrace(JNIEnv *env,
                             bool hookAll,
                             const std::list<string> &forbid_list,
                             const std::list<string> &filter_list,
                             std::ofstream *os) {
    isHookAll = hookAll;
    LOGE("start jni trace is hook all %s", isHookAll ? "true" : "false");
    for (const std::string &str: forbid_list) {
        LOGE("start jni trace forbid_list %s", str.c_str())
    }

    //copy orig list
    forbidSoList = std::list<string>(forbid_list);
    filterSoList = std::list<string>(filter_list);
    if (os != nullptr) {
        jnitraceOs.store(os);
        isSave.store(true);
    }
    init(env);
}

[[maybe_unused]] void Jnitrace::stopjnitrace() {
    filterSoList.clear();
    //文件流由调用方(main.cpp)持有,这里只放弃引用。
    //原来在这里delete,stringHandler::stopjnitrace()又会delete同一个对象,是double free
    jnitraceOs.store(nullptr);
    isSave.store(false);
}





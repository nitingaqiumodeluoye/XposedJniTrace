

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
#include <unordered_map>
#include <vector>

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

    /**
     * A 变体(Call*MethodA / NewObjectA)的参数打印。
     * 必须在这里先声明: A 变体 hook 写在文件前部, 而它的实现依赖一堆后置的辅助函数
     * (mid 缓存 / 签名解析 / printArgValue), 放到后面定义就只能前置声明。
     */
    static void
getArgsInfoFromArray(JNIEnv *env, jobject obj, jmethodID jmethodId, const jvalue *args,
                      bool isStatic);

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
 * A 变体(Call*MethodA / NewObjectA)的参数打印。
 * 参数是 const jvalue*, 不需要 va_end。
 */
#define GET_METHOD_INFO_ARGS_A(env, obj, methodid, args, isStatic) \
    getArgsInfoFromArray(env,obj,methodid,args,isStatic);

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

    /**
     * 打印路径重入抑制计数(线程内)。
     *
     * 取一个对象的字符串表示需要调用 JNI(GetObjectClass / CallObjectMethod / GetMethodID...),
     * 而这些函数本身也被 hook 了 —— 一旦它们又把控制权交回打印路径就是无限递归。
     * 之前 GetObjectClass/GetMethodID/GetArrayLength 没被 hook 时这个隐患不明显,
     * 补上以后必须显式挡住: 打印期间发出的 JNI 调用一律不记录,
     * 那些调用本来也只是打印基础设施自己的动作, 不是目标程序的业务调用。
     */
    static thread_local int gPrintDepth = 0;

    struct PrintGuard {
        PrintGuard() { ++gPrintDepth; }

        ~PrintGuard() { --gPrintDepth; }
    };

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
        //打印路径自己发出的 JNI 调用不记录, 否则 GetObjectClass/GetMethodID 会递归打印自己
        if (gPrintDepth > 0) {
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
    //--------------------------方法ID缓存----------------------------
    //
    // 加固后的 so(如 GameVMP)只通过 JNI 调 Java 方法, 日志里原先只有 mid 地址,
    // 看不出调的是哪个方法。这里把 GetMethodID/GetStaticMethodID 的结果记下来,
    // Call*Method 命中时直接查表拿到 类名/方法名/签名。
    //
    // 用 mid 作为 key: mid 在 ART 里就是 ArtMethod*, 同一个 mid 必然对应同一个方法。
    // 这是解析加固 so 调用链的关键 —— 没有它, 遇到 CallObjectMethodA(参数是 jvalue 数组)
    // 时根本无法得知该怎么解释那段数组。
    struct CachedMethodInfo {
        string className;
        string name;
        string signature;
    };

    static std::mutex gMethodInfoMutex;
    static std::unordered_map<jmethodID, CachedMethodInfo> gMethodInfoCache;

    /**
     * 缓存上限, 防止长时间运行无限增长(超出后不再新增, 已缓存条目仍可用)
     */
    static constexpr size_t MAX_METHOD_CACHE = 16384;

    static void cacheMethodInfo(jmethodID mid, const string &className, const char *name,
                                const char *sig) {
        if (mid == nullptr) {
            return;
        }
        std::lock_guard<std::mutex> lock(gMethodInfoMutex);
        if (gMethodInfoCache.size() >= MAX_METHOD_CACHE) {
            return;
        }
        CachedMethodInfo info;
        info.className = className;
        info.name = name == nullptr ? "" : name;
        info.signature = sig == nullptr ? "" : sig;
        gMethodInfoCache[mid] = info;
    }

    static bool lookupMethodInfo(jmethodID mid, CachedMethodInfo &out) {
        if (mid == nullptr) {
            return false;
        }
        std::lock_guard<std::mutex> lock(gMethodInfoMutex);
        auto it = gMethodInfoCache.find(mid);
        if (it == gMethodInfoCache.end()) {
            return false;
        }
        out = it->second;
        return true;
    }

    static string formatMethodInfoLine(const CachedMethodInfo &info) {
        return "invoke method  " + info.className + "." + info.name + info.signature;
    }

    /**
     * 把JNI方法签名拆成单个参数的签名片段。
     *   "(ILjava/lang/String;[B)V" -> {"I","Ljava/lang/String;","[B"}
     * 返回 false 表示签名畸形, 调用方应回退到反射方式。
     */
    static bool parseMethodSignature(const string &sig, std::vector<string> &types) {
        if (sig.empty() || sig[0] != '(') {
            return false;
        }
        size_t i = 1;
        while (i < sig.size() && sig[i] != ')') {
            const size_t start = i;
            while (i < sig.size() && sig[i] == '[') {
                ++i;
            }
            if (i >= sig.size()) {
                return false;
            }
            if (sig[i] == 'L') {
                const size_t end = sig.find(';', i);
                if (end == string::npos) {
                    return false;
                }
                i = end + 1;
            } else if (strchr("ZBCSIJFD", sig[i]) != nullptr) {
                ++i;
            } else {
                return false;
            }
            types.push_back(sig.substr(start, i - start));
        }
        return i < sig.size() && sig[i] == ')';
    }

    /**
     * 把参数签名片段转成类型名(供 fetchArgValue / formatArgValue 使用)。
     *   "I" -> "int"   "Ljava/lang/String;" -> "java.lang.String"   "[B" -> "[B"
     */
    static string sigToTypeName(const string &s) {
        if (s.size() == 1) {
            switch (s[0]) {
                case 'Z': return "boolean";
                case 'B': return "byte";
                case 'C': return "char";
                case 'S': return "short";
                case 'I': return "int";
                case 'J': return "long";
                case 'F': return "float";
                case 'D': return "double";
                case 'V': return "void";
                default: return s;
            }
        }
        if (s[0] == '[') {
            //数组直接给 getJavaArrayString 认的签名形式("[B"/"[I"/... )
            return s;
        }
        if (s[0] == 'L' && s.size() >= 2) {
            string n = s.substr(1, s.size() - 2);
            for (char &ch: n) {
                if (ch == '/') {
                    ch = '.';
                }
            }
            return n;
        }
        return s;
    }

    /**
     * 从 jvalue 数组取第 index 个参数。
     *
     * A 变体(Call*MethodA/NewObjectA)的参数是 `const jvalue*`: jvalue 是 union,
     * 在 64 位下 sizeof(jvalue) == 8, 所以数组下标与参数序号一一对应。
     * 这比 V 变体好处理得多 —— 不需要 va_list, 也不会把参数读错位。
     */
    static void fetchArrayArgValue(const jvalue *args, size_t index, const string &typeName,
                                   jvalue &value) {
        if (args == nullptr) {
            value.l = nullptr;
            return;
        }
        const jvalue &src = args[index];
        if (typeName == "boolean") {
            value.z = src.z;
        } else if (typeName == "byte") {
            value.b = src.b;
        } else if (typeName == "char") {
            value.c = src.c;
        } else if (typeName == "short") {
            value.s = src.s;
        } else if (typeName == "int") {
            value.i = src.i;
        } else if (typeName == "long") {
            value.j = src.j;
        } else if (typeName == "float") {
            value.f = src.f;
        } else if (typeName == "double") {
            value.d = src.d;
        } else {
            value.l = src.l;
        }
    }
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

    //--------------------------A 变体(jvalue 数组)----------------------------
    //
    // 加固后的 so 普遍用 A 变体而不是 V 变体: A 变体的参数是一段连续的 jvalue 数组,
    // 比 va_list 好构造也好传递。GameVMP 就是这样 —— 它调用 Java 方法几乎全走 A 变体,
    // 而原来只 hook 了 V 变体, 于是整条调用链在日志里是空白的。
    //
    // 注意: 这里不使用 JNI_HOOK_DEF 宏 —— 宏会把原函数声明成 varargs(...),
    // 而 A 变体实际是 (const jvalue*), 类型不匹配时传递参数是未定义行为。

    static jobject (*orig_CallObjectMethodA)(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                             const jvalue *args) = nullptr;

    static jobject new_CallObjectMethodA(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                         const jvalue *args) {
        DL_INFO
        IS_MATCH
            jobject ret = orig_CallObjectMethodA(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallObjectMethodA")
            GET_METHOD_INFO_ARGS_A(env, obj, jmethodId, args, false)
            getJObjectInfoInternal(env, ret, "result object :", true, "");
            return ret;
        }
        return orig_CallObjectMethodA(env, obj, jmethodId, args);
    }

    static jobject (*orig_CallStaticObjectMethodA)(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                                   const jvalue *args) = nullptr;

    static jobject new_CallStaticObjectMethodA(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                               const jvalue *args) {
        DL_INFO
        IS_MATCH
            jobject ret = orig_CallStaticObjectMethodA(env, clazz, jmethodId, args);
            GET_JOBJECT_INFO(env, clazz, "CallStaticObjectMethodA")
            GET_METHOD_INFO_ARGS_A(env, clazz, jmethodId, args, true)
            getJObjectInfoInternal(env, ret, "result object :", true, "");
            return ret;
        }
        return orig_CallStaticObjectMethodA(env, clazz, jmethodId, args);
    }

    static void (*orig_CallStaticVoidMethodA)(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                              const jvalue *args) = nullptr;

    static void new_CallStaticVoidMethodA(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                          const jvalue *args) {
        DL_INFO
        IS_MATCH
            GET_JOBJECT_INFO(env, clazz, "CallStaticVoidMethodA")
            GET_METHOD_INFO_ARGS_A(env, clazz, jmethodId, args, true)
            orig_CallStaticVoidMethodA(env, clazz, jmethodId, args);
            return;
        }
        orig_CallStaticVoidMethodA(env, clazz, jmethodId, args);
    }

    static jboolean (*orig_CallStaticBooleanMethodA)(JNIEnv *env, jclass clazz,
                                                     jmethodID jmethodId,
                                                     const jvalue *args) = nullptr;

    static jboolean new_CallStaticBooleanMethodA(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                                 const jvalue *args) {
        DL_INFO
        IS_MATCH
            jboolean ret = orig_CallStaticBooleanMethodA(env, clazz, jmethodId, args);
            GET_JOBJECT_INFO(env, clazz, "CallStaticBooleanMethodA")
            GET_METHOD_INFO_ARGS_A(env, clazz, jmethodId, args, true)
            write("result Boolean :  " + to_string(static_cast<int>(ret)) + "\n");
            return ret;
        }
        return orig_CallStaticBooleanMethodA(env, clazz, jmethodId, args);
    }

    static jint (*orig_CallStaticIntMethodA)(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                             const jvalue *args) = nullptr;

    static jint new_CallStaticIntMethodA(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                         const jvalue *args) {
        DL_INFO
        IS_MATCH
            jint ret = orig_CallStaticIntMethodA(env, clazz, jmethodId, args);
            GET_JOBJECT_INFO(env, clazz, "CallStaticIntMethodA")
            GET_METHOD_INFO_ARGS_A(env, clazz, jmethodId, args, true)
            write("result Int :  " + to_string(ret) + "\n");
            return ret;
        }
        return orig_CallStaticIntMethodA(env, clazz, jmethodId, args);
    }

    static jlong (*orig_CallStaticLongMethodA)(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                               const jvalue *args) = nullptr;

    static jlong new_CallStaticLongMethodA(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                           const jvalue *args) {
        DL_INFO
        IS_MATCH
            jlong ret = orig_CallStaticLongMethodA(env, clazz, jmethodId, args);
            GET_JOBJECT_INFO(env, clazz, "CallStaticLongMethodA")
            GET_METHOD_INFO_ARGS_A(env, clazz, jmethodId, args, true)
            write("result Long :  " + to_string(ret) + "\n");
            return ret;
        }
        return orig_CallStaticLongMethodA(env, clazz, jmethodId, args);
    }

    static void (*orig_CallVoidMethodA)(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                        const jvalue *args) = nullptr;

    static void new_CallVoidMethodA(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                    const jvalue *args) {
        DL_INFO
        IS_MATCH
            GET_JOBJECT_INFO(env, obj, "CallVoidMethodA")
            GET_METHOD_INFO_ARGS_A(env, obj, jmethodId, args, false)
            orig_CallVoidMethodA(env, obj, jmethodId, args);
            return;
        }
        orig_CallVoidMethodA(env, obj, jmethodId, args);
    }

    static jboolean (*orig_CallBooleanMethodA)(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                               const jvalue *args) = nullptr;

    static jboolean new_CallBooleanMethodA(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                           const jvalue *args) {
        DL_INFO
        IS_MATCH
            jboolean ret = orig_CallBooleanMethodA(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallBooleanMethodA")
            GET_METHOD_INFO_ARGS_A(env, obj, jmethodId, args, false)
            write("result Boolean :  " + to_string(static_cast<int>(ret)) + "\n");
            return ret;
        }
        return orig_CallBooleanMethodA(env, obj, jmethodId, args);
    }

    static jint (*orig_CallIntMethodA)(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                       const jvalue *args) = nullptr;

    static jint new_CallIntMethodA(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                   const jvalue *args) {
        DL_INFO
        IS_MATCH
            jint ret = orig_CallIntMethodA(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallIntMethodA")
            GET_METHOD_INFO_ARGS_A(env, obj, jmethodId, args, false)
            write("result Int :  " + to_string(ret) + "\n");
            return ret;
        }
        return orig_CallIntMethodA(env, obj, jmethodId, args);
    }

    static jlong (*orig_CallLongMethodA)(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                         const jvalue *args) = nullptr;

    static jlong new_CallLongMethodA(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                     const jvalue *args) {
        DL_INFO
        IS_MATCH
            jlong ret = orig_CallLongMethodA(env, obj, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "CallLongMethodA")
            GET_METHOD_INFO_ARGS_A(env, obj, jmethodId, args, false)
            write("result Long :  " + to_string(ret) + "\n");
            return ret;
        }
        return orig_CallLongMethodA(env, obj, jmethodId, args);
    }

    static jobject (*orig_NewObjectA)(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                      const jvalue *args) = nullptr;

    static jobject new_NewObjectA(JNIEnv *env, jclass clazz, jmethodID jmethodId,
                                  const jvalue *args) {
        DL_INFO
        IS_MATCH
            jobject obj = orig_NewObjectA(env, clazz, jmethodId, args);
            GET_JOBJECT_INFO(env, obj, "NewObjectA")
            GET_METHOD_INFO_ARGS_A(env, clazz, jmethodId, args, true)
            return obj;
        }
        return orig_NewObjectA(env, clazz, jmethodId, args);
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
        //打印期间调用的 JNI 一律不记录(详见 gPrintDepth 注释)。
        //这里是递归链的关键节点: GetMethodID/GetObjectClass/NewObjectArray 的 hook
        //会直接调它, 而它内部又要用 GetObjectClass —— 不挡就是无限递归。
        PrintGuard guard;
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
     * 单条日志里最多 dump 多少个原始字节。
     * hex 是 2 字符/字节, ascii 是 1 字符/字节, 取 MAX_PRINT_SIZE/3 保证整行不超上限。
     */
    static constexpr jsize MAX_DUMP_BYTES = static_cast<jsize>(MAX_PRINT_SIZE / 3);

    /**
     * 把原始字节渲染成 hex, 附一列可打印 ASCII。
     *
     * 二进制数据一律走这里, 不做任何字符集解码 —— 见 byteArrayToHexView 的注释。
     */
    static string bytesToHexView(const jbyte *data, jsize total, jsize dumped) {
        static const char *kHex = "0123456789abcdef";
        string hex;
        string ascii;
        hex.reserve(static_cast<size_t>(dumped) * 2);
        ascii.reserve(static_cast<size_t>(dumped));
        for (jsize i = 0; i < dumped; ++i) {
            auto c = static_cast<unsigned char>(data[i]);
            hex.push_back(kHex[c >> 4]);
            hex.push_back(kHex[c & 0x0F]);
            ascii.push_back((c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.');
        }
        string out = hex;
        out += "  ascii=";
        out += ascii;
        if (total > dumped) {
            out += "  ...(truncated)";
        }
        return out;
    }

    /**
     * [B 的 hex + ASCII 视图。
     *
     * 原实现走 new String(bytes, "UTF-8") 再转 std::string:
     * 二进制里的非法 UTF-8 字节会被解码成 U+FFFD 替换符(日志里就是乱码方块),
     * 原始字节就此丢失 —— 签名/密文/协议帧这类数据一旦被替换就再也还原不出来。
     * 现在不做任何字符集解码: 一律输出 hex, 另附 ASCII 列方便肉眼定位其中的文本片段。
     */
    static string byteArrayToHexView(JNIEnv *env, jbyteArray array) {
        if (env == nullptr || array == nullptr) {
            return "null";
        }
        jsize total = env->GetArrayLength(array);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            return {};
        }
        if (total <= 0) {
            return "[B len=0]";
        }
        const jsize dumped = total < MAX_DUMP_BYTES ? total : MAX_DUMP_BYTES;
        jbyte buf[MAX_DUMP_BYTES + 8] = {};
        env->GetByteArrayRegion(array, 0, dumped, buf);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            return {};
        }
        return "[B len=" + to_string(total) + "  hex=" + bytesToHexView(buf, total, dumped);
    }

    /**
     * C 字符串转义: 可打印字符原样输出, 其余按 \xNN 转义。
     *
     * NewStringUTF / GetStringUTFChars 的入参是 char*, 内容不保证是文本
     * (协议帧、密文都会走这条路径)。原来直接 append 进日志:
     * 非 UTF-8 字节会被日志层替换成 U+FFFD, 原始字节丢失且无法还原,
     * 而 hex 视图是纯 ASCII, 永远不会被替换。
     */
    static string escapeCString(const char *data, size_t maxLen) {
        if (data == nullptr) {
            return "null";
        }
        static const char *kHex = "0123456789abcdef";
        string out;
        out.reserve(64);
        for (size_t i = 0; i < maxLen; ++i) {
            auto c = static_cast<unsigned char>(data[i]);
            if (c == 0) {
                break;
            }
            if (c == '\n') {
                out += "\\n";
            } else if (c == '\r') {
                out += "\\r";
            } else if (c == '\t') {
                out += "\\t";
            } else if (c >= 0x20 && c < 0x7F) {
                out.push_back(static_cast<char>(c));
            } else {
                out += "\\x";
                out.push_back(kHex[c >> 4]);
                out.push_back(kHex[c & 0x0F]);
            }
        }
        return out;
    }

    /**
     * 取java数组的文本表示。
     * byte[]走 hex 视图(不做字符集解码, 不丢原始字节),其余类型走 java.util.Arrays.toString
     */
    static string getJavaArrayString(JNIEnv *env, jobject array, const string &classInfo) {
        if (env == nullptr || array == nullptr) {
            return "null";
        }
        if (classInfo == "[B") {
            return byteArrayToHexView(env, reinterpret_cast<jbyteArray>(array));
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
        PrintGuard guard;
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
     * 用方法ID缓存的签名直接打印方法名与全部参数。
     *
     * 相比反射(ToReflectedMethod + getParameterTypes)的优势:
     *   1) 不往 Java 层绕, 不会在打印自己时再触发一堆 JNI 调用;
     *   2) 加固 so 直接拿 mid 调用时, 反射未必能拿到完整信息, 而签名是 GetMethodID 当场记的;
     *   3) A 变体的参数是 jvalue 数组, 必须先知道签名才能解释那段内存 —— 这是唯一可行途径。
     *
     * @param readArg 取值回调: (参数序号, 参数签名片段) -> jvalue
     * @return true 表示缓存命中且签名可解析(已打印完毕)
     */
    template<typename ReadArg>
    static bool printArgsFromCache(JNIEnv *env, const CachedMethodInfo &cached, ReadArg readArg) {
        std::vector<string> paramTypes;
        if (!parseMethodSignature(cached.signature, paramTypes)) {
            return false;
        }
        write(formatMethodInfoLine(cached) + "\n");
        for (size_t i = 0; i < paramTypes.size(); ++i) {
            const string typeName = sigToTypeName(paramTypes[i]);
            jvalue value{};
            readArg(i, paramTypes[i], value);
            char indexBuf[48] = {};
            snprintf(indexBuf, sizeof(indexBuf), "args index [%d] ", static_cast<int>(i));
            printArgValue(env, typeName, value, indexBuf);
        }
        return true;
    }

    /**
     * A 变体(Call*MethodA / NewObjectA)的参数打印。
     * 参数是 jvalue 数组, 完全依赖 GetMethodID 缓存里记下的签名。
     */
    static void getArgsInfoFromArray(JNIEnv *env, jobject obj, jmethodID jmethodId,
                                     const jvalue *args, bool isStatic) {
        if (env == nullptr || obj == nullptr || jmethodId == nullptr) {
            return;
        }
        if (env->ExceptionCheck()) {
            return;
        }
        PrintGuard guard;
        CachedMethodInfo cached;
        if (!lookupMethodInfo(jmethodId, cached)) {
            (void) isStatic;
            write("args  <未记录到 GetMethodID, 无法解析 jvalue 数组  mid=" +
                  getAddressHex((void *) jmethodId) + ">\n");
            return;
        }
        printArgsFromCache(env, cached,
                           [args](size_t i, const string &raw, jvalue &v) {
                               fetchArrayArgValue(args, i, sigToTypeName(raw), v);
                           });
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
        PrintGuard guard;
        //优路径: GetMethodID 已经记下签名, 直接按签名解析 —— 不往 Java 层反射。
        //加固 so 的调用链靠这条路径才能拿到 "类名.方法名+签名"。
        CachedMethodInfo cached;
        if (lookupMethodInfo(jmethodId, cached)) {
            va_list walk;
            va_copy(walk, args);
            if (printArgsFromCache(env, cached,
                                   [&walk](size_t, const string &raw, jvalue &v) {
                                       fetchArgValue(walk, sigToTypeName(raw), v);
                                   })) {
                return;
            }
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
                    escapeCString(bytes, MAX_PRINT_SIZE)).append("\n"));
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
            write(string("<" + address + ">GetStringUTFChars : ").append(
                    escapeCString(chars, MAX_PRINT_SIZE)).append("\n"));
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


    /**
     * UTF-16(jchar*) 转义视图。
     * NewString 的入参不以 0 结尾 —— 长度由 len 单独给出, 不能用 escapeCString。
     */
    static string escapeJCharString(const jchar *data, jsize len) {
        if (data == nullptr) {
            return "null";
        }
        string out;
        out.reserve(64);
        for (jsize i = 0; i < len && i < 256; ++i) {
            auto c = static_cast<unsigned int>(data[i]);
            if (c >= 0x20 && c < 0x7F) {
                out.push_back(static_cast<char>(c));
            } else {
                char buf[16] = {};
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
        }
        return out;
    }

    //jmethodID   (*GetMethodID)(JNIEnv*, jclass, const char*, const char*);
    //
    // 这个 hook 不只是"多打印一行": 它把 mid -> {类名, 方法名, 签名} 记进缓存,
    // 后续 Call*MethodV/A 全靠它把一串 mid 地址翻译成可读调用链。
    // 加固 so 用 JNI 调 Java 时, 日志里原来只有 mid, 根本看不出调的是什么。
    JNITRACE_HOOK_DEF(jmethodID, GetMethodID, JNIEnv *env, jclass clazz, const char *name,
                      const char *sig) {
        DL_INFO
        IS_MATCH
            jmethodID ret = orig_GetMethodID(env, clazz, name, sig);
            if (ret != nullptr) {
                string classInfo = getJObjectToString(env, clazz);
                cacheMethodInfo(ret, classInfo, name, sig);
                GET_ADDRESS
                write(string("<" + address + ">GetMethodID ").append(classInfo).append(".")
                              .append(name == nullptr ? "" : name)
                              .append(sig == nullptr ? "" : sig)
                              .append(" mid=").append(getAddressHex((void *) ret))
                              .append("\n"));
            }
            return ret;

        }
        return orig_GetMethodID(env, clazz, name, sig);
    }

    //jmethodID   (*GetStaticMethodID)(JNIEnv*, jclass, const char*, const char*);
    JNITRACE_HOOK_DEF(jmethodID, GetStaticMethodID, JNIEnv *env, jclass clazz, const char *name,
                      const char *sig) {
        DL_INFO
        IS_MATCH
            jmethodID ret = orig_GetStaticMethodID(env, clazz, name, sig);
            if (ret != nullptr) {
                string classInfo = getJObjectToString(env, clazz);
                cacheMethodInfo(ret, classInfo, name, sig);
                GET_ADDRESS
                write(string("<" + address + ">GetStaticMethodID ").append(classInfo).append(".")
                              .append(name == nullptr ? "" : name)
                              .append(sig == nullptr ? "" : sig)
                              .append(" mid=").append(getAddressHex((void *) ret))
                              .append("\n"));
            }
            return ret;

        }
        return orig_GetStaticMethodID(env, clazz, name, sig);
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

    // ============================ 补齐的 hook ============================
    //
    // 下面这批是原实现没有覆盖、而加固 so(实测 GameVMP)大量使用的 JNI 入口。
    // 少了它们调用链在日志里就是断的 —— 比如它只用 GetStaticObjectField 取字段、
    // 只用 NewObjectArray/GetObjectArrayElement 摆参数, 完全不碰 NewObjectV。
    //
    // 实测依据(指令级 trace 把 blr 目标映射到 libart 符号):
    //   CallStaticObjectMethodA / CallObjectMethodA / NewObjectA / GetMethodID /
    //   GetStaticMethodID / GetObjectArrayElement / SetObjectArrayElement /
    //   NewObjectArray / GetStaticFieldID / GetStaticObjectField
    // 这些在原来的 hook 列表里全部缺失。

    //jstring     (*NewString)(JNIEnv*, const jchar*, jsize);
    JNITRACE_HOOK_DEF(jstring, NewString, JNIEnv *env, const jchar *unicodeChars, jsize len) {
        DL_INFO
        IS_MATCH
            jstring ret = orig_NewString(env, unicodeChars, len);
            if (ret != nullptr && unicodeChars != nullptr && len > 0) {
                GET_ADDRESS
                write(string("<" + address + ">NewString : ").append(
                        escapeJCharString(unicodeChars, len)).append("\n"));
            }
            return ret;
        }
        return orig_NewString(env, unicodeChars, len);
    }

    //jbyteArray  (*NewByteArray)(JNIEnv*, jsize);
    JNITRACE_HOOK_DEF(jbyteArray, NewByteArray, JNIEnv *env, jsize length) {
        DL_INFO
        IS_MATCH
            jbyteArray ret = orig_NewByteArray(env, length);
            if (ret != nullptr) {
                GET_ADDRESS
                write(string("<" + address + ">NewByteArray len=").append(
                        to_string(static_cast<int>(length))).append("\n"));
            }
            return ret;
        }
        return orig_NewByteArray(env, length);
    }

    //jsize       (*GetArrayLength)(JNIEnv*, jarray);
    JNITRACE_HOOK_DEF(jsize, GetArrayLength, JNIEnv *env, jarray array) {
        DL_INFO
        IS_MATCH
            jsize ret = orig_GetArrayLength(env, array);
            GET_ADDRESS
            write(string("<" + address + ">GetArrayLength = ").append(
                    to_string(static_cast<int>(ret))).append("\n"));
            return ret;
        }
        return orig_GetArrayLength(env, array);
    }

    //jobjectArray (*NewObjectArray)(JNIEnv*, jsize, jclass, jobject);
    JNITRACE_HOOK_DEF(jobjectArray, NewObjectArray, JNIEnv *env, jsize length, jclass elementClass,
                      jobject initialElement) {
        DL_INFO
        IS_MATCH
            jobjectArray ret = orig_NewObjectArray(env, length, elementClass, initialElement);
            GET_ADDRESS
            write(string("<" + address + ">NewObjectArray len=").append(
                    to_string(static_cast<int>(length))).append(" elementClass=").append(
                    getJObjectToString(env, elementClass)).append("\n"));
            return ret;
        }
        return orig_NewObjectArray(env, length, elementClass, initialElement);
    }

    //jobject     (*GetObjectArrayElement)(JNIEnv*, jobjectArray, jsize);
    JNITRACE_HOOK_DEF(jobject, GetObjectArrayElement, JNIEnv *env, jobjectArray array,
                      jsize index) {
        DL_INFO
        IS_MATCH
            jobject ret = orig_GetObjectArrayElement(env, array, index);
            GET_ADDRESS
            getJObjectInfoInternal(env, ret,
                                   "<" + address + ">GetObjectArrayElement index=" +
                                   to_string(static_cast<int>(index)) + " result object :",
                                   true, "");
            return ret;
        }
        return orig_GetObjectArrayElement(env, array, index);
    }

    //void        (*SetObjectArrayElement)(JNIEnv*, jobjectArray, jsize, jobject);
    JNITRACE_HOOK_DEF(void, SetObjectArrayElement, JNIEnv *env, jobjectArray array, jsize index,
                      jobject value) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            getJObjectInfoInternal(env, value,
                                   "<" + address + ">SetObjectArrayElement index=" +
                                   to_string(static_cast<int>(index)) + " value object :",
                                   true, "");
            orig_SetObjectArrayElement(env, array, index, value);
            return;
        }
        orig_SetObjectArrayElement(env, array, index, value);
    }

    //jclass      (*GetObjectClass)(JNIEnv*, jobject);
    JNITRACE_HOOK_DEF(jclass, GetObjectClass, JNIEnv *env, jobject obj) {
        DL_INFO
        IS_MATCH
            jclass ret = orig_GetObjectClass(env, obj);
            if (ret != nullptr) {
                GET_ADDRESS
                write(string("<" + address + ">GetObjectClass : ").append(
                        getJObjectToString(env, ret)).append("\n"));
            }
            return ret;
        }
        return orig_GetObjectClass(env, obj);
    }

    //jboolean    (*IsInstanceOf)(JNIEnv*, jobject, jclass);
    JNITRACE_HOOK_DEF(jboolean, IsInstanceOf, JNIEnv *env, jobject obj, jclass clazz) {
        DL_INFO
        IS_MATCH
            jboolean ret = orig_IsInstanceOf(env, obj, clazz);
            GET_ADDRESS
            write(string("<" + address + ">IsInstanceOf = ").append(
                    ret == JNI_TRUE ? "true" : "false").append("\n"));
            return ret;
        }
        return orig_IsInstanceOf(env, obj, clazz);
    }

    //jbyte*      (*GetByteArrayElements)(JNIEnv*, jbyteArray, jboolean*);
    JNITRACE_HOOK_DEF(jbyte*, GetByteArrayElements, JNIEnv *env, jbyteArray array,
                      jboolean *isCopy) {
        DL_INFO
        IS_MATCH
            jbyte *ret = orig_GetByteArrayElements(env, array, isCopy);
            if (ret != nullptr && array != nullptr) {
                PrintGuard guard;
                jsize len = env->GetArrayLength(array);
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                } else if (len > 0) {
                    const jsize dumped = len < MAX_DUMP_BYTES ? len : MAX_DUMP_BYTES;
                    GET_ADDRESS
                    write(string("<" + address + ">GetByteArrayElements [B len=" +
                                 to_string(static_cast<int>(len)) + "  hex=" +
                                 bytesToHexView(ret, len, dumped)).append("\n"));
                }
            }
            return ret;
        }
        return orig_GetByteArrayElements(env, array, isCopy);
    }

    // ============================ 数组 / 字符串 / 异常 等补齐 ============================
    //
    // 原实现只有 byte[] 一条路径, 而加固 so 摆参数时会用各种基本类型数组:
    // int[] 装索引、Object[] 装可变参数、String[] 装请求头……
    // 缺了这些, 日志里就只剩一个 "传了个数组" 的空壳。

    /**
     * 数组 region 的公共打印。
     *
     * 按原始字节 dump: 数组内容常常是二进制(密文/协议帧/序列化结构),
     * 按数值渲染既看不出一致性, 又会把明显的前缀特征冲散。
     * hex 视图是纯 ASCII, 能完整穿过日志层。
     */
    static void printArrayRegion(const char *kind, const string &address, const char *typeName,
                                 const void *buf, jsize start, jsize len, size_t elemSize) {
        const string head = string("<") + address + ">" + kind + " " + typeName +
                            " start=" + to_string(static_cast<int>(start)) +
                            " len=" + to_string(static_cast<int>(len));
        if (buf == nullptr || len <= 0) {
            write(head + " buf=null\n");
            return;
        }
        const size_t total = static_cast<size_t>(len) * elemSize;
        const jsize totalBytes = total > 0x7FFFFFFF ? 0x7FFFFFFF : static_cast<jsize>(total);
        const jsize dumped = totalBytes < MAX_DUMP_BYTES ? totalBytes : MAX_DUMP_BYTES;
        write(head + "  hex=" + bytesToHexView(static_cast<const jbyte *>(buf), totalBytes,
                                               dumped) + "\n");
    }

    /**
     * 批量生成 Get/Set<Type>ArrayRegion 的 hook。
     *
     * 这一族有 14 个函数(7 种类型 × Get/Set), 逻辑完全一样。
     * 逐个手写既啰嗦, 又容易在“数组类型 / 元素类型”这两个名字上抄错 —— 参数化生成更可靠。
     *
     * Get 版在 orig 之后打印(打印的是刚读出来的内容), Set 版打印的是即将写入的内容,
     * 两者都用同一个 buf 视图, 所以可以共用一段实现。
     */
#define JNI_ARRAY_REGION_HOOK(func, arrType, elemType, typeName)                           \
    JNITRACE_HOOK_DEF(void, func, JNIEnv *env, arrType array, jsize start, jsize len,      \
                      elemType *buf) {                                                     \
        DL_INFO                                                                            \
        IS_MATCH                                                                           \
            orig_##func(env, array, start, len, buf);                                      \
            GET_ADDRESS                                                                    \
            printArrayRegion(#func, address, typeName, buf, start, len, sizeof(elemType)); \
            return;                                                                        \
        }                                                                                  \
        orig_##func(env, array, start, len, buf);                                          \
    }

    JNI_ARRAY_REGION_HOOK(GetBooleanArrayRegion, jbooleanArray, jboolean, "boolean[]")
    JNI_ARRAY_REGION_HOOK(GetCharArrayRegion, jcharArray, jchar, "char[]")
    JNI_ARRAY_REGION_HOOK(GetShortArrayRegion, jshortArray, jshort, "short[]")
    JNI_ARRAY_REGION_HOOK(GetIntArrayRegion, jintArray, jint, "int[]")
    JNI_ARRAY_REGION_HOOK(GetLongArrayRegion, jlongArray, jlong, "long[]")
    JNI_ARRAY_REGION_HOOK(GetFloatArrayRegion, jfloatArray, jfloat, "float[]")
    JNI_ARRAY_REGION_HOOK(GetDoubleArrayRegion, jdoubleArray, jdouble, "double[]")

    JNI_ARRAY_REGION_HOOK(SetBooleanArrayRegion, jbooleanArray, const jboolean, "boolean[]")
    JNI_ARRAY_REGION_HOOK(SetCharArrayRegion, jcharArray, const jchar, "char[]")
    JNI_ARRAY_REGION_HOOK(SetShortArrayRegion, jshortArray, const jshort, "short[]")
    JNI_ARRAY_REGION_HOOK(SetIntArrayRegion, jintArray, const jint, "int[]")
    JNI_ARRAY_REGION_HOOK(SetLongArrayRegion, jlongArray, const jlong, "long[]")
    JNI_ARRAY_REGION_HOOK(SetFloatArrayRegion, jfloatArray, const jfloat, "float[]")
    JNI_ARRAY_REGION_HOOK(SetDoubleArrayRegion, jdoubleArray, const jdouble, "double[]")

#undef JNI_ARRAY_REGION_HOOK

    /**
     * 批量生成 New<Type>Array 的 hook。
     * 数组长度本身就有信息量(能看出是不是定长协议帧; 也能对上一一对应的 region 日志)。
     */
#define JNI_NEW_ARRAY_HOOK(func, arrType, typeName)                                        \
    JNITRACE_HOOK_DEF(arrType, func, JNIEnv *env, jsize length) {                          \
        DL_INFO                                                                            \
        IS_MATCH                                                                           \
            arrType ret = orig_##func(env, length);                                        \
            if (ret != nullptr) {                                                          \
                GET_ADDRESS                                                                \
                write(string("<") + address + ">" + #func + " " + typeName +             \
                      " len=" + to_string(static_cast<int>(length)) + "\n");            \
            }                                                                              \
            return ret;                                                                    \
        }                                                                                  \
        return orig_##func(env, length);                                                   \
    }

    JNI_NEW_ARRAY_HOOK(NewBooleanArray, jbooleanArray, "boolean[]")
    JNI_NEW_ARRAY_HOOK(NewCharArray, jcharArray, "char[]")
    JNI_NEW_ARRAY_HOOK(NewShortArray, jshortArray, "short[]")
    JNI_NEW_ARRAY_HOOK(NewIntArray, jintArray, "int[]")
    JNI_NEW_ARRAY_HOOK(NewLongArray, jlongArray, "long[]")
    JNI_NEW_ARRAY_HOOK(NewFloatArray, jfloatArray, "float[]")
    JNI_NEW_ARRAY_HOOK(NewDoubleArray, jdoubleArray, "double[]")

#undef JNI_NEW_ARRAY_HOOK

    //jint        (*RegisterNatives)(JNIEnv*, jclass, const JNINativeMethod*, jint);
    //
    // 这条日志直接给出 "Java 类 -> 方法名+签名 -> native 地址" 的对应关系。
    // 加固 so 通常不让 Java 层调 native, 而是自己在 JNI_OnLoad 里注册进来;
    // 有了这张表就能反过来定位加固 so 的真实入口(拿到地址再去反汇编),
    // 不用去逐个猜哪个 anonymouse mapping 是解密后的代码段。
    JNITRACE_HOOK_DEF(jint, RegisterNatives, JNIEnv *env, jclass clazz,
                      const JNINativeMethod *methods, jint nMethods) {
        DL_INFO
        IS_MATCH
            jint ret = orig_RegisterNatives(env, clazz, methods, nMethods);
            if (ret == JNI_OK && methods != nullptr && nMethods > 0) {
                const string classInfo = getJObjectToString(env, clazz);
                GET_ADDRESS
                for (jint i = 0; i < nMethods; ++i) {
                    write(string("<") + address + ">RegisterNatives [" + classInfo + "] " +
                          (methods[i].name == nullptr ? "?" : methods[i].name) +
                          (methods[i].signature == nullptr ? "" : methods[i].signature) +
                          " -> " + getAddressHex(methods[i].fnPtr) + "\n");
                }
            }
            return ret;
        }
        return orig_RegisterNatives(env, clazz, methods, nMethods);
    }

    //jsize       (*GetStringLength)(JNIEnv*, jstring);
    JNITRACE_HOOK_DEF(jsize, GetStringLength, JNIEnv *env, jstring str) {
        DL_INFO
        IS_MATCH
            jsize ret = orig_GetStringLength(env, str);
            GET_ADDRESS
            write(string("<") + address + ">GetStringLength = " +
                  to_string(static_cast<int>(ret)) + "\n");
            return ret;
        }
        return orig_GetStringLength(env, str);
    }

    //const jchar* (*GetStringChars)(JNIEnv*, jstring, jboolean*);
    //
    // 与 GetStringUTFChars 不同: 这里是 UTF-16 原文, 不走 MUTF-8 编码,
    // 所以中文/emoji 不会被改写成代理对字节, 能直接看到字符串真实内容。
    JNITRACE_HOOK_DEF(const jchar*, GetStringChars, JNIEnv *env, jstring str,
                      jboolean *isCopy) {
        DL_INFO
        IS_MATCH
            const jchar *ret = orig_GetStringChars(env, str, isCopy);
            if (ret != nullptr && str != nullptr) {
                PrintGuard guard;
                jsize len = env->GetStringLength(str);
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                } else if (len > 0) {
                    GET_ADDRESS
                    write(string("<") + address + ">GetStringChars len=" +
                          to_string(static_cast<int>(len)) + "  " +
                          escapeJCharString(ret, len) + "\n");
                }
            }
            return ret;
        }
        return orig_GetStringChars(env, str, isCopy);
    }

    //const char* (*GetStringUTFChars)(JNIEnv*, jstring, jboolean*);
    //void        (*ReleaseStringUTFChars)(JNIEnv*, jstring, const char*);
    JNITRACE_HOOK_DEF(void, ReleaseStringUTFChars, JNIEnv *env, jstring str, const char *chars) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            write(string("<") + address + ">ReleaseStringUTFChars : " +
                  escapeCString(chars, MAX_PRINT_SIZE) + "\n");
            orig_ReleaseStringUTFChars(env, str, chars);
            return;
        }
        orig_ReleaseStringUTFChars(env, str, chars);
    }

    //void        (*ReleaseStringChars)(JNIEnv*, jstring, const jchar*);
    JNITRACE_HOOK_DEF(void, ReleaseStringChars, JNIEnv *env, jstring str, const jchar *chars) {
        DL_INFO
        IS_MATCH
            if (chars != nullptr && str != nullptr) {
                PrintGuard guard;
                jsize len = env->GetStringLength(str);
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                } else if (len > 0) {
                    GET_ADDRESS
                    write(string("<") + address + ">ReleaseStringChars len=" +
                          to_string(static_cast<int>(len)) + "  " +
                          escapeJCharString(chars, len) + "\n");
                }
            }
            orig_ReleaseStringChars(env, str, chars);
            return;
        }
        orig_ReleaseStringChars(env, str, chars);
    }

    //void*       (*GetPrimitiveArrayCritical)(JNIEnv*, jarray, jboolean*);
    //
    // Critical 区间有硬约束: 从 GetPrimitiveArrayCritical 返回到 ReleasePrimitiveArrayCritical
    // 之间, 除少数几个函数外**禁止调用任何 JNI**(包括 GetArrayLength / GetObjectClass)。
    // 在 hook 里调它们看似无害, 实际会让目标程序在 GC 或类准备阶段直接卡死/崩。
    // 所以这里只记录两个裸指针和 isCopy, 不碰任何 JNI;
    // 想知道它是哪个数组、多长, 看紧跟在后面的 Set/Get<Type>ArrayRegion 或 New<Type>Array 日志。
    JNITRACE_HOOK_DEF(void*, GetPrimitiveArrayCritical, JNIEnv *env, jarray array,
                      jboolean *isCopy) {
        DL_INFO
        IS_MATCH
            void *ret = orig_GetPrimitiveArrayCritical(env, array, isCopy);
            if (ret != nullptr) {
                GET_ADDRESS
                write(string("<") + address + ">GetPrimitiveArrayCritical array=" +
                      getAddressHex(array) + " buf=" + getAddressHex(ret) + " isCopy=" +
                      (isCopy == nullptr ? "?" : (isCopy[0] ? "true" : "false")) + "\n");
            }
            return ret;
        }
        return orig_GetPrimitiveArrayCritical(env, array, isCopy);
    }

    //void        (*ReleasePrimitiveArrayCritical)(JNIEnv*, jarray, void*, jint);
    JNITRACE_HOOK_DEF(void, ReleasePrimitiveArrayCritical, JNIEnv *env, jarray array, void *carray,
                      jint mode) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            write(string("<") + address + ">ReleasePrimitiveArrayCritical array=" +
                  getAddressHex(array) + " buf=" + getAddressHex(carray) + " mode=" +
                  to_string(static_cast<int>(mode)) + "\n");
            orig_ReleasePrimitiveArrayCritical(env, array, carray, mode);
            return;
        }
        orig_ReleasePrimitiveArrayCritical(env, array, carray, mode);
    }

    //jint        (*Throw)(JNIEnv*, jthrowable);
    //
    // 必须在 orig_Throw 之前打印: Throw 返回后异常已挂起,
    // 此时除少数几个函数外再调 JNI(GetObjectClass/CallObjectMethod...) 是未定义行为。
    JNITRACE_HOOK_DEF(jint, Throw, JNIEnv *env, jthrowable obj) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            getJObjectInfoInternal(env, obj,
                                   string("<") + address + ">Throw exception object :", true, "");
            return orig_Throw(env, obj);
        }
        return orig_Throw(env, obj);
    }

    //jint        (*ThrowNew)(JNIEnv*, jclass, const char*);
    //
    // 校验失败/反调试命中时通常靠抛异常改变控制流, 这条日志是这类分支最直接的证据。
    // 与 Throw 同理, 打印必须发生在异常挂起之前。
    JNITRACE_HOOK_DEF(jint, ThrowNew, JNIEnv *env, jclass clazz, const char *message) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            write(string("<") + address + ">ThrowNew [" + getJObjectToString(env, clazz) +
                  "] " + escapeCString(message, MAX_PRINT_SIZE) + "\n");
            return orig_ThrowNew(env, clazz, message);
        }
        return orig_ThrowNew(env, clazz, message);
    }

    //void        (*ExceptionDescribe)(JNIEnv*);
    JNITRACE_HOOK_DEF(void, ExceptionDescribe, JNIEnv *env) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            write(string("<") + address + ">ExceptionDescribe\n");
            orig_ExceptionDescribe(env);
            return;
        }
        orig_ExceptionDescribe(env);
    }

    //jint        (*MonitorEnter)(JNIEnv*, jobject);
    //
    // 在 orig 之前打印: 若在后面调 toString, 而该对象的 toString 恰好又需要这把锁,
    // 就会自锁(MonitorEnter 成功后同一线程重入可重入锁不至于死等,
    // 但其他线程持锁时打印会隐式延长锁的语义, 干脆统一成进锁前打印)。
    JNITRACE_HOOK_DEF(jint, MonitorEnter, JNIEnv *env, jobject obj) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            getJObjectInfoInternal(env, obj,
                                   string("<") + address + ">MonitorEnter object :", true, "");
            return orig_MonitorEnter(env, obj);
        }
        return orig_MonitorEnter(env, obj);
    }

    //jint        (*MonitorExit)(JNIEnv*, jobject);
    JNITRACE_HOOK_DEF(jint, MonitorExit, JNIEnv *env, jobject obj) {
        DL_INFO
        IS_MATCH
            GET_ADDRESS
            getJObjectInfoInternal(env, obj,
                                   string("<") + address + ">MonitorExit object :", true, "");
            return orig_MonitorExit(env, obj);
        }
        return orig_MonitorExit(env, obj);
    }

    //jint        (*GetVersion)(JNIEnv *);
    JNITRACE_HOOK_DEF(jint, GetVersion, JNIEnv *env) {
        DL_INFO
        IS_MATCH
            const jint ret = orig_GetVersion(env);
            GET_ADDRESS
            write(string("<") + address + ">GetVersion = " + to_string(ret) + "\n");
            return ret;
        }
        return orig_GetVersion(env);
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

    //A 变体: 参数是 jvalue 数组。
    //加固后的 so 几乎只用这一组 —— 它自己拿 mid 直接把参数拼成 jvalue 再一次性传进来,
    //不需要构造 va_list。原来只 hook 了 V 变体, 于是这类调用在日志里完全空白。
    HOOK_JNITRACE(env, CallObjectMethodA)
    HOOK_JNITRACE(env, CallBooleanMethodA)
    HOOK_JNITRACE(env, CallIntMethodA)
    HOOK_JNITRACE(env, CallLongMethodA)
    HOOK_JNITRACE(env, CallVoidMethodA)

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

    HOOK_JNITRACE(env, CallStaticObjectMethodA)
    HOOK_JNITRACE(env, CallStaticBooleanMethodA)
    HOOK_JNITRACE(env, CallStaticIntMethodA)
    HOOK_JNITRACE(env, CallStaticLongMethodA)
    HOOK_JNITRACE(env, CallStaticVoidMethodA)


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

    //获取方法ID —— 必须 hook: 它同时把 mid -> {类名, 方法名, 签名} 写进缓存,
    //后面 Call*Method 的日志靠这个缓存才能把裸 mid 翻译成可读调用链。
    HOOK_JNITRACE(env, GetMethodID)
    HOOK_JNITRACE(env, GetStaticMethodID)

    HOOK_JNITRACE(env, NewObjectV)
    HOOK_JNITRACE(env, NewObjectA)

    //将C数组中的数据复制到Java字节数组
    HOOK_JNITRACE(env, SetByteArrayRegion)
    HOOK_JNITRACE(env, GetByteArrayRegion)

    //从Java字符串中获取指定范围的字符
    HOOK_JNITRACE(env, GetStringRegion)
    HOOK_JNITRACE(env, GetStringUTFRegion)

    //字符串长度与 UTF-16 内容(UTF-16 是原文, 中文/emoji 不会被改写成代理对字节)
    HOOK_JNITRACE(env, GetStringLength)
    HOOK_JNITRACE(env, GetStringChars)
    HOOK_JNITRACE(env, ReleaseStringUTFChars)
    HOOK_JNITRACE(env, ReleaseStringChars)

    //数组与对象基础操作
    //加固 so 根本不碰 NewString(UTF-16 版), 字符串全走 NewStringUTF;
    //但它大量用 NewByteArray/NewObjectArray/GetObjectArrayElement 摆参数,
    //少了这些就像看一段没有参数列表的调用链。
    HOOK_JNITRACE(env, NewString)
    HOOK_JNITRACE(env, NewByteArray)
    HOOK_JNITRACE(env, NewObjectArray)
    HOOK_JNITRACE(env, GetArrayLength)
    HOOK_JNITRACE(env, GetObjectArrayElement)
    HOOK_JNITRACE(env, SetObjectArrayElement)
    HOOK_JNITRACE(env, GetByteArrayElements)
    HOOK_JNITRACE(env, GetObjectClass)
    HOOK_JNITRACE(env, IsInstanceOf)

    //数组创建与 Get/Set<Type>ArrayRegion 全族
    HOOK_JNITRACE(env, NewBooleanArray)
    HOOK_JNITRACE(env, NewCharArray)
    HOOK_JNITRACE(env, NewShortArray)
    HOOK_JNITRACE(env, NewIntArray)
    HOOK_JNITRACE(env, NewLongArray)
    HOOK_JNITRACE(env, NewFloatArray)
    HOOK_JNITRACE(env, NewDoubleArray)

    HOOK_JNITRACE(env, GetBooleanArrayRegion)
    HOOK_JNITRACE(env, GetCharArrayRegion)
    HOOK_JNITRACE(env, GetShortArrayRegion)
    HOOK_JNITRACE(env, GetIntArrayRegion)
    HOOK_JNITRACE(env, GetLongArrayRegion)
    HOOK_JNITRACE(env, GetFloatArrayRegion)
    HOOK_JNITRACE(env, GetDoubleArrayRegion)

    HOOK_JNITRACE(env, SetBooleanArrayRegion)
    HOOK_JNITRACE(env, SetCharArrayRegion)
    HOOK_JNITRACE(env, SetShortArrayRegion)
    HOOK_JNITRACE(env, SetIntArrayRegion)
    HOOK_JNITRACE(env, SetLongArrayRegion)
    HOOK_JNITRACE(env, SetFloatArrayRegion)
    HOOK_JNITRACE(env, SetDoubleArrayRegion)

    //Critical 版数组访问(不拷贝, 直接拿堆内指针; 加固 so 读写大数组常用)
    HOOK_JNITRACE(env, GetPrimitiveArrayCritical)
    HOOK_JNITRACE(env, ReleasePrimitiveArrayCritical)

    // native 方法注册: 直接给出 "Java 类 -> 方法名+签名 -> native 地址" 对应关系, 
    // 是定位加固 so真实入口最快的途径(低频, 每个类只调一次)
    HOOK_JNITRACE(env, RegisterNatives)

    //异常与同步
    HOOK_JNITRACE(env, Throw)
    HOOK_JNITRACE(env, ThrowNew)
    HOOK_JNITRACE(env, ExceptionDescribe)
    HOOK_JNITRACE(env, MonitorEnter)
    HOOK_JNITRACE(env, MonitorExit)

    HOOK_JNITRACE(env, GetVersion)


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





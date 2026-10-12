//
// Created by zhenxi on 2022/1/21.
//
#include <iosfwd>
#include <iostream>
#include <string>
#include <map>
#include <list>
#include <jni.h>
#include <dlfcn.h>
#include <cstddef>
#include <fcntl.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sstream>
#include <ostream>

#include <cstdlib>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <syscall.h>
#include <climits>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <pthread.h>
#include <vector>
#include <zlib.h>
#include <list>
#include <string>
#include <map>
#include <list>

#include <cstring>
#include <cstdio>
#include <regex>
#include <cerrno>
#include <climits>
#include <iostream>
#include <fstream>

#include "stringHandler.h"
#include "mylibc.h"
#include "logging.h"
#include "HookUtils.h"
#include "ZhenxiLog.h"
#include "traceLog.h"

using namespace std;
/**
 * 因为需要hook一些string处理的函数,所以尽可能使用C语言去实现这些功能
 *
 * ======================= 关于bionic的IFUNC函数(必读) =======================
 * bionic里 strlen / strcmp / strcpy 是 IFUNC(GNU indirect function)符号,
 * 加载时由resolver按CPU特性挑一个实现(通常是 *aarch64 的SIMD版本):
 *     strcpy_resolver:
 *       adrp x9, __strcpy_aarch64_mte
 *       adrp x10, __strcpy_aarch64
 *       tst  w8, #0x4
 *       csel x0, x10, x9, eq           <-- dlsym("strcpy")拿到的就是这个结果
 * 所以 dlsym 拿到的其实是 __strcpy_aarch64 这类实现函数的地址,
 * hook 它就是 hook 了真实的实现体(而不是那个 resolver)。
 *
 * 这些SIMD实现在入口就把 x17(IP1) 算好,而且整个主循环都依赖它:
 *     __strcpy_aarch64:
 *       bti  c
 *       and  x9, x1, #0xfff
 *       mov  x12, #0x0101010101010101
 *       and  x17, x1, #0xf             <-- 入口初始化x17
 *       ...
 *       sub  x2, x1 - x17              <-- 循环体继续用x17算指针
 *
 * 于是"跳板回跳时用哪个寄存器"就变成了生死问题:
 *
 *   - 老版本用的 Dobby:回跳固定 ldr x17,...; br x17。跳板搬走了入口那几条指令
 *     (x17 的初始化就在其中),执行完再用 x17 跳回函数体,x17 此时已是跳板地址,
 *     函数拿它算指针 -> SIGSEGV。实测 Android 12/arm64 一打开 App,
 *     RenderThread 分配 GraphicBuffer 调 strcpy 时必崩:
 *         #00 __strcpy_aarch64+216  ldp x4,x5,[x2]   (x2 = x1 - 被污染的x17)
 *         #01 libjnitrace.so  new_strcpy+...
 *
 *   - 现在用的 Vector wxshadow:wxshadow 的 write_jump_back 会先看搬移过的指令
 *     有没有写过 x17,写过就改用 x16 做中转(hook_engine_mem.c 的 write_jump_back),
 *     所以理论上不会再踩这个坑。但它仍有已知缺口:
 *       a) 成对 load 的第二个目标寄存器(bits[14:10],如 ldp x0,x17,[..])在
 *          arm64_relocator 里不被记录;
 *       b) x16/x17 都被搬移指令写过时,它只打一条 warning 仍然用 x17。
 *
 * 所以 strlen / strcmp / strcpy 这三个最热的 SIMD 实现**不通过 backup 转发**,
 * 直接使用 mylibc.h 里的自实现(my_strlen / my_strcmp / my_stpcpy):
 * 语义与 libc 等价,代价只是少了 SIMD 加速 —— 对调试工具可以接受,
 * 换来的是完全不依赖重定位精度。
 *
 * 其余 hook 的函数都确认过入口是普通实现(stp x29,x30 标准帧,不把 x17 当作
 * 跨指令状态),保留 backup 转发:
 *   __strlen_chk / strstr / fgets / strdup
 * ==========================================================================
 */
namespace ZhenxiRunTime::stringHandlerHook {

#define HOOK_SYMBOL(handle, func)  \
  hook_libc_function(handle, #func, (void*) new_##func, (void**) &orig_##func); \


//HOOK_DEF/JNITRACE_HOOK_DEF 用HookUtils.h里的定义(那里的orig_指针会初始化为nullptr),
//这里不要再重定义一遍,否则编译器会报macro redefined

#define  ORIG_BUFF_SIZE  100

#define  MATCH_SO_NAME_SIZE  100

#define  MAX_PRINTF_SIZE  PATH_MAX

#define INIT_ORIG_BUFF \
    char *buff = (char*)malloc(ORIG_BUFF_SIZE); \
    my_memset(buff,0,ORIG_BUFF_SIZE); \

#define HOOK_SYMBOL_DOBBY(handle, func)  \
  hook_libc_function(handle, #func, (void*) new_##func, (void**) &orig_##func); \

//这块是为了防止他把一个void*当成char*去strlen挂掉
# define IS_NULL(value) value \

# define APPEND_INT(buff, value) \
     char* int_value = int_to_str(value);           \
     if(int_value!=nullptr){                           \
        APPEND(buff,int_value);                   \
        free(int_value);                           \
     }


# define APPEND(buff, value) \
     if(my_strlen(value)>0){     \
        buff = (char *)realloc(buff,my_strlen(buff)+my_strlen(value)+1); \
        my_strcat(buff,value);  \
     }  \



# define CLEAN_APPEND(buff, value, size) \
     my_memset(buff,0,size); \
     my_strcat(buff,value);  \

    /**
     * 是否监听第二级返回结果。
     *
     */
    static bool isHookSecondRet = false;

    /**
     * 过滤列表的最大条目数(原来是100且不校验下标,传入超过100个就会越界写)
     */
    static constexpr int MAX_FILTER_SO_COUNT = 32;

    static std::ofstream *hookStrHandlerOs = nullptr;
    static char *filterSoList[MAX_FILTER_SO_COUNT] = {};
    static char *forbidSoList[MAX_FILTER_SO_COUNT] = {};
    static bool isHookAll = false;

    static bool isSave = false;

    /**
     * 当前线程命中的so名。isLister()写入,write()读取,同一线程内成对使用,
     * 用thread_local避免多线程互相覆盖。
     */
    static thread_local char match_so_name[MATCH_SO_NAME_SIZE] = {};


    static bool isAppFile(const char *path) {
        if (my_strstr(path, "/data/") != nullptr) {
            return true;
        }
        return false;
    }

    const char *getFileNameForPath(const char *path) {
        const char *fileName = strrchr(path, '/');
        if (fileName != nullptr) {
            return fileName + 1;
        }
        return path;
    }

# define DL_INFO \
    Dl_info info={nullptr}; \
    int addr_ret_0 = dladdr((void *) __builtin_return_address(0), &info); \

# define IS_MATCH \
        if(ZhenxiRunTime::stringHandlerHook::isLister(addr_ret_0,&info)){  \


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
        //比如我们注入的SO文件
        for (auto forbid: forbidSoList) {
            if (my_strstr(name, forbid) != nullptr) {
                //找到了则不进行处理
                return false;
            }
        }
        //如果是监听全部直接返回true
        if (isHookAll) {
            CLEAN_APPEND(match_so_name, getFileNameForPath(name), MATCH_SO_NAME_SIZE);
            return true;
        } else {
            //根据关键字进行过滤
            for (auto filter: filterSoList) {
                //默认监听一级
                if (my_strstr(name, filter) != nullptr) {
                    CLEAN_APPEND(match_so_name, getFileNameForPath(name), MATCH_SO_NAME_SIZE);
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * 指针转成可打印字符串(调用者负责free)
     */
    static char *ptrToHex(const void *ptr) {
        char *buffer = (char *) malloc(20);
        if (buffer == nullptr) {
            return nullptr;
        }
        snprintf(buffer, 20, "%p", ptr);
        return buffer;
    }


    /**
     * 日志输出实现。
     *
     * callerOffset 是"调用方在它自己所属模块里的偏移",需要在hook函数里算好传进来:
     *     (size_t) __builtin_return_address(0) - (size_t) info.dli_fbase
     *
     * 原实现是在这个函数内部取 __builtin_return_address(0),那时拿到的是
     * libjnitrace.so 自己的地址,再减去目标so的基址,算出来的偏移没有任何意义。
     */
    static void traceWriteImpl(const char *msg, Dl_info info, size_t callerOffset) {
        INIT_ORIG_BUFF
        APPEND(buff, "[")
        APPEND(buff, match_so_name)
        APPEND(buff, "] ")
        if (info.dli_fbase != nullptr) {
            char offsetBuff[32] = {};
            snprintf(offsetBuff, sizeof(offsetBuff), "<0x%zx>", callerOffset);
            APPEND(buff, offsetBuff)
        }
        APPEND(buff, msg)
        if (isSave && hookStrHandlerOs != nullptr) {
            //和jnitrace用的是同一把锁,否则两个模块同时往同一个ofstream里写会互相踩
            TraceLog::writeLine(hookStrHandlerOs, buff);
        }
        LOG(INFO) << buff;
        if (msg != nullptr) {
            free((void *) msg);
        }
        if (buff != nullptr) {
            free((void *) buff);
        }
    }

    /**
     * 统一日志出口(宏)。
     *
     * callerOffset在宏展开处取值,所以拿到的是hook函数的调用者地址,
     * 而不是traceWriteImpl自己的返回地址 —— 这正是原实现算错的地方。
     */
#define traceWrite(msg, info) \
    traceWriteImpl((msg), (info), \
        (size_t) __builtin_return_address(0) - (size_t) (info).dli_fbase)





// char* strstr(char* h, const char* n)
    HOOK_DEF(char*, strstr, char *h, const char *n) {
        DL_INFO
        IS_MATCH char *ret = orig_strstr(h, n);
            if (ret != nullptr) {
                INIT_ORIG_BUFF
                APPEND(buff, "strstr() arg1 -> ")
                APPEND(buff, IS_NULL(h))
                APPEND(buff, "  arg2-> ")
                APPEND(buff, IS_NULL(n))
                APPEND(buff, "\n")
                traceWrite(buff, info);
            }
            return ret;

        }
        return orig_strstr(h, n);
    }

    //size_t __strlen_chk(const char *a1, size_t a2)
    HOOK_DEF(size_t, __strlen_chk, const char *__s,size_t a2) {
        DL_INFO
        IS_MATCH
        size_t size = orig___strlen_chk(__s,a2);
            if (size > 0) {
                INIT_ORIG_BUFF
                APPEND(buff, "strlen_chk() arg1 -> ")
                APPEND(buff, IS_NULL(__s))
                APPEND(buff, "\n")
                traceWrite(buff, info);
            }
            return size;
        }
        return orig___strlen_chk(__s,a2);
    }

    HOOK_DEF(size_t, strlen, const char *__s) {
        DL_INFO
        //不能用orig_strlen(见文件头的IFUNC说明),用自实现
        size_t size = my_strlen(__s);
        IS_MATCH
            if (size > 0) {
                INIT_ORIG_BUFF
                APPEND(buff, "strlen() arg1 -> ")
                APPEND(buff, IS_NULL(__s))
                APPEND(buff, "\n")
                traceWrite(buff, info);
            }
        }
        return size;
    }

//char* strcat(char* __dst, const char* __src);
    HOOK_DEF(char *, strcat, char *__dst, const char *__src) {
        DL_INFO
        IS_MATCH char *ret = orig_strcat(__dst, __src);
            INIT_ORIG_BUFF
            APPEND(buff, "strcat() arg1 -> ")
            APPEND(buff, IS_NULL(__dst))
            APPEND(buff, "  arg2-> ")
            APPEND(buff, IS_NULL(__src))
            if (ret != nullptr) {
                APPEND(buff, " result -> ")
                APPEND(buff, IS_NULL(ret))
            }
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;

        }
        return orig_strcat(__dst, __src);
    }
//int strcmp(const char* __lhs, const char* __rhs)
    HOOK_DEF(int, strcmp, const char *__lhs, const char *__rhs) {
        DL_INFO
        //不能用orig_strcmp(见文件头的IFUNC说明)。
        //libc的strcmp碰到nullptr会崩,这里给出确定结果,免得调试工具把目标程序带崩
        int ret;
        if (__lhs == nullptr || __rhs == nullptr) {
            ret = (__lhs == __rhs) ? 0 : (__lhs != nullptr ? 1 : -1);
        } else {
            ret = my_strcmp(__lhs, __rhs);
        }
        IS_MATCH
            INIT_ORIG_BUFF
            APPEND(buff, "strcmp() arg1 -> ")
            APPEND(buff, IS_NULL(__lhs))
            APPEND(buff, "  arg2-> ")
            APPEND(buff, IS_NULL(__rhs))
            APPEND(buff, "\n")
            traceWrite(buff, info);
        }
        return ret;
    }
//char* strcpy(char* __dst, const char* __src);
    HOOK_DEF(char *, strcpy, char *__dst, const char *__src) {
        DL_INFO
        //不能用orig_strcpy(见文件头的IFUNC说明),ARM64上必崩
        if (__dst != nullptr && __src != nullptr) {
            my_stpcpy(__dst, __src);
        }
        IS_MATCH
            INIT_ORIG_BUFF
            APPEND(buff, "strcpy() arg1 -> ")
            APPEND(buff, IS_NULL(__dst))
            APPEND(buff, "  arg2-> ")
            APPEND(buff, IS_NULL(__src))
            APPEND(buff, "\n")
            traceWrite(buff, info);
        }
        return __dst;
    }
//int sprintf(char* __s, const char* __fmt, ...)
    HOOK_DEF(int, sprintf, char *__s, const char *__fmt, char *p...) {
        DL_INFO
        IS_MATCH int ret = orig_sprintf(__s, __fmt, p);
            INIT_ORIG_BUFF
            APPEND(buff, "sprintf() arg1 -> ")
            APPEND(buff, IS_NULL(__s))
            APPEND(buff, "  arg2-> ")
            APPEND(buff, IS_NULL(__fmt))
            APPEND(buff, "  arg3-> ")
            APPEND(buff, IS_NULL(p))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;

        }

        return orig_sprintf(__s, __fmt, p);
    }
//int printf(const char* __fmt, ...)
    HOOK_DEF(int, printf, const char *__fmt, char *p...) {
        DL_INFO
        IS_MATCH int ret = orig_printf(__fmt, p);
            INIT_ORIG_BUFF
            APPEND(buff, "printf() arg1 -> ")
            APPEND(buff, IS_NULL(__fmt))
            APPEND(buff, "  arg2-> ")
            APPEND(buff, IS_NULL(p))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;

        }

        return orig_printf(__fmt, p);
    }
//char *strtok(char *str, const char *delim)
    HOOK_DEF(char *, strtok, char *str, const char *delim) {
        DL_INFO
        IS_MATCH char *ret = orig_strtok(str, delim);
            INIT_ORIG_BUFF
            APPEND(buff, "strtok() arg1 -> ")
            APPEND(buff, IS_NULL(str))
            APPEND(buff, "  arg2-> ")
            APPEND(buff, IS_NULL(delim))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret; }
        return orig_strtok(str, delim);
    }
//char* strdup(const char* __s);
    HOOK_DEF(char*, strdup, char *__s) {

        DL_INFO
        IS_MATCH

            INIT_ORIG_BUFF
            APPEND(buff, "strdup() arg1 -> ")
            APPEND(buff, IS_NULL(__s))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return orig_strdup(__s);

        }
        return orig_strdup(__s);
    }


//把 str1 和 str2 进行比较，结果取决于 LC_COLLATE 的位置设置。
//int strcoll(const char* __lhs, const char* __rhs) __attribute_pure__;
    HOOK_DEF(int, strcoll, const char *__lhs, const char *__rhs) {
        DL_INFO
        IS_MATCH int ret = orig_strcoll(__lhs, __rhs);

            INIT_ORIG_BUFF
            APPEND(buff, "strcoll() arg1 -> ")
            APPEND(buff, IS_NULL(__lhs))
            APPEND(buff, "  arg2-> ")
            APPEND(buff, IS_NULL(__rhs))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;

        }
        return orig_strcoll(__lhs, __rhs);
    }
//size_t strxfrm(char *dest, const char *src, size_t n)
    HOOK_DEF(size_t, strxfrm, char *dest, const char *src, size_t n) {

        DL_INFO
        IS_MATCH size_t ret = orig_strxfrm(dest, src, n);
            INIT_ORIG_BUFF
            APPEND(buff, "strxfrm() arg1 -> ")
            APPEND(buff, IS_NULL(dest))
            APPEND(buff, "  arg2-> ")
            APPEND(buff, IS_NULL(src))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;

        }
        return orig_strxfrm(dest, src, n);
    }
//char* fgets(char* __buf, int __size, FILE* __fp);
    HOOK_DEF(char*, fgets, char *__buf, int __size, FILE *__fp) {
        DL_INFO
        IS_MATCH char *ret = orig_fgets(__buf, __size, __fp);
            INIT_ORIG_BUFF
            APPEND(buff, "fgets() arg1 -> ")
            APPEND(buff, IS_NULL(__buf))
            APPEND(buff, "  arg2-> ")
            APPEND_INT(buff, __size)
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;

        }
        return orig_fgets(__buf, __size, __fp);
    }
    //void *memcpy(void *destin, void *source, unsigned n);
    HOOK_DEF(void*, memcpy, void *destin, void *source, size_t __n) {
        DL_INFO
        IS_MATCH

            //原实现把判断写反了:orig_memcpy为null时反而去调用nullptr,直接崩
            void *ret = (orig_memcpy != nullptr) ? orig_memcpy(destin, source, __n)
                                                 : my_memcpy(destin, source, __n);
            if (source == nullptr || destin == nullptr) {
                return ret;
            }
            //memcpy的内容不以\0结尾,原来当字符串打印会越界读,这里只打印指针和长度
            char *destHex = ptrToHex(destin);
            char *sourceHex = ptrToHex(source);
            INIT_ORIG_BUFF
            APPEND(buff, "memcpy() arg1 -> ")
            APPEND(buff, destHex)
            APPEND(buff, "  arg2-> ")
            APPEND(buff, sourceHex)
            APPEND(buff, "  arg3-> ")
            APPEND_INT(buff, __n)
            APPEND(buff, "\n")
            traceWrite(buff, info);
            if (destHex != nullptr) {
                free(destHex);
            }
            if (sourceHex != nullptr) {
                free(sourceHex);
            }
            return ret;
        }

        return orig_memcpy(destin, source, __n);
    }
//int snprintf(char* __buf, size_t __size, const char* __fmt, ...) __printflike(3, 4);
    HOOK_DEF(int, snprintf, char *__buf, size_t __size, const char *__fmt, char *p  ...) {
        DL_INFO
        IS_MATCH int ret = orig_snprintf(__buf, __size, __fmt, p);
            if (ret == -1) {
                return ret;
            }
            INIT_ORIG_BUFF
            APPEND(buff, "snprintf() arg1 -> ")
            APPEND(buff, IS_NULL(__buf))
            APPEND(buff, "  arg2-> ")
            APPEND_INT(buff, __size)
            APPEND(buff, "  arg3-> ")
            APPEND(buff, IS_NULL(__fmt))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;

        }

        return orig_snprintf(__buf, __size, __fmt, p);
    }

    HOOK_DEF(void *, malloc, size_t __byte_count) {
        DL_INFO
        IS_MATCH void *ret = orig_malloc(__byte_count);
            if (ret == nullptr || __byte_count == 0) {
                return ret;
            }
            INIT_ORIG_BUFF
            APPEND(buff, "malloc() arg1 -> ")
            APPEND_INT(buff, __byte_count)
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;

        }
        return orig_malloc(__byte_count);
    }
//int vsnprintf(char* __buf, size_t __size, const char* __fmt, va_list __args) __printflike(3, 0);
    HOOK_DEF(int, vsnprintf, char *__buf, size_t __size, const char *__fmt, va_list __args) {
        DL_INFO
        IS_MATCH
            int ret = orig_vsnprintf(__buf, __size, __fmt, __args);
            INIT_ORIG_BUFF
            APPEND(buff, "vsnprintf() arg1 -> ")
            APPEND(buff, IS_NULL(__buf))
            APPEND(buff, "  arg2-> ")
            APPEND_INT(buff, __size)
            APPEND(buff, "  arg3-> ")
            APPEND(buff, IS_NULL(__fmt))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;
        }
        return orig_vsnprintf(__buf, __size, __fmt, __args);
    }
    //void *memmove(void *dest, const void *src, size_t n);
    HOOK_DEF(void *, memmove, void *dest, const void *src, size_t n) {
        DL_INFO
        IS_MATCH auto ret = orig_memmove(dest, src, n);
            char *destHex = ptrToHex(dest);
            char *sourceHex = ptrToHex(src);
            INIT_ORIG_BUFF
            APPEND(buff, "memmove() arg1 -> ")
            APPEND(buff, destHex)
            APPEND(buff, "  arg2-> ")
            APPEND(buff, sourceHex)
            APPEND(buff, "  arg3-> ")
            APPEND_INT(buff, n)
            APPEND(buff, "\n")
            traceWrite(buff, info);
            if (destHex != nullptr) {
                free(destHex);
            }
            if (sourceHex != nullptr) {
                free(sourceHex);
            }
            return ret;

        }

        return orig_memmove(dest, src, n);
    }
    //char *strncat(char *dest, const char *src, size_t n)
    HOOK_DEF(char *, strncat, char *dest, const char *src, size_t n) {
        DL_INFO
        IS_MATCH
            auto ret = orig_strncat(dest, src, n);
            INIT_ORIG_BUFF
            APPEND(buff, "strncat() arg1 -> ")
            APPEND(buff, IS_NULL((char *) dest))
            APPEND(buff, "  arg2-> ")
            APPEND(buff, IS_NULL((char *) src))
            APPEND(buff, "  arg3-> ")
            APPEND_INT(buff, n)
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;
        }
        return orig_strncat(dest, src, n);
    }
    //char *strlwr(char *str)
    HOOK_DEF(char *, strlwr, char *str) {
        DL_INFO
        IS_MATCH
            auto ret = orig_strlwr(str);
            INIT_ORIG_BUFF
            APPEND(buff, "strlwr() arg1 -> ")
            APPEND(buff, IS_NULL((char *) str))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;
        }
        return orig_strlwr(str);
    }
//char *strupr(char *str)
    HOOK_DEF(char *, strupr, char *str) {
        DL_INFO
        IS_MATCH
            auto ret = orig_strupr(str);
            INIT_ORIG_BUFF
            APPEND(buff, "strupr() arg1 -> ")
            APPEND(buff, IS_NULL((char *) str))
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;
        }
        return orig_strupr(str);
    }
//char *strchr(const char *str, int c)
    HOOK_DEF(char *, strchr, const char *str, int c) {
        DL_INFO
        IS_MATCH
            auto ret = orig_strchr(str, c);
            INIT_ORIG_BUFF
            APPEND(buff, "strchr() arg1 -> ")
            APPEND(buff, IS_NULL((char *) str))
            APPEND(buff, "  arg2-> ")
            APPEND_INT(buff, c)
            APPEND(buff, "\n")
            traceWrite(buff, info);
            return ret;
        }
        return orig_strchr(str, c);
    }

}


using namespace ZhenxiRunTime::stringHandlerHook;


void stringHandler::init() {
    void *handle = dlopen("libc.so", RTLD_NOW);

    if (handle == nullptr) {
        LOG(ERROR) << "str handler get handle == null   ";
        return;
    }

    HOOK_SYMBOL(handle, strlen)
    //strlen buff check
    HOOK_SYMBOL(handle, __strlen_chk)
    HOOK_SYMBOL(handle, strcmp)
    HOOK_SYMBOL(handle, strstr)
    HOOK_SYMBOL(handle, fgets)
    HOOK_SYMBOL(handle, strcpy)
    HOOK_SYMBOL(handle, strdup)

//    HOOK_SYMBOL_DOBBY(handle, strxfrm)
//    HOOK_SYMBOL_DOBBY(handle, strtok)
//    HOOK_SYMBOL_DOBBY(handle, strncat)
//    HOOK_SYMBOL_DOBBY(handle, strlwr)
//    HOOK_SYMBOL_DOBBY(handle, strupr)
//    HOOK_SYMBOL_DOBBY(handle, strchr)

    //strcat底层走的是strcpy
    //https://cs.android.com/android/platform/superproject/+/master:external/musl/src/string/strcat.c;l=5?q=strcat
//    HOOK_SYMBOL_DOBBY(handle, strcat)
    //strcoll底层是strcmp
    //https://cs.android.com/android/platform/superproject/+/master:external/musl/src/locale/strcoll.c;l=12;drc=master?q=strcoll&ss=android%2Fplatform%2Fsuperproject
//    HOOK_SYMBOL_DOBBY(handle, strcoll)


    //HOOK_SYMBOL_DOBBY(handle, sprintf)
    //HOOK_SYMBOL_DOBBY(handle, printf)
    //HOOK_SYMBOL_DOBBY(handle, snprintf)
    //HOOK_SYMBOL_DOBBY(handle, vsnprintf)

//    HOOK_SYMBOL_DOBBY(handle, memmove)
//    HOOK_SYMBOL_DOBBY(handle, memcpy)




    dlclose(handle);

    LOG(ERROR) << ">>>>>>>>> string handler init success !  ";
}

void stringHandler::hookStrHandler(bool hookAll, const std::list<string> &forbid_list,
                                   const std::list<string> &filter_list, std::ofstream *os) {
    isHookAll = hookAll;

    int i = 0;
    for (const auto &string: forbid_list) {
        if (i >= MAX_FILTER_SO_COUNT) {
            LOGE("forbidSoList too many items, max is %d", MAX_FILTER_SO_COUNT)
            break;
        }
        forbidSoList[i] = strdup(string.c_str());
        LOG(ERROR) << "forbidSoList -> " << i << " " << forbidSoList[i];
        i++;
    }
    i = 0;
    for (const auto &string: filter_list) {
        if (i >= MAX_FILTER_SO_COUNT) {
            LOGE("filterSoList too many items, max is %d", MAX_FILTER_SO_COUNT)
            break;
        }
        filterSoList[i] = strdup(string.c_str());
        LOG(ERROR) << "filterSoList -> " << i << " " << filterSoList[i];
        i++;
    }
    if (os != nullptr) {
        isSave = true;
        hookStrHandlerOs = os;
    } else {
        LOG(ERROR) << ">>>>>>>>>>>>> string handler init fail hookStrHandlerOs == null  ";
    }
    init();
}

[[maybe_unused]]
void stringHandler::stopjnitrace() {
    for (auto str: forbidSoList) {
        free(str);
    }
    for (auto str: filterSoList) {
        free(str);
    }
    //文件流的生命周期由调用方(main.cpp)管理。
    //原来这里delete一次,jnitrace的stopjnitrace()也delete同一个对象,会double free
    hookStrHandlerOs = nullptr;
    isSave = false;
}



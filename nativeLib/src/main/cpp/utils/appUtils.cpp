//
// Created by zhenxi on 2021/12/12.
//

//#include <VAJni.h>

#include <utility>
#include <cstdlib>

#include "includes/appUtils.h"
#include "includes/HookUtils.h"
#include "includes/libpath.h"

using namespace StringUtils;
using namespace ZhenxiRunTime;

bool isSystemFile(const string& path){
    return endsWith(path, "/libc.so") || //允许libc调用
           startWith(path, "/system/") ||
           startWith(path, "/apex/") ;
}

void getAllOpenFdInfo(){
#define F_LEN 1024

    struct dirent *dirent;
    char path[PATH_MAX];
    size_t status;
    DIR *dirp;

    /* Open the virtual directory "/proc/$pid/fd". */
    dirp = opendir("/proc/");
    if (dirp == nullptr)
        return ;
    while ((dirent = readdir(dirp)) != nullptr) {
        long procPid = strtol(dirent->d_name, nullptr, 10);
        if (procPid){
            char filename[F_LEN]={};
            char buf[F_LEN]={};
            snprintf(filename, F_LEN, "/proc/self/fd/%s",  dirent->d_name);
            status = readlink(filename, buf, F_LEN);
            if (status < 0 || status >= PATH_MAX){
                LOGW(">>>>>>>>> find fd error filename [%s] %s",filename, strerror(errno))
                continue;
            }
            path[status] = '\0';
            LOGI(">>>>>>>>> find fd %s [%s] %s",dirent->d_name,buf,filename)
        }
    }
    closedir(dirp);
}


void inline findSymBySo(size_t address, MapAddresInfo* info) {
//    SandHook::ElfImg elfImg(info->fname);
//    elfImg.getAddressSym(address, info);
}


/**
 * 根据一个地址获取所在的so信息
 */
string getSymbolforAddress(size_t address,pid_t pid) {
    if (address == 0) {
        LOGE("getSymbolforAddress  address == null ")
        return {};
    }
    FILE *fp = fopen(string("/proc/").append(
            to_string(pid)).append("/maps").c_str(),"r");
    char *line = nullptr;
    char perm[12] = {'\0'}, dev[12] = {'\0'},mapname[PATH_MAX] = {'\0'};
    size_t begin, end, inode, foo;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1) {
        sscanf(line, "%lx-%lx %s %lx %s %ld %s",
               &begin, &end, perm, &foo, dev, &inode, mapname);
        if (address >= begin && address <= end) {
            syscall(__NR_close, fp);
            return {mapname};
        }
    }
    LOGI("getSymbolforAddress not found address in maps   0x%zx ", address)
    //找不到也需要关闭
    syscall(__NR_close, fp);
    return {};
}



//将内存指定地址设置可读,可执行,
//但是不可写
bool MPROTECT(size_t addr,size_t size,int __prot){
    //计算扇叶
    auto alignment = (unsigned) ((unsigned long long) addr % sysconf(_SC_PAGESIZE));
    //保证开始地址 减去扇叶大小
    int i = mprotect((void *) (addr - alignment), (size_t) (alignment + size),__prot);
    if (i == 0) {
        return true;
    }
    LOGE("Helper mprotect error   %s ", strerror(errno))
    return false;
}
#define BUF_SIZE 1024


/**
 * 从 /proc/self/maps 的一行里取出被映射的文件路径(第一个 '/' 起,到行尾)。
 */
static void mapLinePath(const char *line, char *out, size_t outSize) {
    out[0] = '\0';
    if (line == nullptr || outSize == 0) {
        return;
    }
    const char *p = strchr(line, '/');
    if (p == nullptr) {
        return;
    }
    size_t n = 0;
    while (p[n] != '\0' && p[n] != '\n' && (n + 1) < outSize) {
        out[n] = p[n];
        ++n;
    }
    out[n] = '\0';
}

MapItemInfo getSoBaseAddress(const char *name) {
    MapItemInfo info{0};
    if(name== nullptr){
        return info;
    }
    //dlopen 传进来的路径不一定等于 /proc/self/maps 里显示的字符串,分三种情况兜:
    //  1) 符号链接: dlopen("/vendor/lib64/hw/xxx.so") 在 maps 里显示的是解析后的
    //     ".../hw/mt6895/xxx.so" —— Android 的 HAL impl so 大量如此,
    //     只按原字符串匹配会得到 start=0(实测 android.hardware.graphics.mapper@4.0
    //     -impl-mediatek.so 就踩了这个);
    //  2) soname: dlopen("libc.so") 在 maps 里是完整路径,靠文件名兜;
    //  3) APK 内 so: dlopen("/path/base.apk!/lib/arm64-v8a/libx.so") 在 maps 里
    //     只有 apk 自身的映射,不含 so 名 —— 这种本质上取不到,返回 0 由调用方标注。
    char realPath[PATH_MAX] = {};
    if (realpath(name, realPath) == nullptr) {
        realPath[0] = '\0';
    }
    const char *base = strrchr(name, '/');
    base = (base != nullptr) ? (base + 1) : name;
    const size_t baseLen = strlen(base);
    //文件名兜底时的路径锚点:同名 so 可能在进程里有多份(不同目录/命名空间),
    //只认第一次命中的那个路径,避免把另一个同名 so 的映射段算进来给出错误地址。
    char baseAnchor[PATH_MAX] = {};

    size_t start = 0 ;
    size_t end = 0 ;
    bool isFirst = true;
    size_t len = 0;
    char buffer[PATH_MAX];
    memset(buffer, 0, PATH_MAX);
    //读取的Maps不进行IO重定向
    FILE *fp =fopen("/proc/self/abcd", "r");
    if(fp == nullptr){
        //找不到用原始文件
        fp = fopen("/proc/self/maps", "r");
        if(fp== nullptr){
            return info;
        }
    }
    char *line = nullptr;
    while (getline(&line, &len, fp) != -1) {
        if (line == nullptr) {
            continue;
        }
        bool matched = strstr(line, name) != nullptr;
        if (!matched && realPath[0] != '\0') {
            matched = strstr(line, realPath) != nullptr;
        }
        if (!matched && baseLen > 0) {
            //按文件名兜:必须是".../文件名"形式,且文件名后紧跟行尾或空格,
            //否则 "libx.so" 会误匹配到 "libx.so.bak" 这类;并且要求路径与锚点一致。
            for (const char *hit = strstr(line, base); hit != nullptr;
                 hit = strstr(hit + 1, base)) {
                if (hit == line || *(hit - 1) != '/') {
                    continue;
                }
                const char tail = hit[baseLen];
                if (tail != '\0' && tail != '\n' && tail != '\r' && tail != ' ') {
                    continue;
                }
                char linePath[PATH_MAX] = {};
                mapLinePath(line, linePath, sizeof(linePath));
                if (baseAnchor[0] == '\0') {
                    snprintf(baseAnchor, sizeof(baseAnchor), "%s", linePath);
                }
                matched = strcmp(baseAnchor, linePath) == 0;
                break;
            }
        }
        if (matched) {
            sscanf(line, "%lx-%lx",&start, &end);
            //start 只有第一次赋值
            if(isFirst){
                info.start = start;
                isFirst= false;
            }
        }
    }
    info.end = end;
    syscall(__NR_close, fp);
    //LOGE("get maps info start -> 0x%zx  end -> 0x%zx ",info.start,info.end);
    return info;
}




bool getpData(char temp[],const void *p, size_t size) {
    memset(temp,0,strlen(temp));
    int i;
    int len = 0;
    for (i = 0; i < size; i++) {
        len += sprintf(temp + len, "%02X", ((char *) p)[i]);
    }
    return true;
}

string getpData(const void *p,int tempSize) {
    char temp[tempSize*2];
    memset(temp,0,strlen(temp));
    int i;
    int len = 0;
    for (i = 0; i < tempSize; i++) {
        len += sprintf(temp + len, "%02X", ((char *) p)[i]);
    }
    return string {temp};
}
bool mProtect(size_t addr, size_t len) {
    auto alignment = (unsigned) ((unsigned long long) addr % sysconf(_SC_PAGESIZE));
    int i = mprotect((void *) (addr - alignment), (size_t) (alignment + len),
                     PROT_READ | PROT_WRITE | PROT_EXEC);
    if (i == -1) {
        return false;
    }
    return true;
}
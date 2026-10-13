# XposedJniTrace (FunJni)

基于 **Vector** 框架的 native JNI 追踪模块：注入目标 App 后监听指定 so 的 JNI 调用、打印参数与返回值，
并附带 libc 字符串函数追踪、RegisterNative / linker / ArtMethod::Invoke 监听与 Java 内存漫游。

> 上游实现见 [w296488320/XposedJniTrace](https://github.com/…)(老 Xposed + `Runtime.nativeLoad` 注入版)。
> 本仓库已改造为 **Vector soLoader 基线的 native 模块**。
>
> **本仓库是 jnitrace 的主力维护目标。** trace 核心(`JnitraceForC.cpp` /
> `stringHandler.cpp` / `traceLog.h`)是从 [JnitraceForCpp](../JnitraceForCpp)
> 融合过来的同一份拷贝,那个仓库已冻结为归档(保留"独立 so"形态与
> `xunwind`/`hidemaps`/`Dobby` 等 nativeLib 能力,详见它的 `MAINTENANCE.md`)。
> 所以这两个文件以后**只在这里改**,不要再回去改 JnitraceForCpp 那一份。

---

## 与老版本的区别

| | 老版本 | 本仓库 |
| --- | --- | --- |
| 框架 | 任意 Xposed(de.robv 包名) | **Vector**(`de.wwb.android.wbosed`) |
| 模块 so 装载 | 自己解压 APK + 反射 `Runtime.nativeLoad` | Vector soLoader(`META-INF/xposed/native_init.list` + `native_init`) |
| native 入口 | `JNI_OnLoad` | 导出 `native_init(const NativeAPIEntries*)` |
| inline hook | Dobby + sandhook 三级降级 | Vector 下发的 **wxshadow**(`entries->hookFunc`) |
| ABI | armeabi-v7a + arm64-v8a | **arm64-v8a**(Vector soLoader 当前只支持它) |
| 配置传递 | root `mv` 到目标 data 目录 | root 写到目标 data 目录(**已修 SELinux 问题**,见下),XSP 路实测不通 |
| 反盗版 | 证书 MD5 校验 + `System.exit(9)` | 保留(必须用仓库自带的 `jnitraceKey.jks` 签名) |

---

## 装载路径(为什么是 MODERN + targetApiVersion=101)

Vector 有两条完全不同的模块装载路径：

| | LEGACY | MODERN |
| --- | --- | --- |
| 判定 | 无 `targetApiVersion` 且 APK 里有 `assets/xposed_init` | `module.prop` 的 `targetApiVersion >= 101` |
| 入口元数据 | `assets/xposed_init` + `assets/native_init` | `META-INF/xposed/java_init.list` + `native_init.list` |
| so 怎么装载 | 框架把 `apk!/lib/<abi>` 塞进 librarySearchPath，**要模块自己 `System.loadLibrary`** | daemon sealed SharedMemory → `NativeAPI.loadNativeLibraries()` → `ElfLoader::LoadLibraryFd()`(匿名装载) |
| native 入口 | `System.loadLibrary` 后由 do_dlopen 监视器的 **DIAG** 分支调 `native_init` | soLoader 装载后经载体 trampoline 调 `native_init` |
| 痕迹 | 目标进程 maps 里留下 `base.apk` 外来代码容器映射 | 无 |

本模块走 **MODERN**：`targetApiVersion=101`。
选 101 而不是 102 是因为 `VectorModuleManager` 里
`blockLegacyApi = targetApiVersion >= 102` —— 101 既能用 soLoader 装载，
又还能用 legacy API(`XSharedPreferences` 等)，改动最小。

入口类是 `LHook extends WbModule`，在 `onModuleLoaded` 里读配置、装 hook。
MODERN 路线拿不到 `LoadPackageParam`，所以目标包名从进程名推导
(`com.foo:remote` → `com.foo`)。

## 安装与使用

1. **安装本 APK**(release,非 debuggable,由 `jnitraceKey.jks` 签名)。
2. 在 **Vector 管理器**里勾选本模块为启用模块。
3. 打开模块 App → 选择目标 App → 填过滤关键字 → 勾选功能 → 确定。
   配置由 App 用 root 写到 `/data/data/<目标包>/FunJniConfig`(见下面"配置是怎么传过去的")。
4. 把目标 App 加进本模块的作用域，**重启目标 App**(模块在进程启动早期注入，配置需要一次冷启动)。

### 配置项

| 项 | 说明 |
| --- | --- |
| 过滤关键字 | 一行一个，`\|` 分隔；`strstr(so完整路径, 关键字)` 命中即追踪。填 `ALL` 表示匹配全部 app so(`/data/` 下的) |
| 功能 `0` | **JNIEnv hook**：`Call*MethodV` / `Get*Field` / `FindClass` / `NewObjectV` / 字符串与 byte 数组读写等 |
| 功能 `1` | **libc 字符串 hook**：`strlen` `strcmp` `strcpy` `strstr` `strdup` `fgets` `__strlen_chk`(热点函数，默认不勾选) |
| 功能 `2` | **RegisterNative hook**：打印静态注册的 native 方法与实现地址 |
| 功能 `3` | **linker hook**：打印 `dlopen` 加载的 so 基址/大小 |
| 功能 `4` | **ArtMethod::Invoke hook**：打印所有 Java 方法调用(极热，慎用) |
| 内存漫游 | `VMDebug.getInstancesOfClasses()` 全量 dump Java 对象成 JSON，30 秒后触发。**开启后其他 hook 全部不生效** |

输出：`/data/data/<目标包>/(<进程名>)[过滤项].txt`，同时输出到 logcat(TAG `Zhenxi`)。
内存漫游输出：`/data/data/<目标包>/<进程名>_MemorySerializationInfo.txt`。

---

## 构建

```bash
./gradlew :app:assembleRelease
```

工具链(与 Vector 对齐)：JDK 21(读 Vector API jar 需要)、NDK `27.3.13750724`、
CMake `3.22.1`、compileSdk 35 / buildTools 35.0.0、C++20、arm64-v8a。

CI：push 触发 `.github/workflows/build.yml`，打 `v*` tag 触发 `release.yml`。
CI 会额外校验：`META-INF/xposed/{module.prop,java_init.list,native_init.list}` /
`lib/arm64-v8a/libFunJni.so` / so 导出 `native_init` / 非 debuggable /
**签名 MD5 与 `sec/checkSign.cpp` 期望一致**
(不校验就会出来一个自己 `System.exit(9)` 的 APK)。

### Vector API jar

`app/libs/vector-api-compile-only.jar` 是从 Vector 仓库导出的 **compileOnly** jar(类由框架在目标进程提供)，
只包含模块用到的 legacy API：

```bash
# 在 Vector 仓库里(需要已有构建产物)
mkdir -p /tmp/apijar && cd /tmp/apijar
unzip -o <Vector>/xposed/build/intermediates/compile_library_classes_jar/release/bundleLibCompileToJarRelease/classes.jar 'de/wwb/android/wbosed/api/*'
unzip -o <Vector>/legacy/build/intermediates/compile_library_classes_jar/release/bundleLibCompileToJarRelease/classes.jar \
      'de/wwb/android/wbosed/*' 'de/wwb/android/wbosed/callbacks/*' 'de/wwb/android/wbosed/services/*' \
      'android/app/*' 'android/content/res/*'
zip -qr libs/vector-api-compile-only.jar .
```

Vector 升级后 API 有变动时要重新导出。

---

## 目录结构

```
app/src/main/cpp/
├── main.cpp                 native_init 入口 + JavaVM 自举 + RegisterNatives + 功能分发
├── hook/
│   ├── JnitraceForC.cpp     JNIEnv 函数 hook(核心)
│   ├── stringHandler.cpp    libc 字符串函数 hook
│   ├── invokePrintf.cpp     ArtMethod::Invoke / RegisterNative hook
│   └── linkerHandler.cpp    linker dlopen hook
├── sec/                     反盗版(证书校验)
└── includes/

nativeLib/src/main/cpp/      native 基础库(被 app 的 CMake add_subdirectory 引入)
├── hook/
│   ├── HookUtils.cpp        inline hook 统一入口(转发到 Vector wxshadow)
│   └── VectorNativeApi.cpp  NativeAPIEntries 封装 + libart .dynsym 解析 + JavaVM 自举
├── adapter/                 JNIEnv 获取 / sdk level
├── dlfc/                    符号解析
├── libpath/                 系统库路径
├── utils/                   工具类
└── raw_syscall/             直接系统调用
```

---

## 已修的坑(迁移过程中踩到的)

1. **va_list 被消费两次**：原实现在 `orig_CallXxxMethodV` 之前就 `va_arg` 打印参数，
   AArch64 上 `va_list` 按引用传递，参数被打印逻辑吃掉，**目标程序的真实调用参数全错**。
   现在先 `va_copy` 快照，用副本打印。
2. **参数一律按 jobject 取值**：`long/double` 在 32 位上会读错位、`float` 会被当指针。
   现在按 ART `ArgArray::BuildArgArrayFromVarArgs` 的类型规则取值
   (`float` 要读 `jdouble`，C 可变参数默认提升)。
3. **静态方法 `ToReflectedMethod` 传错 clazz**，静态方法参数永远打印不出来。
4. **释放后使用**：`getJObjectClassInfo` 在 `ReleaseStringUTFChars` 之后把指针返回给调用者。
5. **泄露**：所有 `GetStringUTFChars` 结果都不释放。
6. **`jstring2str` 空串崩溃**：`std::string(nullptr)`。
7. **libc IFUNC 函数的 x17 陷阱**：`strlen/strcmp/strcpy` 是 bionic 的 IFUNC SIMD 实现，
   入口初始化 x17 且主循环依赖它；老 Dobby 跳板回跳固定用 x17 → 一打开 App 必崩。
   现在这三个函数用 `mylibc.h` 的自实现转发(Vector 的 wxshadow 有 x17 检测，但仍有
   `ldp` 第二目标寄存器不记录的缺口)。
8. **线程安全**：`match_so_name` 改 `thread_local`；日志文件写入加锁，且四个模块**共用同一把锁**
   (`traceLog.h`)，否则两个模块同时写同一个 `ofstream` 是 UB。
9. **double free**：各模块的 `stopjnitrace()` 都 `delete` 同一个 `ofstream`。
10. **过滤列表越界**：固定 100 项不校验下标。
11. **`memcpy` hook 判断写反**，且把非 `\0` 结尾内存当字符串打印会越界读。
12. **配置传不到目标 App：SELinux MCS 类别**。模块 App 自己创建配置后 `mv` 过去，
    而 `mv` 是 `rename(2)`、保留源 inode 和它的 SELinux 标签——标签带的是模块自己的
    MCS 类别(`app_data_file:s0:c<模块appid>`)，目标 App 的类别是`c<目标appid>`，
    两边不同 → SELinux 直接拒绝，**文件即使 `chmod 777` 也读不了**。
    现象是 `open failed: EACCES (Permission denied)`，然后
    `tag package name -> null`、一个 hook 都不装（功能静默失效）。
    现在改成在目标目录 `cp` 新建(`cp` 由 root 创建，标签是 `app_data_file:s0`，
    不带 MCS 类别，任何 App 都能读)，再同目录 `mv` 原子替换成正式名。
    注意：换目标 App 时旧配置文件标签仍是错的，重新点一次“确定”即可。
13. **`RootUtils.execShell` 不同步**：先跑一遍非 root 的同一条命令(白跑)、
    写完 `su` 的 stdin 就立刻返回不等 `waitFor`；于是连续调用的 `rm`/`cp`/`mv`
    各自起一个 `su`、**顺序毫无保证**(可能搞出半个配置文件)。
    现在同一 `su` 里写 `命令 + exit` 并 `waitFor(5s)`，写配置那几条合并成一条 `&&` 链。
14. **`RegisterNative` 符号位置搬过家**：`art::ArtMethod::RegisterNative` 在
    Android 8 之后已从 libart 移除，现在是
    `art::ClassLinker::RegisterNative(Thread*, ArtMethod*, const void*)`。
    只认老符号会让功能 2 静默失效。现在按新→旧多候选查找。
15. **`getSoBaseAddress` 遇行号链接拿不到地址**：`dlopen("/vendor/lib64/hw/x.so")`
    是行号链接，而 maps 里显示的是解析后的真实路径(`hw/mt6895/x.so`)，
    完整路径 `strstr` 匹配失败 → 返回 0。Android 的 HAL impl so 大量如此。
    现在按 原样路径 → `realpath` 解析后 → 文件名兜底(带路径锚点防同名串味) 依次匹配。
16. **功能 3 不该自己抢 `do_dlopen`**：Vector 框架自己已经用 wxshadow 挂了同一个地址，
    同址二次 hook 必失败(`ret=-8`)。而框架那次 hook 干的正是同样的事，
    所以改成吃框架的加载通知(`native_init` 返回的回调)，代码从 418 行缩到 98 行。
17. **功能 0 参数错位（AArch64 `va_list` 按值传参会丢推进）**：`va_list` 是 32 字节
    结构体，按值传参时编译器在每个调用点重新复制描述符，被调函数里的 `va_arg`
    推进只写回副本 → 每读一个参数都从第一个槽位重新开始。表现为多参数调用的
    参数全部重复成第一个值，更严重的是把整数当 `jobject` 交给 ART，
    `Thread::DecodeJObject` 解引用未映射地址直接 SIGSEGV(实测 hunter、localsend 秒崩)。
    现在 `fetchArgValue` 改收 `va_list&`，`getArgsInfo` 内部显式 `va_copy` 一份走查。

---

## 致谢

- [Vector](https://github.com/JingMatrix/Vector)：ART hook 框架与 native 模块 API
- [LSPosed](https://github.com/LSPosed/LSPosed)：ART hooking 框架

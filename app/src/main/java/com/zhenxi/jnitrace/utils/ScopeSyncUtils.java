package com.zhenxi.jnitrace.utils;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;

import com.zhenxi.jnitrace.BuildConfig;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import de.wwb.android.wbosed.service.WbService;
import de.wwb.android.wbosed.service.WbServiceHelper;

/**
 * 把 FunJni 里选中的目标 App 同步进 Vector 的 scope,省掉"还要去管理面板再勾一次"。
 *
 * <h3>为什么需要同步</h3>
 * FunJni 选中的应用只写进了自己的配置(config SP + root cp 出去的 FunJniConfig),
 * 它不碰 Vector 的数据库;/data/adb/lspd/config/modules_config.db 里 scope 表才是
 * "模块注入哪些进程"的唯一真相(daemon 的 ModuleDatabase.setModuleScope)。
 * 两套开关互相不知道,所以用户必须两边各勾一次。
 *
 * <h3>用的什么通道</h3>
 *
 * 两条,按优先级:
 *
 * <b>1. root CLI(优先)</b> —— root 跑 {@code /data/adb/lspd/cli scope add <模块包> <目标包>}。
 * 走 daemon 的 LocalSocket({@code /data/adb/lspd/.cli_sock}),不碰通知与资源,
 * 零交互、完全自动。daemon 侧 CliHandler 会做全部校验并调 setModuleScope,
 * 后者触发 ConfigCache 重建,加完立即生效。
 *
 * <b>2. requestScope 通知(无 root 时兜底)</b> —— Vector 自带 libxposed service:
 * <pre>
 *   daemon  ModuleAppService.sendBinder(uid)
 *     -> getContentProviderExternal("&lt;applicationId&gt;.WbService", ...)
 *     -> provider.call("SendBinder", {binder: IWbService})
 *   app     WbProvider.call() -> WbServiceHelper.onBinderReceived()
 *     -> WbServiceHelper.registerListener() 的回调拿到 WbService 句柄
 * </pre>
 * 拿到句柄后调 {@code requestScope(packages, callback)}:daemon 侧
 * {@code ModuleAppService.requestScope} 会校验 staticScope、检查"永不询问"拉黑,
 * 然后弹一条高优先级通知(NotificationManager.requestModuleScope)让用户点 Approve。
 *
 * <h3>为什么 root CLI 优先(而不是直接用通知)</h3>
 *
 * 2026-10-15 实测(rubens / MTK 天玛 8100):daemon 构建 scope 请求通知时会在
 * {@code NotificationManager.getBitmap()} 撞上联发科私有类的空指针,
 * 整个 binder 事务被打断,通知从未发出:
 *
 * <pre>
 *   13:40:19.571  FunJni 保存配置 + requestScope(com.zhenxi.hunter)
 *   13:40:19.582  W Binder: Caught a RuntimeException from the binder stub implementation.
 *                   android.content.res.Resources$NotFoundException:
 *                     Drawable org.matrix.vector.daemon:drawable/ic_statue_monochrome
 *                   Caused by: java.lang.NullPointerException
 *                     at com.mediatek.res.AsyncDrawableCache.putCacheList(...:165)   &lt;- MTK 私有
 *                     at android.content.res.ResourcesImpl.cacheDrawable(...:800)
 *                     at ad.onTransact(...)                                        &lt;- daemon binder stub
 *   13:41:19.578  FunJni: ScopeSync sync result: success=false msg=等待 Vector 授权超时  (60s 后)
 * </pre>
 *
 * 根因在 {@code FileSystem.resources}(反射手工构造的 {@code Resources(am, null, null)},
 * 无真实 DisplayMetrics/Configuration)在 MIUI 的 {@code MiuiResourcesImpl} 上触发了 MTK
 * 的 drawable 缓存分支。它与模块代码无关,但会吃掉整条通知通道。
 *
 * <p>所以有 root 时优先走 CLI —— 既零交互,也顺带避开通知通道的所有坑。
 * 无 root 时才退回通知(那条路上第一次必须用户点一次"允许",
 * 因为 Vector 把 scope 变更定义为需知情同意的操作)。
 *
 * <p>AIDL 里 requestScope 是 oneway,回调也是 oneway,所以通知通道必须等到
 * onScopeRequestApproved/onScopeRequestFailed 才算完成;本类用 CountDownLatch 把它
 * 转成同步结果,方便在保存配置的流程里顺序调用。
 */
public final class ScopeSyncUtils {

    private static final String TAG = "ScopeSync";
    private static final long REQUEST_TIMEOUT_SECONDS = 60L;
    /** 服务尚未投递时最多等多久(冷启动场景:FunJni 刚被拉起,daemon 还没送 binder)。 */
    private static final long SERVICE_WAIT_SECONDS = 5L;
    /** root CLI 通道的超时;daemon 自己会快得多,这里的超时是为了防 su 卡死。 */
    private static final long CLI_TIMEOUT_SECONDS = 15L;

    /** daemon 启动时由 FileSystem.setupCli() 拷到这里。 */
    private static final String CLI_PATH = "/data/adb/lspd/cli";
    /** 模块自己的包名,作为 scope add 的第一个参数。 */
    private static final String MODULE_PACKAGE = BuildConfig.APPLICATION_ID;

    /** 框架服务句柄;回调可能来自 binder 线程,所以用 volatile + 主线程可见性保证。 */
    private static volatile WbService sService;
    private static volatile boolean sListenerRegistered;

    /**
     * 本进程内已经同步过的包,避免重复跑 CLI / 重复弹通知。
     *
     * <p>用普通 Set 而非 WeakHashMap:键是运行期新建的 String,WeakHashMap 会把它当
     * 弱引用在下次 GC 时清掉,于是同一个包会被反复同步。包名数量很少,不值当为它做
     * 弱引用。重启后重新同步一次是廉价且正确的行为。
     */
    private static final Set<String> sAutoApproved =
            Collections.synchronizedSet(new HashSet<String>());

    private ScopeSyncUtils() {
    }

    /**
     * 注册服务监听。幂等,可以在 Application.onCreate 与 Activity.onCreate 都调。
     *
     * <p>必须在任何 requestScope 之前调用:WbServiceHelper 在 registerListener 之前收到的
     * binder 只会被缓存,不会回调;注册后会把缓存里的一并回调过来,所以顺序上不会漏。
     */
    public static void init(Context context) {
        if (sListenerRegistered) {
            return;
        }
        synchronized (ScopeSyncUtils.class) {
            if (sListenerRegistered) {
                return;
            }
            try {
                WbServiceHelper.registerListener(new WbServiceHelper.OnServiceListener() {
                    @Override
                    public void onServiceBind(@NonNull WbService service) {
                        sService = service;
                        CLog.i(TAG + " Vector service bound: "
                                + safeFrameworkName(service));
                    }

                    @Override
                    public void onServiceDied(@NonNull WbService service) {
                        if (sService == service) {
                            sService = null;
                        }
                        CLog.e(TAG + " Vector service died");
                    }
                });
                sListenerRegistered = true;
                CLog.i(TAG + " Vector service listener registered");
            } catch (Throwable e) {
                // 框架没装 / jar 与框架版本不匹配时不要让模块 App 崩在启动路径上。
                CLog.e(TAG + " registerListener failed: " + e, e);
            }
        }
    }

    /** 框架服务是否已就绪(UI 可以据此显示"已连接 Vector")。 */
    public static boolean isServiceAvailable() {
        return sService != null;
    }

    /**
     * 自动同步链路是否可用:root CLI 或 Vector 服务任一就绪即可。
     *
     * <p>供 UI 提示用。root CLI 优先,所以即使 WbService 没投递到(例如 daemon 在
     * MIUI/MTK 上构建通知图标崩溃),只要设备有 root,同步依旧可用。
     *
     * <p>会计一次 root 探测,所以不要在布局渲染的热路径里反复调。
     */
    public static boolean isSyncAvailable() {
        return sService != null || RootUtils.checkGetRootAuth();
    }

    /** 同步结果,供 UI 区分"已批准/被拒/超时/框架不可用"。 */
    public static final class Result {
        public final boolean success;
        public final boolean serviceUnavailable;
        public final String message;

        private Result(boolean success, boolean serviceUnavailable, String message) {
            this.success = success;
            this.serviceUnavailable = serviceUnavailable;
            this.message = message;
        }

        static Result ok(String msg) {
            return new Result(true, false, msg);
        }

        static Result fail(String msg) {
            return new Result(false, false, msg);
        }

        static Result noService(String msg) {
            return new Result(false, true, msg);
        }
    }

    /**
     * 把 {@code targetPackages} 追加进 FunJni 在 Vector 里的 scope。
     *
     * <p>先试 root CLI(立刻返回),不可用时才回退到 requestScope 通知。
     * 通知通道会阻塞等待用户批准(最长 {@link #REQUEST_TIMEOUT_SECONDS} 秒),
     * <b>所以必须在线程调用</b>,不要放在主线程。
     *
     * @param context        任意 context,仅用于 toast 与日志
     * @param targetPackages 目标包名,已同步过的会从后续请求里剔除
     * @return 同步结果;成功时表示这些包已进 scope 并已触发注入
     */
    public static Result syncScope(Context context, List<String> targetPackages) {
        if (targetPackages == null || targetPackages.isEmpty()) {
            return Result.ok("没有需要同步的目标");
        }

        // 去掉已经批准过的,只把新包发给框架,避免重复弹同一条通知。
        final List<String> pending = new ArrayList<>();
        for (String pkg : targetPackages) {
            if (pkg == null || pkg.isEmpty()) {
                continue;
            }
            if (sAutoApproved.contains(pkg)) {
                continue;
            }
            if (!pending.contains(pkg)) {
                pending.add(pkg);
            }
        }
        if (pending.isEmpty()) {
            return Result.ok("目标已在 Vector scope 中");
        }

        // ── 通道 1:root CLI(优先)────────────────────────────────────────
        //
        // 实测(2026-10-15,rubens/MTK):daemon 构建 scope 请求通知时会在
        // NotificationManager.getBitmap() 撞上联发科的 AsyncDrawableCache NPE
        // (com.mediatek.res.AsyncDrawableCache.putCacheList),整个 binder 事务被
        // 打断 —— 通知从未发出,模块侧只能等到 60s 超时。日志形态:
        //
        //   W Binder: Caught a RuntimeException from the binder stub implementation.
        //     Resources$NotFoundException: Drawable ...:drawable/ic_statue_monochrome
        //     Caused by: NPE at com.mediatek.res.AsyncDrawableCache.putCacheList
        //       at ad.onTransact(daemon 的 IWbService stub)
        //
        // 而 vector-cli 走的是 daemon 的 LocalSocket,完全不碰通知/资源,不受此 bug 影响:
        //
        //   su -c "/data/adb/lspd/cli scope add <模块包> <目标包>"   ->  退出码 0
        //
        // 所以有 root 时优先走 CLI:零交互、完全自动,也顺带避开了通知通道的所有坑。
        final Result cliResult = syncViaRootCli(pending);
        if (cliResult != null) {
            if (cliResult.success) {
                for (String pkg : pending) {
                    sAutoApproved.add(pkg);
                }
            }
            return cliResult;
        }

        // ── 通道 2:requestScope 通知(无 root / CLI 不可用时兜底)──────
        final WbService service = awaitService();
        if (service == null) {
            return Result.noService(
                    "未连上 Vector 服务,也没有 root 可用:请启用模块并重启 FunJni,或去管理面板手动勾选");
        }

        // 已经是 scope 成员的就跳过,减少通知里的噪音(也是幂等保护)。
        try {
            final List<String> current = service.getScope();
            if (current != null) {
                pending.removeAll(current);
            }
        } catch (Throwable e) {
            // getScope 失败不影响主流程:交给 requestScope 自己去判重。
            CLog.e(TAG + " getScope failed: " + e);
        }
        if (pending.isEmpty()) {
            return Result.ok("目标已在 Vector scope 中");
        }

        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<Result> outcome = new AtomicReference<>();

        try {
            service.requestScope(pending, new WbService.OnScopeEventListener() {
                @Override
                public void onScopeRequestApproved(@NonNull List<String> approved) {
                    for (String pkg : approved) {
                        sAutoApproved.add(pkg);
                    }
                    outcome.set(Result.ok("已批准并同步进 Vector scope: " + approved));
                    latch.countDown();
                }

                @Override
                public void onScopeRequestFailed(@NonNull String message) {
                    outcome.set(Result.fail("Vector 拒绝了 scope 请求: " + message));
                    latch.countDown();
                }
            });
        } catch (Throwable e) {
            CLog.e(TAG + " requestScope threw: " + e, e);
            return Result.fail("scope 请求失败: " + e);
        }

        boolean answered;
        try {
            // 用户要点通知,给足时间;超时说明通知被划掉或没看到。
            answered = latch.await(REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Result.fail("等待 Vector 授权被中断");
        }

        final Result result = outcome.get();
        if (!answered || result == null) {
            return Result.fail("等待 Vector 授权超时,请在通知栏点\"允许\"后重试");
        }
        return result;
    }

    /**
     * 通过 root 跑 vector-cli 把目标加进 scope。
     *
     * <p>走 daemon 的 LocalSocket(`/data/adb/lspd/.cli_sock`),不碰通知与资源,
     * 所以不受 MIUI/MTK 那个图标 NPE 影响。实测可用:
     *
     * <pre>
     *   # /data/adb/lspd/cli scope add com.zhenxi.jnitrace com.zhenxi.hunter
     *   Successfully appended 1 apps to com.zhenxi.jnitrace scope.   (退出码 0)
     * </pre>
     *
     * <p>daemon 侧 CliHandler.handleScope 的 "add" 分支会自己做全部校验
     * (rejectBeyondStaticScope / 已有去重)并调 ModuleDatabase.setModuleScope,
     * 后者触发 ConfigCache.requestCacheUpdate() —— 所以加完立即生效。
     *
     * @return 成功/失败的 Result;null 表示「这条路不可用」(无 root 或 cli 不存在),
     *         调用方应回退到 requestScope 通知通道。
     */
    private static Result syncViaRootCli(List<String> pending) {
        // RootUtils.execShell 不返回退出码,这里需要自己跑并读 exit code,
        // 否则会把「su 被拒」当成「同步成功」。
        //
        // redirectErrorStream(true):CLI 的错误走 System.err(OutputFormatter 里
        // System.err.println("Error: ..."))。若不合并而只读 stdout,stderr 缓冲区写满时
        // 子进程会阻塞,stdout 永远等不到 EOF —— 经典管道死锁。
        Process process = null;
        BufferedReader reader = null;
        try {
            if (!RootUtils.checkGetRootAuth()) {
                CLog.i(TAG + " no root; falling back to requestScope");
                return null;
            }

            // CLI 路径:daemon 启动时 FileSystem.setupCli() 会把脚本拷到这里
            final StringBuilder cmd = new StringBuilder();
            cmd.append(CLI_PATH).append(" scope add ").append(MODULE_PACKAGE);
            for (String pkg : pending) {
                cmd.append(' ').append(pkg);
            }

            process = new ProcessBuilder("su").redirectErrorStream(true).start();
            final DataOutputStream os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(cmd + "\n");
            // 让 su 执行完就退出,否则 waitFor 会一直等输入。
            // sh 的裸 exit 不带参数时,退出码 = 最后一条命令的退出码,
            // 所以 CLI 的 0/1 能传到我们这里。
            os.writeBytes("exit\n");
            os.flush();
            os.close();

            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            final StringBuilder stdout = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stdout.append(line).append('\n');
            }

            if (!process.waitFor(CLI_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                CLog.e(TAG + " vector-cli timed out: " + cmd);
                return null;
            }

            final int exit = process.exitValue();
            final String out = stdout.toString().trim();
            CLog.i(TAG + " vector-cli exit=" + exit + " out=" + out);

            if (exit == 0 && out.contains("Successfully")) {
                return Result.ok("已同步进 Vector scope(root CLI): " + pending);
            }

            // 退出码非 0。只有 staticScope 拒绝是确定性的 —— 那条 requestScope 也会拒,
            // 再弹一次通知没意义。其余(daemon 没跑 / socket 不存在 / cli 脚本缺失)
            // 都应该回退到通知通道,那里是另一条完全不同的路。
            if (out.contains("fixes its scope")) {
                return Result.fail("Vector 拒绝了 scope 请求(模块声明了 staticScope): " + out);
            }
            CLog.w(TAG + " vector-cli unusable (exit=" + exit + " out=" + out + "), falling back");
            return null;
        } catch (Throwable e) {
            // 没 root / cli 缺失 / su 报错 —— 都不是致命错误,交给通知通道。
            CLog.i(TAG + " vector-cli path unavailable: " + e);
            return null;
        } finally {
            try {
                if (reader != null) {
                    reader.close();
                }
            } catch (IOException ignored) {
            }
            if (process != null) {
                process.destroy();
            }
        }
    }

    /**
     * 在后台线程做同步,并在主线程 toast 结果。用于保存配置之后"顺手生效"。
     *
     * <p>调用方不用关心线程,方法自己起线程。
     */
    public static void syncScopeAsync(final Context context, final List<String> targetPackages) {
        if (targetPackages == null || targetPackages.isEmpty()) {
            return;
        }
        final Context appContext = context == null ? null : context.getApplicationContext();
        new Thread(new Runnable() {
            @Override
            public void run() {
                final Result result = syncScope(appContext, targetPackages);
                CLog.i(TAG + " sync result: success=" + result.success
                        + " noService=" + result.serviceUnavailable
                        + " msg=" + result.message);
                if (appContext == null) {
                    return;
                }
                // 用户已经能在通知栏看到结果,只有失败/需要人工介入时才打扰。
                if (!result.success && !result.serviceUnavailable) {
                    new Handler(Looper.getMainLooper()).post(new Runnable() {
                        @Override
                        public void run() {
                            ToastUtils.showToast(appContext, result.message);
                        }
                    });
                }
            }
        }, "FunJni-ScopeSync").start();
    }

    /**
     * 等框架服务就绪。
     *
     * <p>binder 是 daemon 主动送的,App 启动早期可能还没到;冷启动时通常几十毫秒内完成。
     * 这里最多等 {@link #SERVICE_WAIT_SECONDS} 秒,不做无限等待。
     */
    private static WbService awaitService() {
        WbService service = sService;
        if (service != null) {
            return service;
        }
        final long deadline = System.currentTimeMillis() + SERVICE_WAIT_SECONDS * 1000L;
        while (System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(100L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return sService;
            }
            service = sService;
            if (service != null) {
                return service;
            }
        }
        return sService;
    }

    private static String safeFrameworkName(WbService service) {
        try {
            return service.getFrameworkName() + " " + service.getFrameworkVersion()
                    + " (api " + service.getApiVersion() + ")";
        } catch (Throwable e) {
            return "<unknown>";
        }
    }
}
package com.zhenxi.jnitrace.utils;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
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
 * Vector 自带 libxposed service 接口,模块 App 在自己的进程里可以拿到框架服务:
 * <pre>
 *   daemon  ModuleAppService.sendBinder(uid)
 *     -> getContentProviderExternal("&lt;applicationId&gt;.WbService", ...)
 *     -> provider.call("SendBinder", {binder: IWbService})
 *   app     WbProvider.call() -> WbServiceHelper.onBinderReceived()
 *     -> WbServiceHelper.registerListener() 的回调拿到 WbService 句柄
 * </pre>
 * 拿到句柄后调 {@code requestScope(packages, callback)}:daemon 侧
 * {@code ModuleAppService.requestScope} 会校验 staticScope、检查"永不询问"拉黑,
 * 然后弹一条高优先级通知(NotificationManager.requestModuleScope)让用户点 Approve,
 * 批准后 {@code ModuleDatabase.setModuleScope} 落库并触发 ConfigCache 重建 —— 立即生效。
 *
 * <p>注意 AIDL 里 requestScope 是 oneway,回调也是 oneway,所以必须等到
 * onScopeRequestApproved/onScopeRequestFailed 才算完成;本类用 CountDownLatch 把它
 * 转成同步结果,方便在保存配置的流程里顺序调用。
 *
 * <h3>为什么不能只是"后台静默"</h3>
 * Vector 把"模块要进哪些 App 的 scope"当作需要用户知情同意的操作,所以第一次必然有
 * 一条通知。用户在那条通知上点 Approve 时如果选"不再询问"(daemon 侧落到
 * PreferenceStore 的 scope_request_blocked 反向集合之外),后续调用才会直接通过。
 * 换句话说:第一次一次点击,之后就是"选中即生效"。
 */
public final class ScopeSyncUtils {

    private static final String TAG = "ScopeSync";
    private static final long REQUEST_TIMEOUT_SECONDS = 60L;
    /** 服务尚未投递时最多等多久(冷启动场景:FunJni 刚被拉起,daemon 还没送 binder)。 */
    private static final long SERVICE_WAIT_SECONDS = 5L;

    /** 框架服务句柄;回调可能来自 binder 线程,所以用 volatile + 主线程可见性保证。 */
    private static volatile WbService sService;
    private static volatile boolean sListenerRegistered;

    /** 已完成"不再询问"授权的包,避免每次都等通知。进程内缓存,重启后重新走一次通知。 */
    private static final Map<String, Boolean> sAutoApproved =
            Collections.synchronizedMap(new WeakHashMap<String, Boolean>());

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
     * <p>阻塞等待用户批准(最长 {@link #REQUEST_TIMEOUT_SECONDS} 秒),<b>必须在线程调用</b>,
     * 不要放在主线程 —— 用户可能十几秒后才点通知。
     *
     * @param context        任意 context,仅用于 toast 与日志
     * @param targetPackages 目标包名,已批准的会从后续请求里剔除
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
            if (Boolean.TRUE.equals(sAutoApproved.get(pkg))) {
                continue;
            }
            if (!pending.contains(pkg)) {
                pending.add(pkg);
            }
        }
        if (pending.isEmpty()) {
            return Result.ok("目标已在 Vector scope 中");
        }

        final WbService service = awaitService();
        if (service == null) {
            return Result.noService(
                    "未连上 Vector 服务,请确认模块已启用并重启 FunJni 后重试");
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
                        sAutoApproved.put(pkg, Boolean.TRUE);
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
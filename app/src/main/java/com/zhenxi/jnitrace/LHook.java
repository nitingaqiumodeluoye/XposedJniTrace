package com.zhenxi.jnitrace;

import static com.zhenxi.jnitrace.config.ConfigKey.CONFIG_JSON;
import static com.zhenxi.jnitrace.config.ConfigKey.FILTER_LIST;
import static com.zhenxi.jnitrace.config.ConfigKey.IS_LISTEN_TO_ALL;
import static com.zhenxi.jnitrace.config.ConfigKey.IS_SERIALIZATION;
import static com.zhenxi.jnitrace.config.ConfigKey.LIST_OF_FUNCTIONS;
import static com.zhenxi.jnitrace.config.ConfigKey.MOUDLE_SO_PATH;
import static com.zhenxi.jnitrace.config.ConfigKey.PACKAGE_NAME;
import static com.zhenxi.jnitrace.config.ConfigKey.SAVE_TIME;

import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;

import androidx.core.app.NotificationCompat;

import com.zhenxi.jnitrace.utils.CLog;
import com.zhenxi.jnitrace.utils.ChooseUtils;
import com.zhenxi.jnitrace.utils.ContextUtils;
import com.zhenxi.jnitrace.utils.FileUtils;
import com.zhenxi.jnitrace.utils.GsonUtils;
import com.zhenxi.jnitrace.utils.ThreadUtils;

import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import de.wwb.android.wbosed.XSharedPreferences;
import de.wwb.android.wbosed.api.WbModule;
import de.wwb.android.wbosed.api.WbModuleInterface;


/**
 * Vector 模块入口。
 *
 * 走 MODERN 路线(module.prop 里 targetApiVersion=101):
 *   - 101 < 102,所以 legacy API(XSharedPreferences 等)仍然可用;
 *   - 但加载走 MODERN:daemon 读 META-INF/xposed/java_init.list + native_init.list,
 *     模块 so 由 Vector soLoader 匿名装载并把 NativeAPIEntries 交给 native_init,
 *     不会像 legacy 路径那样要求模块自己 System.loadLibrary(APK zip entry 直载 linker)。
 *
 * 101 与 102 的差别只在 legacy API 是否被封禁
 * (VectorModuleManager: blockLegacyApi = targetApiVersion >= 102)。
 */
public class LHook extends WbModule {

    private static final String DEF_VALUE = "DEF";


    /**
     * 目标的包名
     */
    private static String mTagPackageName = null;

    /**
     * 进程名字
     */
    private static String mProcessName = null;
    /**
     * 注入模块的so文件路径
     */
    private static String mIntoSoPath = null;

    private static long mSaveTime = 0;
    /**
     * 是否开启内存序列化
     */
    private static boolean isSerialization = false;

    /**
     * 是否监听全部的SO调用
     */
    private static boolean isListenAll = false;

    private static final ArrayList<String> mFilterList = new ArrayList<>();

    private static final ArrayList<String> mFunctionList = new ArrayList<>();

    /**
     * start hook jni
     *
     * @param filterList   so name filter list
     * @param functionList function list
     * @param save_path    save file path ,when the null is not saved
     */
    public static native void startHookJni(boolean isHookAll,
                                           ArrayList<String> filterList,
                                           ArrayList<String> functionList,
                                           String save_path);


    private static boolean isInit = false;

    private void initConfigData(String configJson) {
        if (configJson == null || configJson.length() == 0 || configJson.equals(DEF_VALUE)) {
            return;
        }
        try {
            JSONObject json = new JSONObject(configJson);
            mTagPackageName = json.optString(PACKAGE_NAME, DEF_VALUE);
            mIntoSoPath = json.optString(MOUDLE_SO_PATH, DEF_VALUE);
            mSaveTime = json.optLong(SAVE_TIME, 0L);
            isSerialization = json.optBoolean(IS_SERIALIZATION, false);

            String functionList = json.optString(LIST_OF_FUNCTIONS, DEF_VALUE);
            CLog.e("json get function list str info -> " + functionList);
            if (!functionList.equals(DEF_VALUE)) {
                ArrayList<?> arrayList = GsonUtils.str2obj(functionList, ArrayList.class);
                if (arrayList != null) {
                    CLog.e("function list get info -> " + arrayList);
                    for (Object obj : arrayList) {
                        String item = String.valueOf(obj);
                        CLog.e("function list add  " + obj);
                        mFunctionList.add(item);
                    }
                } else {
                    CLog.e("function list  == null !!!!!!!");
                }
            }

            isListenAll = json.optBoolean(IS_LISTEN_TO_ALL, false);
            if (!isListenAll) {
                String filterList = json.optString(FILTER_LIST, DEF_VALUE);
                if (!filterList.equals(DEF_VALUE)) {
                    ArrayList<?> arrayList = GsonUtils.str2obj(filterList, ArrayList.class);
                    if (arrayList != null) {
                        for (Object obj : arrayList) {
                            mFilterList.add((String) obj);
                        }
                        CLog.e("filter so list  " + mFilterList);
                    } else {
                        CLog.e("filter so list  == null !!!!!!!");
                    }
                }
            }
        } catch (Throwable e) {
            CLog.e("initConfigData error " + e, e);
        }
    }

    /**
     * 从进程名推导包名(子进程形如 com.foo:remote)。
     * MODERN 路线拿不到 LoadPackageParam,但配置里的目标包名和被注入进程是一致的,
     * 而日志/序列化文件都写在目标包自己的 data 目录下,所以按进程名推导即可。
     */
    private static String packageNameOf(String processName) {
        if (processName == null) {
            return null;
        }
        int idx = processName.indexOf(':');
        return idx > 0 ? processName.substring(0, idx) : processName;
    }

    @Override
    public void onModuleLoaded(WbModuleInterface.ModuleLoadedParam param) {
        mProcessName = param.getProcessName();
        final String processPackageName = packageNameOf(mProcessName);

        try {
            String configJson = DEF_VALUE;
            try {
                //尝试通过 XSharedPreferences 读取
                XSharedPreferences shared = new XSharedPreferences(BuildConfig.APPLICATION_ID, "config");
                shared.reload();
                configJson = shared.getString(CONFIG_JSON, DEF_VALUE);
                CLog.i(">>>>>>>>> XSharedPreferences find config package name " + configJson);
                initConfigData(configJson);
            } catch (Throwable e) {
                CLog.e("handleLoadPackage XSharedPreferences getString error " + e);
                configJson = DEF_VALUE;
            }
            //二次尝试读取root移动过来的配置文件
            if (configJson.equals(DEF_VALUE)) {
                String configInfo = null;
                try {
                    CLog.i("find config package name == null ,start read config  ");
                    File file = new File("/data/data/" +
                            processPackageName + "/" + BuildConfig.project_name + "Config");
                    if (!file.exists()) {
                        CLog.e("not find root config file " + file.getPath());
                        return;
                    }
                    file.setExecutable(true, false);
                    file.setReadable(true, false);
                    file.setWritable(true, false);

                    configInfo = FileUtils.readToString(file);
                    CLog.i("start read config success  " + configInfo);
                } catch (Throwable e) {
                    //这里最常见的是 EACCES (Permission denied)。它不是 Unix 权限问题,
                    //而是 SELinux 的 MCS 类别不匹配:配置文件是从模块自己的目录弄过来的,
                    //标签带的是模块自己的类别(app_data_file:s0:c<模块appid>),
                    //目标 App 的类别是 c<目标appid>,两边不同 → SELinux 直接拒绝,
                    //chmod 777 一点用没有。
                    //解法在写入侧(MainListViewAdapter.initConfig):用 cp 新建文件而不是 mv,
                    //让文件拿到不带 MCS 类别的标签。
                    CLog.e("read root file config error (若是 EACCES 请看写入侧是否用了 cp 而不是 mv) " + e, e);
                }
                initConfigData(configInfo);
            }

            CLog.i("load process -> " + mProcessName
                    + " (package " + processPackageName + ")"
                    + "  tag package name -> " + mTagPackageName);

            if (isMatch(processPackageName)) {
                CLog.e("find tag app ->  " + processPackageName);
                CLog.i("[" + mTagPackageName + "] init config success ! isSerialization -> "
                        + isSerialization + "  is hook all -> " + isListenAll
                        + "  functions -> " + mFunctionList);
                startInit();
            }
        } catch (Throwable e) {
            e.printStackTrace();
            CLog.e("onModuleLoaded Exception  " + e.getMessage());
        }
    }


    private boolean isMatch(String packageName) {
        //包名匹配&&10分钟的有效期
        return packageName.equals(mTagPackageName);
                //&& (System.currentTimeMillis() - mSaveTime) < (1000 * 60 * 10);
    }

    /**
     * 初始化。
     *
     * 变更点(相对老的 Xposed 版本):
     *   1. 不再需要 passApiCheck() —— Vector 会对模块 ClassLoader 做 hidden api 豁免
     *      (VectorModuleManager 里的 HookBridge.exemptModuleClassLoaderHiddenApi);
     *   2. 不再需要 intoMySo() 解压 + 反射注入 —— 模块 so 由 Vector 的 soLoader 装载,
     *      native 入口是 native_init(见 app/src/main/cpp/main.cpp);
     *   3. 只有内存漫游还需要 Context(取包名/路径),所以 Context 的获取只给这一条路径用。
     */
    @SuppressWarnings("all")
    private void startInit() {
        if (isSerialization) {
            // 内存漫游只需要一个能取到包名/文件路径的 Context。
            // 原来这里 hook android.app.ContextImpl#createAppContext 来拿 Context ——
            // MODERN 路线里模块拿到的是 WbModule 上下文,不需要也不该再去 hook ContextImpl;
            // ContextUtils 自己会用 VMDebug.getInstancesOfClasses 找 Application 实例。
            startSerialization(ContextUtils.getContext());
        } else {
            initFunJni();
        }
    }

    @SuppressWarnings("all")
    private void startSerialization(Context context) {
        try {
            //手动触发gc,清空多余实例
            System.gc();
            final File file = new File("/data/data/"
                    + mTagPackageName + "/" + mProcessName + "_MemorySerializationInfo.txt");
            if (file.exists()) {
                file.delete();
            }
            file.createNewFile();
            //子线程和主线程共享数据
            ThreadUtils.runOnNonUIThread(() -> {
                ArrayList<Object> choose = ChooseUtils.choose(Object.class, true);
                int size = choose.size();
                CLog.e("memory object size -> " + size);
                for (int index = 0; index < size; index++) {
                    Object obj = choose.get(index);
                    String objStr = GsonUtils.obj2str(obj);
                    if (objStr != null) {
                        String objClassName = obj.getClass().getName();
                        String infoStr = index + "/" + size + "[" + mProcessName + "]" + objClassName + " " + objStr + "\n";
                        //增加效率暂不打印进度
                        //printfProgress(size,index,context);
                        //ToastUtils.showToast(context,"MemorySerialization["+index+"/"+size+"]");
                        CLog.i(infoStr);
                        FileUtils.saveStringNoClose(infoStr, file);
                    }
                }
                FileUtils.saveStringClose();
            }, 30 * 1000);
        } catch (Throwable e) {
            CLog.e("startSerialization error " + e);
        }
    }

    private static final int NOTIFICATION_ID = 8888;
    private static final String CHANNEL_ID = "MEMORY_SERIALIZATION";
    private NotificationCompat.Builder builder = null;

    @SuppressWarnings("unused")
    private void printfProgress(int max, int index, Context context) {
        try {
            ThreadUtils.runOnMainThread(() -> {
                if (builder == null) {
                    NotificationManager notificationManager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
                    builder =
                            new NotificationCompat.Builder(context, CHANNEL_ID)
                                    .setSmallIcon(R.drawable.ic_launcher_foreground)
                                    .setContentTitle("MemorySerialization")
                                    .setProgress(max, index, false);
                    //显示Notification
                    notificationManager.notify(NOTIFICATION_ID, builder.build());
                }
                builder.setProgress(max, index, false);
                builder.setContentText("Downloaded " + index + "%");
            });
        } catch (Throwable e) {
            CLog.e("printfProgress error " + e);
        }
    }

    @SuppressWarnings("All")
    private void initFunJni() {
        if (isInit) {
            return;
        }
        if (mFunctionList == null || mFunctionList.isEmpty()) {
            CLog.e("function list size == 0 !!!!!!!!!!!!!!!!! " + mProcessName);
            CLog.e("function list size == 0 !!!!!!!!!!!!!!!!! " + mTagPackageName);
            CLog.e("function list size == 0 !!!!!!!!!!!!!!!!! ");
            return;
        }
        isInit = true;
        CLog.i(">>>>>>>> start init funJni , process [" + mProcessName + "]");
        try {
            // 输出文件放在目标 app 自己的私有目录下(注入进程就是目标进程,uid 相同,可写)
            File file = new File("/data/data/"
                    + mTagPackageName + "/(" + mProcessName + ")"
                    + (isListenAll ? "[ALL]" : mFilterList.toString()) + ".txt");
            if (file.exists()) {
                file.delete();
            }
            file.createNewFile();
            CLog.i(">>>>>>>>>>> start hook jni " + file.getPath());
            //start hook native
            startHookJni(isListenAll, mFilterList, mFunctionList, file.getPath());
        } catch (Throwable e) {
            CLog.e("start hook jni error " + e);
        }
    }


}

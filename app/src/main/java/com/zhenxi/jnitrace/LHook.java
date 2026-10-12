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

import de.wwb.android.wbosed.IXposedHookZygoteInit;
import de.wwb.android.wbosed.WbLoadPackage;
import de.wwb.android.wbosed.XC_MethodHook;
import de.wwb.android.wbosed.XSharedPreferences;
import de.wwb.android.wbosed.XposedBridge;
import de.wwb.android.wbosed.callbacks.XC_LoadPackage;


public class LHook implements WbLoadPackage, IXposedHookZygoteInit {

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

    @Override
    @SuppressWarnings("all")
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        mProcessName = loadPackageParam.processName;

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
                            loadPackageParam.packageName + "/" + BuildConfig.project_name + "Config");
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
                    CLog.e("read root file config error " + e, e);
                }
                initConfigData(configInfo);
            }

            CLog.i("load app -> " +
                    loadPackageParam.packageName + " process name ->[" + mProcessName + "]" +
                    "  tag package name -> " + mTagPackageName);

            if (isMatch(loadPackageParam.packageName)) {
                CLog.e("find tag app ->  " + loadPackageParam.packageName);
                CLog.i("[" + mTagPackageName + "]init config success ! isSerialization -> "
                        + isSerialization + "  into so path -> " + mIntoSoPath + " is hook all -> " + isListenAll);
                startInit();
            }
        } catch (Throwable e) {
            e.printStackTrace();
            CLog.e("handleLoadPackage  Exception  " + e.getMessage());
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
            Context context = ContextUtils.getContext();
            if (context != null) {
                startSerialization(context);
                return;
            }
            try {
                XposedBridge.hookAllMethods(
                        Class.forName("android.app.ContextImpl"),
                        "createAppContext",
                        new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                super.afterHookedMethod(param);
                                CLog.e("hook createAppContext success !");
                                startSerialization((Context) param.getResult());
                            }
                        });
            } catch (Throwable e) {
                CLog.e("hook createAppContext error  " + e.getMessage());
            }
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


    @Override
    public void initZygote(StartupParam startupParam) {

    }


}

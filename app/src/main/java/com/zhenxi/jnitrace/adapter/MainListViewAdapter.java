package com.zhenxi.jnitrace.adapter;

import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageInfo;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;


import com.zhenxi.jnitrace.BuildConfig;
import com.zhenxi.jnitrace.R;
import com.zhenxi.jnitrace.bean.AppBean;

import com.zhenxi.jnitrace.utils.CLog;
import com.zhenxi.jnitrace.utils.Constants;
import com.zhenxi.jnitrace.utils.FileUtils;
import com.zhenxi.jnitrace.utils.GsonUtils;
import com.zhenxi.jnitrace.utils.RootUtils;
import com.zhenxi.jnitrace.utils.SpUtil;
import com.zhenxi.jnitrace.utils.ToastUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;


import static com.zhenxi.jnitrace.config.ConfigKey.CONFIG_JSON;
import static com.zhenxi.jnitrace.config.ConfigKey.FILTER_LIST;
import static com.zhenxi.jnitrace.config.ConfigKey.IS_LISTEN_TO_ALL;
import static com.zhenxi.jnitrace.config.ConfigKey.IS_SERIALIZATION;
import static com.zhenxi.jnitrace.config.ConfigKey.LIST_OF_FUNCTIONS;
import static com.zhenxi.jnitrace.config.ConfigKey.MOUDLE_SO_PATH;
import static com.zhenxi.jnitrace.config.ConfigKey.PACKAGE_NAME;
import static com.zhenxi.jnitrace.config.ConfigKey.SAVE_TIME;


import androidx.appcompat.app.AlertDialog;

import org.json.JSONObject;


/**
 * Created by lyh on 2019/2/14.
 */
public class MainListViewAdapter extends BaseAdapter {


    private ArrayList<AppBean> data;

    private final Context mContext;
    private final CheckBox isSerialization;


    private AppBean mAppBean = null;

    public MainListViewAdapter(Context context,
                               ArrayList<AppBean> data,
                               CheckBox info) {
        this.mContext = context;
        this.data = data;
        this.isSerialization = info;

    }


    public void setData(ArrayList<AppBean> data) {

        this.data = data;

        notifyDataSetChanged();
    }


    @Override
    public int getCount() {
        return data == null ? 0 : data.size();
    }

    @Override
    public Object getItem(int position) {
        return data.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(final int position, View convertView, ViewGroup parent) {

        if (convertView == null) {
            convertView = View.inflate(mContext, R.layout.activity_list_item, null);
        }
        ViewHolder holder = ViewHolder.getHolder(convertView);
        AppBean appBean = data.get(position);

        holder.iv_appIcon.setImageBitmap(Constants.drawable2Bitmap(appBean.appIcon));
        holder.tv_appName.setText(appBean.appName);
        holder.tv_packageName.setText(appBean.packageName);
        holder.All.setOnClickListener(v ->
                initConfig(appBean)
        );
        return convertView;
    }

    private static final String[] items = {
            "JniTrace(JniEnv交互监听)",
            "libcString处理函数监听",
            "RegisterNative监听",
            "Linker加载SO监听",
            "监听全部Java方法调用(慎选,很容易造成程序卡顿)"
    };

    /**
     * 弹出对话框收集用户需要采集的So调用信息
     */
    private void showDialogForList(Context context) {
        View view = LayoutInflater.from(mContext).inflate(R.layout.dialog_input, null);
        EditText input = view.findViewById(R.id.ed_input);
        JSONObject jsonObject = new JSONObject();
        ArrayList<String> filtersList = new ArrayList<>();
        ArrayList<String> functionsList = new ArrayList<>();
        new AlertDialog.Builder(context)
                .setView(view)
                .setPositiveButton("确定", (dialog, which) -> {
                    String inputStr = input.getText().toString();
                    if (inputStr.length() == 0) {
                        ToastUtils.showToast(context, "输入错误,未找到需要需要监听的SO信息");
                        return;
                    }
                    try {
                        if (inputStr.equals("ALL")) {
                            jsonObject.put(IS_LISTEN_TO_ALL, true);
                        } else {
                            jsonObject.put(IS_LISTEN_TO_ALL, false);
                            String[] split = inputStr.split("\\|");
                            CLog.e("input str msg -> " + Arrays.toString(split));
                            filtersList.addAll(Arrays.asList(split));
                            if (!isSerialization.isChecked()) {
                                String listJsonStr = GsonUtils.obj2str(filtersList);
                                CLog.e("filter list json -> " + listJsonStr);
                                jsonObject.put(FILTER_LIST, listJsonStr);
                            }
                        }
                        String functionsStr = GsonUtils.obj2str(functionsList);
                        CLog.e("functions list json -> " + functionsStr);
                        jsonObject.put(LIST_OF_FUNCTIONS, functionsStr);
                    } catch (Throwable e) {
                        CLog.e("put filter list error " + e);
                    }
                    //保存数据
                    saveConfig(mAppBean, jsonObject);
                    // 点击了确认按钮
                    dialog.dismiss();
                })
                .setNegativeButton("取消", (dialog, which) -> {
                    // 点击了取消按钮
                    dialog.dismiss();
                })
                .setMultiChoiceItems(items, null, (dialog, which, isChecked) -> {
                    if (isChecked) {
                        functionsList.add(which+"");
                    } else {
                        functionsList.remove(which+"");
                    }
                    CLog.e("functions list " + functionsList);
                })
                .create()
                .show();
    }

    /**
     * 保存配置信息
     */
    public void initConfig(AppBean bean) {
        mAppBean = bean;
        if (!isSerialization.isChecked()) {
            //没有选中内存漫游,则执行正常逻辑,在弹窗里面进行保存
            showDialogForList(mContext);
            return;
        }
        saveConfig(bean, null);
    }

    private void saveConfig(AppBean bean, JSONObject jsonObject) {
        if (jsonObject == null) {
            jsonObject = new JSONObject();
        }
        try {
            jsonObject.put(PACKAGE_NAME, bean.packageName);
            try {
                PackageInfo packageInfo =
                        mContext.getPackageManager().getPackageInfo(BuildConfig.APPLICATION_ID, 0);
                jsonObject.put(MOUDLE_SO_PATH, packageInfo.applicationInfo.publicSourceDir);
            } catch (Throwable ignored) {
                jsonObject.put(MOUDLE_SO_PATH, null);
            }
            //保存时间,增加时效性
            jsonObject.put(SAVE_TIME, System.currentTimeMillis());
            jsonObject.put(IS_SERIALIZATION, isSerialization.isChecked());
        } catch (Throwable e) {
            CLog.e("save config to json error " + e);
        }
        saveConfigForLocation(bean, jsonObject);
    }

    private void saveConfigForLocation(AppBean bean, JSONObject jsonObject) {
        SpUtil.putString(mContext, CONFIG_JSON, jsonObject.toString());
        initConfig(bean.packageName, jsonObject);
        CLog.e("save config file info -> " + jsonObject);
        ToastUtils.showToast(mContext,
                "保存成功文件路径为\n" +
                        "data/data/" + bean.packageName);
    }

    /**
     * 把配置写一份到目标 App 的私有目录(目标进程里的模块从那里读)。
     *
     * 为什么不只用 XSharedPreferences:很多加壳 App 上
     * shared = new XSharedPreferences(BuildConfig.APPLICATION_ID, "config") 会失效,
     * 所以额外用 root 强行写一份到目标 App 私有目录兜底。
     *
     * 关于写入方式的一个坑(真机实测):
     * 原来是把模块自己创建的文件 mv 到目标目录 —— mv 是 rename(2),会保留源 inode
     * 和它的 SELinux 标签。源文件是模块自己创建的,标签带的是**模块的 MCS 类别**
     * (app_data_file:s0:c<模块appid>,...);而目标 App 的类别是 c<目标appid>。
     * MCS 规则要求"主体类别集合 ⊇ 客体类别集合",两边类别不同,所以就算文件权限
     * 是 777,SELinux 依然拒绝,目标进程读配置直接
     *   java.io.FileNotFoundException: ... open failed: EACCES (Permission denied)
     * 后果是这条兜底路静默失效(日志表现为 tag package name -> null,什么 hook 都不装),
     * 而 chmod 777 修不了它 —— 这是 SELinux 不是 Unix 权限。
     *
     * 改成先在目标目录里 cp 出一个临时文件:cp 新建 inode,标签由 root 生成
     * (app_data_file:s0,不带任何 MCS 类别);客体类别是空集,任何 App 的类别集合
     * 都能覆盖它,于是目标 App 就能正常读了。
     * 再同目录 mv 成正式名字:rename(2) 原子替换且保留刚拿到的正确标签,
     * 顺带把历史遗留的错标签文件顶掉。
     */
    @SuppressWarnings("All")
    private void initConfig(String packageName, JSONObject jsonObject) {
        try {

            File config = new File("/data/data/"
                    + BuildConfig.APPLICATION_ID + "/" + BuildConfig.project_name + "Config");
            config.setExecutable(true, false);
            config.setReadable(true, false);
            config.setWritable(true, false);
            CLog.e("temp config file path " + config.getPath());
            if (config.exists()) {
                boolean delete = config.delete();
                if (!delete) {
                    CLog.e("delete org config file error");
                }
            }
            CLog.e("start save config file " + config.getPath());
            FileUtils.saveString(config, jsonObject.toString());

            File temp = new File("/data/data/" + packageName);
            File tagFile = new File(temp.getPath() + "/" + BuildConfig.project_name + "Config");
            //先 cp 到临时名再 mv 成正式名:cp 负责拿到无 MCS 类别的标签,mv 负责原子替换。
            //
            //三条命令必须用 && 连成一条一次性交给 su,不能拆成多次 execShell:
            //原来的 execShell 写进 su 的 stdin 就返回、不等 waitFor,多次调用会各自起一个 su,
            //顺序毫无保证(rm/cp/mv 乱序执行会直接搞出半个配置文件)。
            //(execShell 那边也已经改成同步了,但一条命令本身就是更硬的保证。)
            final String tmpPath = tagFile.getPath() + ".tmp";
            CLog.i(">>>>>>>>> copy config " + config.getPath() + " -> " + tagFile.getPath());
            //关键链路用 && 连成一条,顺序有保证
            RootUtils.execShell("rm -f " + tmpPath
                    + " && cp -f " + config.getPath() + " " + tmpPath
                    + " && mv -f " + tmpPath + " " + tagFile.getPath()
                    //SELinux 那关靠 cp 解决;这里只是补 Unix 文件权限(默认权限取决于 umask,
                    //root 建的 600 文件目标 App 依然读不了)
                    + " && chmod 777 " + tagFile.getPath());
            //尝试利用magisk本身的busybox命令,直接chmod有的手机会失败(失败无所谓,放关键链路之外)
            RootUtils.execShell("busybox chmod 777 " + tagFile.getPath());
            CLog.i(">>>>>>>> initConfig finish  ");
        } catch (Throwable e) {
            CLog.e("initConfig error  " + e, e);
        }
    }


    private static class ViewHolder {
        TextView tv_appName, tv_packageName;
        LinearLayout All;
        ImageView iv_appIcon;

        ViewHolder(View convertView) {
            All = convertView.findViewById(R.id.ll_all);
            tv_packageName = convertView.findViewById(R.id.tv_packName);
            tv_appName = convertView.findViewById(R.id.tv_appName);
            iv_appIcon = convertView.findViewById(R.id.iv_appIcon);
        }

        static ViewHolder getHolder(View convertView) {
            ViewHolder holder = (ViewHolder) convertView.getTag();
            if (holder == null) {
                holder = new ViewHolder(convertView);
                convertView.setTag(holder);
            }
            return holder;
        }
    }
}

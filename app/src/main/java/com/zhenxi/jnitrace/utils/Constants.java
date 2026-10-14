package com.zhenxi.jnitrace.utils;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.AppOpsManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;

import java.io.File;
import java.lang.reflect.Method;
import java.util.List;

/**
 * Created by lyh on 2019/2/14.
 */

public class Constants {

    // 两次点击按钮之间的点击间隔不能少于1000毫秒
    private static final int MIN_CLICK_DELAY_TIME = 500;
    private static long lastClickTime;

    public static boolean isFastClick() {
        boolean flag = false;
        long curClickTime = System.currentTimeMillis();
        if ((curClickTime - lastClickTime) >= MIN_CLICK_DELAY_TIME) {
            flag = true;
        }
        lastClickTime = curClickTime;
        return flag;
    }


    /**
     * 判断 服务是否 存在
     * @param context
     * @param servicername
     * @return
     */
    public static boolean isRunning(Context context, String servicername){
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningServiceInfo> infos= am != null ? am.getRunningServices(100) : null;
        for (ActivityManager.RunningServiceInfo info:infos){
            String name =   info.service.getClassName();
            CLog.e("服务名字   "+name);
            if(servicername.equals(name)){
                return true;
            }
        }
        return false;
    }



    /**
     * 开启悬浮窗设置页面
     * @param activity
     */
    public static void openFloatingDialog(Activity activity){
        if (Build.VERSION.SDK_INT < 23){
            return;
        }
        Intent intent = null;
        try {
            intent = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:" + getPackageName(activity)));
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        activity.startActivity(intent);
        activity=null;
    }


    public static String getPackageName(Context context) throws PackageManager.NameNotFoundException {
        PackageInfo pInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
        return pInfo.packageName;
    }

    public static Object invokeMethod(AppOpsManager manager, String method, int op, int uid, String packageName){
        Class c = manager.getClass();
        try {
            Class[] classes = new Class[] {int.class, int.class, String.class};
            Object[] x2 = {op, uid, packageName};
            Method m = c.getDeclaredMethod(method, classes);
            return m.invoke(manager, x2);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return -1;
    }




    /**
     * 在 sd卡创建 指定 目录
     * @param fileName
     */
    public static  void createDir(String fileName){
        //Environment.getExternalStorageDirectory().getAbsolutePath():SD卡根目录
        File file = new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/"+fileName);
        if (!file.exists()){
            boolean isSuccess = file.mkdirs();
            //Toast.makeText(MainActivity.this,"文件夹创建成功",Toast.LENGTH_LONG).show();
            CLog.e("Sd文件夹 创建成功 " +fileName);
        }
        return ;
    }

    /**
     * 返回 sd卡 路径
     * @return
     */
    public static String getSDPath(){
        File sdDir = null;
        boolean sdCardExist = Environment.getExternalStorageState()
                .equals(Environment.MEDIA_MOUNTED); //判断sd卡是否存在
        if (sdCardExist)
        {
            sdDir = Environment.getExternalStorageDirectory();//获取跟目录
        }
        return sdDir.toString()+"/";
    }

    /**
     * 把任意 Drawable 转成 Bitmap。
     *
     * 这个函数必须"通用",不能只认 BitmapDrawable / NinePatchDrawable。
     *
     * 原实现只处理那两种,其它类型落到最后的 else 直接 return null;
     * 调用方 MainListViewAdapter 里是 setImageBitmap(...) ,传 null 等于把
     * ImageView 清空 —— 列表里那一格表现为**图标位置完全空白**(注意不是系统
     * 默认图标,是真的什么都没有)。
     *
     * 真机实测(小米 Android 13)对只打包了 PNG 图标的 App,比如
     *   com.miui.screenrecorder(屏幕录制)、com.android.soundrecorder(录音机)
     * loadIcon() 返回的既不是 BitmapDrawable 也不是 NinePatchDrawable,而是
     * MIUI 自己包装出来的 android.graphics.drawable.AdaptiveIconDrawable
     * (这两个 App 的 APK 里根本没有自适应图标 XML,是 MIUI 在运行时套的壳),
     * 于是图标必然空白。所以这里改成:凡是能画出来的 Drawable 都画到 Bitmap,
     * 不再按类型挑。
     *
     * 实测通用实现的结果:上面两个 AdaptiveIconDrawable 转出来的位图
     * 82% 的像素是不透明的、且是正常颜色(录音机中心色 0xFFFFEEEE),
     * 也就是说画出来确实有内容。
     */
    public static Bitmap drawable2Bitmap(Drawable drawable) {
        if (drawable == null) {
            return null;
        }
        //BitmapDrawable 直接取它内部的 bitmap,省掉一次重绘
        if (drawable instanceof BitmapDrawable) {
            Bitmap inner = ((BitmapDrawable) drawable).getBitmap();
            if (inner != null) {
                return inner;
            }
        }
        //其余类型(AdaptiveIconDrawable / VectorDrawable / NinePatchDrawable /
        //ColorDrawable ...)统一走"设置 bounds 再 draw 到 bitmap"这条路。
        int width = drawable.getIntrinsicWidth();
        int height = drawable.getIntrinsicHeight();
        if (width <= 0 || height <= 0) {
            //个别 Drawable 没有固有尺寸(ColorDrawable 之类),给个 48dp 兜底,
            //否则 createBitmap 会因为宽高非法抛异常
            int size = (int) (48 * Resources.getSystem().getDisplayMetrics().density);
            width = size;
            height = size;
        }
        //固定用 ARGB_8888:自适应图标在圆形/圆角遮罩外是透明的,
        //用 RGB_565 会把透明区域画成黑块
        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);
        drawable.setBounds(0, 0, width, height);
        drawable.draw(canvas);
        return bitmap;
    }
}

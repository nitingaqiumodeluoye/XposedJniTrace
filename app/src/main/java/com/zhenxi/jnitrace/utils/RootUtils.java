package com.zhenxi.jnitrace.utils;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

/**
 * Created by Lyh on
 * 2019/10/28
 */
public class RootUtils {
    public static boolean checkGetRootAuth() {
        Process process = null;
        DataOutputStream os = null;
        try {
            try {
                process = Runtime.getRuntime().exec("su");
            } catch (Throwable e) {
                CLog.e("exec error  " + e);
                e.printStackTrace();
            }

            os = new DataOutputStream(process.getOutputStream());
            os.writeBytes("exit\n");
            os.flush();
            int exitValue = process.waitFor();
            if (exitValue == 0) {
                CLog.e("checkGetRootAuth  ture");

                return true;
            } else {
                return false;
            }
        } catch (Throwable e) {
            return false;
        } finally {
            try {
                if (os != null) {
                    os.close();
                }
                process.destroy();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 应用程序运行命令获取 Root权限，设备必须已破解(获得ROOT权限)
     *
     * @return 应用程序是/否获取Root权限
     */
    public static boolean upgradeRootPermission(String pkgCodePath) {
        Process process = null;
        DataOutputStream os = null;
        try {
            String cmd = "chmod 777 " + pkgCodePath;
            process = Runtime.getRuntime().exec("su"); //切换到root帐号
            os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(cmd + "\n");
            os.writeBytes("exit\n");
            os.flush();

        } catch (Exception e) {
            CLog.e("get root error 111111 " + e.getMessage());
            return false;
        } finally {
            try {
                if (os != null) {
                    os.close();
                }
                if (process != null) {
                    process.destroy();
                }
            } catch (Exception e) {
                CLog.e("get root error 222222" + e.getMessage());
            }
        }
        return true;
    }

    /**
     * 以 root 执行一条命令,并等待它真正执行完返回。
     *
     * 原实现有三个问题(都会直接坑到调用方):
     *   1) 先用 runtime.exec(cmd) 跑了一遍**非 root**的命令 —— 结果丢弃,
     *      对 /data/data/<别的包> 这种路径必然失败("Permission denied"),纯粹白跑;
     *      而且 cmd+"\n" 里的换行会被拼进最后一个参数。
     *   2) 命令写进 su 的 stdin 之后立刻就 close 并返回,没有 waitFor(),
     *      调用方以为执行完了其实还在跑。
     *   3) 于是连着写的多条命令(如 rm -> cp -> mv)各自起一个 su,顺序完全没有保证,
     *      可能乱序执行 —— 写配置文件那里就会因此偶尔只剩半个文件。
     *
     * 现在:同一个 su 里写入"命令 + exit",并用 waitFor(5s) 等它结束。
     * 加超时是为了防 su 卡死把调用方(可能在主线程)挂住。
     * 调用方仍然应该把多条有前后依赖的命令用 && 连成一条 —— 比依赖多次调用更稳。
     */
    public static void execShell(String cmd) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return;
        }
        Process process = null;
        OutputStream outputStream = null;
        DataOutputStream dataOutputStream = null;
        try {
            process = Runtime.getRuntime().exec("su");
            outputStream = process.getOutputStream();
            dataOutputStream = new DataOutputStream(outputStream);
            dataOutputStream.writeBytes(cmd + "\n");
            //让 su 执行完就退出,否则 waitFor() 会一直等输入
            dataOutputStream.writeBytes("exit\n");
            dataOutputStream.flush();
            dataOutputStream.close();
            dataOutputStream = null;
            outputStream = null;
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                CLog.e("execShell timeout(5s) cmd= " + cmd);
            }
        } catch (Throwable t) {
            CLog.e("execShell error " + t.getMessage() + " cmd= " + cmd);
            t.printStackTrace();
        } finally {
            if (dataOutputStream != null) {
                try {
                    dataOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (process != null) {
                process.destroy();
            }
        }
    }
}

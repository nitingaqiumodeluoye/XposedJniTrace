//
// Created by zhenxi on 2022/1/21.
//

#ifndef QCONTAINER_PRO_LINKERHANDLER_H
#define QCONTAINER_PRO_LINKERHANDLER_H

#include <fstream>

class linkerHandler {
public:

    /**
     * 启用 so 加载监视(function id "3")。
     *
     * 注意:该功能不再自己 hook linker 的 do_dlopen ——
     * Vector 框架已经挂过那个地址(wxshadow 不允许同址二次 hook),
     * 这里只是接管框架送来的加载通知,真正的数据入口是 onModuleLoaded。
     */
    static void linkerCallBack(std::ofstream *os);

    /**
     * so 加载通知的落地点。
     *
     * 由 main.cpp 里 native_init 返回的 NativeOnModuleLoaded 回调转调过来,
     * 框架每次 dlopen 成功(handle != null)都会调一次。
     *
     * @param filename 被加载的 so 路径
     * @param handle   dlopen 返回的 handle
     */
    static void onModuleLoaded(const char *filename, void *handle);

    static void stopjnitrace();

};


#endif

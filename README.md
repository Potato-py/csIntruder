# 0x01 概述

- 本项目包含**CobaltStrike密码爆破**、**伪造上线**以及**DDos**功能。其中伪造上线**支持常见魔改版CS**。

![image](/img/33.png)

- This project includes **CobaltStrike password blasting**, **fake online** and **DDos** functions. Among them, fake online **supports common secondary development version CS**.

# 0x02 环境准备

    pip3 install netstruct
    
    pip3 install pefile

# 0x03 文件说明

- 1、**csIntruder.py**
```
cs密码爆破
```
- 2、**csFakeShell.py**
  - <u>可二开至**CVE-2022-39197**进行**RCE**，我懒，懂得都懂，坐等pull request</u>
```
cs伪造上线骚扰
```

- 3、**csDDos.py**
```
cs多线程本地(隔离机)上线Dos骚扰
```

# 0x04 csIntruder.py-cs密码爆破

- 1、参数：

| Parameter | Note | Required |
| :----: | :----: | :----: |
| -o | CS服务端地址 | True |
| -p | CS服务端端口(default:50050) | False |
| -r | 密码字典文件路径 | True |
| -t | 线程数(default:默认30) | False |

- 2、使用：

![image](/img/2.png)

# 0x05 csFakeShell.py-cs伪造上线骚扰
  
  支持原版CS以及常见魔改版CS的上线伪造

- 1、参数：

| Parameter | Note | Required |
| :----: | :----: | :----: |
| -f | CsBeacon木马文件路径/CsBeaconUrl【支持URL哦】 | True |
| -n | 上线虚假主机个数 | True |
| -c | 电脑名字典路径【默认自带字典】 | False |
| -u | 用户名字典路径【默认自带字典】 | False |
| -p | 线程名字典路径【默认自带字典】 | False |

- 2、使用：

![image](/img/3.png)

![image](/img/1.png)

![image](/img/33.png)

### csFackShell.py二开/添加其他魔改请求注意：

- ① DumpKeys.java用于解密通信信息，需要cs服务端密钥

- ② 使用命令：java -cp "cobaltstrike.jar" DumpKeys.java

- ③ 在线RSA加解密：https://the-x.cn/cryptography/Rsa.aspx

# 0x06 csDDos.py-cs多线程本地(隔离机)上线Dos骚扰

- 1、参数：

| Parameter | Note | Required |
| :----: | :----: | :----: |
| -f | CS木马文件路径/执行命令 | True |
| -t | 线程数(default:300) | False |

- 2、使用：

![image](/img/4.png)


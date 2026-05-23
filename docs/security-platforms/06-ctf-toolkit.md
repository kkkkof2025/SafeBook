# CTF 工具箱与速查手册

> 一场 CTF 比的是谁的装备更全、记的更牢。这个页面是你参赛时的第二大脑。

---

## 环境搭建

### 一键 CTF 环境（Kali 替代方案）

```bash
# Parrot OS CTF 版（轻量）
wget https://download.parrotsec.org/parrot/iso/Parrot-security-6.0_amd64.iso

# Docker CTF 靶场
docker pull vulhub/vulhub
docker run -d -p 80:80 vulhub/thinkphp/2-rce

# Python CTF 环境
python3 -m venv ctfenv
source ctfenv/bin/activate
pip install pwntools pycryptodome gmpy2 numpy requests scapy
```

### Windows CTF 环境

推荐安装：
1. **WSL2** — 跑 Linux 工具链
2. **Python 3** — pwntools + 脚本
3. **Ghidra** — 逆向分析
4. **IDA Free** — 反编译
5. **Wireshark** — 流量分析
6. **010 Editor** — 十六进制编辑

## 工具快速索引

### 信息收集
```bash
dirsearch -u http://target -e php,asp,js
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
nmap -sV -sC -p- target
```

### Web 利用
```bash
sqlmap -u "http://target/?id=1" --batch --random-agent
sqlmap -r request.txt --os-shell         # POST 请求

# XSS 平台（自建）
# https://github.com/mandatoryprogrammer/xsshunter

# SSRF 探测
ffuf -w ports.txt -u "http://target/?url=http://127.0.0.1:FUZZ/"
```

### 逆向与二进制
```bash
file binary                    # 文件类型
checksec --file=binary         # 安全机制（pwntools）
readelf -h binary              # ELF 头
objdump -d binary | less       # 反汇编
strings binary | grep -i flag  # 字符串提取
ltrace ./binary                # 库调用跟踪
strace ./binary                # 系统调用跟踪
```

### 密码学
```bash
# 快速识别
python3 -c "import base64; print(base64.b64decode('ZmxhZ3t0ZXN0fQ=='))"
echo "flag{test}" | base64

# RsaCtfTool
python3 RsaCtfTool.py -n 123 -e 65537 --uncipher 456

# Hashcat
hashcat -m 0 hash.txt rockyou.txt
hashcat -m 1000 hash.txt rockyou.txt  # NTLM
```

## Writeup 模板

```
# [题目名称] - Writeup

## 基本信息
- **比赛**: [CTF 名称] [年份]
- **题型**: [Web/PWN/Crypto/Reverse/Forensics/Misc]
- **难度**: ⭐/⭐⭐/⭐⭐⭐/⭐⭐⭐⭐/⭐⭐⭐⭐⭐
- **考点**: [知识点]

## 解题思路
1. [第一步]
2. [第二步]
3. [第三步]

## 关键代码/Payload
```[language]
[payload]
```

## Flag
```
flag{[flag内容]}
```
```

## CTF 资源导航

### 比赛日历
- [CTFtime](https://ctftime.org/) — 全球 CTF 赛历
- [CTFHub](https://www.ctfhub.com/) — 中文比赛信息

### 模板/工具仓库
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [CTF-Wiki](https://github.com/ctf-wiki/ctf-wiki)

### 在线沙箱
- [cryptii](https://cryptii.com/) — 编码转换
- [CyberChef](https://gchq.github.io/CyberChef/) — 万能解码器
- [dogbolt](https://dogbolt.org/) — 在线反编译

## Cheatsheet

### 常用 Python 一行流

```python
# 反转字符串
s[::-1]

# XOR 解码
bytes([c ^ key for c in data])

# hex 转字符串
bytes.fromhex(h).decode()

# 进制转换
int(s, 2)   # 二进制 → 整数
int(s, 16)  # 十六进制 → 整数
hex(n)      # 整数 → 十六进制
bin(n)      # 整数 → 二进制

# Xor 多重校验
from itertools import cycle
bytes([a ^ b for a, b in zip(data, cycle(key))])
```

### Linux 常用命令

```bash
nc target 1234            # 连接远程服务
nc -lvnp 4444             # 监听端口（listener）
python3 -c 'import pty;pty.spawn("/bin/bash")'  # 升级 shell
export TERM=xterm-256color
Ctrl+Z
stty raw -echo; fg
reset
```

*上一篇：[CTF 密码学与取证分析](05-ctf-crypto-forensics.md)*

*下一篇：[CTF 赛题精讲与实战复盘](07-ctf-writeups.md)*

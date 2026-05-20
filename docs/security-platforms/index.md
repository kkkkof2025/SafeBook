# 安全学习平台与 CTF 练习资源

> 从国际顶级 CTF 到国内白帽社区——每个安全学习者的必备资源清单

---

## 平台全景概览

```yaml
推荐学习路线:
  新手入门:  PicoCTF → TryHackMe → BUUCTF
  进阶提升:  HackTheBox → OverTheWire → Root-Me
  专项训练:  PortSwigger WebSec → Cryptohack → VulHub
  实战模拟:  HVV 靶场 → 攻防世界 → 墨者学院
  社区交流:  看雪论坛 → 补天平台 → i 春秋
```

---

## 国际 CTF 练习平台

### Hack The Box（HTB）

```yaml
网址: https://www.hackthebox.com/
难度: ⭐⭐⭐⭐（中高级）
特点: 最著名的渗透测试靶场
  实时虚拟机靶机
  认证体系（CPTS/OSCP 备考）
  定期举办 CTF 比赛

新手建议: 先完成 Starting Point → 再挑战 Active Machines
费用: 免费版有限制，VIP 需付费
```

### TryHackMe（THM）

```yaml
网址: https://tryhackme.com/
难度: ⭐⭐（新手友好）
特点: 循序渐进的学习路径
  适合零基础入门
  浏览器内置 Kali 环境（无需搭建）
  课程式引导（从 OSI 模型到渗透测试）

推荐路径:
  Pre Security → Jr Penetration Tester → Offensive Pentesting

费用: 免费版可完成部分房间，VIP $10/月
优点: 英语不好的同学可用浏览器翻译插件辅助
```

### PicoCTF

```yaml
网址: https://picoctf.org/
难度: ⭐（入门级）
特点: 面向初学者的 CTF
  由 CMU 大学主办
  题目分类清晰（Web/Crypto/Reverse/Forensics）
  适合完全没有 CTF 基础的新手

费用: 完全免费
```

### OverTheWire

```yaml
网址: https://overthewire.org/wargames/
难度: ⭐⭐（基础-中级）
特点: 战争游戏式学习
  Bandit → 最经典的 Linux 入门
  Natas → Web 安全基础
  Leviathan → Linux 权限提升

费用: 完全免费
推荐: Bandit 是学习 Linux 命令行的最佳入口
```

### 其他国际平台

| 平台 | 网址 | 难度 | 特色 |
|------|------|------|------|
| **CTFtime** | https://ctftime.org/ | - | 全球 CTF 赛事日历 |
| **Root-Me** | https://www.root-me.org/ | ⭐⭐⭐ | 400+ 挑战，支持多语言 |
| **CryptoHack** | https://cryptohack.org/ | ⭐⭐⭐ | 密码学专项平台 |
| **PortSwigger** | https://portswigger.net/web-security | ⭐⭐ | Web 安全专项（免费） |
| **CMD Challenge** | https://cmdchallenge.com/ | ⭐ | Linux 命令行练习 |
| **HackThisSite** | https://www.hackthissite.org/ | ⭐⭐ | 老牌在线黑客挑战 |
| **Hellbound Hackers** | https://www.hellboundhackers.org/ | ⭐⭐ | 多种安全练习 |
| **HackMyVM** | https://hackmyvm.eu/ | ⭐⭐⭐ | 虚拟机靶机 |
| **Attack-Defense** | https://attackdefense.com/ | ⭐⭐⭐ | 1800+ 实验室 |
| **RingZer0 CTF** | https://ringzer0ctf.com/ | ⭐⭐⭐ | 综合 CTF |

---

## 国内 CTF/安全学习平台

### 综合平台

| 平台 | 网址 | 难度 | 特色 |
|------|------|------|------|
| **攻防世界 (XCTF)** | https://adworld.xctf.org.cn/ | ⭐⭐⭐ | 国内最活跃的 CTF 平台 |
| **BUUCTF** | https://buuoj.cn/ | ⭐⭐~⭐⭐⭐⭐ | 安恒搭建，题目丰富 |
| **CTFSHOW** | https://ctf.show/ | ⭐⭐ | 新平台，界面简洁 |
| **i 春秋** | https://www.ichunqiu.com/ | ⭐⭐ | 视频课程+实验 |
| **合天网安实验室** | https://www.hetianlab.com/ | ⭐⭐ | 系统化课程平台 |
| **掌控安全（封神台）** | https://zkaq.cn/ | ⭐⭐ | 在线攻防演练靶场 |
| **墨者学院** | https://www.mozhe.cn/ | ⭐⭐ | 安全培训+靶场 |
| **青少年 CTF 平台** | https://qfnuoj.com/ | ⭐ | 公益性质，面向青少年 |

### 攻防世界（推荐首选）

```yaml
网址: https://adworld.xctf.org.cn/
维护方: 赛宁网安
分类: Misc / Pwn / Web / Reverse / Crypto / Mobile

特点:
  - 新手区 + 进阶区
  - 积分+排名系统（组队打怪）
  - 支持题解查看
  - 定期举办 XCTF 联赛

推荐: 国内 CTF 入门第一站
```

### BUUCTF（题库最丰富）

```yaml
网址: https://buuoj.cn/
维护方: 安恒信息
特点:
  - 大量 CTF 真题复现
  - 涵盖国内外比赛题目
  - Web/Reverse/Pwn/Crypto/Misc 齐全
  - 在线评测系统（O2平台）

难度: 入门的题目不算多，适合有一定基础后刷题
```

### 看雪 CTF 与论坛

```yaml
网址: https://bbs.kanxue.com/
特点:
  - 国内最老牌的安全社区（1999年成立）
  - CTF 竞赛平台（KCTF）
  - 逆向工程和漏洞分析资源丰富
  - 看雪学院 → 在线课程

定位: 安全行业从业者的社区交流平台
```

---

## 安全社区与漏洞平台

### 社区类

| 平台 | 网址 | 定位 |
|------|------|------|
| **看雪论坛** | https://bbs.kanxue.com/ | 逆向/底层安全 |
| **补天平台** | https://butian.360.cn/ | 漏洞响应+白帽社区 |
| **Seebug** | https://www.seebug.org/ | 漏洞分析+Paper |
| **先知社区** | https://xz.aliyun.com/ | 阿里安全技术分享 |
| **FreeBuf** | https://www.freebuf.com/ | 安全资讯+技术 |
| **安全客** | https://www.anquanke.com/ | 安全新闻+漏洞预警 |
| **嘶吼 Roar** | https://www.4hou.com/ | 国际安全资讯翻译 |
| **CNVD 公告** | https://www.cnvd.org.cn/ | 国家漏洞预警 |
| **PeiQi-WIKI** | https://github.com/PeiQi0/PeiQi-WIKI-POC | 中文漏洞 Wiki |

### 公众号/自媒体

```yaml
推荐关注（微信搜索 -> 搜狗可搜到）:
  安全类:
    - 安在 (anzer_sh)
    - 知道创宇 (knownsec)
    - 奇安信 (qianxin)
    - 绿盟科技 (nsfocus)
    - 360安全 (qihoo_360)

  技术分享类:
    - 橘猫学安全
    - HACK学习呀
    - 暴暴的皮卡丘
    - 听风安全
    - 网络安全自修室
    - 信安之路
    - 暗影安全

  漏洞情报类:
    - 阿里云安全
    - 腾讯安全
    - 华为安全
```

---

## 专业靶场（漏洞复现）

### VulHub（强烈推荐）

```yaml
网址: https://github.com/vulhub/vulhub
维护方: 社区开源
特点: Docker 一键搭建漏洞环境
  使用 docker-compose up -d 即可启动
  涵盖: Web安全/中间件/数据库/框架

常用靶场:
  vulhub/thinkphp/5-rce     →  ThinkPHP RCE
  vulhub/log4j/CVE-2021-44228 → Log4Shell
  vulhub/spring/CVE-2022-22965 → Spring4Shell
  vulhub/shiro/CVE-2016-4437  → Shiro反序列化
```

### DVWA + 同类

```yaml
DVWA (Damn Vulnerable Web Application):
  网址: https://github.com/digininja/DVWA
  安装: Docker 一键部署
  难度: 1-10 可调
  包含: SQL/XSS/CSRF/文件包含等

同类开源靶场:
  - Sqli-labs: SQL 注入专项
  - Upload-labs: 文件上传专项
  - Xss-labs: XSS 专项
  - PentesterLab: 多项 Web 漏洞
  - bWAPP: 100+ 漏洞
  - WebGoat: OWASP 官方靶场
  - Juice Shop: 现代 Web 安全靶场
```

### 在线靶场

```yaml
国内在线靶场:
  - 网络信息安全攻防学习平台: http://hackinglab.cn
  - 重生信息安全在线靶场: https://bc.csxa.cn
  - 掌控安全封神台: https://zkaq.cn
  - 墨者学院在线靶场: https://www.mozhe.cn

国际在线靶场:
  - HackTheBox: https://www.hackthebox.com
  - TryHackMe: https://tryhackme.com
  - VulnHub 本地镜像: https://www.vulnhub.com
  - PentesterLab: https://pentesterlab.com
```

---

## 安全书籍与课程

### 入门书籍

```yaml
《白帽子讲Web安全》— 吴翰清
  Web 安全入门圣经

《Web安全攻防渗透测试实战指南》
  实战导向，包含大量案例

《CTF竞赛权威指南-Pwn篇》
  CTF Pwn 入门必读

《红蓝攻防：构建实战化网络安全防御体系》
  奇安信安服团队经验总结

《Metasploit渗透测试指南》
  Metasploit 使用手册
```

### 在线课程平台

```yaml
国际:
  SANS Institute — 最高质量的安全认证课程
  Offensive Security — OSCP/OSEP 认证
  Pluralsight — IT 安全课程
  Coursera — 名校安全课程

国内:
  i 春秋 — 国内最大安全在线教育平台
  安全牛课堂 — 企业安全培训
  看雪学院 — 逆向/底层安全
  合天网安 — 体系化课程
  掌控安全 — 渗透测试实战
```

---

## 社区论坛与组织

```yaml
国际:
  Reddit r/netsec — 国际安全社区
  Stack Overflow — 技术问答
  HackTheBox Forum — HTB 玩家社区
  Discord 安全频道 — 实时讨论

国内:
  看雪论坛 — 逆向/安全分析
  先知社区 (阿里) — 漏洞分析
  FreeBuf — 安全资讯
  安全客 — 漏洞情报
  CSDN 安全板块 — 技术分享
  V2EX 安全节点 — 技术讨论

安全组织:
  OWASP — 开源 Web 安全组织
  FIRST — 应急响应论坛
  NULLCON — 安全会议
  KCon/ISC — 国内安全大会
  POC — 韩国 POC 大会
  DEFCON — 全球最大黑客大会
```

---

## 延伸阅读

- [20个渗透/CTF练习平台资源 (2025)](https://blog.csdn.net/wly55690/article/details/145794830)
- [26个渗透测试靶场推荐 (2025)](https://blog.csdn.net/m0_71745484/article/details/155069634)
- [最全CTF练习网站总结](https://blog.csdn.net/java_zzzzz/article/details/131510492)
- [6个合法学习黑客技术网站](https://blog.csdn.net/shanguicsdn000/article/details/141432464)
- [5个免费练习黑客技术的网站](https://blog.csdn.net/innocence_0/article/details/129373316)
- [HackTheBox 官方网站](https://www.hackthebox.com/)
- [TryHackMe 官方网站](https://tryhackme.com/)
- [PicoCTF 官方网站](https://picoctf.org/)
- [OverTheWire Wargames](https://overthewire.org/wargames/)
- [VulHub 官方仓库](https://github.com/vulhub/vulhub)
- [CTFtime 赛事日历](https://ctftime.org/)
- [CTF Wiki](https://ctf-wiki.org/)（中文）

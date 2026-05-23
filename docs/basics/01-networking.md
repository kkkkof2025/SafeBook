# 计算机网络基础

> 理解安全漏洞，首先得理解网络是怎么工作的

---

## 为什么网络基础对安全很重要

```
你看到"SQL 注入" → 攻击者发送 HTTP 请求 → 服务器解析参数 → 拼接 SQL → 数据库执行

你看到"反弹 Shell" → 目标机器  → TCP 连接 → 你的监听端口
                  → 交互式 Shell  → 控制
```

如果不理解 TCP 握手、HTTP 请求/响应、DNS 解析，你就无法真正理解漏洞是如何被利用的。

---

## 核心概念

### 1. OSI 七层模型 与 TCP/IP 四层模型

| OSI 七层 | TCP/IP 四层 | 常见协议 | 安全影响 |
|----------|-------------|----------|---------|
| 应用层 | 应用层 | HTTP、FTP、SMTP、DNS | Web 漏洞、协议滥用 |
| 表示层 | ↑ | SSL/TLS | 中间人攻击 |
| 会话层 | ↑ | Sockets | Session 劫持 |
| 传输层 | 传输层 | TCP、UDP | 端口扫描、DoS |
| 网络层 | 网络层 | IP、ICMP | IP 欺骗、Smurf 攻击 |
| 数据链路层 | 网络接口层 | ARP、MAC | ARP 欺骗、MAC 泛洪 |
| 物理层 | ↑ | 以太网、Wi-Fi | 信号干扰、物理接入 |

### 2. HTTP 协议基础

```
┌─────────────────────────────────┐
│         HTTP 请求               │
├─────────────────────────────────┤
│ GET /login.php?user=admin HTTP/1.1 │
│ Host: example.com               │
│ Cookie: session=abc123          │
│ User-Agent: Mozilla/5.0         │
│                                 │
│ (空行)                          │
│ (请求体 - POST 时有)             │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│         HTTP 响应               │
├─────────────────────────────────┤
│ HTTP/1.1 200 OK                 │
│ Content-Type: text/html         │
│ Set-Cookie: session=xyz456      │
│                                 │
│ <html>...</html>                │
└─────────────────────────────────┘
```

**关键点**：HTTP 是明文传输的！没有 HTTPS 时，中间人可以看到一切。

### 3. DNS 解析

```
你输入 example.com
    ↓
浏览器问 DNS 服务器：example.com 的 IP 是多少？
    ↓
DNS 返回：93.184.216.34
    ↓
浏览器向 93.184.216.34:80 发起 HTTP 请求
```

**安全问题**：DNS 劫持、DNS 缓存投毒、DNS 隧道。

---

## 安全中常用网络概念

### 端口

| 端口 | 协议 | 服务 | 常见攻击 |
|------|------|------|---------|
| 80 | TCP | HTTP | Web 漏洞 |
| 443 | TCP | HTTPS | SSL 剥离 |
| 22 | TCP | SSH | 暴力破解 |
| 21 | TCP | FTP | 匿名访问、明文凭据 |
| 3306 | TCP | MySQL | 数据库泄露 |
| 6379 | TCP | Redis | 未授权访问 |

### IP 地址分类

- **公网 IP**：互联网上可见
- **内网 IP**：10.x.x.x、172.16-31.x.x、192.168.x.x
- **本地回环**：127.0.0.1（localhost）

---

## 安全工具中的网络操作

```bash
# 查看本机 IP
ipconfig          # Windows
ifconfig          # Linux / Mac

# 测试连通性
ping example.com

# 查看路由路径
tracert example.com   # Windows
traceroute example.com # Linux / Mac

# 查看 DNS 解析
nslookup example.com

# 查看端口状态（需要 nmap）
nmap -sV 192.168.1.1
```

---

## 小结

- 网络是安全的基础——不理解网络就无法理解攻击路径
- HTTP、DNS、TCP 是安全中最常接触的三个协议
- 熟练使用 `curl`、`nmap`、`tcpdump` 等网络工具是基本功

[上一章：成为白帽黑客之路](00-intro.md) | [下一章：HTTP 协议详解 →](02-http.md)

*上一篇：[成为白帽黑客之路](00-intro.md)*

*下一篇：[HTTP 协议详解](02-http.md)*

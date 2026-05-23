# TLS/HTTPS 与 PKI

## 概述

TLS 是互联网安全的基石——保护着从网上银行到消息应用的几乎一切网络通信。本章覆盖 TLS 握手、证书验证、PKI 架构和常见配置错误。

---

## 1. TLS 握手详解

```
TLS 1.3 握手（2-RTT → 1-RTT）:

  Client                              Server
    |                                   |
    |-- ClientHello ------------------>|
    |   (支持的密码套件)                 |
    |   (key_share: X25519 公钥)       |
    |                                   |
    |<-- ServerHello ------------------|
    |   (选定的密码套件)                 |
    |   (key_share: X25519 公钥)       |
    |   证书链 (ECDSA P-256)           |
    |   Finished (加密握手记录)          |
    |                                   |
    |-- Finished --------------------->|
    |   (加密握手记录)                   |
    |                                   |
    |<======== 加密数据传输 ===========>|

  优势:
  - DH 密钥交换已在第一个 RTT 完成
  - 0-RTT 模式: 已访问过的网站可以第一字节就发送加密数据
    但 0-RTT 缺乏前向安全性（重放风险）
```

---

## 2. 证书与 PKI

### 2.1 证书验证引擎

```python
import ssl
import socket
from datetime import datetime

class CertificateChecker:
    """TLS 证书安全检查"""

    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port

    def check_certificate(self):
        """全面证书检查"""
        ctx = ssl.create_default_context()

        with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                cert = ssock.getpeercert()

        issues = []

        # 1. 检查是否过期
        not_after = datetime.strptime(
            cert['notAfter'],
            '%b %d %H:%M:%S %Y %Z'
        )
        days_left = (not_after - datetime.utcnow()).days

        if days_left < 0:
            issues.append(('CRITICAL', '证书已过期'))
        elif days_left < 30:
            issues.append(('WARNING', f'证书将在 {days_left} 天后过期'))

        # 2. 检查公钥强度
        pubkey = ssock.getpeercert(binary_form=True)
        from cryptography import x509
        cert_obj = x509.load_der_x509_certificate(pubkey)
        key_size = cert_obj.public_key().key_size

        if key_size < 2048:
            issues.append(('CRITICAL', f'RSA 密钥 {key_size} 位（建议 2048+）'))

        # 3. 检查 SAN（Subject Alternative Name）
        sans = []
        for field in cert.get('subjectAltName', []):
            sans.append(field[1])

        if self.hostname not in sans:
            issues.append(('CRITICAL', f'SAN 不包含 {self.hostname}'))

        # 4. 检查签名算法
        sig_algo = cert_obj.signature_algorithm_oid._name
        if 'sha1' in sig_algo.lower():
            issues.append(('CRITICAL', f'SHA-1 签名（已不信任）'))
        elif 'md5' in sig_algo.lower():
            issues.append(('CRITICAL', f'MD5 签名'))

        # 5. 检查是否自签名
        if cert_obj.issuer == cert_obj.subject:
            issues.append(('WARNING', '自签名证书'))

        return {
            'hostname': self.hostname,
            'days_left': days_left,
            'key_size': key_size,
            'signature_algorithm': sig_algo,
            'issues': issues,
            'grade': self._calculate_grade(issues)
        }

    def _calculate_grade(self, issues):
        severities = [s for s, _ in issues]
        if 'CRITICAL' in severities:
            return 'F'
        elif 'WARNING' in severities:
            return 'B'
        return 'A+'
```

### 2.2 证书透明度 (Certificate Transparency)

```bash
# 查询证书透明日志（发现子域名 + 未授权证书）
curl "https://crt.sh/?q=%.example.com&output=json" | jq '.[].name_value' | sort -u

# 监控组织的所有证书
# 例: 发现未通过内部审批流程的 "野证书"
```

---

## 3. 密码套件安全

```yaml
推荐密码套件:

  TLS 1.3（支持 5 个密码套件）:
    - TLS_AES_256_GCM_SHA384  ← 最推荐
    - TLS_AES_128_GCM_SHA256
    - TLS_CHACHA20_POLY1305_SHA256  ← 移动端最优
    - TLS_AES_128_CCM_SHA256      ← IoT
    - TLS_AES_128_CCM_8_SHA256    ← IoT (短Tag)

  禁止的密码套件:
    - TLS_RSA_WITH_*    # 无前向安全性
    - TLS_*_CBC_*       # 填充预言攻击 (POODLE)
    - TLS_*_RC4_*       # RC4 已完全攻破
    - TLS_*_NULL_*      # 无加密
    - TLS_*_EXPORT_*    # 出口级弱加密 (FREAK)
    - TLS_*_DES_*, TLS_*_3DES_*  # DES/3DES 弱加密

  工具:
    - testssl.sh: 全面 TLS 测试
    - sslscan: 密码套件扫描
    - Mozilla SSL Configuration Generator
```

---

## 4. HSTS 配置

```nginx
# Nginx HSTS 配置
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# max-age=63072000: 2 年（浏览器会记住强制 HTTPS）
# includeSubDomains: 所有子域名也强制 HTTPS
# preload: 可被纳入浏览器内置 HSTS 预加载列表

# 预加载列表提交:
# https://hstspreload.org/
# 提交后，浏览器出厂即强制该域名的 HTTPS
```

---

## 5. 常见配置错误

```yaml
TLS 常见配置错误:

  1. 未启用 TLS 1.3:
     Nginx: ssl_protocols TLSv1.2 TLSv1.3;
     影响: 1-RTT 握手优势丧失

  2. 证书私钥未保护:
     文件权限 644 → 所有用户可读
     修复: chmod 600 /etc/ssl/private/*.key

  3. 过期的中间证书:
     cert.pem 只有叶子证书，缺少 CA bundle
     修复: cat cert.pem ca-bundle.pem > fullchain.pem

  4. 使用通配符证书:
     *.example.com → 攻击者获取 *.example.com 私钥 = 全局危害
     替代: 使用 Let's Encrypt 多域名证书

  5. OCSP Stapling 未启用:
     客户端必须主动查询 OCSP 服务器确认证书未被吊销
     修复: ssl_stapling on; ssl_stapling_verify on;

  6. 弱 DH 参数:
     使用 1024 位 DH → 可被 NSA 级算力攻破
     修复: openssl dhparam -out dhparam.pem 4096
```

---

*上一篇：[哈希算法](01-hash.md)*

*下一篇：[数字签名与公钥基础设施](04-digital-signatures.md)*

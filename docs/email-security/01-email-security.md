# 电子邮件安全

> 90% 的 APT 攻击以邮件为入口——邮件安全是网络防线的第一道门。

---

## 邮件安全三件套

```mermaid
graph LR
    SPF[SPF<br>发件人策略框架] --> DKIM[DKIM<br>域名密钥识别邮件]
    DKIM --> DMARC[DMARC<br>域消息认证报告与合规]
    style SPF fill:#4a90d9,color:#fff
    style DKIM fill:#50b86c,color:#fff
    style DMARC fill:#e74c3c,color:#fff
```

### SPF 配置

```txt
DNS TXT 记录:
v=spf1 ip4:192.168.1.0/24 ip4:203.0.113.5 include:_spf.google.com ~all

参数说明:
  ip4: — 授权发送邮件服务器 IP
  include: — 包含第三方邮件服务商
  a: — 域名 A 记录（仅简易部署）
  mx: — 域名 MX 记录（所有邮件服务器）
  ptr: — 反向解析（已弃用，耗时）
  ~all — 软失败（测试用）
  -all — 硬失败（生产推荐）
  ?all — 中立（无策略—不推荐）
```

### DKIM 配置

```bash
# 生成 DKIM 密钥
# 使用 OpenSSL
openssl genrsa -out dkim-private.pem 2048
openssl rsa -in dkim-private.pem -pubout -out dkim-public.pem

# 生成公钥的 DNS 记录值
# selector._domainkey.example.com TXT
# "v=DKIM1; h=sha256; k=rsa; p=MIGfMA0GC..."

# DKIM 签名头（邮件服务器自动添加）
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  d=example.com; s=selector;
  h=from:to:subject:date:message-id;
  bh=2jUSOH9NhtVGCQWNr9BrIAP3K...;
  b=Au3oGQkLyYnHk...
```

### DMARC 配置

```txt
DNS TXT 记录 (_dmarc.example.com):
v=DMARC1; p=reject; rua=mailto:dmarc@example.com;
  ruf=mailto:forensic@example.com; fo=1;
  pct=100; rf=afrf; ri=86400

参数说明:
  p= — 策略（none/quarantine/reject）
  rua — 聚合报告接收邮箱
  ruf — 取证报告接收邮箱  
  fo — 失败选项（0/1/d/s）
  pct — 策略应用百分比
  ri — 报告间隔（秒）
  sp — 子域策略
  adkim — DKIM 对齐模式（r/s）
  aspf — SPF 对齐模式（r/s）
```

### 部署策略

```
Phase 1: p=none (2-4周)
  → 观察报告，确认合法邮件源
Phase 2: p=quarantine (4-8周)  
  → 可疑邮件进垃圾箱
Phase 3: p=reject (持续)
  → 不合规邮件直接拒收
```

## 邮件网关配置

### 邮件安全过滤规则

```yaml
邮件过滤优先级:
  1. SPF/DKIM/DMARC 验证失败 → 直接拒收
  2. 附件类型阻断:
     - .exe/.scr/.bat/.cmd 全部阻断
     - .docm/.xlsm/.pptm → 沙箱扫描
     - .pdf → 检测 JavaScript/表单
     - .zip → 需要密码的压缩包阻断
  3. URL 检查:
     - 短链接展开后检查
     - 新注册域名（<30天）标记
     - 已知钓鱼 URL 数据库匹配
  4. 内容分析:
     - 关键词匹配（"紧急"、"密码"、"转账"）
     - 异常请求检测
     - NLP 钓鱼评分

白名单策略:
  - 合法第三方服务域名
  - 公司子公司邮件服务器
  - 已知供应商发件人

灰名单策略:
  - 首次发件人延迟接受
  - 观察重试是否符合 RFC
```

## 邮件安全威胁类型

| 威胁类型 | 检测难度 | 防御手段 |
|---------|---------|---------|
| 常规钓鱼 | 低 | SPF/DKIM/DMARC + URL 检测 |
| 鱼叉钓鱼 | 中 | 内容分析 + 行为基线 |
| 业务邮件欺诈(BEC) | 高 | 发件人行为分析 + 人工确认 |
| 账户接管(OAuth) | 高 | MFA + 异常登录检测 |
| 零日利用 | 极高 | 沙箱 + 行为检测 |
| QR 钓鱼(Quishing) | 中 | OCR 二维码检测 |
| 语音钓鱼(电话) | 高 | 外呼 SOP 培训 |

## 邮件安全基线

```yaml
基础配置:
  SPF: 使用 -all（硬失败）
  DKIM: RSA 2048 bit, 每年轮换密钥
  DMARC: p=reject, 聚合报告每日发送
  
  TLS: 强制 StartTLS (MTA-STS)
  MTA-STS: policy.mta-sts.example.com
  TLS-RPT: rua=mailto:tls@example.com

进阶配置:
  BIMI: 品牌标识，通过认证的 logo 显示
  ARC: 邮件转发链认证
  SMTP MTA Strict Transport Security
  
  DANE: DNSSEC + TLSA 记录
  _25._tcp.mail.example.com. IN TLSA 3 1 1 <cert_hash>
```

## 钓鱼邮件排查流程

```bash
# 1. 查看原始邮件头
# 重点关注:
# Received-SPF: pass/fail/neutral
# DKIM-Signature: 验证结果
# Authentication-Results: 综合性验证

# 2. 查看 Received 链
# 从下往上读 → 确定真实发件服务器 IP
# Received: from [SENDER_IP] by mail-gw.company.com

# 3. 追踪重定向链
# 经过多次中转 → 可能是垃圾/钓鱼

# 4. 检查 URL 有效性
# curl -I "http://suspicious-url.com"
# whois suspicious-url.com
# VirusTotal URL 检查
```

*下一篇：[电子邮件安全攻击技术](02-email-attacks.md)*

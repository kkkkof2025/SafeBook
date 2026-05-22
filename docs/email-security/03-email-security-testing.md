# 电子邮件攻击与防御测试

## 概述

电子邮件仍是企业攻击的首要入口——91% 的网络攻击始于钓鱼邮件 (Verizon DBIR 2024)。本章介绍自动化的邮件安全测试方法论，帮助安全团队在攻击者之前发现邮件系统的弱点。

---

## 1. 邮件安全测试工具

| 工具 | 功能 |
|------|------|
| **GoPhish** | 钓鱼演练平台 |
| **King Phisher** | 钓鱼测试框架 |
| **SpoofCheck** | 邮件伪造检测 |
| **TrustedSec** | 邮件安全评估 |
| **Email Header Analyzer** | 邮件头分析 |
| **mailspoof** | SPF/DKIM/DMARC 检测 |

---

## 2. SPF/DKIM/DMARC 测试

### 2.1 自动检测脚本

```bash
#!/bin/bash
# email_auth_test.sh - 邮件认证安全检测

DOMAIN="$1"

echo "=== 邮件认证安全检测: $DOMAIN ==="
echo ""

# 1. SPF 检查
echo "--- SPF ---"
spf_record=$(dig +short TXT $DOMAIN | grep "v=spf1")
if [ -z "$spf_record" ]; then
    echo "[FAIL] 未配置 SPF 记录!"
    echo "  → 任何人都可以伪造你的域名发邮件"
else
    echo "[PASS] SPF: $spf_record"
    
    # 检查 SPF 配置质量
    if echo "$spf_record" | grep -q "\-all"; then
        echo "  严格策略 (-all): 优秀"
    elif echo "$spf_record" | grep -q "~all"; then
        echo "  宽松策略 (~all): 建议改为 -all"
    elif echo "$spf_record" | grep -q "+all"; then
        echo "  [WARNING] 策略 +all: 允许所有人发邮件!"
    fi
    
    # 检查 DNS 查询次数 (SPF 限制 10 次)
    lookup_count=$(echo "$spf_record" | grep -oP "(include|a|mx|ptr):" | wc -l)
    if [ "$lookup_count" -gt 10 ]; then
        echo "  [WARNING] SPF DNS 查询超过 10 次限制!"
    fi
fi

echo ""

# 2. DKIM 检查
echo "--- DKIM ---"
for selector in google default k1 dkim selector1 selector2 mail; do
    dkim_record=$(dig +short TXT "${selector}._domainkey.${DOMAIN}")
    if [ -n "$dkim_record" ]; then
        echo "[PASS] DKIM selector='$selector'"
        if echo "$dkim_record" | grep -q "k=rsa" && echo "$dkim_record" | grep -q "p=.*MIG"; then
            key_len=$(echo "$dkim_record" | grep -oP 'p=[A-Za-z0-9+/]+=*' | wc -c)
            if [ "$key_len" -lt 400 ]; then
                echo "  [WARNING] DKIM 密钥长度较短 (<1024 bits)"
            fi
        fi
    fi
done

if [ -z "$(dig +short TXT "*._domainkey.${DOMAIN}" | grep "v=DKIM1")" ]; then
    echo "[FAIL] 未检测到 DKIM 记录!"
fi

echo ""

# 3. DMARC 检查
echo "--- DMARC ---"
dmarc_record=$(dig +short TXT "_dmarc.${DOMAIN}")
if [ -z "$dmarc_record" ]; then
    echo "[FAIL] 未配置 DMARC 记录!"
else
    echo "[PASS] DMARC: $dmarc_record"
    
    # 策略检查
    if echo "$dmarc_record" | grep -q "p=reject"; then
        echo "  策略 reject: 优秀 (拒绝未通过认证的邮件)"
    elif echo "$dmarc_record" | grep -q "p=quarantine"; then
        echo "  策略 quarantine: 良好 (隔离未通过认证的邮件)"
    elif echo "$dmarc_record" | grep -q "p=none"; then
        echo "  策略 none: 建议升级为 quarantine 或 reject"
    fi
    
    # 报告配置
    if echo "$dmarc_record" | grep -q "rua="; then
        echo "  聚合报告: 已配置"
    else
        echo "  [WARNING] 未配置 DMARC 聚合报告 (rua)"
    fi
fi
```

### 2.2 邮件伪造测试

```python
import smtplib
from email.mime.text import MIMEText

def test_email_spoofing(target_domain, spoofed_from):
    """
    测试邮件伪造 (仅授权测试!)
    """
    
    # 测试 1: 直接伪造 From (无 SPF 保护)
    msg = MIMEText("这是邮件伪造测试")
    msg['From'] = spoofed_from
    msg['To'] = f"test@{target_domain}"
    msg['Subject'] = "Spoofing Test - Security Assessment"

    try:
        # 尝试发送
        smtp = smtplib.SMTP(f'mail.{target_domain}', 25, timeout=10)
        smtp.sendmail(spoofed_from, [f"test@{target_domain}"], msg.as_string())
        print(f"[VULNERABLE] 成功发送伪造邮件 From: {spoofed_from}")
        return True
    except smtplib.SMTPRecipientsRefused:
        print(f"[PASS] SPF 防护有效 — 拒绝伪造邮件")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return None
```

---

## 3. 钓鱼演练自动化

### 3.1 GoPhish 部署

```bash
# GoPhish 钓鱼演练平台

# 1. 部署
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
cd gophish
chmod +x gophish

# 2. 编辑配置 (修改默认密码)
vim config.json
# admin_server.listen_url: "0.0.0.0:3333"
# phish_server.listen_url: "0.0.0.0:80"

# 3. 启动
./gophish

# 4. 访问
# https://localhost:3333
# 默认密码通常会被提示修改
```

### 3.2 自动化指标

```python
class PhishingMetrics:
    """钓鱼演练效果评估"""

    def __init__(self, gophish_data):
        self.sent = gophish_data['emails_sent']
        self.opened = gophish_data['emails_opened']
        self.clicked = gophish_data['links_clicked']
        self.credentials = gophish_data['credentials_submitted']

    def calculate_rates(self):
        return {
            '打开率': f'{self.opened / self.sent * 100:.1f}%',
            '点击率': f'{self.clicked / self.sent * 100:.1f}%',
            '凭证提交率': f'{self.credentials / self.sent * 100:.1f}%',
            '目标': {
                '打开率': '< 10%',
                '点击率': '< 5%',
                '凭证提交率': '< 1%'
            }
        }

    def get_improvement_areas(self):
        """需要改进的领域"""
        areas = []

        if self.opened / self.sent > 0.30:
            areas.append('邮件安全意识培训 — 打开率过高 (>30%)')
        if self.clicked / self.sent > 0.15:
            areas.append('链接点击意识 — 点击率过高 (>15%)')
        if self.credentials / self.sent > 0.05:
            areas.append('凭证安全意识 — 提交率过高 (>5%)')

        return areas
```

---

## 参考资源

- [GoPhish 钓鱼演练平台](https://getgophish.com/)
- [DMARC 检测工具](https://dmarcian.com/)
- [MxToolbox](https://mxtoolbox.com/)
- [SPF 详解](https://www.dmarcanalyzer.com/spf/)

---

*上一篇：[邮件攻击分析](02-email-attacks.md)*

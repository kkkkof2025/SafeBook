# OSINT 信息收集实战

> OSINT 是安全工作的起点——没有侦察就没有攻击。

---

## 主动 vs 被动侦察

```yaml
被动侦察（不接触目标）:
  - DNS 记录（历史/被动 DNS）
  - Certificate Transparency (crt.sh)
  - 搜索引擎缓存
  - 社工信息（LinkedIn/GitHub）
  - 攻防社区/漏洞披露

主动侦察（接触目标）:
  - Nmap 端口扫描
  - Web 目录扫描
  - 服务指纹识别
  - 子域名爆破
  - 技术栈识别
```

## 子域名收集完整工作流

```bash
#!/bin/bash
# 子域名收集自动化脚本

DOMAIN=$1
OUTPUT_DIR="recon_${DOMAIN}_$(date +%Y%m%d)"
mkdir -p $OUTPUT_DIR

echo "=== Passive Collection ==="

# 1. crt.sh (Certificate Transparency)
curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | sort -u > ${OUTPUT_DIR}/crtsh.txt
echo "[+] crt.sh: $(wc -l ${OUTPUT_DIR}/crtsh.txt) subdomains"

# 2. Subfinder
subfinder -d ${DOMAIN} -silent -o ${OUTPUT_DIR}/subfinder.txt
echo "[+] Subfinder: $(wc -l ${OUTPUT_DIR}/subfinder.txt) subdomains"

# 3. Amass (passive)
amass enum -passive -d ${DOMAIN} -o ${OUTPUT_DIR}/amass_passive.txt
echo "[+] Amass passive: $(wc -l ${OUTPUT_DIR}/amass_passive.txt) subdomains"

echo "=== Active Collection ==="

# 4. DNS 爆破
dnsx -d ${DOMAIN} -w /wordlists/subdomains.txt \
  -o ${OUTPUT_DIR}/dns_bruteforce.txt -r 8.8.8.8
echo "[+] DNS Brute: $(wc -l ${OUTPUT_DIR}/dns_bruteforce.txt) valid"

# 5. 合并去重
cat ${OUTPUT_DIR}/*.txt | sort -u > ${OUTPUT_DIR}/all_subdomains.txt
echo "[+] Total unique: $(wc -l ${OUTPUT_DIR}/all_subdomains.txt)"

echo "=== Probing ==="

# 6. HTTP 探测
cat ${OUTPUT_DIR}/all_subdomains.txt | \
  httpx -silent -o ${OUTPUT_DIR}/live_hosts.txt
echo "[+] Live hosts: $(wc -l ${OUTPUT_DIR}/live_hosts.txt)"

# 7. 截图
cat ${OUTPUT_DIR}/live_hosts.txt | \
  gowitness file -f ${OUTPUT_DIR}/live_hosts.txt -P ${OUTPUT_DIR}/screenshots/
```

## Google Dorking 黄金查询

```sql
-- 敏感文件
site:example.com filetype:env
site:example.com filetype:sql
site:example.com filetype:bak inurl:wp-config
site:example.com ext:log | ext:txt password

-- 管理后台
site:example.com intitle:"admin login"
site:example.com inurl:admin | inurl:dashboard
site:example.com inurl:phpmyadmin

-- 暴露服务
site:example.com intitle:"index of" /etc
site:example.com inurl:server-status
site:example.com intitle:"swagger ui"
site:example.com inurl:/actuator | /swagger

-- 第三方泄露
site:pastebin.com "example.com"
site:github.com "example.com" "api_key"
site:gist.github.com "example.com" "password"
inurl:trello.com "example.com"

-- 技术栈识别
site:example.com "powered by"
site:example.com intitle:"jenkins" | "kibana"
site:example.com intitle:"grafana"
```

## 技术栈指纹

```bash
# Web 技术栈识别
whatweb -a 3 https://example.com
wappalyzer-cli https://example.com

# WAF 识别
wafw00f https://example.com

# Cloudflare IP 发现
# 真 IP 泄露方法:
# 1. 历史 DNS 记录
# 2. 邮件 MX 记录
# 3. SSL 证书
# 4. 子域名不在 Cloudflare 上

# CDN 绕过
# CloudFail
python cloudfail.py -t example.com

# CMS 识别
cmseek -u https://example.com

# 指纹数据库
# Favicon Hash
python favicon_hash.py https://example.com/favicon.ico
```

## 邮件与人员探测

```python
class EmailDiscovery:
    def __init__(self, domain):
        self.domain = domain
    
    def discover_format(self, names: list) -> str:
        """发现邮箱命名规则"""
        # 如果已知某人的邮箱，可推断格式
        # first.last@company.com
        # flastname@company.com
        # firstl@company.com
        pass
    
    def verify_email(self, email: str) -> bool:
        """邮箱存在验证"""
        # SMTP 验证
        # 不发送邮件，仅检测服务器是否接受
        import smtplib
        try:
            server = smtplib.SMTP(f'mail.{self.domain}', 25, timeout=5)
            server.helo()
            server.mail('verify@test.com')
            code, _ = server.rcpt(email)
            server.quit()
            return code == 250
        except:
            return False
    
    def linkedin_lookup(self, name: str) -> list:
        """LinkedIn 人员搜索"""
        # 使用 Google dork
        # site:linkedin.com/in "company" "name"
        pass
```

*上一篇：[OSINT 进阶与社工库](01-osint-advanced.md)*

*下一篇：[暗网情报收集](03-dark-web-intelligence.md)*

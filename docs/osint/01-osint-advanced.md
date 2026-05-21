# OSINT 进阶与社工库

> 公开源情报——攻击者用30%的时间做侦察，防御者却只花5%。

---

## OSINT 方法论

```mermaid
graph TB
    A[目标定义<br>公司/人员/IP/域名] --> B[被动信息收集]
    B --> C[主动侦察]
    C --> D[关联分析]
    D --> E[报告/情报输出]
```

## 域名与子域名发现

```bash
# 子域名枚举
# Passive（无直接接触）
amass enum -passive -d example.com
subfinder -d example.com
shuffledns -d example.com -w subdomains.txt

# DNS 历史记录
# SecurityTrails
curl "https://api.securitytrails.com/v1/domain/example.com/subdomains"

# Certificate Transparency
# crt.sh
curl -s "https://crt.sh/?q=%.example.com&output=json"
```

## 人员信息收集

```python
import requests
import json
from bs4 import BeautifulSoup

class PeopleOSINT:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def search_github(self, username: str) -> dict:
        """GitHub 信息收集"""
        result = {
            "repos": [],
            "email": None,
            "orgs": [],
            "contributions": []
        }
        
        # 用户信息
        user = requests.get(f"https://api.github.com/users/{username}", 
                           headers=self.headers).json()
        result["email"] = user.get("email")
        result["orgs"] = [org["login"] for org in 
                         requests.get(f"https://api.github.com/users/{username}/orgs",
                                    headers=self.headers).json()]
        
        # 仓库分析
        repos = requests.get(f"https://api.github.com/users/{username}/repos",
                            headers=self.headers).json()
        for repo in repos:
            if not repo.get("private"):
                result["repos"].append({
                    "name": repo["name"],
                    "description": repo.get("description"),
                    "language": repo.get("language"),
                    "topics": repo.get("topics", []),
                    "last_updated": repo.get("updated_at")
                })
        
        # 贡献统计
        contributions = requests.get(
            f"https://github-contributions-api.jerga.workers.dev/{username}"
        ).json()
        result["total_contributions"] = sum(
            day["count"] for day in contributions.get("contributions", [])
        )
        
        return result
    
    def search_email_breaches(self, email: str) -> dict:
        """检查邮箱泄露"""
        # DeHashed / HaveIBeenPwned API
        # 注意: 部分接口需要 API Key
        breaches = []
        
        # Have I Been Pwned
        hibp = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}")
        if hibp.status_code == 200:
            breaches = [b["Name"] for b in hibp.json()]
        
        return {
            "email": email,
            "breaches": breaches,
            "breach_count": len(breaches)
        }
```

## 代码搜索与情报

```bash
# GitHub 代码搜索
# 搜索硬编码密钥
git dumper — 下载整个仓库历史

# GitLeaks — 扫描 Git 历史中的秘密
gitleaks detect --source . --report-format json --report gitleaks.json

# TruffleHog — 扫描 Git 历史
trufflehog filesystem --directory . --json

# GitHub 搜索语法
org:company "aws_access_key"
org:company filename:.env
org:company "-----BEGIN RSA PRIVATE KEY-----"
filename:config.php password
```

## Telegram 监控

```python
# Telegram API 监控
# 使用 Telethon / MTProto API
from telethon import TelegramClient

class TelegramOSINT:
    def __init__(self, api_id, api_hash):
        self.client = TelegramClient('session', api_id, api_hash)
    
    async def monitor_channel(self, channel_name: str, keywords: list):
        """监控频道特定关键词"""
        await self.client.start()
        channel = await self.client.get_entity(channel_name)
        
        async for message in self.client.iter_messages(channel, limit=100):
            if message.text:
                for keyword in keywords:
                    if keyword.lower() in message.text.lower():
                        yield {
                            "channel": channel_name,
                            "timestamp": message.date.isoformat(),
                            "text": message.text[:200],
                            "keyword": keyword
                        }
    
    async def search_public_groups(self, query: str):
        """搜索公开群组"""
        result = await self.client.get_dialogs()
        groups = []
        for dialog in result:
            if dialog.is_group and query.lower() in dialog.name.lower():
                groups.append({
                    "name": dialog.name,
                    "id": dialog.id,
                    "members": getattr(dialog.entity, 'participants_count', 0)
                })
        return groups
```

## 网络侦查工具

```bash
# Shodan — 联网设备搜索
shodan search "port:3389 country:CN city:Beijing"
shodan search "org:CompanyName ssl:example.com"

# Censys — 证书/服务搜索
censys search "services.service_name: HTTP and location.country: CN"

# ZoomEye — 国内搜索引擎
zoomeye search "app:nginx country:CN"

# FOFA — 最全面的中文网络空间搜索引擎
fofa search "domain=example.com || org=Company"

# Pulsedive — IOC 关联分析
pulsedive search "ioc=1.2.3.4"  # 关联所有相关事件

# GreyNoise — 区分恶意扫描 vs 背景噪声
greynoise riot 1.2.3.4
```

## IOC 关联工具链

```python
class IocCorrelation:
    def __init__(self):
        self.ioc_db = {
            "ips": {},       # IP → 关联恶意事件
            "domains": {},   # Domain → 关联恶意活动
            "hashes": {}     # Hash → 恶意软件家族
        }
    
    def correlate(self, indicator: str, ioc_type: str):
        """关联 IOC 所有上下文"""
        results = {}
        
        # 被动 DNS
        results["passive_dns"] = self._query_passive_dns(indicator)
        
        # WHOIS
        results["whois"] = self._query_whois(indicator)
        
        # SSL 证书
        results["ssl"] = self._query_certificate(indicator)
        
        # 威胁情报源
        for source in ["virustotal", "alienvault", "misp", "threatbook"]:
            results[source] = self._query_threat_intel(indicator, source)
        
        # 关联度评分
        score = self._calculate_malicious_score(results)
        results["malicious_score"] = score
        
        return results
```

## 信息收集清单

```
域名收集:
[ ] 主域名注册商/WHOIS
[ ] 子域名（amass/crt.sh/SecurityTrails）
[ ] CDN IP 源站发现
[ ] 历史 DNS 记录

人员画像:
[ ] LinkedIn/脉脉/Boss 直聘
[ ] GitHub 活动 + 代码泄露
[ ] 社交媒体发文
[ ] 技术博客/演讲/论文

技术资产:
[ ] Web 技术栈（Wappalyzer/BuiltWith）
[ ] 云服务商识别
[ ] 第三方 JS/SaaS 组件
[ ] 暴露的管理面板/API 端点

泄露数据:
[ ] Have I Been Pwned
[ ] 暗网监控（Telegram/IRL）
[ ] 公开的 GitHub 泄露
[ ] 资料库（RaidForums/BreachForums）
```

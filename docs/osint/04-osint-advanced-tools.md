# OSINT 高级工具与自主情报挖掘

## 概述

开源情报 (OSINT) 已从简单的 Google 搜索发展为融合多数据源的情报分析学科。攻击者在行动前利用 OSINT 绘制目标数字足迹，防御者则利用 OSINT 主动发现暴露的资产和泄露的数据。

---

## 1. 高级 OSINT 工具库

### 1.1 SpiderFoot HX

```bash
# SpiderFoot — 自动化 OSINT 扫描平台

# Docker 部署
docker run -d -p 5001:5001 \
    --name spiderfoot \
    -v spiderfoot-data:/var/lib/spiderfoot \
    spiderfoot/spiderfoot

# 命令行扫描
python sf.py -s example.com \
    -m sfp_email,sfp_names,sfp_webserver,sfp_dns,sfp_shodan,sfp_abuseipdb \
    -o csv

# 模块分类:
# - Recon: DNS/子域名/证书透明度
# - Discovery: IP/端口/Web技术栈
# - Correlation: 关联分析
# - Leaks: 数据泄露搜索
```

### 1.2 theHarvester

```bash
# theHarvester — 信息收集瑞士军刀

# 全方位扫描
theHarvester -d example.com -b all -f report.html

# 支持的源:
# google, bing, yahoo, baidu, shodan
# linkedin, twitter, github
# crtsh (证书透明度), threatcrowd, virustotal
# dnsdumpster, ssl-certificates

# 命令行输出:
# [+] Emails found: 47
# [+] Hosts found: 312
# [+] IPs found: 23
# [+] URLs found: 86
```

### 1.3 Recon-ng

```bash
# Recon-ng — 模块化侦查框架

# 创建工作区
recon-ng
[recon-ng] > workspaces create example-com

# 加载模块
[recon-ng] > marketplace search github
[recon-ng] > modules load recon/contacts-contacts/github_creds

# 设置选项
[recon-ng][github_creds] > set SOURCE example.com

# 运行
[recon-ng][github_creds] > run

# 报告
[recon-ng] > modules load reporting/list
[recon-ng] > set FILENAME ~/example_report.html
[recon-ng] > run
```

---

## 2. 暗网情报收集

### 2.1 Tor 服务扫描

```bash
# 暗网情报收集 (法律规定: 仅用于被动侦查)

# 1. OnionScan — 扫描 Tor 隐藏服务
git clone https://github.com/s-rah/onionscan.git
onionscan -verbose -jsonReport example.onion

# 2. Ahmia 暗网搜索引擎
# 通过 Tor 访问: http://juhanurmihxlp77nkq76byazcldy2hlmocv3qg3b.cfd
ahmia-scrapy crawl -s "keyword"
```

### 2.2 数据泄露监控

```python
import requests
import hashlib
from datetime import datetime, timedelta

class DataLeakMonitor:
    """数据泄露监控 (仅监控自有域名)"""

    def __init__(self, monitored_domains):
        self.domains = monitored_domains
        self.leak_sources = []

    def check_haveibeenpwned(self, domain):
        """检查 Have I Been Pwned 域泄露"""
        # API v3 需要 API Key
        headers = {'hibp-api-key': self.api_key}

        response = requests.get(
            f'https://haveibeenpwned.com/api/v3/breaches',
            params={'domain': domain},
            headers=headers
        )

        if response.status_code == 200:
            breaches = response.json()
            for breach in breaches:
                yield {
                    'source': 'HaveIBeenPwned',
                    'breach_name': breach['Name'],
                    'date': breach['BreachDate'],
                    'data_classes': breach['DataClasses'],
                    'compromised_accounts': breach['PwnCount'],
                    'verified': breach['IsVerified']
                }

    def check_dehashed(self, domain):
        """检查 DeHashed 泄露"""
        response = requests.get(
            'https://api.dehashed.com/search',
            params={'query': f'email:@*{domain}'},
            auth=(self.dehashed_email, self.dehashed_key)
        )

        if response.status_code == 200:
            entries = response.json()['entries']
            for entry in entries:
                yield {
                    'source': 'DeHashed',
                    'email': entry['email'],
                    'password_hash': entry.get('hashed_password', 'HIDDEN'),
                    'database': entry.get('database_name', 'Unknown'),
                    'breach_date': entry.get('date', 'Unknown')
                }

    def monitor_cloud_exposure(self):
        """监控云资源暴露"""
        findings = []

        # 公开 S3 存储桶
        for domain in self.domains:
            company_name = domain.split('.')[0]

            # 常见存储桶命名模式
            bucket_patterns = [
                f'{company_name}-prod',
                f'{company_name}-backup',
                f'{company_name}-logs',
                f'{company_name}-terraform',
            ]

            for bucket in bucket_patterns:
                url = f'https://{bucket}.s3.amazonaws.com'
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        findings.append({
                            'type': 'public_s3_bucket',
                            'url': url,
                            'severity': 'HIGH'
                        })
                except:
                    pass

        return findings

    def generate_leak_report(self):
        """生成数据泄露报告"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'domains': self.domains,
            'findings': []
        }

        for domain in self.domains:
            # HIBP
            for breach in self.check_haveibeenpwned(domain):
                report['findings'].append(breach)

            # 云暴露
            for exposure in self.monitor_cloud_exposure():
                report['findings'].append(exposure)

        return report
```

---

## 3. Shodan 高级查询

```python
# Shodan 高级搜索 — Internet 设备发现

import shodan

api = shodan.Shodan('YOUR_API_KEY')

# 查询 1: 搜索暴露的工业控制系统
# Modbus (端口 502)
results = api.search('port:502 country:CN')
for result in results['matches']:
    print(f"{result['ip_str']}:{result['port']} — {result['org']}")
    for key in ['modbus', 's7', 'bacnet']:
        if key in result.get('data', '').lower():
            print(f"  → ICS protocol: {key}")

# 查询 2: 暴露的数据库
search_queries = {
    'Elasticsearch 无认证': 'product:Elastic port:9200 -"You Know, for Search"',
    'MongoDB 无认证': 'product:MongoDB port:27017',
    'Redis 无密码': 'product:Redis port:6379',
    'Jenkins 暴露': 'x-jenkins port:8080',
    'Docker API 暴露': 'Docker Containers port:2375',
    'Kubernetes Dashboard': 'Kubernetes port:6443',
    'Webcam 暴露': 'webcamxp country:CN',
    'SCADA 暴露': 'SCADA port:502',
}

for name, query in search_queries.items():
    try:
        count = api.count(query)
        if count['total'] > 0:
            print(f"{name}: {count['total']} 台设备暴露!")
    except:
        pass

# 查询 3: 多维度组合
# 搜索中国境内运行旧版 OpenSSH 的 Cisco 设备
results = api.search(
    'org:"China Telecom" product:"Cisco IOS" openssh'
)

# 查询 4: 证书透明度搜索
# 通过 crt.sh 查找子域名
import subprocess
def get_subdomains_ct(domain):
    """通过证书透明度查询子域名"""
    response = requests.get(
        f'https://crt.sh/?q=%.{domain}&output=json',
        headers={'User-Agent': 'Mozilla/5.0'}
    )
    if response.status_code == 200:
        names = set()
        for entry in response.json():
            name = entry['name_value']
            for n in name.split('\n'):
                if n.startswith('*.'):
                    # 通配符证书
                    names.add(f'wildcard:{n}')
                else:
                    names.add(n)
        return sorted(names)
    return []
```

---

## 4. 社交媒体情报 (SOCMINT)

```bash
# Sherlock — 跨平台用户名搜索

git clone https://github.com/sherlock-project/sherlock.git
cd sherlock
pip install -r requirements.txt

# 搜索用户名在 300+ 平台的注册情况
python sherlock.py target_username --output results/

# 示例输出:
# [+] Instagram: https://instagram.com/target_username
# [+] GitHub: https://github.com/target_username
# [+] Reddit: https://reddit.com/user/target_username
# [!] Twitter: Not Found

# Holehe — 邮箱注册检查
pip install holehe
holehe target@company.com

# maigret — 带元数据的用户名搜索
maigret target_username --all-sites --html
```

---

## 参考资源

- [SpiderFoot HX](https://www.spiderfoot.net/)
- [OSINT Framework](https://osintframework.com/)
- [Bellingcat 开源调查指南](https://www.bellingcat.com/)
- [IntelTechniques OSINT](https://inteltechniques.com/)

---

*上一篇：[OSINT 开源情报收集](./03-osint-tools-mastery.md)*

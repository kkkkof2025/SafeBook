# 暗网情报收集

## 概述

暗网（Dark Web）情报是威胁情报的重要组成部分。勒索软件团伙的泄露站点、地下论坛的漏洞交易、数据泄露的市场——这些都是暗网情报的关键来源。本章介绍安全、合法地收集暗网情报的技术。

---

## 1. 暗网技术基础

### 1.1 暗网层次架构

```
表层网络 (Surface Web):
  Google, Twitter, GitHub, 新闻网站
  → 占互联网的 ~4%

深网 (Deep Web):
  企业内部网, 数据库, 付费内容, 邮件
  → 占互联网的 ~90%

暗网 (Dark Web):
  Tor (.onion), I2P (.i2p), Freenet, ZeroNet
  → 占互联网的 ~6%
```

### 1.2 Tor 网络原理

```
客户端 → Guard Node → Middle Node → Exit Node → 目标服务器
         [加密1]      [加密2]      [加密3]      [明文]

每层解密 L1/L2/L3，没有单一节点知道完整路径。
```

### 1.3 安全访问暗网

```bash
# 1. Tor 浏览器 (最安全)
# 下载: https://www.torproject.org/

# 2. Tor CLI (用于自动化)
sudo apt install tor
sudo systemctl start tor

# 3. 通过 SOCKS5 代理使用 Tor
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/

# 4. Python 通过 Tor 请求
pip install requests[socks]
```

```python
import requests

# 通过 Tor SOCKS5 代理访问 .onion 站点
def tor_request(url):
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'
    })
    return session.get(url, timeout=30)
```

---

## 2. 暗网情报来源

### 2.1 主要威胁情报来源

| 来源 | 类型 | 内容 | 风险 |
|------|------|------|------|
| 勒索软件泄露站 | .onion | 受害者名单、泄露数据 | 避免下载恶意文件 |
| 地下论坛 (XSS, Exploit) | .onion | 漏洞交易、工具销售 | 不参与非法交易 |
| 数据泄露市场 | .onion/.i2p | 被盗数据库 | 不下载被盗数据 |
| Telegram 频道 | Surface | APT组织通信 | 截图取证 |
| Pastebin/Ghostbin | Surface | 泄露凭证 | 合规验证 |
| GitHub/GitLab | Surface | 泄露密钥 | 有漏洞赏金计划可报告 |

### 2.2 勒索软件团伙追踪

```python
import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime

class RansomwareTracker:
    """勒索软件泄露站点追踪器"""

    # 已知勒索软件团伙站点 (2024年更新)
    KNOWN_SITES = {
        'LockBit': 'lockbitapt.onion',
        'ALPHV/BlackCat': 'alphvmmm27.onion',
        'Clop': 'santat7kpllt6iyvqbr7q4amdv6dzky6rp2s5m3a.onion',
        'BianLian': 'bianlianlbc5.onion',
        'Play': 'k7kg3jqxang3wh7.onion',
    }

    def __init__(self):
        self.session = self._setup_tor_session()
        self.victims = []

    def _setup_tor_session(self):
        session = requests.Session()
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        return session

    def scrape_victims(self, group_name, onion_url):
        """爬取受害组织列表"""
        try:
            resp = self.session.get(
                f'http://{onion_url}',
                timeout=60
            )

            soup = BeautifulSoup(resp.text, 'html.parser')
            victims = []

            # LockBit 风格页面
            for post in soup.find_all('div', class_='post'):
                title = post.find('h4')
                date = post.find('span', class_='date')
                desc = post.find('div', class_='description')

                if title:
                    victims.append({
                        'group': group_name,
                        'victim': title.text.strip(),
                        'published': self._parse_date(date.text) if date else None,
                        'description': desc.text.strip()[:500] if desc else '',
                        'source': onion_url,
                        'collected_at': datetime.now().isoformat()
                    })

            self.victims.extend(victims)
            return victims

        except Exception as e:
            logging.error(f"Failed to scrape {group_name}: {e}")
            return []

    def generate_threat_report(self):
        """生成威胁情报报告（仅含公开数据）"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_victims': len(self.victims),
            'by_group': {},
            'by_industry': {},
            'recent_7d': []
        }

        for v in self.victims:
            group = v['group']
            report['by_group'][group] = report['by_group'].get(group, 0) + 1

        return report
```

---

## 3. 自动化情报收集

### 3.1 Telegram 威胁情报监控

```python
from telethon import TelegramClient, events
import re

class TelegramIntelMonitor:
    """Telegram 威胁情报频道监控"""

    # 公开研究用的安全频道
    CHANNELS = [
        'vxunderground',      # 恶意软件样本
        'ransomware_leaks',    # 勒索软件情报
        'ddosecrets',          # 数据泄露
        'monitor_crime'        # 网络犯罪监控
    ]

    def __init__(self, api_id, api_hash):
        self.client = TelegramClient('intel_monitor', api_id, api_hash)
        self.findings = []

    async def monitor_channels(self):
        """监控频道消息"""
        await self.client.start()

        for channel in self.CHANNELS:
            try:
                entity = await self.client.get_entity(f'@{channel}')

                @self.client.on(events.NewMessage(chats=[entity]))
                async def handler(event):
                    await self._analyze_message(event.message, channel)

            except Exception as e:
                print(f"Failed to join {channel}: {e}")

        await self.client.run_until_disconnected()

    async def _analyze_message(self, msg, channel):
        """分析消息是否包含威胁情报"""

        # 提取 IOC
        iocs = {
            'ips': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg.text),
            'domains': re.findall(r'\b[a-zA-Z0-9-]+\.(?:onion|xyz|top|tk)\b', msg.text),
            'hashes': re.findall(r'\b[a-fA-F0-9]{32,64}\b', msg.text),
            'urls': re.findall(r'https?://[^\s]+', msg.text)
        }

        if any(iocs.values()):
            self.findings.append({
                'channel': channel,
                'timestamp': msg.date.isoformat(),
                'iocs': iocs,
                'snippet': msg.text[:500]
            })
```

### 3.2 Pastebin 泄露监控

```python
from pastebin import PastebinAPI
import re

class PastebinLeakMonitor:
    """Pastebin 数据泄露监控"""

    KEYWORDS = [
        'password', 'api_key', 'secret', 'token',
        'database', 'dump', 'leak', 'breach',
        'credentials', 'connection_string', 'private_key'
    ]

    def __init__(self, api_key):
        self.api = PastebinAPI(api_key)
        self.alerts = []

    def scan_recent_pastes(self, limit=100):
        """扫描最近的 Paste"""
        pastes = self.api.trending(limit)

        for paste in pastes:
            score = self._scan_content(paste)

            if score > 3:
                self.alerts.append({
                    'paste_id': paste.id,
                    'title': paste.title,
                    'score': score,
                    'url': paste.url,
                    'detected_at': datetime.now().isoformat()
                })

    def _scan_content(self, paste):
        """内容评分"""
        score = 0
        content = paste.text.lower()

        for keyword in self.KEYWORDS:
            if keyword in content:
                score += 1

        # 检测结构化数据
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', paste.text):
            score += 2  # 包含邮箱

        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', paste.text):
            score += 1  # SSN 格式

        if 'BEGIN RSA PRIVATE KEY' in paste.text:
            score += 5  # 私钥泄露

        return score
```

---

## 4. 操作安全与合规

### 4.1 OPSEC 清单

```yaml
暗网情报 OPSEC:
  环境隔离:
    - [ ] 使用专用虚拟机 (非宿主机)
    - [ ] Tor 流量不得接触企业网络
    - [ ] 禁用 JavaScript/WebRTC (防IP泄露)
    - [ ] 专用 VPN + Tor (Tor over VPN)

  身份保护:
    - [ ] 不登录任何个人账户
    - [ ] 不下载任何文件到宿主机
    - [ ] 截图去元数据 (exiftool -all= screenshot.png)
    - [ ] 不与攻击者交互

  数据安全:
    - [ ] 仅收集公开信息
    - [ ] 证据链保全 (哈希 + 时间戳)
    - [ ] 隔离存储 (气隙硬盘)
    - [ ] 定期销毁不需要的截图
```

### 4.2 法律边界

```
✅ 允许的活动:
  - 访问公开的 .onion 站点（信息收集）
  - 搜索开源威胁情报
  - 在安全研究框架内监控公开频道
  - 向执法机构报告发现

❌ 禁止的活动:
  - 购买被盗数据/漏洞
  - 在论坛注册账户并参与讨论
  - 下载恶意软件样本到非隔离环境
  - 尝试利用找到的漏洞
  - 未经授权访问受保护系统
```

---

## 5. 情报分析平台

### 5.1 MISP 集成

```python
from pymisp import PyMISP, MISPEvent

class DarknetIntel2MISP:
    """将暗网情报导入 MISP"""

    def __init__(self, misp_url, misp_key):
        self.misp = PyMISP(misp_url, misp_key, False)

    def create_event_from_finding(self, finding):
        event = MISPEvent()
        event.info = f"Darknet Intel: {finding['type']}"
        event.threat_level_id = 3  # 高
        event.analysis = 1  # 进行中
        event.add_tag('tlp:amber')
        event.add_tag('source:darknet-monitoring')

        # 添加 IOC
        for ip in finding.get('ips', []):
            event.add_attribute('ip-dst', ip)

        for domain in finding.get('domains', []):
            event.add_attribute('domain', domain)

        for file_hash in finding.get('hashes', []):
            event.add_attribute('sha256', file_hash)

        return self.misp.add_event(event)
```

---

## 参考资源

- [Tor Project](https://www.torproject.org/)
- [MISP Threat Sharing](https://www.misp-project.org/)
- [Darknet Diaries (播客)](https://darknetdiaries.com/)
- [Ahmia - 暗网搜索引擎](https://ahmia.fi/)

---

*上一篇：[OSINT 信息收集实战](./02-osint-practical.md)*

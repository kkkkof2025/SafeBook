# 威胁情报平台 (TIP) 与自动化

## 概述

积累 IOC 不叫威胁情报，把 IOC 自动化推送到 SIEM/EDR/防火墙并产生闭环反馈，才叫威胁情报运营。本章介绍威胁情报平台 (TIP) 的建设和自动化集成。

---

## 1. TIP 架构

```
威胁情报平台 (TIP) 架构:

  ┌────────────────────────────────────────────┐
  │               威胁情报平台 (TIP)              │
  │                                              │
  │  输入 ──→ 处理 ──→ 分析 ──→ 输出             │
  │                                              │
  │  OSINT     去重      关联      SIEM (Splunk)  │
  │  Commerci. 富化      评分      EDR (CS)      │
  │  ISAC      标准化    归因      防火墙 (PA)    │
  │  Internal  分类      趋势      工单 (Jira)    │
  │                                              │
  └────────────────────────────────────────────┘
```

---

## 2. MISP 部署与配置

### 2.1 Docker 部署

```yaml
# docker-compose.yml
version: '3'
services:
  misp:
    image: coolacid/misp-docker:latest
    container_name: misp
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - misp_data:/var/www/MISP
    environment:
      MYSQL_ROOT_PASSWORD: changeme
      MISP_BASEURL: https://misp.example.com
      MISP_ADMIN_EMAIL: admin@example.com
    depends_on:
      - misp-db

  misp-db:
    image: mariadb:10.4
    environment:
      MYSQL_ROOT_PASSWORD: changeme
      MYSQL_DATABASE: misp
    volumes:
      - misp_db:/var/lib/mysql

volumes:
  misp_data:
  misp_db:
```

### 2.2 Feeds 配置

```bash
# MISP 订阅开源威胁源

# 1. 启用默认 Feeds
curl -k -H "Authorization: YOUR_API_KEY" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -X POST https://misp.example.com/feeds/fetchFromAllFeeds

# 2. 添加自定义 Feed
curl -k -H "Authorization: YOUR_API_KEY" \
    -H "Content-Type: application/json" \
    -X POST https://misp.example.com/feeds/add \
    -d '{
        "Feed": {
            "name": "Abuse.ch URLhaus",
            "provider": "Abuse.ch",
            "url": "https://urlhaus.abuse.ch/downloads/misp/",
            "enabled": true,
            "distribution": 1,
            "default": true,
            "source_format": "misp"
        }
    }'

# 3. 配置定时拉取 (Cron)
# 0 */4 * * * curl -k -H "Authorization: YOUR_API_KEY" \
#   -X POST https://misp.example.com/feeds/fetchFromAllFeeds
```

---

## 3. 自动化集成

### 3.1 MISP → Splunk

```python
#!/usr/bin/env python3
"""
MISP → Splunk 自动化同步
拉取 MISP IOC → 推送到 Splunk 查找表
"""

import requests
from datetime import datetime, timedelta

class MISPSplunkSync:
    def __init__(self, misp_url, misp_key, splunk_url, splunk_token):
        self.misp_url = misp_url
        self.misp_key = misp_key
        self.splunk_url = splunk_url
        self.splunk_token = splunk_token

    def fetch_recent_iocs(self, hours=24):
        """获取最近 24 小时的 IOC"""
        response = requests.post(
            f"{self.misp_url}/attributes/restSearch",
            headers={
                'Authorization': self.misp_key,
                'Content-Type': 'application/json'
            },
            json={
                'returnFormat': 'json',
                'timestamp': int(
                    (datetime.now() - timedelta(hours=hours)).timestamp()
                ),
                'to_ids': 1,
                'includeEventTags': 1,
                'includeContext': 1
            },
            verify=False
        )

        if response.status_code == 200:
            data = response.json()
            return data.get('response', {}).get('Attribute', [])

        return []

    def push_to_splunk_lookup(self, iocs):
        """推送到 Splunk 查找表"""

        for ioc in iocs:
            entry = {
                'ioc_type': ioc.get('type'),
                'ioc_value': ioc.get('value'),
                'category': ioc.get('category'),
                'comment': ioc.get('comment', ''),
                'tags': ','.join(tag.get('name') for tag in ioc.get('Tag', [])),
                'source': 'MISP',
                'updated': datetime.now().isoformat()
            }

            # Splunk KV Store 方式
            requests.post(
                f"{self.splunk_url}/servicesNS/nobody/search/data/kvstore_collections/misp_iocs",
                headers={
                    'Authorization': f'Bearer {self.splunk_token}',
                    'Content-Type': 'application/json'
                },
                json=entry,
                verify=False
            )

    def run(self):
        iocs = self.fetch_recent_iocs()
        self.push_to_splunk_lookup(iocs)
        print(f"Synced {len(iocs)} IOCs to Splunk")
```

### 3.2 MISP → EDR (CrowdStrike)

```python
class MISPEDRSync:
    """MISP → CrowdStrike Falcon 自动阻断"""

    def __init__(self, misp_client, falcon_client):
        self.misp = misp_client
        self.falcon = falcon_client

    def sync_high_confidence_iocs(self):
        """同步高置信度 IOC 到 Falcon"""

        # 获取高置信度 IOC
        iocs = self.misp.search_attributes(
            to_ids=True,
            tags=['confidence:high', 'action:block'],
            timestamp=int((datetime.now() - timedelta(hours=1)).timestamp())
        )

        for ioc in iocs:
            if ioc['type'] == 'ip-dst' or ioc['type'] == 'ip-src':
                self.falcon.create_ioc(
                    type='ipv4',
                    value=ioc['value'],
                    policy='prevent',  # 阻断
                    platforms=['windows', 'linux', 'mac'],
                    description=f"MISP: {ioc.get('comment', 'No comment')}",
                    severity='high'
                )

            elif ioc['type'] == 'domain':
                self.falcon.create_ioc(
                    type='domain',
                    value=ioc['value'],
                    policy='prevent',
                    platforms=['windows', 'linux', 'mac'],
                    description=f"MISP: {ioc.get('comment', '')}",
                    severity='high'
                )

            elif ioc['type'] == 'sha256':
                self.falcon.create_ioc(
                    type='sha256',
                    value=ioc['value'],
                    policy='prevent',
                    platforms=['windows', 'linux', 'mac'],
                    description=f"MISP: Malware hash",
                    severity='critical'
                )
```

### 3.3 自动创建工单

```python
class ThreatIntelWorkflow:
    """威胁情报自动工单工作流"""

    def auto_ticket_for_critical_ioc(self, ioc, siem_hits):
        """
        当关键 IOC 在 SIEM 中有命中时，自动创建工单
        """

        if siem_hits == 0:
            print(f"[INFO] {ioc['value']}: 无 SIEM 命中，跳过工单")
            return

        ticket = {
            'title': f'[TI] {ioc["value"]} 检测到活动 ({siem_hits} 命中)',
            'severity': 'HIGH' if siem_hits > 10 else 'MEDIUM',
            'description': (
                f"威胁情报 IOC 在生产环境中检测到活动:\n\n"
                f"- IOC: {ioc['value']}\n"
                f"- 类型: {ioc['type']}\n"
                f"- 命中数: {siem_hits}\n"
                f"- 来源: {ioc.get('source', 'Unknown')}\n"
                f"- 标签: {ioc.get('tags', [])}\n\n"
                f"行动:\n"
                f"1. 确认 IOC 真实性\n"
                f"2. 隔离影响主机\n"
                f"3. 更新阻断列表\n"
                f"4. 启动事件响应\n"
            ),
            'labels': ['threat-intel', 'automated'],
            'components': ['SOC', 'IR']
        }

        # TheHive API
        requests.post(
            'https://thehive.example.com/api/case',
            json=ticket,
            headers={'Authorization': f'Bearer {THEHIVE_KEY}'}
        )
```

---

## 4. IOC 生命周期管理

```yaml
IOC 生命周期:

  创建 → 验证 → 激活 → 监控 → 降级 → 过期

  创建: 从情报源/内部发现生成 IOC
  验证: 内部/外部验证 IOC 真实性
  激活: 推送到检测/阻断系统
  监控: 跟踪命中率和效果
  降级: 命中率下降 → 改为监控模式
  过期: 长时间无命中 → 归档

  关键指标:
    - 命中率 (Hit Rate): 有用 IOC / 总 IOC
    - 存活时间 (TTL): IOC 进入激活到过期的时间
    - 误报率 (FPR): 误命中 / 总命中
```

---

## 参考资源

- [MISP 开源威胁情报平台](https://www.misp-project.org/)
- [TheHive 事件响应平台](https://thehive-project.org/)
- [Cortex 可观测性和响应](https://github.com/TheHive-Project/Cortex)

---

*上一篇：[威胁情报分析](./03-threat-intel-analysis.md)*

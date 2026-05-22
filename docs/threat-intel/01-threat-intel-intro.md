# 威胁情报基础：从 IOC 到 TTP

## 概述

威胁情报的起点不是 "IP 黑名单"——而是回答一个基本问题："敌人在做什么？"。本章从威胁情报的基础概念出发，建立从 IOC 到 TTP 的分析框架。

---

## 1. 威胁情报金字塔 (Pyramid of Pain)

```
威胁情报金字塔 (David Bianco):

              难度   价值
  TTPs        ★★★★★  ★★★★★   (战术/技术/过程)
  工具        ★★★★   ★★★★    (Cobalt Strike/Mimikatz)
  网络/主机   ★★★    ★★★     (域名/C2 IP/URL)
  哈希值      ★★     ★★      (MD5/SHA256)
  IP 地址     ★      ★        (单次攻击 IP)

  ← 对攻击者来说 越难改变 → 对防御者来说 越有价值
```

---

## 2. IOC 生命周期

```python
from datetime import datetime, timedelta

class IOCManager:
    """IOC 生命周期管理"""

    def __init__(self):
        self.iocs = {}  # IOC → metadata

    def create_ioc(self, ioc_type, ioc_value, source, confidence):
        """创建 IOC"""

        # 根据类型设置默认 TTL
        default_ttl = {
            'ip': timedelta(days=7),
            'domain': timedelta(days=30),
            'url': timedelta(days=30),
            'sha256': timedelta(days=90),
            'email': timedelta(days=14),
            'registry': timedelta(days=90),
        }

        self.iocs[ioc_value] = {
            'type': ioc_type,
            'value': ioc_value,
            'source': source,
            'confidence': confidence,
            'created': datetime.now(),
            'ttl': default_ttl.get(ioc_type, timedelta(days=30)),
            'status': 'active',
            'hit_count': 0,
            'false_positive_count': 0,
            'last_seen': None
        }

    def record_hit(self, ioc_value, is_false_positive=False):
        """记录 IOC 命中"""
        if ioc_value not in self.iocs:
            return

        ioc = self.iocs[ioc_value]
        ioc['last_seen'] = datetime.now()

        if is_false_positive:
            ioc['false_positive_count'] += 1
            # 如果误报率超过 30%, 自动降级
            total = ioc['hit_count'] + ioc['false_positive_count']
            if total > 10 and ioc['false_positive_count'] / total > 0.3:
                ioc['status'] = 'deprecated'
                ioc['ttl'] = timedelta(days=1)  # 24 小时内过期
        else:
            ioc['hit_count'] += 1

    def expire_old_iocs(self):
        """过期清理"""
        now = datetime.now()
        expired = []

        for value, ioc in self.iocs.items():
            if ioc['status'] == 'deprecated':
                expired.append(value)
                continue

            age = now - ioc['created']
            if age > ioc['ttl']:
                # 如果仍有活跃命中, 延长期限
                if ioc['last_seen'] and (now - ioc['last_seen']) < timedelta(days=3):
                    ioc['ttl'] += timedelta(days=7)
                    continue

                ioc['status'] = 'expired'
                expired.append(value)

        for value in expired:
            del self.iocs[value]

        return len(expired)

    def get_quality_score(self, ioc_value):
        """IOC 质量评分"""
        ioc = self.iocs.get(ioc_value)
        if not ioc:
            return 0

        score = 0

        # 高置信度源
        trusted_sources = ['CrowdStrike', 'Mandiant', 'Recorded Future',
                          'VirusTotal (10+ engines)', 'ISAC']
        if ioc['source'] in trusted_sources:
            score += 30

        # 有实际命中
        if ioc['hit_count'] > 0:
            score += min(ioc['hit_count'] * 5, 25)

        # 低误报
        total = ioc['hit_count'] + ioc['false_positive_count']
        if total > 0 and ioc['false_positive_count'] / total < 0.1:
            score += 25

        # 最近被观察到
        if ioc['last_seen'] and (datetime.now() - ioc['last_seen']) < timedelta(days=7):
            score += 20

        return min(score, 100)
```

---

## 3. 从 IOC 到 TTP：威胁画像

```yaml
TTP 映射示例: APT41

  侦察 (Reconnaissance):
    - T1595:  主动扫描 (Active Scanning)
    - T1592:  收集受害者主机信息
    - T1598:  钓鱼获取信息 (Phishing for Information)

  资源开发 (Resource Development):
    - T1587:  开发/获取能力
      → SQL 注入工具、Webshell
    - T1583:  获取基础设施
      → 租用 C2 域名、VPS

  初始访问 (Initial Access):
    - T1190:  利用公开应用漏洞 (Exploit Public-Facing Application)
      → CVE-2021-44228 (Log4Shell)
      → CVE-2023-XXXXX (VPN 零日)
    - T1566:  钓鱼 (Phishing)
      → 针对 HR/财务的目标鱼叉邮件

  执行 (Execution):
    - T1059.001: PowerShell
    - T1053:      计划任务 (Scheduled Task)

  持久化 (Persistence):
    - T1505.003: IIS/Web 模块
    - T1546.015: COM 劫持

  防御规避 (Defense Evasion):
    - T1027:     混淆文件
    - T1562.001: 禁用 Windows Defender
    - T1070.004: 删除文件 (覆盖删除)

  凭据访问 (Credential Access):
    - T1003.001: LSASS 内存导出
    - T1552.001: 凭证文件 (sysprep.xml)
    - T1555.003: Web 浏览器密码

  发现 (Discovery):
    - T1082:     系统信息发现
    - T1018:     远程系统发现
    - T1069:     权限组发现

  横向移动 (Lateral Movement):
    - T1021.001: RDP
    - T1570:     横向工具传输

  收集 (Collection):
    - T1005:     本地系统数据
    - T1114.002: 远程邮箱

  命令与控制 (C2):
    - T1071.001: HTTPS
    - T1132:     数据编码 (Base64/Custom)

  数据外泄 (Exfiltration):
    - T1041:     C2 通道外泄
    - T1567.002: 云存储 (OneDrive/Google Drive)
```

---

## 4. 情报源评估

```yaml
威胁情报源评估矩阵:

  权威性:    来源可信度
  及时性:    更新频率
  准确性:    误报率
  可操作性:  是否易于集成到安全工具

  推荐情报源 (按类型):
  
  高价值 (直接可操作):
    - CrowdStrike Falcon Intelligence
    - Mandiant Advantage
    - Recorded Future
    - Anomali ThreatStream

  开源 (免费但需过滤):
    - Abuse.ch (URLhaus, ThreatFox, FeodoTracker)
    - AlienVault OTX
    - MISP (自建/社区)
    - VirusTotal (需商业许可用于自动化)

  社区共享:
    - ISAC/ISAO (行业特定)
    - FS-ISAC (金融)
    - H-ISAC (医疗)
```

---

## 参考资源

- [Pyramid of Pain (David Bianco)](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Abuse.ch](https://abuse.ch/)

---

*下一篇：[威胁情报平台自动化](02-tip-automation.md)*

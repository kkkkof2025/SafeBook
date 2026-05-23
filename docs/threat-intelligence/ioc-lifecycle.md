# IOC 管理与威胁情报平台

> 从原始数据到可操作情报的生命周期

---

## 1. IOC 生命周期

```
IOC 生命周期 (Pyramid of Pain):
        ┌─────────────┐
        │   TTP        │ ← 最难改变: 攻击手法
        ├─────────────┤
        │   Tools      │ ← 工具链
        ├─────────────┤
        │   Network    │ ← C2/Domain/IP
        ├─────────────┤
        │   Host       │ ← Registry/Mutex/Filename
        ├─────────────┤
        │   Artifact   │ ← Hash/Memory Pattern
        └─────────────┘
```

### IOC 验证流程
```python
class IOCLifecycleManager:
    """IOC 生命周期管理 (Collect → Validate → Distribute → Expire)"""

    def __init__(self):
        self.iocs = {}  # ioc_id → IOC record
        self.tlp_colors = {
            'RED': '仅限收件人',
            'AMBER': '有限分发',
            'GREEN': '社区内',
            'WHITE': '无限制',
        }

    def ingest(self, raw_ioc, source, confidence):
        """接收原始 IOC"""
        ioc_id = hashlib.sha256(
            f"{raw_ioc['type']}:{raw_ioc['value']}:{source}".encode()
        ).hexdigest()[:16]

        if ioc_id in self.iocs:
            # 更新置信度
            self.iocs[ioc_id]['confidence'] = max(
                self.iocs[ioc_id]['confidence'],
                confidence
            )
            return ioc_id

        self.iocs[ioc_id] = {
            'id': ioc_id,
            'type': raw_ioc['type'],
            'value': raw_ioc['value'],
            'source': source,
            'confidence': confidence,
            'status': 'new',
            'first_seen': datetime.utcnow(),
            'last_seen': datetime.utcnow(),
            'expires': datetime.utcnow() + timedelta(days=90),
            'tlp': 'AMBER',
            'tags': raw_ioc.get('tags', []),
        }

        # 自动验证
        self.enrich(ioc_id)
        return ioc_id

    def enrich(self, ioc_id):
        """自动丰富 IOC"""
        ioc = self.iocs[ioc_id]

        if ioc['type'] == 'domain':
            # Whois + DNS
            whois = self.query_whois(ioc['value'])
            ioc['whois'] = whois
            ioc['age_days'] = whois.get('age_days')

            # 新注册域名 → 提升风险
            if ioc.get('age_days', 999) < 30:
                ioc['confidence'] += 20
                ioc['tags'].append('newly_registered')

        elif ioc['type'] == 'ip':
            # GeoIP + ASN + 威胁情报反向查询
            geo = self.geoip(ioc['value'])
            ioc['geo'] = geo

            # 已知恶意 ASN
            if geo['asn'] in KNOWN_MALICIOUS_ASN:
                ioc['confidence'] += 15

        elif ioc['type'] == 'hash':
            # VirusTotal 查询
            vt = self.virustotal(ioc['value'])
            ioc['vt_ratio'] = f"{vt['positives']}/{vt['total']}"

            if vt['positives'] > 10:
                ioc['confidence'] = max(ioc['confidence'], 90)

    def expire(self):
        """自动过期 IOC"""
        now = datetime.utcnow()
        expired = []
        for ioc_id, ioc in self.iocs.items():
            if now > ioc['expires'] or (
                (now - ioc['last_seen']).days > 180
            ):
                ioc['status'] = 'expired'
                expired.append(ioc_id)
        return expired
```

---

## 2. STIX/TAXII 集成

```python
import stix2

class STIXConverter:
    """IOC → STIX 2.1 格式转换"""

    def to_stix_indicator(self, ioc):
        """转换为 STIX Indicator"""
        indicator = stix2.Indicator(
            name=f"IOC: {ioc['value']}",
            pattern=self._to_pattern(ioc),
            pattern_type="stix",
            valid_from=ioc['first_seen'],
            indicator_types=["malicious-activity"],
            labels=ioc.get('tags', []),
            confidence=ioc['confidence'],
            created_by_ref=self.identity_id,
        )
        return indicator

    def _to_pattern(self, ioc):
        patterns = {
            'ip': f"[ipv4-addr:value = '{ioc['value']}']",
            'domain': f"[domain-name:value = '{ioc['value']}']",
            'url': f"[url:value = '{ioc['value']}']",
            'hash_md5': f"[file:hashes.MD5 = '{ioc['value']}']",
            'hash_sha256': f"[file:hashes.'SHA-256' = '{ioc['value']}']",
            'email': f"[email-addr:value = '{ioc['value']}']",
        }
        return patterns.get(ioc['type'], '')

    def to_taxii_bundle(self, iocs):
        """生成 TAXII Bundle"""
        bundle = stix2.Bundle(
            objects=[self.to_stix_indicator(i) for i in iocs]
        )
        return bundle.serialize()
```

---

## 3. 威胁情报平台对比

| 平台 | 类型 | IOC 管理 | STIX | 集成 |
|------|------|---------|------|------|
| MISP | 开源 | ✅✅ | ✅ | SIEM/IDS/Sandbox |
| OpenCTI | 开源 | ✅✅✅ | ✅✅ | 全系集成 |
| ThreatConnect | 商业 | ✅✅✅ | ✅ | SOAR/SIEM |
| Anomali | 商业 | ✅✅ | ✅ | Splunk/QRadar |
| Yeti | 开源 | ✅ | ✅ | API 驱动 |

```bash
# MISP 部署
docker run -d -p 443:443 \
  -v misp-db:/var/lib/mysql \
  -v misp-data:/var/www/MISP/app/files \
  misp/misp:latest

# OpenCTI 部署
docker-compose -f docker-compose.yml up -d
# 包含: OpenCTI + Elasticsearch + Redis + MinIO + RabbitMQ
```

---

## 4. 自动化情报消费

```python
class ThreatIntelConsumer:
    """自动化威胁情报消费"""

    def consume_feed(self, feed_url):
        feed = self.fetch_feed(feed_url)

        for entry in feed:
            # 1. 提取 IOC
            iocs = self.extract_iocs(entry)

            # 2. 自动验证
            validated = [i for i in iocs
                        if self.validate_ioc(i)]

            # 3. 高危自动封禁
            for ioc in validated:
                if ioc['confidence'] >= 90:
                    self.automated_blacklist(ioc)
                    log.info(f"Auto-blocked: {ioc['value']} "
                            f"(confidence={ioc['confidence']})")

                elif ioc['confidence'] >= 70:
                    self.create_alert(ioc)

    def automated_blacklist(self, ioc):
        """自动加入黑名单"""
        if ioc['type'] == 'ip':
            self.firewall.block_ip(ioc['value'])
            self.proxy.block(ioc['value'])
        elif ioc['type'] == 'domain':
            self.dns_sinkhole.redirect(ioc['value'])
        elif ioc['type'] == 'hash':
            self.edr.block_hash(ioc['value'])
```

---

*上一篇：[威胁建模与 ATT&CK 框架](02-threat-modeling.md)*

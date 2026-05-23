# SOAR 安全编排自动化

> 从告警到响应：安全自动化的完整 Playbook

---

## 1. SOAR 架构

```
┌──────────────────────────────────────────────────────┐
│                    SOAR 平台                          │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │  告警源   │  │ Playbook │  │  响应 Action     │   │
│  │          │  │ 引擎     │  │                  │   │
│  │ SIEM    ─┼─→│          ├─→│  封禁 IP/Firewall│   │
│  │ EDR     ─┼─→│ 触发 →   │  │  隔离主机         │   │
│  │ WAF     ─┼─→│ 研判 →   │  │  吊销凭证         │   │
│  │ DL      ─┼─→│ 决策 →   │  │  创建工单         │   │
│  │ 威胁情报 ─┼─→│ 执行     │  │  发送通知         │   │
│  └──────────┘  └──────────┘  └──────────────────┘   │
└──────────────────────────────────────────────────────┘
```

---

## 2. Playbook 设计

### 钓鱼邮件自动响应
```python
class PhishingPlaybook:
    """钓鱼邮件检测 → 自动响应"""

    def __init__(self):
        self.email_gateway = EmailGateway()
        self.edr = EDRClient()
        self.siem = SIEMClient()
        self.firewall = FirewallAPI()

    def on_phishing_alert(self, alert):
        email_id = alert['email_id']
        report = {'id': email_id, 'actions': []}

        # Step 1: 提取 IOC
        iocs = self.extract_iocs(email_id)

        # Step 2: 扫描所有收件人
        recipients = self.email_gateway.get_recipients(email_id)
        for user in recipients:
            if action := self.check_user_impact(user, iocs):
                report['actions'].append(action)

        # Step 3: 删除所有实例中的该邮件
        deleted = self.email_gateway.purge_email(
            email_id, reason='PHISHING_CONFIRMED'
        )
        report['actions'].append({
            'action': 'purge_email',
            'count_deleted': deleted,
            'status': 'completed'
        })

        # Step 4: 封锁恶意 IOC
        for url in iocs.get('urls', []):
            self.firewall.block_url(url, duration_hours=168)
            report['actions'].append({
                'action': 'block_url', 'url': url
            })

        for hash_val in iocs.get('file_hashes', []):
            self.edr.block_hash(hash_val)
            report['actions'].append({
                'action': 'block_hash', 'sha256': hash_val
            })

        return report

    def check_user_impact(self, user, iocs):
        """检查用户是否点击了恶意链接"""
        url_clicks = self.siem.query_logs(
            f'user:{user} AND event:url_click',
            time_range='24h'
        )

        for click in url_clicks:
            if any(url in click['url'] for url in iocs.get('urls', [])):
                return {
                    'action': 'user_clicked_malware',
                    'user': user,
                    'url': click['url'],
                    'mitigation': [
                        'reset_password',
                        'revoke_sessions',
                        'scan_endpoint'
                    ]
                }
        return None
```

### 暴力破解自动封禁
```python
class BruteForcePlaybook:
    def on_bruteforce_alert(self, alerts):
        """暴力破解 → 分级响应"""

        # 聚合最近 5 分钟的所有暴力破解告警
        src_ips = Counter(a['src_ip'] for a in alerts)
        targets = Counter(a['target'] for a in alerts)

        for ip, count in src_ips.items():
            if count > 50:
                # 高严重度: 永久封禁 + 情报共享
                self.firewall.block_ip(ip, duration_hours=720)
                self.threat_intel.report_ip(ip, 'BRUTE_FORCE')
                self.create_ticket({
                    'title': f'Aggressive brute force from {ip}',
                    'attempts': count,
                    'priority': 'P1'
                })
            elif count > 10:
                # 中严重度: 24小时封禁
                self.firewall.block_ip(ip, duration_hours=24)
                self.notify_soc(f'Blocked {ip}: {count} brute force attempts')
            else:
                # 低严重度: 1小时封禁
                self.firewall.block_ip(ip, duration_hours=1)

        # 检查受攻击账户是否需要额外保护
        for target, count in targets.items():
            if count > 20:
                self.iam.require_mfa(target)
                self.iam.force_password_reset(target)
```

---

## 3. 自动研判 (Enrichment)

```python
class AlertEnricher:
    """告警自动丰富：添加上下文，减少误报"""

    def enrich(self, alert):
        enriched = dict(alert)

        # 1. IP 情报查询
        if 'src_ip' in alert:
            intel = self.threat_intel.lookup(alert['src_ip'])
            enriched['ip_intel'] = intel
            enriched['ip_reputation'] = intel.get('score', 0)

        # 2. 地理位置
        if 'src_ip' in alert:
            geo = self.geoip.lookup(alert['src_ip'])
            enriched['geo'] = {
                'country': geo.country,
                'city': geo.city,
                'is_tor': geo.tor_exit_node,
                'is_vpn': geo.vpn
            }

        # 3. 漏洞情报
        if 'cve' in alert:
            cve_info = self.nvd.lookup(alert['cve'])
            enriched['cve'] = {
                'cvss': cve_info.cvss_score,
                'severity': cve_info.severity,
                'exploit_available': cve_info.has_exploit,
                'patch_available': cve_info.has_patch
            }

        # 4. 资产上下文
        if 'hostname' in alert:
            asset = self.cmdb.lookup(alert['hostname'])
            enriched['asset'] = {
                'environment': asset.env,  # prod/staging
                'owner': asset.owner,
                'criticality': asset.crit,  # P0-P4
                'exposed_to_internet': asset.internet_facing
            }

        # 5. 计算风险评分 (0-100)
        enriched['risk_score'] = self.calculate_risk(enriched)
        enriched['recommendation'] = self.get_recommendation(
            enriched['risk_score']
        )

        return enriched

    def calculate_risk(self, enriched):
        """多因子风险评分"""
        score = 0

        if enriched.get('cve', {}).get('cvss', 0) >= 9.0: score += 30
        if enriched.get('cve', {}).get('exploit_available'): score += 20
        if enriched.get('ip_reputation', 0) > 80: score += 20
        if enriched.get('asset', {}).get('environment') == 'prod': score += 20
        if enriched.get('asset', {}).get('criticality') in ['P0', 'P1']: score += 10

        return min(100, score)
```

---

## 4. SOAR 工具对比

| 工具 | 类型 | 优势 | 适合 |
|------|------|------|------|
| Splunk SOAR (Phantom) | 商业 | 生态最大 | 大企业 |
| Palo Alto XSOAR | 商业 | MITRE ATT&CK 集成 | 大企业 |
| Swimlane | 商业 | 低代码 Playbook | 中等企业 |
| Shuffle | 开源 | 完全开源、灵活 | 中小企业 |
| n8n + Python | 自建 | 最大化定制 | 自研团队 |
| Tines | 商业 | 无代码自动化 | 中小 SOC |

---

## 5. SOAR 成熟度

| 级别 | 自动化程度 | 示例 |
|------|-----------|------|
| L1 | 完全手动 | 工单系统 |
| L2 | 半自动 | 告警富化 + 人工研判 |
| L3 | 自动决策 | 中低风险自动响应 |
| L4 | 自适应 | AI 驱动动态 Playbook |
| L5 | 自治 | 全自动安全运营 |

---

*上一篇：[SOC 自动化运营](04-soc-soar.md)*

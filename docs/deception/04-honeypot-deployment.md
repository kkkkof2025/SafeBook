# 蜜罐部署实战

> 从设计到部署：欺骗防御技术完整指南

---

## 1. 欺骗防御架构

```
蜜罐部署阶梯:
  Level 1: 低交互蜜罐
    ├── Cowrie (SSH/Telnet)
    ├── Dionaea (SMB/HTTP/FTP/MSSQL)
    └── Honeytrap (多协议自动响应)

  Level 2: 高交互蜜罐
    ├── 真实操作系统 + 监控
    ├── 完整服务栈 (Web + DB + 文件系统)
    └── 可用于收集攻击者 TTP

  Level 3: 蜜网 (Honeynet)
    ├── 多个蜜罐组成模拟网络
    ├── 包含"面包屑"(诱饵) 引导攻击
    └── 重度监控 + 流量镜像

  Level 4: 分布式欺骗
    ├── Canarytokens (遍布全网的诱饵)
    ├── Deception Grid (欺骗网格)
    └── 结合 EDR/XDR 的主动欺骗
```

---

## 2. 低交互蜜罐部署

### Cowrie (SSH 蜜罐)
```bash
# Docker 部署
docker run -d --name cowrie \
  -p 2222:2222 \
  -v cowrie-data:/cowrie/cowrie-git/var \
  cowrie/cowrie:latest

# 配置文件 cowrie.cfg
[ssh]
listen_port = 2222
hostname = db-prod-01
# 模拟的 SSH 版本
ssh_version = SSH-2.0-OpenSSH_7.4

# 日志收集
docker exec cowrie tail -f /cowrie/cowrie-git/var/log/cowrie/cowrie.json

# Cowrie 日志示例
{
  "eventid": "cowrie.login.success",
  "username": "root",
  "password": "admin123",
  "timestamp": "2024-09-15T14:23:00Z",
  "src_ip": "192.168.1.100",
  "session": "abc123"
}
```

### T-Pot (全能蜜罐集群)
```bash
# T-Pot 部署 (20+ 蜜罐一体化)
git clone https://github.com/telekom-security/tpotce
cd tpotce/iso/installer/
# 选择 Standard/Full 安装
# Web 管理界面: https://<IP>:64297
# Kibana 仪表盘: https://<IP>:64294

# 包含蜜罐:
# - Cowrie/Dionaea/Honeytrap/Conpot/Elasticpot...
# - Elastic Stack + Attack Map + Spiderfoot
```

---

## 3. 企业级部署策略

```python
class DeceptionOrchestrator:
    """欺骗防御编排器"""

    def __init__(self):
        self.decoys = []  # 诱饵列表
        self.alerts = []  # 告警列表

    def deploy_decoy(self, decoy_type, location):
        """部署诱饵"""
        decoys = {
            'web': self.deploy_web_bait,
            'database': self.deploy_db_bait,
            'ssh': self.deploy_ssh_honeypot,
            's3': self.deploy_s3_bucket_decoy,
            'api_key': self.plant_fake_api_key,
        }
        return decoys[decoy_type](location)

    def plant_fake_api_key(self, location):
        """植入假 API Key (breadcrumb)"""
        fake_key = f"AKIA{secrets.token_hex(16)}"
        fake_secret = secrets.token_hex(20)

        # 植入到: ~/.aws/credentials, .env, 代码注释
        locations = [
            '/home/user/.aws/credentials',
            '/var/www/.env',
            '/tmp/backup_config.txt'
        ]

        for path in locations:
            if self.can_write(path):
                with open(path, 'a') as f:
                    f.write(f"\n# AWS Access Key\n")
                    f.write(f"AWS_ACCESS_KEY_ID={fake_key}\n")
                    f.write(f"AWS_SECRET_ACCESS_KEY={fake_secret}\n")

        # 监控: 任何使用此 Key 的 API 调用 = 告警
        self.create_canarytoken(key=fake_key, alert_on_use=True)
```

---

## 4. 攻击者行为分析

```python
class HoneypotAnalyzer:
    """蜜罐日志深度分析"""

    def analyze_attack_session(self, session_log):
        findings = []

        # 1. 命令时间线
        commands = self.extract_commands(session_log)
        timeline = [(t, c) for t, c in commands]

        # 2. TTP 识别 (MITRE ATT&CK 映射)
        ttp_map = {
            ('whoami', 'id'): 'T1033 (System Owner/User Discovery)',
            ('ifconfig', 'ip a'): 'T1016 (System Network Config Discovery)',
            ('uname -a', 'cat /etc/os-release'): 'T1082 (System Info Discovery)',
            ('wget', 'curl'): 'T1105 (Ingress Tool Transfer)',
            ('chmod +x',): 'T1222 (File Permission Modification)',
            ('crontab',): 'T1053 (Scheduled Task)',
        }

        for (timestamp, cmd) in commands:
            for patterns, ttp in ttp_map.items():
                if any(p in cmd.lower() for p in patterns):
                    findings.append({
                        'time': timestamp,
                        'cmd': cmd,
                        'ttp': ttp,
                        'mitre_id': ttp.split('(')[0].strip()
                    })

        return findings
```

---

## 5. 蜜罐部署清单

```yaml
蜜罐部署 Checklist:
  - 隔离:
    - [ ] 蜜罐网络与生产网络完全隔离
    - [ ] 蜜罐出口流量严格控制 (仅允许必要的外联)
    - [ ] 监控所有蜜罐间通信

  - 诱饵:
    - [ ] 散布似真的面包屑 (假凭据, 配置文件)
    - [ ] 诱饵服务使用真实软件栈
    - [ ] 模拟数据足够逼真但无真实价值

  - 监控:
    - [ ] 所有蜜罐活动实时告警
    - [ ] 完整流量捕获 (pcap)
    - [ ] 会话录像 (ssh/telnet)
    - [ ] 时间戳精确同步 (NTP)

  - 法律:
    - [ ] 部署符合当地法律
    - [ ] 明确标签 (Entrapment 问题)
    - [ ] 数据收集合规 (仅攻击者行为,非正常用户)
```

---

*上一篇：[蜜罐基础与架构](03-honeypot-analysis.md)*

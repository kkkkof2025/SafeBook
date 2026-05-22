# 欺骗防御技术

## 概述

欺骗防御 (Deception Technology) 颠覆了传统的"被动防御"思维——主动部署蜜罐、蜜标和诱饵，让攻击者在虚拟战场上暴露行踪。Gartner 预测到 2028 年 40% 的企业将采用欺骗技术。

---

## 1. 欺骗防御矩阵

### 1.1 欺骗层次

```
欺骗防御金字塔:

         ┌─────────┐
         │  文件    │ Honeyfile, Canary Token
         ├─────────┤
         │  凭据    │ Honeycred (假密码/Token)
         ├─────────┤
         │  服务    │ Honeypot (假 SSH/HTTP/MySQL)
         ├─────────┤
         │  主机    │ Honeynet (整台假服务器)
         ├─────────┤
         │  网络    │ 假子网/VLAN
         ├─────────┤
         │  应用    │ 假 API/假数据库
         ├─────────┤
         │  数据    │ 假 PII/假业务数据 (Canary Data)
         ├─────────┤
         │  身份    │ 假用户/假管理员
         └─────────┘
```

### 1.2 MITRE Engage 框架

| 攻击阶段 | 欺骗技术 | 目标 |
|----------|----------|------|
| 侦察 | 假 DNS/假子域 | 暴露攻击者 |
| 初始访问 | 诱饵凭证/假 VPN | 延迟/收集 TTPs |
| 横向移动 | 蜜罐 RDP/SSH | 检测内网扫描 |
| 提权 | 假 SUID 二进制 | 触发告警 |
| 数据收集 | Canary 文件 | 检测窃取行为 |
| C2 | 假 C2 服务器 | 干扰通信 |

---

## 2. Honeypot 实战

### 2.1 SSH 蜜罐 (Cowrie)

```bash
# Cowrie - 中交互 SSH/Telnet 蜜罐

# 安装
git clone https://github.com/cowrie/cowrie.git /opt/cowrie
cd /opt/cowrie

# 配置
cat > etc/cowrie.cfg << EOF
[honeypot]
hostname = db-prod-01
# 伪装成生产数据库服务器

[ssh]
listen_port = 2222
# 真实 SSH 在 22, 蜜罐在 2222

[output_jsonlog]
logfile = log/cowrie.json
EOF

# 启动
bin/cowrie start

# 攻击者看到:
# $ ssh root@10.0.0.50 -p 2222
# root@db-prod-01's password:
# $ (输入任何密码都接受)
# root@db-prod-01:~# whoami
# root
# root@db-prod-01:~# ls
# backup.sql  payroll.xlsx  server.crt

# Cowrie 记录:
# - 攻击者 IP
# - 尝试的密码
# - 执行的所有命令
# - 下载的文件 (通过 scp)
# - 时间线完整记录
```

### 2.2 HTTP 蜜罐

```python
# 简单 HTTP 蜜罐 — 模拟企业内部应用

from flask import Flask, request, jsonify, make_response
import logging
import time
import json

app = Flask(__name__)

# 配置日志
logging.basicConfig(
    filename='/var/log/honeyhttp.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

@app.route('/api/login', methods=['POST'])
def login():
    """模拟登录端点 — 记录凭证尝试"""
    data = request.get_json() or {}

    logging.warning(json.dumps({
        'event': 'LOGIN_ATTEMPT',
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'username': data.get('username'),
        'password': data.get('password'),
        'headers': dict(request.headers),
    }))

    # 总是返回失败
    return jsonify({
        'error': 'Invalid credentials',
        'attempts_remaining': 2  # 诱导攻击者继续尝试
    }), 401

@app.route('/api/admin/users', methods=['GET'])
def get_users():
    """返回假用户数据 (Canary Data)"""
    token = request.headers.get('Authorization', '')

    # Canary Token — 记录任何使用此 API 的人
    logging.warning(json.dumps({
        'event': 'SENSITIVE_API_ACCESS',
        'ip': request.remote_addr,
        'endpoint': '/api/admin/users',
        'token': token,
    }))

    # 返回包含 Canary 数据的假用户列表
    users = [
        {
            'id': 1001,
            'username': 'admin',
            'email': 'admin@company.local',
            'role': 'superadmin',
            'last_login': '2024-01-15T08:22:33Z',
            'canary': True  # 标记为假数据
        },
        {
            'id': 1002,
            'username': 'svc_backup',
            'email': 'backup@company.local',
            'role': 'admin',
            'password_hint': 'See /etc/backup/creds.txt',
            'canary': True  # 蜜标 — 引导攻击者去蜜罐文件
        }
    ]
    return jsonify(users)

@app.route('/api/export/reports', methods=['GET'])
def export_reports():
    """模拟数据导出 — 追踪数据窃取"""
    logging.critical(json.dumps({
        'event': 'DATA_EXFILTRATION_ATTEMPT',
        'ip': request.remote_addr,
        'export_type': request.args.get('type'),
        'date_range': request.args.get('date_range'),
    }))

    # 返回假报告数据
    return jsonify({
        'revenue': {'q1': 45230000, 'q2': 49800000},
        'employees': 1247,
        'canary': True
    })

@app.route('/robots.txt')
def robots():
    # 蜜标 — 引导扫描器到蜜罐陷阱
    return """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
"""

if __name__ == '__main__':
    # 监听所有接口，端口 8080
    app.run(host='0.0.0.0', port=8080)
```

---

## 3. Canary Token

### 3.1 蜜标部署

```python
class CanaryTokenManager:
    """蜜标管理器 — 检测数据被访问时触发告警"""

    def __init__(self):
        self.tokens = {}
        self.alerts = []

    def create_aws_key_canary(self):
        """
        创建假 AWS Access Key
        部署到 ~/.aws/credentials 中
        任何使用此 Key 的 API 调用都会触发告警
        """
        return {
            'type': 'aws_credentials',
            'access_key': 'AKIA' + self._random(16),
            'secret_key': self._random(40),
            'location': '/home/deploy/.aws/credentials',
            'alert_trigger': 'Any AWS API call using this key'
        }

    def create_file_canary(self, path, filename):
        """
        创建蜜文件 — 包含唯一水印
        """
        canary_id = self._random(32)

        # 在文件中嵌入不可见的水印
        content = f"""
# Confidential - Internal Use Only
# Document ID: {canary_id}
# This document contains proprietary information

Database Credentials:
  Host: db-prod-01.internal
  Port: 5432
  User: admin
  Password: P@ssw0rd_2024_Fake!

API Keys:
  STRIPE_API_KEY: sk_live_CANARY_{canary_id[:8]}

# 如果有人访问或下载此文件 → 触发告警
        """

        # 在真实服务器上部署蜜文件
        with open(f'{path}/{filename}', 'w') as f:
            f.write(content)

        self.tokens[canary_id] = {
            'file': f'{path}/{filename}',
            'type': 'honeyfile',
            'created': datetime.now().isoformat(),
            'triggered': False
        }

        return canary_id

    def create_url_canary(self):
        """
        创建 Canary URL Token
        嵌入到文档/邮件中
        任何访问该 URL 的人都会暴露其 IP
        """
        canary_id = self._random(32)
        url = f"https://canary.company.com/{canary_id}"

        # 部署: 公司内网、DNS txt 记录、代码注释、git 提交
        return {
            'canary_id': canary_id,
            'url': url,
            'usage': [
                'ssh-key 注释',
                'DNS TXT 记录',
                r'C:\Users\*\AppData\Roaming\.bash_history',
                '/var/log/auth.log 假日志'
            ]
        }

    def alert_on_trigger(self, canary_id, trigger_info):
        """蜜标被触发时发送最高优先级告警"""
        self.alerts.append({
            'severity': 'CRITICAL',
            'confidence': 100,  # 蜜标触发 = 100% 确认攻击
            'canary_id': canary_id,
            'trigger': trigger_info,
            'message': '蜜标已被触发 — 数据泄露或内部威胁确认'
        })

        # 发送即时告警
        self._send_slack_alert()
        self._trigger_siem()
        self._isolate_compromised_system(trigger_info.get('ip'))
```

### 3.2 Thinkst Canary

```yaml
Thinkst Canary 部署:

  Canary (硬件/虚拟设备):
    - 模仿: 打印机、交换机、Windows Server、数据库
    - 任何端口扫描 → 告警
    - 任何登录尝试 → 告警
    - 任何 SMB/HTTP/SSH 访问 → 告警

  Canarytoken (软件):
    - AWS Key token
    - SQL Server token
    - Windows Folder token
    - PDF/DOCX token
    - 二维码 token
    - DNS token

  部署策略:
    1. 每子网至少 1 个 Canary
    2. 关键资产旁必有 Canary
    3. Canarytoken 嵌入:
       - 配置文件 (AWS credentials)
       - 代码仓库 (API keys)
       - 敏感文件夹 (desktop.ini)
       - WireGuard 配置文件
```

---

## 4. Active Directory 欺骗

### 4.1 假用户和假管理组

```powershell
# AD 蜜罐用户—检测密码喷洒和横向移动

# 创建蜜罐用户
New-ADUser -Name "svc_sql_backup" `
    -SamAccountName "svc_sql_backup" `
    -Description "SQL Backup Service Account - DO NOT DISABLE" `
    -Enabled $true `
    -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force)

# 添加到 Domain Admins (做个样子)
# 不授予实际权限，但审计任何访问尝试

# 设置蜜罐属性
Set-ADUser svc_sql_backup -Add @{
    "info" = "Contains sensitive data - see \\DC01\SQLBackupConfig"
    "homeDirectory" = "\\fileserver\backup"  # 假路径
}

# 创建假 SPN (诱饵 Kerberoasting)
setspn -S HTTP/fake-app.internal/svc_sql_backup svc_sql_backup

# 监控:
# 1. Event ID 4625 (登录失败) → svc_sql_backup
# 2. Event ID 4769 (Kerberos TGS) → svc_sql_backup
# 3. 任何 lsass.exe 转储包含此用户
```

---

## 参考资源

- [MITRE Engage Framework](https://engage.mitre.org/)
- [Thinkst Canary](https://canary.tools/)
- [Cowrie SSH Honeypot](https://github.com/cowrie/cowrie)
- [T-Pot 多蜜罐平台](https://github.com/telekom-security/tpotce)

---

*下一篇：[蜜罐网络部署实战](./02-honeynet-deployment.md)*

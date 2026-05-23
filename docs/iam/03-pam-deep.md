# PAM 特权访问管理深度

## 概述

PAM（Privileged Access Management）管理组织的"致命钥匙"——域管理员、数据库 SA、云 Root 等特权账户。一个被攻破的特权账户 = 整个环境被攻破。

---

## 1. PAM 核心能力

```
PAM 能力矩阵:

  密码保管库 (Vault)
    → 特权密码集中存储、加密
    → 自动轮换 (Password Rotation)
    → 使用后回收 (Check-out/Check-in)

  会话管理 (Session Management)
    → 代理访问 (Proxy)
    → 会话录制 (Recording)
    → 实时监控 (Live Monitoring)

  最小权限 (Least Privilege)
    → JIT 访问 (Just-in-Time)
    → 请求-审批流程
    → 时限制 (Time-bound)

  威胁分析 (Threat Analytics)
    → 异常特权使用检测
    → 特权账户行为基线
    → UEBA 集成
```

---

## 2. 密码保管库实现

### 2.1 HashiCorp Vault

```bash
# Vault PAM 配置

# 1. 启用 Secrets Engine
vault secrets enable -path=pam kv-v2

# 2. 存储特权密码
vault kv put pam/domain-admin \
    username="Administrator" \
    password="SuperSecret123!" \
    domain="corp.local"

# 3. 启用自动轮换
vault write sys/policies/password/pam-policy \
    length=32 \
    rule='charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"' \
    min_uppercase=2 \
    min_lowercase=2 \
    min_numeric=2 \
    min_special=1

# 4. 动态密钥 (数据库)
vault write database/roles/readonly \
    db_name=mysql-prod \
    creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; GRANT SELECT ON *.* TO '{{name}}'@'%';" \
    default_ttl="1h" \
    max_ttl="24h"

# 5. 客户端获取临时凭证
vault read database/creds/readonly
# 输出: username, password (1h TTL)
```

### 2.2 密码自动轮换

```python
import hvac
from datetime import datetime, timedelta

class PasswordRotationEngine:
    """特权密码自动轮换"""

    def __init__(self, vault_addr, token):
        self.client = hvac.Client(url=vault_addr, token=token)

    def rotate_all_passwords(self):
        """轮换所有过期密码"""

        # 1. 获取所有特权凭证
        secrets = self.client.secrets.kv.v2.list_secrets(
            path='pam',
            mount_point='pam'
        )

        for secret in secrets.get('data', {}).get('keys', []):
            metadata = self.client.secrets.kv.v2.read_secret_metadata(
                path=f'pam/{secret}',
                mount_point='pam'
            )

            last_rotated = metadata.get('data', {}).get('last_rotated')
            rotation_interval = metadata.get('data', {}).get('rotation_days', 90)

            # 2. 检查是否需要轮换
            if last_rotated:
                last = datetime.fromisoformat(last_rotated)
                if datetime.now() - last < timedelta(days=rotation_interval):
                    continue

            # 3. 生成新密码
            new_password = self._generate_password()

            # 4. 更新目标系统
            target_type = metadata.get('data', {}).get('target_type')
            if target_type == 'active_directory':
                self._rotate_ad_password(secret, new_password)
            elif target_type == 'ssh':
                self._rotate_ssh_key(secret)
            elif target_type == 'database':
                self._rotate_db_password(secret, new_password)

            # 5. 更新 Vault
            self.client.secrets.kv.v2.create_or_update_secret(
                path=f'pam/{secret}',
                mount_point='pam',
                secret={
                    'password': new_password,
                    'last_rotated': datetime.now().isoformat(),
                    'rotated_by': 'automation'
                }
            )
```

---

## 3. 会话管理

### 3.1 代理访问架构

```
PAM 会话代理:

  管理员 → PAM 代理 → 目标系统

  PAM 代理提供:
    1. 免直接暴露目标凭证给管理员
    2. 会话录制 (所有输入/输出)
    3. 命令过滤 (禁止危险命令)
    4. 实时告警 (检测异常命令)

  支持协议:
    - RDP (Windows 远程桌面)
    - SSH (Linux/网络设备)
    - HTTP/HTTPS (Web 控制台)
    - SQL (数据库客户端)
```

### 3.2 Teleport SSH 审计

```yaml
# Teleport PAM 配置
# teleport.yaml

auth_service:
  enabled: true
  session_recording: "node-sync"  # 录制模式
  proxy_listener_mode: "multiplex"

proxy_service:
  enabled: true
  ssh_public_addr: "teleport.example.com:3023"

ssh_service:
  enabled: true
  commands:
    - name: "hostname"
      command: ["hostname"]
      period: 1m

# 审计策略
auth_preference:
  type: local
  second_factor: "webauthn"

# 会话录制回放
session_recording: "node-sync"
```

```bash
# Teleport 会话审计命令

# 1. 查看活跃会话
tsh sessions

# 2. 加入活跃会话 (Shadow)
tsh join <session-id>

# 3. 回放历史会话
tsh play <session-id>

# 4. 导出会话记录
tsh play <session-id> --format=asciicast > session.cast
```

---

## 4. PAM 部署清单

```yaml
PAM 实施路线图:

  第一阶段 (0-3 月): 发现与基础
    - [ ] 发现所有特权账户 (AD/Unix/DB/云/应用)
    - [ ] 集中密码保管
    - [ ] 启动密码轮换 (域管理员优先)

  第二阶段 (3-6 月): 会话管理
    - [ ] SSH/RDP 代理部署
    - [ ] 会话录制启用
    - [ ] 命令过滤策略

  第三阶段 (6-12 月): JIT 与自动化
    - [ ] JIT 工作流 (ServiceNow/Jira 集成)
    - [ ] 自动审批 (低风险操作)
    - [ ] 异常检测规则

  第四阶段 (12+ 月): 持续优化
    - [ ] 最小权限重构
    - [ ] 零信任架构迁移
    - [ ] PAM 成熟度评估
```

---

## 参考资源

- [HashiCorp Vault PAM](https://developer.hashicorp.com/vault/docs)
- [CyberArk PAM](https://www.cyberark.com/products/privileged-access-manager/)
- [Teleport](https://goteleport.com/)
- [BeyondTrust PAM](https://www.beyondtrust.com/products/privileged-access-management)

---

*上一篇：[IAM 联邦](02-iam-federation-jit.md)*

*下一篇：[零信任架构实践](05-zero-trust.md)*

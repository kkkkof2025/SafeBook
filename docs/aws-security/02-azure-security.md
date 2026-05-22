# Azure 云安全服务

## 概述

Azure 提供了与 AWS 对等的安全能力集合，但概念映射不总是 1:1。本章对比 AWS/Azure 安全服务，避免多云环境下的安全盲区。

---

## 1. AWS vs Azure 安全服务对照

| 安全域 | AWS | Azure | 关键差异 |
|--------|-----|-------|----------|
| IAM | IAM | Azure AD / Entra ID | Entra ID 原生集成 O365 |
| 密钥管理 | KMS | Key Vault | Key Vault 集成 HSM |
| 威胁检测 | GuardDuty | Microsoft Defender | Defender 跨 PaaS 覆盖更广 |
| DDoS | Shield | Azure DDoS Protection | 架构类似 |
| WAF | WAF | Application Gateway WAF | Azure 集成前门 CDN |
| 合规 | Artifact | Compliance Manager | Azure 合规仪表板更集中 |
| 加密 | CloudHSM | Dedicated HSM | 都是 FIPS 140-2 Level 3 |
| 日志 | CloudTrail | Monitor + Activity Log | Sentinel 比 CloudWatch 更 SIEM 化 |

---

## 2. Azure 安全核心服务

### 2.1 Microsoft Sentinel (SIEM + SOAR)

```kusto
// KQL 查询：检测暴力破解 RDP
SecurityEvent
| where EventID == 4625  // 登录失败
| where AccountType == "User"
| where SubStatus == "0xC000006A"  // 用户不存在
| summarize FailureCount = count() by Account, IPAddress, Computer
| where FailureCount > 10
| order by FailureCount desc
```

```yaml
# Sentinel Analytics Rule
# 检测非工作时间的管理员登录
query: |
  SigninLogs
  | where TimeGenerated between (datetime(22:00:00)..datetime(06:00:00))
  | where UserPrincipalName contains "admin"
  | project TimeGenerated, UserPrincipalName, IPAddress, Location

trigger:
  threshold: 1  # 一次非工作时间登录即告警
  severity: Medium
  tactics: [InitialAccess]
```

### 2.2 Azure Key Vault

```bash
# Azure CLI: Key Vault 安全配置

# 1. 创建 Key Vault (启用软删除 + 清除保护)
az keyvault create \
    --name "prod-keyvault" \
    --resource-group "security-rg" \
    --location "eastus" \
    --enable-soft-delete true \
    --enable-purge-protection true \
    --retention-days 90

# 2. 网络隔离 (仅允许特定 VNet)
az keyvault network-rule add \
    --name "prod-keyvault" \
    --subnet "/subscriptions/xxx/resourceGroups/vnet-rg/providers/Microsoft.Network/virtualNetworks/prod-vnet/subnets/keyvault-subnet" \
    --ip-address "10.0.0.0/24"

# 3. 启用日志到 Log Analytics
az monitor diagnostic-settings create \
    --resource "/subscriptions/xxx/resourceGroups/security-rg/providers/Microsoft.KeyVault/vaults/prod-keyvault" \
    --workspace "/subscriptions/xxx/resourceGroups/security-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-workspace" \
    --logs '[{"category": "AuditEvent", "enabled": true}]'

# 4. RBAC 最小权限
az role assignment create \
    --assignee "admin@example.com" \
    --role "Key Vault Secrets Officer" \
    --scope "/subscriptions/xxx/resourceGroups/security-rg/providers/Microsoft.KeyVault/vaults/prod-keyvault"
```

### 2.3 Azure Policy

```json
{
  "properties": {
    "displayName": "强制所有存储账户启用 HTTPS",
    "policyType": "BuiltIn",
    "mode": "All",
    "parameters": {},
    "policyRule": {
      "if": {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.Storage/storageAccounts"
          },
          {
            "field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
            "equals": "false"
          }
        ]
      },
      "then": {
        "effect": "deny"
      }
    }
  }
}
```

---

## 3. Azure 安全基准

```yaml
Azure CIS Benchmark 关键检查 (Level 1):

  身份与访问管理:
    - MFA 强制所有用户
    - 禁用传统认证 (POP/IMAP/SMTP)
    - 紧急访问账户 (Break Glass)

  Azure AD:
    - 超过 2 个全局管理员
    - Privileged Identity Management (PIM) 启用
    - 自服务密码重置仅限指定用户

  存储:
    - 存储账户密钥不过期 > 90 天
    - "安全传输必需" 启用
    - 存储账户禁止公共 Blob 访问

  数据库:
    - SQL 审计启用
    - SQL TDE 启用
    - "Allow Azure Services" 防火墙规则禁用
```

---

## 参考资源

- [Azure Security Benchmark v3](https://learn.microsoft.com/azure/security/benchmarks/)
- [Microsoft Cloud Security Benchmark](https://aka.ms/mcsb)
- [Azure CIS Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)

---

*上一篇：[AWS 安全服务](01-aws-security-services.md)*

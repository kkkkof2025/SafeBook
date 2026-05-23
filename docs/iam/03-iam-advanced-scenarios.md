# IAM 高级场景配置

## IAM 高级场景概述

身份与访问管理 (IAM) 在企业环境中需要处理复杂场景。

### 核心挑战

1. **混合云身份** - 本地 AD + 云端 IdP
2. **B2B 协作** - 外部合作伙伴访问
3. **特权访问** - PAM (特权访问管理)
4. **合规审计** - 满足等保/SOX/GDPR

---

## 场景1：混合云身份联邦

### 架构

```
+----------+     +----------+     +----------+
| 本地 AD   | --> |  AD FS   | <--> |  Azure AD |
| (On-prem) |     | (联邦)  |     | (云端)  |
+----------+     +----------+     +----------+
      |                  |                  |
      v                  v                  v
  [用户认证]      [SSO 令牌]      [云端资源访问]
```

### 实施步骤

#### 1. 配置 AD FS

```powershell
# 添加信赖方信任 (Relying Party Trust)
Add-AdfsRelyingPartyTrust -Name "Azure AD" `
  -MetadataUrl "https://nexus.microsoftonline-p.com/fedrationmetadata/2007-06/fedrationmetadata.xml" `
  -IssuanceAuthorizationRulesFile "C:\rules\auz_rules.tx" `
  -IssuanceTransformRulesFile "C:\rules\issuance_rules.tx"

# 配置声明规则 (Claims Rules)
Add-AdfsClaimsProviderTrust -Name "Active Directory" `
  -Type LocalClaimsProvider `
  -Enabled $true
```

#### 2. 配置 Azure AD 联合

```powershell
# 安装 Azure AD 模块
Install-Module MSOnline

# 配置联合域
$domaiName = "example.com"
$adfsServer = "adfs.example.com"

Set-MsolDomainAuthentication -DomainName $domaiName `
  -FederationBrandName $domaiName `
  -PassiveLogOnUri "https://$adfsServer/adfs/ls/" `
  -SigningCertificate (Get-AdfsCertificate | Where {$_.Certificate -ne $null}).Certificate `
  -IssuerUri "http://$adfsServer/adfs/services/trust" `
  -ActiveLogOnUri "https://$adfsServer/adfs/services/trust/2005/usernamemixed" `
  -LogOffUri "https://$adfsServer/adfs/ls/?wa=wsignout1.0" `
  -PreferredAuthenticationProtocolType Samlp
```

#### 3. 测试 SSO

```bash
# 使用 curl 测试 SAML 请求
curl -X POST "https://adfs.example.com/adfs/ls/" \
  -d "SAMLRequest=<Base64编码的SAML请求>" \
  -d "RelayState=<中继状态>"

# 验证令牌
python3 -c "
import jwt
token = '<从响应中获取>'
decoded = jwt.decode(token, options={'verify_signature': False})
print(decoded)
"
```

### 故障排查

| 问题 | 原因 | 解决方案 |
|------|------|------------|
| SSO 失败 | 证书过期 | 更新 AD FS 签名证书 |
| 声明丢失 | 规则配置错误 | 检查声明颁发规则 |
| 循环重定向 | Cookie 冲突 | 清除浏览器 Cookie |

---

## 场景2：B2B 协作访问

### 架构

```
+----------+     +----------+     +----------+
| 合作伙伴 | --> |   B2B    | --> |  资源    |
| (外部)   |     | 门户     |     | (内部)  |
+----------+     +----------+     +----------+
                        |
                        v
                   [审批工作流]
                        |
                        v
                   [JIT 访问]
```

### 实施：Azure AD B2B

#### 1. 邀请外部用户

```powershell
# 安装 Azure AD 模块
Install-Module AzureAD

# 邀请外部用户
$inviteRedeemUrl = "https://myapp.com/redeem"
$invitedUserEmail = "partner@contoso.com"

New-AzureADMSInvitation -InvitedUserEmailAddress $invitedUserEmail `
  -InviteRedirectUrl $inviteRedeemUrl `
  -SendInvitationMessage $true
```

#### 2. 配置 JIT (即时) 访问

```json
// Azure AD PIM (Privileged Identity Management)
{
  "policy": {
    "role": "Contributor",
    "eligibleAssignments": [
      {
        "member": {
          "objectId": "user-001",
          "type": "user"
        },
        "schedule": {
          "startDateTime": "2026-05-22T08:00:00Z",
          "endDateTime": "2026-05-22T17:00:00Z",
          "type": "once"
        },
        "approval": {
          "isApprovalRequired": true,
          "approvers": [
            {
              "objectId": "approver-001",
              "type": "user"
            }
          ]
        }
      }
    ]
  }
}
```

#### 3. 监控外部访问

```kusto
// Azure Monitor 查询
AuditLogs
| where ActivityDisplayName == "Invite external user"
| project TimeGenerated, InitiatedBy, TargetResources
| where Todatetime(TimeGenerated) > ago(30d)
```

### 安全控制

1. **MFA 强制** - 外部用户必须 MFA
2. **条件访问** - 限制 IP 范围
3. **定期访问评审** - 每季度评审外部访问
4. **自动过期** - 设置访问过期时间

---

## 场景3：特权访问管理 (PAM)

### 架构

```
+----------+     +----------+     +----------+
| 管理员   | --> |   PAM    | --> |  资源    |
| (请求)   |     | (审批)  |     | (目标)  |
+----------+     +----------+     +----------+
      |                  |
      v                  v
 [请求提升]      [审批工作流]
      |                  |
      v                  v
 [JIT 访问]      [会话录制]
```

### 实施：CyberArk PAM

#### 1. 配置安全邮箱 (Safe)

```bash
# 创建 Safe
Create-Safe -SafeName "Unix-Root-Safe" \
  -Description "UNIX 根账户保险箱" \
  -ManagingCPM "PasswordManager" \
  -NumberOfDaysRetention 7

# 添加账户到 Safe
Add-Account -SafeName "Unix-Root-Safe" \
  -PlatformID "UnixSSH" \
  -Address "192.168.1.100" \
  -UserName "root" \
  -Password "Initia1Password" \
  -Name "Unix-Root-192.168.1.100"
```

#### 2. 配置 PSM (Privileged Session Manager)

```bash
# 配置 PSM 策略
Set-PSMConfig -PolicyName "Unix-SSH-Proxy" \
  -TargetPlatform "UnixSSH" \
  -PSMServer "psm.example.com" \
  -RecordingType "Always" \
  -NotifyWhenRecordingFails $true
```

#### 3. 请求特权访问

```bash
# 使用 REST API 请求访问
curl -X POST "https://vault.example.com/PasswordVault/API/Accounts/{AccountID}/LinkAccount" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "紧急故障排查",
    "ticketNumber": "INC-001",
    "expirationDate": "2026-05-22T17:00:00Z"
  }'
```

### 实施：HashiCorp Boundary

#### 1. 配置 Boundary

```hcl
# boundary.hcl
controller {
  name = "boundary-controller"
  database {
    url = "postgres://boundary:password@postgres:5432/boundary?sslmode=disable"
  }
}

worker {
  name     = "boundary-worker"
  controller_generated_activation_token = true
  public_addr = "boundary-worker.example.com"
}

listener "tcp" {
  address = "0.0.0.0:9200"
  tls_disable = true  # 生产环境应启用 TLS
}
```

#### 2. 定义角色和权限

```bash
# 创建角色
boundary roles create -scope-id global \
  -name "DB-Access-Role" \
  -description "数据库访问角色"

# 授予权限
boundary roles add-granted-scope-ids -id r_1234567890 \
  -scope-id p_0987654321

boundary roles add-principals -id r_1234567890 \
  -principal user_abcdefg
```

#### 3. 请求会话

```bash
# 认证 Boundary
boundary authenticate password \
  -auth-method-id ampw_1234567890 \
  -login-name admin \
  -password <password>

# 创建会话
boundary connect ssh \
  -target-id tnats_0987654321 \
  -host 192.168.1.100 \
  -port 22 \
  -username root
```

---

## 场景4：合规审计

### 等保 2.0 要求

| 控制项 | 要求 | IAM 实施 |
|----------|------|------------|
| 身份鉴别 | 双因素认证 | MFA 强制 |
| 访问控制 | 最小权限 | RBAC + ABAC |
| 安全审计 | 日志留存 6 个月 | SIEM 集成 |
| 数据完整性 | 操作不可抵赖 | 数字签名 + 时间戳 |

### 实施：IAM 日志聚合

#### 1. 配置 Azure AD 日志发送到 SIEM

```powershell
# 安装 Azure AD 诊断设置
$workspaceId = "/subscriptions/{sub}/resourcegroups/{rg}/providers/microsoft.operationalinsights/workspaces/{ws}"

Set-AzDiagnosticSetting -Name "SendToSIEM" `
  -ResourceId "/tenants/{tenantId}" `
  -WorkspaceId $workspaceId `
  -Category @("AuditLogs", "SignInLogs", "NonInteractiveUserSignInLogs")
```

#### 2. Splunk 查询 IAM 异常

```splunk
# 检测异常登录位置
index=azure_ad sourcetype=SignInLogs
| eval city=if(isnull(City), "Unknown", City)
| stats dc(city) as unique_cities by UserId
| where unique_cities > 2
| `security_incident_create`

# 检测特权账户异常活动
index=azure_ad sourcetype=AuditLogs "Actor"="admin*"
| stats count by ActivityDisplayName, Actor, IpAddress
| where count > 10
| `security_incident_create`
```

#### 3. 生成合规报告

```python
# 使用 Python 生成等保合规报告
import pandas as pd
from datetime import datetime, timedelta

# 读取 IAM 日志
logs = pd.read_csv('iam_logs.csv')

# 检查 MFA 覆盖率
mfa_coverage = logs[logs['MFAStatus'] == 'Success'].shape[0] / logs.shape[0]
print(f'MFA 覆盖率: {mfa_coverage:.2%}')

# 检查特权账户活动
privileged_accounts = ['admin', 'root', 'sa']
privileged_activity = logs[logs['User'].isin(privileged_accounts)]
print(f'特权账户活动次数: {privileged_activity.shape[0]}')

# 生成报告
report = pd.DataFrame({
    '指标': ['MFA 覆盖率', '特权账户活动次数', '异常登录次数'],
    '值': [f'{mfa_coverage:.2%}', privileged_activity.shape[0], 0]
})
report.to_excel('iam_compliance_report.xlsx', index=False)
```

---

## IAM 安全最佳实践清单

### 身份管理

- [ ] 实施 SSO (单点登录)
- [ ] 强制 MFA (多因素认证)
- [ ] 使用强密码策略 (长度 + 复杂度)
- [ ] 定期审查身份生命周期

### 访问管理

- [ ] 实施 RBAC (基于角色的访问控制)
- [ ] 实施 ABAC (基于属性的访问控制)
- [ ] 使用 JIT (即时) 访问
- [ ] 定期访问评审 (季度)

### 特权管理

- [ ] 使用 PAM 解决方案 (CyberArk/HashiCorp Boundary)
- [ ] 录制特权会话
- [ ] 实施审批工作流
- [ ] 定期轮换特权凭证

### 监控审计

- [ ] 聚合 IAM 日志到 SIEM
- [ ] 配置异常检测规则
- [ ] 生成合规报告
- [ ] 定期渗透测试

---

## 延伸阅读

- [Azure AD B2B 文档](https://docs.microsoft.com/azure/active-directory/external-identities/)
- [CyberArk PAM 文档](https://docs.cyberark.com/)
- [HashiCorp Boundary 文档](https://boundaryproject.io/docs/)
- [等保 2.0 标准](https://www.sca.gov.cn/)

---

**下一步：** 学习 )，掌握安全左移实践。

*上一篇：[IAM 高级场景实践](02-iam-federation-jit.md)*

*下一篇：[PAM 特权访问管理深度](03-pam-deep.md)*

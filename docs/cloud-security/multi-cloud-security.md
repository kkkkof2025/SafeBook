# 多云安全架构

> AWS + Azure + GCP 统一安全策略

---

## 1. 多云安全挑战

```
单云 vs 多云:
┌─────────────────┐     ┌─────────────────────────┐
│    单云安全     │     │       多云安全          │
├─────────────────┤     ├─────────────────────────┤
│ 统一 IAM       │  →  │ 跨云身份联邦           │
│ 一种监控工具    │  →  │ 多源日志聚合           │
│ 一种加密 KMS   │  →  │ 跨云密钥管理           │
│ 一种网络模型    │  →  │ 多云网络拓扑           │
│ 一套合规框架    │  →  │ 跨云合规映射           │
└─────────────────┘     └─────────────────────────┘
```

---

## 2. 统一身份管理

```yaml
跨云身份联邦:
  IdP (身份提供者):
    - Okta / Azure AD / AWS SSO
    - SAML 2.0 连接所有云账户
    - 集中管理用户 + 组 + 角色

  AWS:
    - IAM Identity Center (SSO)
    - 角色映射: Okta Group → AWS Permission Set

  Azure:
    - Azure AD + PIM (Privileged Identity Management)
    - 条件访问: 设备合规 + 位置 + MFA

  GCP:
    - Cloud Identity + Workforce Identity Federation
    - 角色映射: Okta → GCP IAM Role

  原则: 无长期凭证 (全部通过 IdP + 临时 Token)
```

### Terraform 统一 IAM
```hcl
# 跨云最小权限策略 (Terraform)
module "cloud_iam" {
  source = "./modules/multi-cloud-iam"

  # 角色定义 (跨云通用)
  roles = {
    "security-readonly" = {
      aws_managed = [
        "arn:aws:iam::aws:policy/SecurityAudit"
      ]
      azure_role = "Security Reader"
      gcp_role    = "roles/iam.securityReviewer"
    }
    "network-admin" = {
      aws_managed = ["arn:aws:iam::aws:policy/NetworkAdministrator"]
      azure_role  = "Network Contributor"
      gcp_role     = "roles/compute.networkAdmin"
    }
  }
}
```

---

## 3. 统一安全监控

### 日志聚合
```yaml
中央 SIEM 架构:
  AWS:
    CloudTrail → S3 → Lambda → Splunk/Elastic
    GuardDuty → EventBridge → SIEM

  Azure:
    Activity Log → Event Hub → SIEM Connector
    Sentinel → Logic App → SIEM

  GCP:
    Cloud Audit Logs → Pub/Sub → Dataflow → SIEM
    Security Command Center → Pub/Sub → SIEM

  推荐工具:
    - Wazuh (开源 SIEM + 多云支持)
    - Splunk (商业 + 多云应用)
    - Chronicle (Google + 多云)
```

### CSPM (云安全态势管理)
```python
class MultiCloudCSPM:
    """多云安全态势管理"""

    def check_s3_public_access(self):
        """跨云对象存储公开访问检查"""
        findings = []

        # AWS S3
        s3_client = boto3.client('s3')
        for bucket in s3_client.list_buckets()['Buckets']:
            try:
                acl = s3_client.get_public_access_block(Bucket=bucket['Name'])
                if not all(acl['PublicAccessBlockConfiguration'].values()):
                    findings.append({
                        'cloud': 'AWS',
                        'resource': bucket['Name'],
                        'issue': 'Public access not fully blocked',
                        'severity': 'CRITICAL'
                    })
            except:
                findings.append({
                    'cloud': 'AWS',
                    'resource': bucket['Name'],
                    'issue': 'No PublicAccessBlock configured',
                    'severity': 'CRITICAL'
                })

        # Azure Blob
        for account in azure_storage_accounts:
            if not account.allow_blob_public_access:
                continue
            containers = blob_client.list_containers()
            for container in containers:
                if container.public_access != 'None':
                    findings.append({
                        'cloud': 'Azure',
                        'resource': f"{account.name}/{container.name}",
                        'issue': f"Public access: {container.public_access}",
                        'severity': 'HIGH'
                    })

        return findings

    def check_iam_root_usage(self):
        """跨云 Root 账号检测"""
        findings = []

        # AWS
        cred_report = iam_client.get_credential_report()
        # Check root_access_key_active + root_mfa_active

        # Azure (Global Administrator)
        global_admins = azure_client.list_directory_role_assignments(
            role_id='62e90394-69f5-4237-9190-012177145e10'
        )

        # GCP (Organization Admin)
        org_admins = gcp_client.list_iam_policies(
            resource='organizations/ORG_ID'
        )

        return findings
```

---

## 4. 多云安全架构原则

```yaml
多云安全黄金法则:

  #1 身份统一:
    - 单点 SSO 管理所有云
    - 禁止长期凭证 (使用 Workload Identity)
    - MFA 强制 + 条件访问

  #2 网络零信任:
    - 云间通信加密 (TLS 1.3 + mTLS)
    - 微分段 (安全组/NSG/Firewall)
    - 私有连接 (PrivateLink/Private Endpoint)

  #3 数据保护:
    - 静态加密 (KMS 跨云通用)
    - 传输加密 (TLS 1.2+)
    - DLP: 跨云数据分类 + 防泄漏

  #4 统一监控:
    - 日志集中 (CloudTrail+Activity+Audit → SIEM)
    - CSPM: Wiz/Prisma Cloud/Checkov
    - 告警统一: PagerDuty/Slack

  #5 合规即代码:
    - Policy-as-Code: OPA/Rego 跨云
    - 合规扫描: prowler/ScoutSuite/Prowler
    - 自动修复: 检测到违规 → 自动回滚
```

---

## 5. 多云安全工具链

| 工具 | 类别 | 云平台 |
|------|------|--------|
| Wiz | CSPM + CNAPP | AWS/Azure/GCP/Oracle |
| Prisma Cloud | CNAPP | 全平台 |
| Prowler | 合规扫描 | AWS/Azure/GCP |
| Checkov | IaC 扫描 | Terraform/CF/K8s |
| Trivy | 漏洞扫描 | 容器+依赖 |
| Falco | 运行时检测 | K8s |

```bash
# Prowler: 跨云合规检查
prowler aws --compliance cis_1.5_aws
prowler azure --compliance cis_2.0_azure
prowler gcp --compliance cis_1.2_gcp

# Checkov: IaC 安全扫描
checkov -d terraform/ --framework all
checkov -d k8s/ --check CKV_K8S_*
```

---

*上一篇：[AWS 安全最佳实践](../aws-security/04-aws-best-practices.md)*

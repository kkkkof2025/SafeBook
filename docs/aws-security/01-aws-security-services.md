# AWS 安全服务全景

## 概述

AWS 拥有最丰富云安全工具生态。本章全景式介绍 AWS 原生安全服务——从身份到网络、从数据保护到威胁检测——帮助安全工程师构建云原生防线。

---

## 1. AWS 安全服务矩阵

```
AWS 安全服务全景:

   身份与访问管理:
   ├── IAM (用户/角色/策略)
   ├── IAM Identity Center (SSO)
   ├── AWS Organizations (多账号 SCP)
   ├── Cognito (用户认证)
   └── Directory Service (AD 托管)

   检测与响应:
   ├── GuardDuty (威胁检测)
   ├── Security Hub (安全态势)
   ├── Detective (调查分析)
   ├── CloudTrail (审计日志)
   ├── Config (资源配置审计)
   └── Macie (敏感数据发现)

   基础设施保护:
   ├── WAF & Shield (Web 防护)
   ├── Network Firewall (网络防火墙)
   ├── Inspector (漏洞扫描)
   └── Firewall Manager (集中管理)

   数据保护:
   ├── KMS (密钥管理)
   ├── CloudHSM (硬件安全模块)
   ├── Secrets Manager (密钥管理)
   ├── Certificate Manager (SSL/TLS)
   └── S3 Encryption (存储加密)
```

---

## 2. IAM 策略审计

### 2.1 最小权限分析

```python
import boto3
import json
from datetime import datetime, timedelta

class IAMPolicyAuditor:
    """IAM 最小权限审计"""

    def __init__(self):
        self.iam = boto3.client('iam')
        self.access_analyzer = boto3.client('accessanalyzer')

    def find_overprivileged_roles(self):
        """找出权限过大的角色"""

        roles = self.iam.list_roles()['Roles']
        findings = []

        for role in roles:
            # 检查 AdministratorAccess 策略
            attached = self.iam.list_attached_role_policies(
                RoleName=role['RoleName']
            )['AttachedPolicies']

            for policy in attached:
                if policy['PolicyName'] == 'AdministratorAccess':
                    findings.append({
                        'role': role['RoleName'],
                        'issue': '拥有 AdministratorAccess (完全管理员权限)',
                        'severity': 'CRITICAL',
                        'recommendation': '替换为细粒度策略'
                    })
                    continue

                # 检查通配符策略 (Action: *)
                policy_doc = self.iam.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=self.iam.get_policy(
                        PolicyArn=policy['PolicyArn']
                    )['Policy']['DefaultVersionId']
                )['PolicyVersion']['Document']

                for statement in policy_doc.get('Statement', []):
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]

                    for action in actions:
                        if action == '*' or action.endswith(':*'):
                            findings.append({
                                'role': role['RoleName'],
                                'issue': f'Action 通配符: {action}',
                                'policy': policy['PolicyName'],
                                'severity': 'HIGH'
                            })

                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    if '*' in resources:
                        findings.append({
                            'role': role['RoleName'],
                            'issue': 'Resource 通配符 (*)',
                            'policy': policy['PolicyName'],
                            'severity': 'HIGH'
                        })

        return findings

    def check_unused_roles(self, days=90):
        """检测未使用的角色"""
        findings = []
        threshold = datetime.now() - timedelta(days=days)

        roles = self.iam.list_roles()['Roles']
        for role in roles:
            # 检查上次使用时间
            job_id = self.iam.generate_service_last_accessed_details(
                Arn=role['Arn']
            )['JobId']

            # 等待分析完成
            waiter = self.iam.get_waiter('service_last_accessed_details_generated')
            waiter.wait(JobId=job_id)

            details = self.iam.get_service_last_accessed_details(
                JobId=job_id
            )

            last_auth = details.get('JobCompletionDate', None)
            if last_auth and last_auth.replace(tzinfo=None) < threshold:
                findings.append({
                    'role': role['RoleName'],
                    'last_used': last_auth.isoformat(),
                    'inactive_days': (datetime.now() - last_auth.replace(tzinfo=None)).days,
                    'recommendation': '考虑删除或禁用此角色'
                })

        return findings
```

### 2.2 SCP (Service Control Policies)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicS3Buckets",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketAcl",
        "s3:PutBucketPublicAccessBlock"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": ["public-read", "public-read-write"]
        }
      }
    },
    {
      "Sid": "DenyRegionOutside",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "cn-north-1",
            "cn-northwest-1"
          ]
        }
      }
    },
    {
      "Sid": "RequireMFAForSensitiveActions",
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "organizations:*",
        "billing:*"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    },
    {
      "Sid": "DenyRootUser",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```

---

## 3. GuardDuty + Security Hub

### 3.1 GuardDuty 发现类型

```yaml
GuardDuty 威胁发现分类:

  侦查 (Recon):
    - PortSweep (端口扫描)
    - PortProbeUnprotectedPort
    - DNS 隧道活动
    - 来自 Tor 出口节点的 API 调用

  后台访问 (Backdoor):
    - C2 通信 (已知恶意 IP/域)
    - DNS 数据外传
    - TCP/UDP 回连
    - 加密货币挖矿 DNS 查询

  权限提升 (Privilege Escalation):
    - IAM 用户异常创建
    - 角色链接异常策略
    - Root 账户使用

  数据外泄 (Exfiltration):
    - S3 异常下载量
    - RDS 快照公开
    - EBS 快照与外部账户共享

  凭证泄露 (Credential Compromise):
    - 不受信 IP 调用 AWS API
    - 异常区域 API 调用
    - 不可能的旅行调用
```

### 3.2 Security Hub 标准

```bash
# Security Hub 合规检查

# 启用 Security Hub
aws securityhub enable-security-hub \
    --enable-default-standards \
    --control-finding-generator SECURITY_CONTROL

# 查看合规状态
aws securityhub get-findings \
    --filters '{
        "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
        "SeverityLabel": [
            {"Value": "CRITICAL", "Comparison": "EQUALS"},
            {"Value": "HIGH", "Comparison": "EQUALS"}
        ],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
    }' \
    --query 'Findings[*].[Title,Severity.Label,Resources[*].Id]'

# 导出报告
aws securityhub get-findings \
    --query 'Findings[*].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Id,Status:Compliance.Status}' \
    --output table
```

---

## 4. CloudTrail 审计

```python
import boto3
import gzip
import json
from datetime import datetime, timedelta

class CloudTrailAuditor:
    """CloudTrail 安全审计"""

    def __init__(self):
        self.cloudtrail = boto3.client('cloudtrail')

    def detect_suspicious_actions(self, hours=24):
        """检测可疑 AWS API 调用"""
        suspicious_patterns = [
            {
                'name': 'Root 账户使用',
                'pattern': lambda e: 'root' in e.get('userIdentity', {}).get('arn', ''),
                'severity': 'CRITICAL'
            },
            {
                'name': '安全组修改',
                'pattern': lambda e: e['eventName'] in [
                    'AuthorizeSecurityGroupIngress',
                    'AuthorizeSecurityGroupEgress',
                    'CreateSecurityGroup',
                    'RevokeSecurityGroupIngress'
                ],
                'severity': 'HIGH'
            },
            {
                'name': 'IAM 策略修改',
                'pattern': lambda e: e['eventName'].startswith('Create') and
                                       'Policy' in e['eventName'],
                'severity': 'HIGH'
            },
            {
                'name': 'S3 公开',
                'pattern': lambda e: e['eventName'] in [
                    'PutBucketAcl', 'PutBucketPolicy'
                ],
                'severity': 'CRITICAL'
            },
            {
                'name': 'CloudTrail 停止',
                'pattern': lambda e: e['eventName'] in [
                    'StopLogging', 'DeleteTrail', 'UpdateTrail'
                ],
                'severity': 'CRITICAL'
            }
        ]

        start_time = datetime.now() - timedelta(hours=hours)
        findings = []

        # 查询 CloudTrail 事件
        response = self.cloudtrail.lookup_events(
            StartTime=start_time,
            EndTime=datetime.now(),
            MaxResults=50
        )

        for event in response.get('Events', []):
            event_data = json.loads(event['CloudTrailEvent'])

            for pattern in suspicious_patterns:
                if pattern['pattern'](event_data):
                    findings.append({
                        'event': event_data['eventName'],
                        'user': event_data.get('userIdentity', {}).get('arn', 'Unknown'),
                        'time': event_data['eventTime'],
                        'pattern': pattern['name'],
                        'severity': pattern['severity']
                    })

        return findings
```

---

## 参考资源

- [AWS Security Reference Architecture](https://docs.aws.amazon.com/whitepapers/latest/aws-security-amazon-web-services/security-reference-architecture.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/)

---

*下一篇：待补充*

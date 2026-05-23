# IAM 高级场景实践

## 概述

现代 IAM 早已超越"用户名+密码"的范畴。本章深入企业级 IAM 的高级场景：跨云联邦、Just-in-Time 访问和持续自适应认证。

---

## 1. 跨云身份联邦

### 1.1 多 IDP 联邦架构

```
跨云联邦 (Federation):

  ┌─────────────────┐
  │  Okta / Azure AD │ ← 中心 IDP
  └────────┬────────┘
           │ SAML/OIDC
    ┌──────┼──────┐
    │      │      │
    ▼      ▼      ▼
  AWS    GCP    Azure
  ┌──┐  ┌──┐  ┌──┐
  │R │  │G │  │A │
  │o │  │C │  │D │
  │l │  │P │  │  │
  │e │  │  │  │  │
  └──┘  └──┘  └──┘
```

### 1.2 AWS IAM Identity Center 配置

```bash
# AWS SSO 配置 (现称 IAM Identity Center)
aws sso-admin create-instance \
    --name "CorporateSSO"

# 连接到外部 IDP (Okta)
aws sso-admin create-trusted-token-issuer \
    --instance-arn "arn:aws:sso:::instance/ssoins-xxxx" \
    --name "Okta" \
    --trusted-token-issuer-configuration '{
        "OidcJwtConfiguration": {
            "ClaimAttributePath": "email",
            "IdentityStoreAttributePath": "emails",
            "IssuerUrl": "https://your-org.okta.com",
            "JwksRetrievalOption": "OPEN_ID_DISCOVERY"
        }
    }'

# 创建权限集
aws sso-admin create-permission-set \
    --instance-arn "arn:aws:sso:::instance/ssoins-xxxx" \
    --name "ReadOnlyAccess" \
    --session-duration "PT1H"
```

### 1.3 GCP Workforce Identity Federation

```bash
# GCP 劳动力身份联合
gcloud iam workforce-pools create "corporate-pool" \
    --location="global" \
    --display-name="Corporate Workforce Pool"

# 配置 OIDC 提供商
gcloud iam workforce-pools providers create-oidc "okta-provider" \
    --workforce-pool="corporate-pool" \
    --location="global" \
    --display-name="Okta Provider" \
    --issuer-uri="https://your-org.okta.com" \
    --client-id="client-id" \
    --client-secret-value="secret" \
    --web-sso-enabled \
    --web-sso-response-type="id_token" \
    --web-sso-assertion-claims-behavior="merge-user-info-over-id-token-claims"

# 绑定角色
gcloud iam workforce-pools providers update-oidc "okta-provider" \
    --workforce-pool="corporate-pool" \
    --location="global" \
    --attribute-mapping="google.subject=assertion.sub,attribute.roles=assertion.groups"
```

---

## 2. Just-in-Time (JIT) 访问

### 2.1 JIT 架构

```yaml
JIT 访问流程:

  1. 开发者提权请求 (PR/工单)
     → 说明需要什么权限/为什么/多久

  2. 自动审批 (低风险) / 人工审批 (高风险)
     → 判断: 常规操作 / 敏感操作

  3. 临时授予 (1-4 小时)
     → 创建临时角色/组/策略
     → 记录审计日志

  4. 自动回收
     → 定时器到期 → 删除临时授权
     → 通知: 权限已回收

  5. 审计
     → 谁/何时/做了什么/结果
```

### 2.2 AWS JIT 实现

```python
import boto3
import json
from datetime import datetime, timedelta

class JITAccessManager:
    """AWS Just-in-Time 访问管理"""

    def __init__(self):
        self.iam = boto3.client('iam')

    def grant_temporary_access(self, user, role, duration_hours=2,
                                 justification=''):
        """临时授权"""

        # 1. 创建临时策略
        temp_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "rds:DescribeDBInstances",
                    "s3:ListBucket"
                ],
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:CurrentTime": (
                            datetime.utcnow() + timedelta(hours=duration_hours)
                        ).isoformat() + 'Z'
                    }
                }
            }]
        }

        # 2. 附加策略
        policy_name = f"JIT-{user}-{datetime.utcnow().strftime('%Y%m%d%H%M')}"
        self.iam.put_user_policy(
            UserName=user,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(temp_policy)
        )

        # 3. 记录审计
        audit_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'user': user,
            'action': 'JIT_GRANT',
            'duration_hours': duration_hours,
            'expires': (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat(),
            'justification': justification
        }

        return audit_record

    def revoke_expired_access(self):
        """回收过期权限 (Cron 任务)"""
        users = self.iam.list_users()['Users']

        for user in users:
            policies = self.iam.list_user_policies(
                UserName=user['UserName']
            )['PolicyNames']

            for policy in policies:
                if not policy.startswith('JIT-'):
                    continue

                policy_doc = self.iam.get_user_policy(
                    UserName=user['UserName'],
                    PolicyName=policy
                )['PolicyDocument']

                # 检查过期
                for stmt in policy_doc.get('Statement', []):
                    condition = stmt.get('Condition', {})
                    time_limit = condition.get('DateLessThan', {}).get('aws:CurrentTime')

                    if time_limit and datetime.fromisoformat(time_limit.replace('Z','')) < datetime.utcnow():
                        self.iam.delete_user_policy(
                            UserName=user['UserName'],
                            PolicyName=policy
                        )
                        print(f"Revoked: {user['UserName']}/{policy}")
```

---

## 3. 持续自适应认证 (CAP)

### 3.1 CAP 信号

```python
class ContinuousAdaptiveAuth:
    """持续自适应认证"""

    def calculate_risk_score(self, context):
        """
        基于上下文信号计算风险分数
        risk_score 越高 → 需要越强的认证
        """

        risk = 0

        # 1. 地理位置
        if context.get('country') != context.get('usual_country'):
            risk += 20
            # 不可能旅行检测
            if self._impossible_travel(context):
                risk += 40

        # 2. 设备信任
        if not context.get('device_managed'):
            risk += 15
        if context.get('device') != context.get('usual_device'):
            risk += 10

        # 3. 时间
        hour = datetime.now().hour
        if hour < 6 or hour > 22:
            risk += 5  # 非工作时间

        # 4. 行为
        if context.get('typing_speed') > 2 * context.get('usual_typing_speed'):
            risk += 10  # 打字速度异常

        # 5. 访问敏感度
        if context.get('resource_sensitivity') == 'HIGH':
            risk *= 1.5

        return min(risk, 100)

    def determine_auth_requirement(self, risk_score):
        """根据风险分数决定认证要求"""
        if risk_score < 30:
            return 'ALLOW'  # 无需额外认证
        elif risk_score < 60:
            return 'MFA_REQUIRED'  # 需要 MFA
        elif risk_score < 80:
            return 'STEP_UP'  # 需要增强认证 (硬件 Key)
        else:
            return 'DENY'  # 拒绝访问

    def _impossible_travel(self, context):
        """不可能旅行检测"""
        last_login = context.get('last_login_location', {})
        current = context.get('current_location', {})

        if not last_login or not current:
            return False

        # 简化的距离计算
        distance = self._haversine(
            last_login['lat'], last_login['lon'],
            current['lat'], current['lon']
        )

        time_diff_hours = (
            context['timestamp'] - context['last_login_time']
        ).total_seconds() / 3600

        # 如果需要在 < 1 小时内移动超过 1000km → 不可能
        if time_diff_hours > 0 and distance / time_diff_hours > 1000:
            return True

        return False
```

---

## 参考资源

- [AWS IAM Identity Center](https://docs.aws.amazon.com/singlesignon/)
- [GCP Workforce Identity Federation](https://cloud.google.com/iam/docs/workforce-identity-federation)
- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)

---

*上一篇：[IAM 概述](index.md)*

*下一篇：[IAM 高级场景配置](03-iam-advanced-scenarios.md)*

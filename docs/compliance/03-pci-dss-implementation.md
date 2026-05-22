# PCI-DSS 合规实施指南

## PCI-DSS 概述

支付卡行业数据安全标准 (PCI-DSS) 适用于处理信用卡数据的组织。

### 版本历史

| 版本 | 发布时间 | 主要变化 |
|------|----------|------------|
| 3.2.1 | 2018 年 5 月 | 多因素认证强制 |
| 4.0 | 2022 年 3 月 | 风险为基础的方法 |

### 适用范围

| 商户级别 | 年交易量 | 要求 |
|----------|----------|--------|
| Level 1 | > 600 万 | 年度现场评估 |
| Level 2 | 100 万 - 600 万 | 年度自我评估 |
| Level 3 | 2 万 - 100 万 | 年度自我评估 |
| Level 4 | < 2 万 | 年度自我评估 |

---

## PCI-DSS v4.0 要求

### 目标1：构建和维护安全的网络

#### 要求 1：安装和维护防火墙配置

**实施：**

```bash
# 防火墙规则示例 (iptables)
# 允许 HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 允许已建立的连接
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 拒绝其他入站流量
iptables -A INPUT -j DROP

# 保存规则
iptables-save > /etc/iptables/rules.v4
```

**验证：**

```bash
# 扫描开放端口
nmap -sT -p 1-65535 $TARGET_IP

# 检查防火墙规则
iptables -L -v -n
```

#### 要求 2：不使用供应商提供的默认值

**实施：**

```bash
# 更改默认密码
passwd root
passwd admin

# 禁用默认账户
usermod -L admin

# 删除不必要的账户
userdel -r telnet
```

**验证：**

```bash
# 检查默认凭据
hydra -l admin -P /usr/share/wordlists/rockyou.txt $TARGET_IP ssh

# 检查不必要的服务
systemctl list-units --type=service --state=running
```

### 目标2：保护持卡人数据

#### 要求 3：保护存储的持卡人数据

**实施：**

```sql
-- 加密信用卡号 (AES-256)
INSERT INTO payments (card_number, expiry) 
VALUES (AES_ENCRYPT('1234567890123456', 'encryption_key'), '12/25');
```

```bash
# 使用 GPG 加密文件
gpg --encrypt --recipient security@example.com card-data.txt
```

**验证：**

```bash
# 检查数据库中的明文数据
SELECT * FROM payments WHERE card_number NOT LIKE 'AES%';

# 检查文件权限
ls -la /var/log/payment.log
```

#### 要求 4：加密跨开放公共网络的传输

**实施：**

```nginx
# Nginx SSL 配置
server {
    listen 443 ssl;
    server_name payment.example.com;

    ssl_certificate /etc/nginx/ssl/payment.crt;
    ssl_certificate_key /etc/nginx/ssl/payment.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
}
```

**验证：**

```bash
# 测试 SSL/TLS 配置
testssl.sh https://payment.example.com

# 检查证书有效期
openssl x509 -in /etc/nginx/ssl/payment.crt -text -noout | grep "Not After"
```

### 目标3：维护漏洞管理程序

#### 要求 5：保护所有系统免受恶意软件侵害

**实施：**

```bash
# 安装 ClamAV
apt-get install clamav clamav-daemon

# 更新病毒库
freshclam

# 扫描文件系统
clamscan -r -i /var/www/html
```

**验证：**

```bash
# 检查 ClamAV 状态
systemctl status clamav-daemon

# 查看扫描日志
tail -f /var/log/clamav/clamav.log
```

#### 要求 6：开发和维护安全系统和应用程序

**实施：**

```yaml
# GitLab CI 示例 (SAST)
stages:
  - test

sast:
  stage: test
  image: registry.gitlab.com/gitlab-org/security-products/analyzers/semgrep:latest
  script:
    - semgrep --config=auto --json --output=gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

**验证：**

```bash
# 检查漏洞扫描结果
cat gl-sast-report.json | jq '.results[] | select(.severity == "HIGH")'

# 检查补丁管理
yum updateinfo list security
```

### 目标4：实施强访问控制措施

#### 要求 7：按业务需要限制访问

**实施：**

```sql
-- 创建数据库角色
CREATE ROLE payment_reader;
GRANT SELECT ON payments TO payment_reader;

-- 分配用户到角色
GRANT payment_reader TO 'app_user'@'localhost';
```

```bash
# 配置 sudo 访问
echo "audit ALL=(ALL) /usr/bin/auditd" >> /etc/sudoers.d/audit
```

**验证：**

```bash
# 检查用户权限
SELECT user, host, authentication_string FROM mysql.user;

# 检查 sudo 访问
sudo -l -U audit
```

#### 要求 8：识别和验证对系统组件的访问

**实施：**

```bash
# 配置 PAM 进行 MFA
apt-get install libpam-google-authenticator

# 编辑 PAM 配置
echo "auth required pam_google_authenticator.so" >> /etc/pam.d/ssd
```

**验证：**

```bash
# 测试 MFA
ssh user@payment-server

# 检查认证日志
tail -f /var/log/auth.log
```

#### 要求 9：限制物理访问持卡人数据

**实施：**

```bash
# 配置 CCTV 监控
ffmpeg -f v4l2 -i /dev/video0 -c:v libx264 -preset ultrafast -f flv rtmp://cctv-server/live

# 记录物理访问
echo "$(date): User $USER accessed server room" >> /var/log/physical-access.log
```

**验证：**

```bash
# 检查 CCTV 录像
ffplay rtmp://cctv-server/live

# 审核物理访问日志
cat /var/log/physical-access.log | grep "unauthorized"
```

### 目标5：定期监控和测试网络

#### 要求 10：跟踪和监控对网络资源和持卡人数据的所有访问

**实施：**

```bash
# 配置 Rsyslog 发送日志到 SIEM
echo "*.* @@siem.example.com:514" >> /etc/rsyslog.conf

# 重启 Rsyslog
systemctl restart rsyslog
```

**验证：**

```bash
# 检查日志发送
tcpdump -i eth0 port 514

# 在 SIEM 中搜索日志
index=main sourcetype=syslog host=payment-server
```

#### 要求 11：定期测试安全系统和流程

**实施：**

```bash
# 使用 Nmap 进行漏洞扫描
nmap -sV -sC -p 1-65535 -T4 $TARGET_IP -oX scan-results.xml

# 使用 OpenVAS 进行漏洞管理
openvas-start
```

**验证：**

```bash
# 解析 Nmap 扫描结果
xsltproc scan-results.xml -o scan-results.html

# 查看 OpenVAS 报告
firefox https://localhost:9392
```

### 目标6：维护信息安全策略

#### 要求 12：维护针对所有人员的信息安全策略

**实施：**

```markdown
# 信息安全策略

## 1. 目的
本策略旨在保护持卡人数据。

## 2. 范围
本策略适用于所有处理信用卡数据的员工。

## 3. 策略
### 3.1 访问控制
- 使用 MFA 访问系统。
- 实施最小权限原则。

### 3.2 数据保护
- 加密存储的持卡人数据。
- 加密传输中的持卡人数据。

## 4. 违规处理
违反本策略将导致纪律处分。
```

**验证：**

```bash
# 分发策略并进行培训
echo "Please read and acknowledge the Information Security Policy." | mail -s "Policy Acknowledgment" user@example.com

# 记录确认
cat /var/log/policy-acknowledgments.log
```

---

## PCI-DSS 合规工具

### 1. Nessus

**功能：** 漏洞扫描

**使用：**

```bash
# 创建扫描策略
nessuscli scan-policy-create --policy-template "PCI-DSS" --policy-name "PCI-DSS-Scan"

# 启动扫描
nessuscli scan-launch --policy "PCI-DSS-Scan" --targets $TARGET_IP
```

### 2. OpenVAS

**功能：** 开源漏洞扫描

**使用：**

```bash
# 创建扫描任务
omp -u admin -w password -C -n "PCI-DSS Scan" -c "daba56c8-73ec-11df-a8b2005056c00008"

# 启动扫描任务
omp -u admin -w password -S -t "daba56c8-73ec-11df-a8b2005056c00008"
```

### 3. Qualys VMDR

**功能：** 云原生漏洞管理

**使用：**

```bash
# 安装 Qualys Agent
curl -u "$QUALYS_USER:$QUALYS_PASSWORD" "https://$QUALYS_SERVER/api/2.0/ams/windows/agent/?action=download_installer" -o QualysAgent.exe

# 安装 Agent
./QualysAgent.exe /i /quiet
```

---

## PCI-DSS 合规清单

### 规划阶段

- [ ] 确定商户级别
- [ ] 选择合规路径 (现场评估/自我评估)
- [ ] 定义范围 (持卡人数据环境)
- [ ] 选择合规工具

### 实施阶段

- [ ] 安装和维护防火墙
- [ ] 不使用供应商提供的默认值
- [ ] 保护存储的持卡人数据
- [ ] 加密跨开放公共网络的传输
- [ ] 保护所有系统免受恶意软件侵害
- [ ] 开发和维护安全系统和应用程序
- [ ] 按业务需要限制访问
- [ ] 识别和验证对系统组件的访问
- [ ] 限制物理访问持卡人数据
- [ ] 跟踪和监控对网络资源和持卡人数据的所有访问
- [ ] 定期测试安全系统和流程
- [ ] 维护针对所有人员的信息安全策略

### 审计阶段

- [ ] 进行漏洞扫描
- [ ] 进行渗透测试
- [ ] 审核安全策略
- [ ] 生成合规报告

### 维护阶段

- [ ] 定期审查访问控制
- [ ] 更新安全策略
- [ ] 监控安全事件
- [ ] 响应安全事件

---

## 延伸阅读

- [PCI-DSS 标准](https://www.pcisecuritystandards.org/document_library)
- [PCI-DSS v4.0 摘要](https://www.pcisecuritystandards.org/standards/pci_dss)
- [PCI-DSS 合规指南](https://www.pcisecuritystandards.org/approved_companies_providers)

---

*上一篇：[PCI-DSS 实施指南](03-pci-dss-implementation.md)*

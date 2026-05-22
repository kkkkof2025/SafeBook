# 威胁情报基础

## 概述

威胁情报不是"一堆 IOC 的集合"——它是经过分析的信息，回答三个问题：谁在攻击？用什么方法？我们该怎么办？

---

## 1. 威胁情报生命周期

```
威胁情报生命周期 (Intelligence Cycle):

  1. 规划 (Planning)
     → 确定情报需求
     → 明确消费者 (CISO / SOC / IR / CTI)
     → 定义输出格式

  2. 收集 (Collection)
     → OSINT (公开来源)
     → 商业情报源 (Recorded Future/Mandiant)
     → 社区共享 (ISAC/ISAO)
     → 内部 Telemetry

  3. 处理 (Processing)
     → 数据清洗/去重
     → 结构化 (STIX)
     → 富化 (WHOIS/GeoIP/PDNS)

  4. 分析 (Analysis)
     → 关联分析
     → 归因分析
     → 置信度评估

  5. 分发 (Dissemination)
     → 战略报告 (CISO)
     → 战术报告 (安全团队)
     → 运营报告 (SOC)
     → 技术 IOC (安全工具)

  6. 反馈 (Feedback)
     → 情报命中率
     → 调整收集策略
```

---

## 2. 威胁情报标准

### 2.1 STIX 2.1

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created": "2024-01-15T08:00:00.000Z",
  "modified": "2024-01-15T08:00:00.000Z",
  "name": "APT41 Malicious C2 IP",
  "description": "该 IP 被 APT41 用作 C2 基础设施",
  "indicator_types": ["malicious-activity"],
  "pattern": "[ipv4-addr:value = '198.51.100.23']",
  "pattern_type": "stix",
  "valid_from": "2024-01-01T00:00:00Z",
  "labels": ["apt41", "c2"],
  "confidence": 85
}
```

### 2.2 MISP 集成

```bash
# MISP API 操作

# 1. 搜索 IOC
curl -H "Authorization: YOUR_API_KEY" \
    "https://misp.example.com/attributes/restSearch/json" \
    -d '{"returnFormat":"json","type":"ip-src","value":"198.51.100.23"}'

# 2. 添加事件
curl -H "Authorization: YOUR_API_KEY" \
    -X POST "https://misp.example.com/events" \
    -d '{"Event":{"info":"APT41 Activity","threat_level_id":1,"distribution":1,"analysis":2}}'

# 3. 自动导入到 SIEM
# 使用 MISP 到 Splunk/ELK 的 feed 集成
python3 misp-to-siem.py --siem splunk --tags "apt,c2"
```

---

## 3. 威胁建模框架

### 3.1 MITRE ATT&CK 应用

```yaml
# ATT&CK 威胁组织示例: APT41
APT41 (中国国家背景的 APT 组织):

  初始访问:
    - T1190: 利用公开应用漏洞
    - T1566: 钓鱼邮件

  执行:
    - T1059.001: PowerShell
    - T1059.005: Visual Basic

  持久化:
    - T1547.001: 注册表 Run Key
    - T1053.005: 计划任务

  防御规避:
    - T1027: 混淆文件/信息
    - T1055: 进程注入

  凭据访问:
    - T1003.001: LSASS 内存
    - T1552.001: 凭证文件

  数据外泄:
    - T1041: C2 通道外泄
    - T1567.002: 云存储外泄
```

### 3.2 Diamond Model

```
Diamond Model 四要素:

           对手 (Adversary)
               │
       ┌───────┼───────┐
       │       │       │
       ▼       ▼       ▼
   基础设施 ──→ 受害者
  (Infrastructure)     │
       ▲               ▼
       └───────── 能力 (Capability)

分析示例:
  对手: APT41
  能力: Cobalt Strike Beacon
  基础设施:  198.51.100.23, apt.malicious.com
  受害者: 某金融科技公司
```

---

## 4. 开源威胁情报源

| 来源 | 类型 | 更新频率 | 质量 |
|------|------|----------|------|
| **AlienVault OTX** | IOC | 实时 | ★★★★ |
| **Abuse.ch** | 恶意软件 C2 | 实时 | ★★★★★ |
| **URLhaus** | 恶意 URL | 实时 | ★★★★★ |
| **VirusTotal** | 文件/URL | 实时 | ★★★★ |
| **PhishTank** | 钓鱼 URL | 实时 | ★★★ |
| **GreyNoise** | 扫描 IP | 每日 | ★★★★ |
| **Shodan** | 资产暴露 | 持续 | ★★★ |

---

## 参考资源

- [MITRE ATT&CK](https://attack.mitre.org/)
- [STIX 2.1 规范](https://docs.oasis-open.org/cti/stix/v2.1/)
- [MISP 开源威胁情报平台](https://www.misp-project.org/)

---

*下一篇：[威胁情报分析进阶](../threat-intel/03-threat-intel-analysis.md)*

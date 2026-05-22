# 威胁情报分析实战

## 威胁情报概述

威胁情报 (Threat Intelligence) 是关于威胁的证据知识。

### 情报类型

1. **战术情报 (Tactical)** - IOC、C2 IP、恶意哈希
2. **运营情报 (Operational)** - TTP、攻击活动、威胁组织
3. **战略情报 (Strategic)** - 威胁趋势、风险评估
4. **技术情报 (Technical)** - 漏洞、恶意软件分析

---

## 威胁情报生命周期

```
+--------------+     +--------------+     +--------------+
| 需求规划     | --> | 数据采集     | --> | 数据处理     |
| (Planning)  |     | (Collection)|     | (Processing) |
+--------------+     +--------------+     +--------------+
                                                          |
+--------------+     +--------------+                     v
| 反馈改进     | <-- | 分发应用     | <-- | 分析生产     |
| (Feedback)   |     | (Dissemination)|   | (Analysis)  |
+--------------+     +--------------+     +--------------+
```

### 阶段1：需求规划

**关键问题：**
- 我们需要防御什么？
- 攻击者是谁？
- 我们的关键资产是什么？

**输出：**
- 情报需求文档 (IRD)
- 优先级列表

### 阶段2：数据采集

**来源：**

| 来源类型 | 示例 |
|----------|------|
| 开源情报 (OSINT) | MISP、OTX、VirusTotal |
| 闭源情报 (Proprietary) | 商用威胁情报服务 |
| 内部日志 | SIEM、EDR、防火墙日志 |
| 威胁共享组织 | ISAC/ISAO、CISA |

### 阶段3：数据处理

**任务：**
- 规范化 (Normalization)
- 去重 (Deduplication)
- 丰富 (Enrichment) - 地理位置、ASN、WHOIS
- 评分 (Scoring) - 置信度、严重性

**工具：**
- **MISP** - 威胁情报平台
- **TheHive** - 安全事件响应平台
- **Cortex** - 分析引擎

### 阶段4：分析生产

**技术：**
1. **关联分析** - 将 IOC 与内部日志关联
2. **归因分析** - 将攻击归因于特定威胁组织
3. **预测分析** - 基于历史数据预测未来攻击
4. **影响分析** - 评估攻击的潜在影响

### 阶段5：分发应用

**格式：**
- **STIX/TAXII** - 结构化威胁信息表达
- **OpenIOC** - 开放入侵指标
- **CSV/JSON** - 简易格式

**渠道：**
- SIEM 集成
- EDR 策略推送
- 防火墙阻断列表
- 邮件告警

### 阶段6：反馈改进

**指标：**
- 情报命中率 (Hit Rate)
- 误报率 (False Positive Rate)
- 检测时间 (Time to Detect)
- 响应时间 (Time to Respond)

---

## 威胁情报标准

### STIX (Structured Threat Information Expression)

**用途：** 表达威胁情报的结构化语言

**核心对象：**

| 对象 | 用途 |
|------|------|
| Indicator | 入侵指标 (IP、域名、哈希) |
| Malware | 恶意软件信息 |
| TTP | 战术、技术和过程 |
| Campaign | 攻击活动 |
| Threat Actor | 威胁行为者 |
| Identity | 身份 (个人/组织) |

**示例：**

```json
{
  "type": "indicator",
  "id": "indicator--aabbccdd-0011-2233-4455-66778899aabb",
  "created": "2026-05-22T00:00:00Z",
  "modified": "2026-05-22T00:00:00Z",
  "name": "Malicious IP Indicator",
  "pattern": "[ipv4-addr:value = '198.51.100.1']",
  "valid_from": "2026-05-22T00:00:00Z"
}
```

### TAXII (Trusted Automated eXchange of Intelligence Information)

**用途：** 传输 STIX 内容的协议

**端点：**

| 端点 | 用途 |
|------|------|
| /taxii/v21/discovery | 发现 API 根 |
| /taxii/v21/api_roots | 列出 API 根 |
| /taxii/v21/collections | 列出集合 |
| /taxii/v21/stix | 获取 STIX 对象 |

**示例：**

```bash
# 发现 TAXII 服务
curl https://taxii.example.com/api/v21/discovery

# 获取集合列表
curl https://taxii.example.com/api/v21/collections

# 获取 STIX 对象
curl https://taxii.example.com/api/v21/stix?match[type]=indicator
```

---

## 威胁情报平台

### 1. MISP (Malware Information Sharing Platform)

**功能：**
- 存储、管理和共享威胁情报
- 支持 STIX/TAXII
- 集成多个威胁源

**安装：**

```bash
# Docker 安装
docker pull harvardit/misp-docker
docker run -it -p 80:80 -p 443:443 harvardit/misp-docker

# 手动安装 (Ubuntu)
sudo apt-get install misp
```

**使用：**

```bash
# 添加事件
misp_event_add --url https://misp.example.com --key YOUR_KEY --info "New Campaign"

# 添加属性 (IOC)
misp_attribute_add --event-id 1 --type ip-src --value "198.51.100.1"

# 搜索 IOC
misp_search --url https://misp.example.com --key YOUR_KEY --value "198.51.100.1"
```

### 2. OpenCTI (Open Cyber Threat Intelligence Platform)

**功能：**
- 基于 STIX 2.1
- 图形化界面
- 关系分析

**安装：**

```bash
# Docker Compose 安装
git clone https://github.com/OpenCTI-Platform/opencti.git
cd opencti
docker-compose up -d
```

**使用：**
- 访问 `https://localhost:8080`
- 导入 STIX 捆绑包
- 可视化威胁关系图

### 3. TheHive + Cortex

**功能：**
  - TheHive: 安全事件响应平台
  - Cortex: 分析引擎 (100+ 分析器)

**安装：**

```bash
# Docker 安装
docker run -d --name thehive -p 9000:9000 thehiveproject/thehive
docker run -d --name cortex -p 9001:9001 thehiveproject/cortex
```

**使用：**
- 访问 `http://localhost:9000` (TheHive)
- 访问 `http://localhost:9001` (Cortex)
- 创建案件 (Case) 并添加可观测数据 (Observable)
- 运行分析器 (如 VirusTotal、AbuseIPDB)

---

## 威胁情报应用

### 1. SIEM 集成

**目标：** 将 IOC 导入 SIEM 进行检测

**示例 (Splunk)：**

```splunk
# 导入恶意 IP 列表
| inputlookup threat_intel.csv
| eval threat_type="malicious_ip"
| table ip, threat_type, source

# 搜索匹配日志
index=firewall src_ip IN (malicious_ip)
| stats count by src_ip, dest_ip
| `security_incident_create`
```

### 2. EDR 策略推送

**目标：** 将恶意哈希推送到 EDR 进行阻断

**示例 (CrowdStrike)：**

```bash
# 使用 Falcon API 添加 IOC
curl -X POST https://api.crowdstrike.com/indicators/entities/v1 \
  -H "Authorization: Bearer $FALCON_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resources": [
      {
        "type": "sha256",
        "value": "aabbccdd...",
        "policy": "detect"
      }
    ]
  }'
```

### 3. 防火墙阻断

**目标：** 将恶意 IP/域名推送到防火墙进行阻断

**示例 (Palo Alto)：**

```xml
<!-- 地址对象 -->
<entry name="malicious-ip-001">
  <ip-netmask>198.51.100.1/32</ip-netmask>
</entry>

<!-- 安全策略 -->
<entry name="block-malicious-ip">
  <from>trust</from>
  <to>untrust</to>
  <source>malicious-ip-001</source>
  <action>deny</action>
</entry>
```

---

## 威胁情报分析技术

### 1. 归因分析 (Attribution Analysis)

**目标：** 将攻击归因于特定威胁组织

**方法：**
- **TTP 匹配** - 比较攻击技术与已知组织
- **基础设施关联** - 分析 C2 IP、域名注册信息
- **恶意软件代码复用** - 比较恶意软件代码片段
- **社会工程特征** - 分析钓鱼邮件语言风格

**工具：**
- **MITRE ATT&CK** - 知识库
- **威胁组织档案** - APT1、Lazarus、Cozy Bear

### 2. 预测分析 (Predictive Analysis)

**目标：** 基于历史数据预测未来攻击

**方法：**
- **时间序列分析** - 分析攻击频率趋势
- **异常检测** - 识别异常行为模式
- **威胁建模** - 模拟攻击路径

**工具：**
- **ELK Stack** (Elasticsearch + Logstash + Kibana)
- **Jupyter Notebook** (Python 数据分析)

### 3. 影响分析 (Impact Analysis)

**目标：** 评估攻击的潜在影响

**方法：**
- **资产估值** - 评估受影响资产的价值
- **业务影响评估** - 评估对业务运营的影响
- **恢复成本估算** - 估算恢复所需的成本

**框架：**
- **FAIR** (Factor Analysis of Information Risk)
- **NIST CSF** (Cybersecurity Framework)

---

## 威胁情报最佳实践清单

### 数据采集

- [ ] 订阅多个开源威胁源 (MISP、OTX、VirusTotal)
- [ ] 购买商用威胁情报服务 (FireEye、CrowdStrike)
- [ ] 加入威胁共享组织 (ISAC/ISAO)
- [ ] 收集内部日志 (SIEM、EDR、防火墙)

### 数据处理

- [ ] 规范化数据格式 (STIX/TAXII)
- [ ] 去重和合并重复 IOC
- [ ] 丰富 IOC (地理位置、ASN、WHOIS)
- [ ] 评分和优先级排序

### 分析生产

- [ ] 关联分析与内部日志
- [ ] 归因分析 (TTP 匹配)
- [ ] 预测分析 (时间序列)
- [ ] 影响分析 (FAIR)

### 分发应用

- [ ] 集成 SIEM (Splunk、Elasticsearch)
- [ ] 推送 EDR 策略 (CrowdStrike、SentinelOne)
- [ ] 更新防火墙阻断列表
- [ ] 发送邮件告警

### 反馈改进

- [ ] 监控情报命中率
- [ ] 跟踪误报率
- [ ] 测量检测时间
- [ ] 优化采集和分析流程

---

## 延伸阅读

- [MITRE ATT&CK](https://attack.mitre.org/) - 威胁组织 TTP 知识库
- [STIX/TAXII 文档](https://oasis-open.github.io/cti-documentation/) - 威胁情报标准
- [MISP 文档](https://www.misp-project.org/documentation/) - 威胁情报平台
- [TheHive 文档](https://docs.thehive-project.org/) - 安全事件响应平台

---

*上一篇：[威胁情报分析入门](../threat-intelligence/01-threat-intel.md)*

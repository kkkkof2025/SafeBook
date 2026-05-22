# HVV 蓝队防御策略

## 概述

蓝队在 HVV 中的核心任务不是"零失陷"（这不可能），而是"快速发现、精准响应、有效溯源"。一家蓝队能在 6 小时内发现红队入侵就是优秀。本章提供实战可用的防御架构和响应手册。

---

## 1. 纵深防御四层体系

```
HVV 蓝队防御四层:

  L0 — 边界防御
    ├── WAF（Web应用防火墙）
    ├── CDN（DDoS + 隐藏源站）
    ├── 网络ACL（入站白名单）
    └── 蜜罐（诱饵系统）

  L1 — 网络检测
    ├── IDS/IPS（入侵检测/防御）
    ├── NDR（网络检测与响应）
    ├── DNS 安全（异常域名检测）
    └── 流量镜像（全量PCAP存档）

  L2 — 主机检测
    ├── EDR（端点检测与响应）
    ├── HIDS（主机入侵检测）
    ├── 日志收集（Sysmon/WinEvent）
    └── 文件完整性监控

  L3 — 应用检测
    ├── RASP（运行时应用自保护）
    ├── WAF（应用层过滤）
    ├── SQL审计
    └── API 安全网关

  L4 — 数据检测
    ├── DLP（数据防泄漏）
    ├── 数据库审计
    ├── 加解密监控
    └── UEBA（用户实体行为分析）
```

---

## 2. 关键发现阶段（0-6 小时）

### 2.1 告警阈值配置

```yaml
蓝队核心检测规则:

  # Windows 安全事件
  - name: 暴力破解检测
    event_id: 4625
    threshold: 5次/分钟/同一源IP
    severity: HIGH
    auto_response: 阻断源IP 30分钟

  - name: 新账户创建
    event_id: 4720
    threshold: 任意
    severity: CRITICAL
    action: 立即通知安全团队

  - name: 特权组变更
    event_id: 4728/4732/4756
    threshold: 任意
    severity: CRITICAL
    action: 撤销变更 + 通知

  - name: 计划任务创建
    event_id: 4698
    threshold: 2次/小时/同一主机
    severity: HIGH

  # 网络检测
  - name: DNS隧道检测
    condition: DNS查询长度 > 200字节
    threshold: 10次/分钟
    severity: HIGH

  - name: 横向移动扫描
    condition: 内网连接 >100目标/分钟
    threshold: 触发
    severity: CRITICAL

  - name: 数据外传
    condition: 出站流量 >100MB/主机
    threshold: 触发
    severity: CRITICAL
```

### 2.2 应急响应流程

```
HVV 蓝队应急 SOP:

  [T+0min] 告警触发
    → SIEM 自动创建工单
    → 通知 Tier 1 分析师（企业微信/钉钉/飞书）

  [T+5min] Tier 1 初步研判
    → 确认是否为误报
    → 快速浏览事件上下文（用户、主机、时间轴）
    → 如确认为攻击 → 升级至 Tier 2

  [T+15min] Tier 2 深入分析
    → 查询关联告警（同源IP/同账号/同主机）
    → 查看 PCAP/进程树/注册表变更
    → 确定攻击阶段（侦察/初始访问/提权/横向）
    → 评估影响范围

  [T+30min] 启动响应
    → 隔离受影响主机（VLAN/ACL 阻断）
    → 禁用受感染账号
    → 阻断恶意 IP/域名
    → 通知业务负责方

  [T+1h] 溯源分析
    → 追溯初始入侵点
    → 分析攻击路径
    → 提取 IOC（IP/域名/文件Hash/注册表）
    → 加固安全策略

  [T+4h] 事件关闭
    → 确认所有后门已清除
    → 验证系统恢复正常
    → 编写事件报告
    → 更新检测规则（防止同类攻击）
```

---

## 3. 日志架构与留存

```bash
# 蓝队日志收集架构

# 1. Sysmon 配置（Windows 端）
# 关键事件 ID（推荐配置）
sysmon -accepteula -i sysmon-config.xml

# 2. Filebeat → Elasticsearch
filebeat.inputs:
- type: winlog
  channels: ["Security", "System", "Microsoft-Windows-Sysmon/Operational"]

- type: log
  paths:
    - /var/log/nginx/access.log
    - /var/log/secure

# 3. Logstash 管道
input {
  beats { port => 5044 }
}

filter {
  if [event_id] == 4624 {
    # 提取登录信息
    grok {
      match => { "message" => "...%{WORD:logon_type}..." }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "logs-%{+YYYY.MM.dd}"
  }
}
```

---

## 4. 蜜罐防御

```bash
# 快速部署蜜罐（Cowrie SSH + Dionaea）
docker run -d --name cowrie -p 2222:2222 cowrie/cowrie
docker run -d --name dionaea -p 21:21 -p 445:445 -p 1433:1433 dinotools/dionaea

# HoneyBadger（主动检测横向移动）
# 在关键 VLAN 上部署 ARP 欺骗检测
honeybadger -i eth0 -n 192.168.1.0/24

# 诱饵文件（canary tokens）
# 创建诱饵 Word 文档，一旦打开即告警
python3 -c "
import canary_tools
canary_tools.create_token(
    memo='Credentials Server',
    kind='doc-msword',
    webhook_url='https://hooks.slack.com/xxx'
)
"
```

---

## 5. 红蓝视角对照

| 维度 | 红队视角 | 蓝队视角 |
|------|---------|---------|
| 时间 | 不限 | TTD < 6小时 |
| 信息 | 全量公开信息收集 | 内部安全态势 |
| 攻击面 | 寻找唯一突破口 | 保护全网每一个点 |
| 特征 | 一次成功即可 | 一次遗漏就输 |
| 核心 | 隐匿 + 创新 | 可见性 + 覆盖度 |
| 工具 | 定制 + 免杀 | 商业/开源 + 规则 |

---

## 参考资源

- [MITRE D3FEND（蓝队框架）](https://d3fend.mitre.org/)
- [SANS Incident Response Poster](https://www.sans.org/posters/incident-response/)
- [Awesome-HVV（红蓝对抗资源）](https://github.com/wgpsec/awesome-hvv)

---

*上一篇：[HVV 攻击技术](02-attack-techniques.md)*

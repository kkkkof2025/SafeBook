# APT 组织深度分析

## APT 组织全景

高级持续性威胁（APT）是由国家支持的黑客组织或顶级黑客团队发起的长期、隐蔽的网络攻击。

## 主要 APT 组织

### Lazarus Group (APT38/HIDDEN COBRA)

- **归属**: 朝鲜（Lazarus 集团）  
- **活跃时间**: 2009至今  
- **目标行业**: 金融、加密货币、国防  
- **著名行动**: 2016 孟加拉银行劫案（8100万美元）、2017 WannaCry、2022 Ronin Bridge（6.2亿美元）
- **TTP**: 社交工程→交付恶意文档→Cobalt Strike→横向移动→数据外泄/勒索

```yaml
# MITRE ATT&CK 映射
Techniques:
  - T1566.001: Spearphishing Attachment
  - T1204.002: User Execution via Malicious File
  - T1059.003: Windows Command Shell
  - T1574.002: DLL Side-Loading
  - T1485: Data Destruction
```

### APT29 (Cozy Bear / The Dukes)

- **归属**: 俄罗斯 SVR（对外情报局）
- **活跃时间**: 2008至今  
- **目标行业**: 政府、外交、智库、能源
- **著名行动**: 2015 DNC 黑客事件、2020 SolarWinds 供应链攻击
- **TTP**: 供应链投毒→后门→凭证窃取→Azure AD/Office 365 横向

```yaml
TTP:
  - T1195.001: Supply Chain Compromise
  - T1078.004: Cloud Accounts
  - T1525: Implant Internal Image
  - T1550.001: Pass the Hash
  - T1040: Network Sniffing
```

### APT41 (Winnti / Barium)

- **归属**: 中国
- **活跃时间**: 2012至今  
- **目标行业**: 游戏、科技、制药、教育
- **著名行动**: 多次游戏公司数据窃取、COVID-19 研究机构入侵
- **特点**: 同时以间谍和经济利益为驱动

## 攻击链分析框架

### 统一杀伤链

```
1. 侦察 → 2. 武器化 → 3. 投递 → 4. 利用 → 5. 安装 → 6. C2 → 7. 行动
```

## APT 常用技术

### 持久化机制

```powershell
# 注册表 Run Key
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Users\Public\svchost.exe"

# 计划任务
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Tasks\msupdate.exe" /sc daily /st 09:00

# WMI 事件订阅
# 使用 __EventFilter 和 CommandLineEventConsumer 实现无文件持久化
```

### C2 通信模式

```yaml
通信协议:
  - HTTPS: 伪装为正常 API 调用（如 Microsoft Graph API）
  - DNS: 域名查询隧道 → 编码数据在子域名中
  - WebSocket: 实时双向通信（如 Cobalt Strike Malleable C2）
  - CDN: 利用 Cloudflare/Akamai 作为中转
```

## 检测策略

### 基于网络的检测

```bash
# DNS 隧道检测 - 高熵域名
# 正常: api-v2.microsoft.com
# 隧道: 3a9f2c8b1e4d.xyz.evil.net

# JA3/S 指纹（TLS 指纹识别）
# Cobalt Strike 默认指纹已被检测

# 使用 Suricata
alert tls $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Cobalt Strike JA3 detect";
    ja3_hash;"a0e9f5d643490fb08a6c16a22ad21834";
    sid:1000001; rev:1;)
```

## 案例：SolarWinds 攻击复盘

### 时间线

```
2019 Sep: SUNBURST 后门植入 SolarWinds Orion 构建系统
2020 Mar: 通过供应链分发更新（签名的合法数字证书）
2020 Dec: FireEye 披露发现（APT29 / UNC2452）
```

### 影响规模

- **18,000** 组织下载了受感染的更新
- 目标组织中被深度入侵的约 **100+**
- 包括美国国务院、司法部、DHS、国防部、商务部

## 总结

APT 防御需要从供应链安全、端点检测、网络检测到事件响应的全链路能力。仅依靠任何一种单一防御手段都不足以防御 APT 级别的攻击。

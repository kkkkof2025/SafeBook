# 红队 OPSEC 与行动安全

## 概述

红队行动的真正考验不在"打进去"，而在"不被发现地完成任务"。OPSEC（Operations Security）是红队真正的核心竞争力——本章涵盖从信息泄露防护到全程匿踪的完整流程。

---

## 1. OPSEC 五步法

```
OPSEC 五步法 (US DoD):

  1. 识别关键信息 (Critical Information)
     → 团队人员/工具/基础设施/C2/目标

  2. 威胁分析 (Threat Analysis)
     → 谁在监视？(SOC/EDR/SIEM/威胁情报)
     → 他们能看见什么？(日志/告警/回溯)

  3. 脆弱性分析 (Vulnerability Analysis)
     → OPSEC 指示器暴露了哪些信息？
     → 哪些行为模式可以被关联？

  4. 风险评估 (Risk Assessment)
     → 如果指示器被检测到，后果是什么？
     → 行动暴露 vs 达成目标的权衡

  5. 应对措施 (Countermeasures)
     → 消除、伪装、欺骗指示器
     → 确保每个指示器都有应对方案
```

---

## 2. 行动 OPSEC 检查要点

### 2.1 基础设施隔离

```yaml
红队基础设施 OPSEC:

  1. 工作环境:
    - 专用虚拟机 (无个人账户/文件)
    - 每次行动后重置
    - 无持久存储(临时快照)

  2. 通信隔离:
    - 红队工具流量 → 独立网络/代理
    - 研究与下载 → 独立环境
    - 永远不在目标网络内搜索技术文档

  3. 域名注册:
    - 使用隐私保护 WHOIS
    - 不同的注册商 → 不同的域名
    - 域名年龄伪装 (购买已过期域名)
    - 定期轮换

  4. CDN/云实例:
    - 使用预付费凭证 (不关联真实身份)
    - VPS 提供商分散 (不集中在同一家)
    - IP 地理分布 (不集中在一个国家/ASN)

  5. 行动数据:
    - 退出行动: 擦除所有虚拟机/容器/日志
    - 离线存储: 加密行动报告
    - 传输: 端到端加密文件共享
```

### 2.2 工具链 OPSEC

```python
class OpsecValidator:
    """工具链 OPSEC 验证"""

    def __init__(self, target_edr=None):
        self.target_edr = target_edr

    def check_tool_artifacts(self, tool_path):
        """
        检查工具是否包含 OPSEC 暴露风险
        """

        checks = {}

        # 1. 硬编码字符串检查
        with open(tool_path, 'rb') as f:
            binary = f.read()

        # 检查作者名、编译路径、POC 注释
        artifacts = [
            b'poc', b'pentest', b'exploit', b'hack',
            b'cobalt', b'beacon', b'meterpreter', b'payload',
            b'C:\\Users\\', b'/home/'
        ]
        for artifact in artifacts:
            if artifact in binary.lower():
                checks[f'string_{artifact.decode()}'] = 'FOUND'

        # 2. 编译信息检查
        # PDB 路径泄漏
        if b'.pdb' in binary:
            checks['pdb_path'] = 'FOUND — 包含调试符号路径'

        # 3. 数字签名检查
        import subprocess
        result = subprocess.run(
            ['sigcheck', '-nobanner', tool_path],
            capture_output=True
        )
        if b'Signed' in result.stdout:
            checks['signature'] = 'SIGNED'
            # 检查签名证书是否泄漏身份
            if b'Organization' in result.stdout:
                checks['cert_org'] = 'CERT_CONTAINS_ORG_INFO'
        else:
            checks['signature'] = 'UNSIGNED — EDR 会标记为可疑'

        return checks

    def check_collector_artifacts(self, collector_output):
        """检查侦察阶段的数据收集是否暴露"""

        # 避免在目标环境中留下收集工具的痕迹
        warnings = []

        # 1. 工具文件留在磁盘上？
        if collector_output.get('files_on_disk', []):
            warnings.append("收集工具残留在磁盘上")

        # 2. 网络扫描速率异常
        if collector_output.get('scan_rate', 0) > 100:
            warnings.append("扫描速率过高 (触发 IDS)")

        # 3. 使用了 nslookup/whois 等被监控的命令
        monitored_commands = ['nslookup', 'whois', 'dig', 'netstat',
                              'net user', 'net group', 'dsquery']
        if collector_output.get('commands_used', []):
            for cmd in collector_output['commands_used']:
                if cmd in monitored_commands:
                    warnings.append(f"监控命令: {cmd}")

        return warnings
```

---

## 3. 退出行动流程

```yaml
红队退出清单 (Exfil Checklist):

  C2 基础设施:
    - [ ] 删除所有 Beacon (10 分钟前发自我删除指令)
    - [ ] 关闭所有 C2 服务器
    - [ ] 清理域名 DNS 记录
    - [ ] 删除 CDN 配置

  目标环境:
    - [ ] 清除持久化 (计划任务/服务/WMI/注册表)
    - [ ] 删除投放的工具和脚本
    - [ ] 清除事件日志 (谨慎 — 这本身可能触发告警)
    - [ ] 还原被修改的配置 (防火墙/GPO)
    - [ ] 关闭所有创建的会话/连接

  本地环境:
    - [ ] 加密行动笔记和截图
    - [ ] 删除本地工具副本
    - [ ] 终止 VPN 连接
    - [ ] 销毁虚拟机快照
```

---

## 4. OPSEC 失败案例分析

```yaml
常见 OPSEC 失败:

  1. GitHub 泄漏:
     红队成员在公共 GitHub 上搜索工具
     → GitHub 记录搜索历史 + IP
     → 目标蓝队通过威胁情报发现

  2. 个人社交账户关联:
     使用个人设备访问行动基础设施
     → 个人账户 cookies/sessions 关联到攻击

  3. 时间模式:
     攻击活动集中在 9-17 时区 (指示团队所在地)
     → 蓝队通过时间分析缩小区域

  4. 工具签名:
     使用未修改的公共工具 (Mimikatz 等)
     → 签名已被所有 EDR 识别

  5. 基础设施重用:
     同一台 C2 服务器用于多个客户
     → 威胁情报交叉关联暴露所有行动
```

---

*上一篇：[红队战术深度](01-red-team-tactics.md)*

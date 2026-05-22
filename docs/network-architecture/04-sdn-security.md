# SDN 与网络虚拟化安全

## 概述

软件定义网络 (SDN) 将控制平面与数据平面分离——这带来了灵活性，但也创造了全新的攻击面。控制器被攻破 = 整个网络被控制。本章分析 SDN 安全威胁与防御。

---

## 1. SDN 安全威胁模型

### 1.1 攻击面分析

```
SDN 攻击面:

  SDN 控制器 (Controller)
    ├── 北向 API (REST) — 应用层攻击
    ├── 南向协议 (OpenFlow) — 协议层攻击
    ├── 东西向通信 — 分布式控制器攻击
    └── 自身漏洞 — 软件/OS 漏洞

  数据平面 (Switch/Router)
    ├── 流表溢出
    ├── 流规则投毒
    └── 侧信道 (时延分析)

  控制通道 (Control Channel)
    ├── TLS 降级攻击
    ├── 中间人攻击
    └── DoS 攻击

  北向应用
    ├── 恶意 SDN 应用
    └── 应用隔离绕过
```

### 1.2 威胁场景

```yaml
SDN 攻击场景:

  1. 控制器劫持:
     攻击者: 获取控制器 root 权限
     影响: 重写全网流表 → 流量重定向/黑洞化
     检测: 配置 drifts + 流规则审计

  2. 流表溢出 (Flow Table Overflow):
     攻击者: 发送大量唯一流 → 触发流表安装
     影响: TCAM 耗尽 → 合法流量被丢弃
     防御: 速率限制 + 流聚合 + 硬超时

  3. 北向 API 滥用:
     攻击者: 伪造 SDN 应用 → 调用控制器 API
     影响: 修改网络策略
     防御: RBAC + API 认证 + 输入验证

  4. 流规则投毒 (Flow Rule Poisoning):
     攻击者: 伪造 OpenFlow Packet-In → 诱导安装恶意规则
     影响: 流量重定向到攻击者
     防御: 流规则验证 + 一致性检查
```

---

## 2. 控制器安全加固

### 2.1 ONOS 安全配置

```yaml
# ONOS 控制器安全配置
# onos-config.yaml

security:
  # 1. 认证配置
  authentication:
    enabled: true
    realm: "ONOS"
    # RADIUS 集成
    radius:
      host: "radius.example.com"
      port: 1812
      secret: "radius_secret"

  # 2. RBAC 配置
  authorization:
    enabled: true
    roles:
      - name: admin
        permissions: [READ, WRITE, ALL]
      - name: operator
        permissions: [READ, FLOW_WRITE]
      - name: viewer
        permissions: [READ]

  # 3. TLS 配置（南向/东西向）
  tls:
    keystore: /etc/onos/keystore.jks
    keystore_password: "changeit"
    truststore: /etc/onos/truststore.jks
    truststore_password: "changeit"
    protocols: [TLSv1.2, TLSv1.3]
    ciphers:
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

  # 4. API 安全
  api:
    rate_limit:
      enabled: true
      max_requests_per_minute: 100
    cors:
      enabled: true
      allowed_origins:
        - "https://admin.example.com"

  # 5. 审计日志
  audit:
    enabled: true
    log_changes: true  # 记录配置变更
    log_flows: false    # 流表变更（大量）
```

### 2.2 OpenFlow 安全

```python
class OpenFlowSecurityValidator:
    """OpenFlow 安全验证"""

    def validate_flow_mod(self, flow_mod):
        """验证流表修改的安全性"""

        # 1. 禁止的通配符匹配（过于宽泛）
        if self._is_catch_all(flow_mod):
            raise ValueError("Catch-all flow_mod rejected")

        # 2. 输出的目标端口验证
        output_port = flow_mod.get('actions', [{}])[0].get('output')
        if output_port and output_port == 'CONTROLLER':
            # Packet 不能无条件发往控制器（DoS 风险）
            if self._is_unconditional_forward(flow_mod):
                raise ValueError("Unconditional control forwarding")

        # 3. 流表修改的来源验证
        if not self._validate_source(flow_mod.get('source_app')):
            raise ValueError("Unauthorized flow source")

        # 4. 硬超时检查（防止僵尸规则）
        hard_timeout = flow_mod.get('hard_timeout', 0)
        if hard_timeout == 0 or hard_timeout > 3600:
            flow_mod['hard_timeout'] = 300  # 强制 5 分钟超时

        # 5. 优先级边界检查
        priority = flow_mod.get('priority', 32768)
        if priority > 60000:
            raise ValueError("Priority too high")

        return flow_mod

    def detect_flow_table_overflow(self, switch_id, threshold=0.9):
        """检测流表溢出"""
        total_capacity = self._get_switch_capacity(switch_id)
        current_usage = self._get_current_flow_count(switch_id)

        if current_usage / total_capacity > threshold:
            # 触发流聚合
            self._compact_flows(switch_id)

            # 拒绝新安装
            return {
                'action': 'BLOCK_NEW_FLOWS',
                'usage': current_usage,
                'capacity': total_capacity,
                'threshold_exceeded': True
            }

        return {'action': 'ALLOW', 'threshold_exceeded': False}

    def _is_catch_all(self, flow):
        """检测是否为全匹配规则"""
        match = flow.get('match', {})
        return all(v == '*' or v is None for v in match.values())
```

---

## 3. SDN 安全监控

### 3.1 拓扑投毒检测

```python
class TopologyGuard:
    """SDN 拓扑投毒检测"""

    def __init__(self, controller):
        self.controller = controller
        self.topology_history = []

    def check_topology_change(self, new_topo):
        """
        检测拓扑投毒攻击
        攻击者伪造 LLDP 包创建虚假链路
        """

        # 1. 物理约束验证
        for link in new_topo.get('links', []):
            src_port = link['src_port']
            dst_port = link['dst_port']

            # 验证: 交换机每个端口最多连接一个邻居
            if self._port_already_used(src_port):
                raise SecurityAlert(
                    f"Duplicate link on {src_port}: possible topology poisoning"
                )

            # 验证: 链接的两个方向必须一致
            if not self._bidirectional_consistency(link):
                raise SecurityAlert(
                    f"Unidirectional link: {link}"
                )

        # 2. 物理速率验证 (端口速率不应在短时间内变化)
        if len(self.topology_history) > 0:
            old_topo = self.topology_history[-1]
            if self._sudden_topo_change(old_topo, new_topo):
                raise SecurityAlert("Sudden topology change detected")

        self.topology_history.append(new_topo)

        # 保留最近 100 个快照
        if len(self.topology_history) > 100:
            self.topology_history.pop(0)

    def _sudden_topo_change(self, old, new, threshold=0.3):
        """检测拓扑突变"""
        old_links = len(old.get('links', []))
        new_links = len(new.get('links', []))

        if old_links == 0:
            return False

        change_ratio = abs(new_links - old_links) / old_links
        return change_ratio > threshold

class SecurityAlert(Exception):
    pass
```

### 3.2 流规则一致性

```python
class FlowConsistencyChecker:
    """流规则一致性检查"""

    def verify_consistency(self, switch_id):
        """
        定期检查流表一致性:
        1. 控制器视图 vs 交换机实际流表
        2. 检测被恶意注入的规则
        """

        # 控制器期望的流表
        expected = self.controller.get_expected_flows(switch_id)
        # 交换机实际的流表
        actual = self.controller.query_switch_flows(switch_id)

        # 差异分析
        rogue_rules = []
        for flow in actual:
            if flow not in expected:
                rogue_rules.append(flow)

        if rogue_rules:
            # 告警 + 自动删除
            for flow in rogue_rules:
                self.controller.delete_flow(switch_id, flow['id'])
                logging.warning(
                    f"Rogue flow removed: {flow['id']} on {switch_id}"
                )

            return {
                'alert': True,
                'rogue_rules_removed': len(rogue_rules)
            }

        return {'alert': False}
```

---

## 参考资源

- [ONOS Security Guide](https://wiki.onosproject.org/display/ONOS/Security)
- [SDN Security Attack Vectors](https://www.sdxcentral.com/articles/analysis/sdn-security-attack-vectors/)
- [OpenFlow Switch Specification](https://opennetworking.org/software-defined-standards/specifications/)

---

*上一篇：[零信任网络架构](02-zero-trust-network.md)*

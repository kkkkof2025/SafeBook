# 5G 网络切片安全

## 概述

网络切片 (Network Slicing) 是 5G 的核心创新——在一张物理网络上创建多个逻辑隔离的虚拟网络，每个切片服务于不同的业务场景（eMBB 增强移动宽带、uRLLC 超低延迟、mMTC 大规模物联网）。切片间的隔离是安全设计的基石。

---

## 1. 网络切片架构安全

### 1.1 切片安全域

```
┌─────────────────────────────────────────┐
│              5G 核心网                   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │Slice A  │ │Slice B  │ │Slice C  │   │
│  │自动驾驶  │ │工业控制  │ │视频流   │   │
│  │uRLLC    │ │uRLLC    │ │eMBB     │   │
│  ├─────────┤ ├─────────┤ ├─────────┤   │
│  │S-NSSAI  │ │S-NSSAI  │ │S-NSSAI  │   │
│  │= 1-00001│ │= 1-00002│ │= 1-00003│   │
│  └─────────┘ └─────────┘ └─────────┘   │
│       ↓           ↓           ↓        │
│  ┌──────────────────────────────────┐   │
│  │       安全隔离层 (NSSMF)          │   │
│  │  - 资源隔离 (计算/存储/网络)       │   │
│  │  - 安全策略隔离                   │   │
│  │  - 密钥隔离                      │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

### 1.2 S-NSSAI 切片标识

```json
{
  "SliceServiceType": {
    "SST": 1,  // eMBB 增强移动宽带
    "description": "高速率、大带宽"
  },
  "SliceDifferentiator": {
    "SD": "000001",  // 可选，区分同 SST 的不同切片
    "description": "运营商A的eMBB切片"
  },
  "SecurityPolicy": {
    "authentication": "5G-AKA",
    "encryption": "NEA2 (AES-128-CTR)",
    "integrity": "NIA2 (AES-128-CMAC)",
    "slice_specific_key": "K_slice_A",
    "isolation_level": "HARD"
  }
}
```

---

## 2. 切片间的隔离攻击

### 2.1 跨切片攻击场景

```python
# 攻击场景 1: 切片间侧信道攻击
class SliceSideChannel:
    """通过资源竞争跨切片窃取信息"""

    def monitor_co_resident_ue(self, target_slice_id):
        """
        攻击者在自己切片中监控:
        - CPU 缓存命中率
        - 内存访问延迟
        - 网络时延变化
        推断同物理节点上其他切片的操作
        """

        latency_samples = []

        for _ in range(10000):
            # 测量内存访问延迟
            start = time.perf_counter_ns()
            _ = self.probe_memory()
            elapsed = time.perf_counter_ns() - start
            latency_samples.append(elapsed)

        # 分析延迟模式推断其他切片活动
        if self._detect_periodic_pattern(latency_samples):
            return {
                'vulnerability': 'CO_RESIDENT_SIDE_CHANNEL',
                'target_slice': target_slice_id,
                'leaked_info': 'Timing patterns suggest high-frequency transactions'
            }

# 攻击场景 2: 切片间 DoS
class SliceDoS:
    """通过资源耗尽攻击其他切片"""

    def exhaust_nf_resources(self, target_nf_id):
        """
        攻击者利用自己切片中的合法流量
        耗尽共享的 NF（网络功能）资源
        """
        for _ in range(100000):
            # 发送大量合法但耗资源的请求
            self.send_nf_request(target_nf_id, complex_query=True)
```

### 2.2 切片安全策略实施

```yaml
# 3GPP TS 33.501 基于切片的安全配置
slice_security_profile:
  slice_1_autonomous_driving:
    isolation: "HARD"  # 物理隔离
    authentication: "5G_AKA + SUPI protection"
    encryption:
      user_plane: "NEA2/128-NEA2"
      control_plane: "NEA2/128-NEA2"
    key_management:
      slice_key_derivation: true  # 切片特有密钥推导
      key_refresh_interval: "1h"
    monitoring:
      slice_specific_audit: true
      cross_slice_anomaly_detection: true

  slice_2_public_internet:
    isolation: "SOFT"  # 逻辑隔离
    authentication: "EAP-AKA'"
    encryption:
      user_plane: "NEA0 (NULL)"  # 可选加密
    monitoring:
      basic_audit: true
```

---

## 3. NSSF 安全分析

### 3.1 NSSF 攻击面

```bash
# NSSF (Network Slice Selection Function) - 切片选择核心

# 攻击面1: 未授权的切片选择
curl -X POST "https://nssf.5gcore/v1/network-slice-selection" \
  -H "Content-Type: application/json" \
  -d '{
    "nfType": "AMF",
    "nfId": "compromised-amf-id",
    "sliceInfoRequestForRegistration": {
      "sNssai": {
        "sst": 2,      # 尝试访问 uRLLC 切片
        "sd": "000002"  # 未授权的工业控制切片
      }
    }
  }'

# 攻击面2: NSSF 配置泄露
# 如果 NSSF 响应包含过多信息
{
  "authorizedNssaiAvailabilityData": [
    {
      "tai": "460-01-000001",
      "supportedSnssaiList": [
        {"sst": 1, "sd": "000001"},
        {"sst": 2, "sd": "000002"},  # 暴露了不应知的切片
        {"sst": 3, "sd": "000003"}
      ]
    }
  ]
}
```

### 3.2 NSSF 安全加固

```python
# NSSF 切片选择安全验证
class NSSFSecurityValidator:
    """NSSF 请求安全验证"""

    def __init__(self):
        self.authorized_slices = self._load_slice_policy()

    def validate_slice_request(self, request):
        """验证切片选择请求"""
        subscriber = SubscriberDB.lookup(request['supi'])
        requested_slice = request['sNssai']

        # 1. 检查订阅切片授权
        if not self._is_slice_authorized(subscriber, requested_slice):
            return {
                'authorized': False,
                'reason': 'Unauthorized slice access',
                'log': f"Subscriber {subscriber.id} attempted unauthorized slice {requested_slice}"
            }

        # 2. 检查切片容量
        if not self._has_slice_capacity(requested_slice):
            return {
                'authorized': False,
                'reason': 'Slice capacity exhausted',
                'alternative': self._suggest_alternative_slice(subscriber)
            }

        # 3. 检查安全合规
        if not self._meets_security_requirements(subscriber, requested_slice):
            return {
                'authorized': False,
                'reason': 'Security requirements not met',
                'action_required': 'Enable SUCI before accessing this slice'
            }

        return {
            'authorized': True,
            'selected_slice': requested_slice,
            'security_context': self._build_security_context(subscriber, requested_slice)
        }
```

---

## 4. 切片生命周期安全

### 4.1 切片创建安全模板

```yaml
# 网络切片实例安全模板
slice_template:
  id: "slice-autonomous-001"
  type: "uRLLC"

  # 创建阶段
  creation:
    nssmf_certificate: "required"     # NSSMF 证书验证
    audit_trail_enabled: true
    resource_isolation: "HARD"

  # 运行阶段
  operation:
    slice_monitoring_interval: "5min"
    security_scan_frequency: "daily"
    anomaly_thresholds:
      cross_slice_traffic: 0          # 禁止跨切片流量
      cpu_contention: ">80% for 1min"
      unauthorized_nf_attach: "immediate_block"

  # 修改阶段
  modification:
    approval_required: "dual_signoff"
    rollback_automated: true
    change_window: "02:00-04:00 UTC"

  # 终止阶段
  termination:
    data_wipe: "NIST 800-88"
    key_destruction: "crypto_shred"
    audit_archive: "7 years"
```

### 4.2 切片间防火墙策略

```python
# 切片间流量策略引擎
class InterSliceFirewall:
    def __init__(self):
        self.rules = self._load_inter_slice_rules()

    def _load_inter_slice_rules(self):
        """默认：禁止所有切片间通信"""
        return {
            'default': 'DENY_ALL',
            'exceptions': {
                ('slice-mgmt', 'slice-*'): 'ALLOW',  # 管理切片可访问所有
                ('slice-iot-1', 'slice-data-lake'): 'ALLOW',  # IoT 数据上送
                ('slice-*', 'slice-security'): 'ALLOW',  # 所有切片可上报安全事件
            }
        }

    def check_cross_slice_traffic(self, src_slice, dst_slice, protocol, port):
        """检查跨切片流量是否允许"""
        key = (src_slice, dst_slice)
        wildcard_key = ('slice-*', dst_slice)

        # 先检查精确匹配
        if key in self.rules['exceptions']:
            return self.rules['exceptions'][key] == 'ALLOW'

        # 再检查通配符匹配
        if wildcard_key in self.rules['exceptions']:
            return self.rules['exceptions'][wildcard_key] == 'ALLOW'

        return False  # 默认拒绝

    def log_cross_slice_violation(self, src, dst):
        """记录跨切片违规"""
        alert = {
            'severity': 'CRITICAL',
            'type': 'Cross-Slice Traffic Violation',
            'source_slice': src['s_nssai'],
            'dest_slice': dst['s_nssai'],
            'timestamp': datetime.now().isoformat(),
            'action': 'BLOCKED'
        }
        send_siem_alert(alert)
```

---

## 5. 未来挑战

- **量子计算威胁**：当前切片密钥推导基于 ECC，需迁移到后量子密码学（NIST SP 800-208）
- **AI 驱动切片**：AI 决策切片创建的认证与授权
- **跨 PLMN 切片**：不同运营商切片互联的信任模型
- **B5G/6G 超密集切片**：每用户一个切片的安全挑战

---

## 参考资源

- [3GPP TS 33.501 - 5G 安全架构](https://www.3gpp.org/ftp/Specs/archive/33_series/33.501/)
- [3GPP TR 33.811 - 网络切片安全研究](https://www.3gpp.org/ftp/Specs/archive/33_series/33.811/)
- [GSMA NG.116 - 网络切片安全指南](https://www.gsma.com/)

---

*上一篇：[5G 核心网安全](./03-5g-core-security.md)*

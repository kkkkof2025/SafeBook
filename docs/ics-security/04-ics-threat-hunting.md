# 工控威胁狩猎

## 概述

工控系统（ICS/SCADA）的威胁狩猎与传统 IT 有本质区别：不能破坏生产连续性、协议极为特殊、流量模式固定。本章聚焦如何在工控环境中主动发现异常与潜伏威胁。

---

## 1. ICS 流量基线

### 1.1 建立正常流量模型

```python
import pandas as pd
from scapy.all import *
from collections import defaultdict

class ICSBaselineBuilder:
    """工控流量基线构建器"""

    def __init__(self, training_period_days=30):
        self.model = defaultdict(dict)
        self.training_days = training_period_days

    def process_packets(self, pcap_file):
        """处理 PCAP 建立基线"""
        packets = rdpcap(pcap_file)

        for pkt in packets:
            if ModbusPDU in pkt:
                self._model_modbus(pkt)
            elif S7Packet in pkt:
                self._model_s7(pkt)
            elif EtherNetIP in pkt:
                self._model_enip(pkt)

    def _model_modbus(self, pkt):
        """Modbus TCP 流量建模"""
        src = pkt[IP].src
        dst = pkt[IP].dst
        func_code = pkt[ModbusPDU].funcCode
        key = f"{src}->{dst}"

        if 'modbus' not in self.model[key]:
            self.model[key]['modbus'] = {
                'function_codes': defaultdict(int),
                'byte_count': [],
                'timestamps': []
            }

        self.model[key]['modbus']['function_codes'][func_code] += 1

    def detect_anomaly(self, pkt):
        """检测偏离基线的异常流量"""
        key = f"{pkt[IP].src}->{pkt[IP].dst}"
        baseline = self.model.get(key, {}).get('modbus')

        if not baseline:
            return {'anomaly': 'unknown_connection', 'severity': 'HIGH'}

        func_code = pkt[ModbusPDU].funcCode
        func_code_freq = baseline['function_codes']

        # 新功能码
        if func_code not in func_code_freq:
            return {
                'anomaly': 'new_function_code',
                'func_code': func_code,
                'severity': 'HIGH'
            }

        # 异常频率（如突然大量写入）
        if func_code in [0x05, 0x06, 0x0F, 0x10]:  # 写入操作
            recent_writes = self._count_recent_writes()
            if recent_writes > baseline.get('avg_write_rate', 0) * 3:
                return {
                    'anomaly': 'write_storm',
                    'count': recent_writes,
                    'severity': 'CRITICAL'
                }

        return {'anomaly': None}
```

### 1.2 ICS 协议特征指纹

| 协议 | 默认端口 | 正常功能码 | 异常信号 |
|------|----------|-----------|----------|
| Modbus TCP | 502 | 03读, 04读, 06写 | 08诊断, 2B封装, 异常频率写入 |
| S7comm | 102 | 读/写, 块操作 | STOP CPU (0x29), 固件更新 |
| EtherNet/IP | 44818 | Class1/3连接 | 枚举服务, 未注册连接 |
| DNP3 | 20000 | 读, 写, 选择-操作 | 未确认操作, 重启命令 |
| OPC UA | 4840 | 浏览, 读, 写, 订阅 | 添加监控项, 调用方法 |
| BACnet | 47808 | 读/写属性 | 设备重启, 文件传输 |

---

## 2. 工控异常检测规则

### 2.1 Zeek (Bro) 工控检测脚本

```zeek
# ics-detect.zeek - 工控异常检测

module ICS;

export {
    redef enum Notice::Type += {
        ICS_Write_Storm,
        ICS_New_Function_Code,
        ICS_Stop_CPU_Command,
        ICS_Firmware_Update,
        ICS_Unauthorized_Connection,
        ICS_Abnormal_Payload_Size
    };

    # 已知设备白名单
    const known_devices: set[addr] = {
        192.168.1.10,  # PLC-01
        192.168.1.11,  # PLC-02
        192.168.1.20,  # HMI-01
        192.168.1.100, # Engineering Station
    };

    # Modbus 写入功能码
    const modbus_write_codes: set[count] = {
        0x05, 0x06, 0x0F, 0x10
    };
}

event modbus_message(c: connection, headers: ModbusHeaders, msg: ModbusMessage)
{
    # 检测未授权设备
    if (c$id$orig_h !in known_devices)
    {
        NOTICE([$note=ICS_Unauthorized_Connection,
                $conn=c,
                $msg=fmt("未授权设备 %s 尝试 Modbus 通信", c$id$orig_h)]);
        return;
    }

    # 检测 CPU STOP 命令
    if (headers$function_code == 0x08 && msg$sub_function == 0x01)
    {
        NOTICE([$note=ICS_Stop_CPU_Command,
                $conn=c,
                $msg=fmt("检测到 STOP CPU 命令: %s -> %s", c$id$orig_h, c$id$resp_h)]);
    }
}

event s7comm_write_var(c: connection, request: S7WriteVarRequest)
{
    # 检测大量写入操作
    local write_count = count_s7_writes(c$id$orig_h);
    if (write_count > 1000)
    {
        NOTICE([$note=ICS_Write_Storm,
                $conn=c,
                $msg=fmt("S7 写入风暴: %d 次/分钟", write_count)]);
    }
}
```

### 2.2 基于机器学习的异常检测

```python
from sklearn.ensemble import IsolationForest
import numpy as np

class ICSAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,  # 预期 10% 异常
            random_state=42
        )
        self.feature_columns = [
            'packet_size', 'inter_arrival_time',
            'function_code', 'data_length',
            'src_port', 'dst_port'
        ]

    def extract_features(self, packets):
        """从网络流提取特征"""
        features = []
        for pkt in packets:
            feat = {
                'packet_size': len(pkt),
                'inter_arrival_time': self._get_iat(pkt),
                'function_code': self._get_func_code(pkt),
                'data_length': self._get_data_len(pkt),
                'src_port': pkt.sport if hasattr(pkt, 'sport') else 0,
                'dst_port': pkt.dport if hasattr(pkt, 'dport') else 0
            }
            features.append(feat)
        return pd.DataFrame(features)

    def train(self, normal_traffic_pcap):
        """使用正常流量训练"""
        packets = rdpcap(normal_traffic_pcap)
        features = self.extract_features(packets)
        self.model.fit(features)
        print(f"训练完成，样本数: {len(features)}")

    def detect(self, live_packet):
        """实时检测"""
        features = self.extract_features([live_packet])
        prediction = self.model.predict(features)
        # -1 = 异常, 1 = 正常
        return prediction[0] == -1
```

---

## 3. 工控蜜罐

### 3.1 Conpot 部署

```bash
# 安装 Conpot 工控蜜罐
pip install conpot

# 基本配置
cat > conpot.cfg << EOF
[modbus]
enabled = True
host = 0.0.0.0
port = 502

[s7comm]
enabled = True
host = 0.0.0.0
port = 102

[snmp]
enabled = True
host = 0.0.0.0
port = 161

[ipmi]
enabled = True
host = 0.0.0.0
port = 623

[bacnet]
enabled = True
host = 0.0.0.0
port = 47808

[http]
enabled = True
host = 0.0.0.0
port = 80
EOF

# 启动
conpot -f --template default -c conpot.cfg
```

### 3.2 蜜罐数据分析

```python
import json
from datetime import datetime

class ICSHoneypotAnalyzer:
    def __init__(self, log_file):
        self.logs = self._parse_logs(log_file)

    def _parse_logs(self, log_file):
        events = []
        with open(log_file) as f:
            for line in f:
                if 'event' in line:
                    events.append(json.loads(line))
        return events

    def analyze_attacks(self):
        attacks = {
            'modbus_scan': 0,
            's7_exploit': 0,
            'web_crawl': 0,
            'custom_payload': 0
        }

        for event in self.logs:
            if event.get('protocol') == 'modbus':
                if event.get('function_code') == 0x2B:
                    attacks['modbus_scan'] += 1
            elif event.get('protocol') == 's7comm':
                if event.get('cpu_command') == 'STOP':
                    attacks['s7_exploit'] += 1
            elif event.get('protocol') == 'http':
                if '/cgi-bin/' in event.get('path', ''):
                    attacks['web_crawl'] += 1
            elif event.get('payload_size', 0) > 1000:
                attacks['custom_payload'] += 1

        return attacks

    def geo_analysis(self):
        """攻击来源地理分析"""
        origins = {}
        for event in self.logs:
            ip = event.get('src_ip')
            geo = self._get_geo(ip)
            origins[geo['country']] = origins.get(geo['country'], 0) + 1
        return origins
```

---

## 4. 工控事件响应

### 4.1 ICS-Specific IR 原则

```yaml
工控事件响应原则:
  安全优先:
    - 人身安全 > 环境安全 > 设备安全 > 数据安全
    - 任何操作前确认不会导致物理伤害

  生产连续性:
    - 先隔离，后取证（非传统 IT）
    - 禁止在生产网络运行主动扫描工具
    - 避免重启 PLC（可能丢失易失性内存证据）

  证据保全:
    - 优先收集 PLC 日志（命中率最高）
    - 网络抓包（镜像端口，非 inline）
    - 工程站取证 (EEMUA 191 指南)
```

### 4.2 快速响应检查表

```markdown
## 工控安全事件应急响应检查表

### Phase 1: 确认 (5分钟内)
- [ ] 确认是否为真实安全事件（非设备故障）
- [ ] 确定受影响范围（单台设备/产线/全厂）
- [ ] 评估对物理安全的影响
- [ ] 通知运营人员暂停受影响产线（如必要）

### Phase 2: 止损 (15分钟内)
- [ ] 隔离受影响设备（VLAN/物理断开）
- [ ] 不重启 PLC（保存易失性证据）
- [ ] 启动 SPAN/镜像端口抓包
- [ ] 通知管理层和安全团队

### Phase 3: 分析 (1小时内)
- [ ] 分析 PLC 工程文件的最后修改时间
- [ ] 检查 OPC/HMI 历史数据异常
- [ ] 审查防火墙和 VPN 日志
- [ ] 确认是否为 APT/内部威胁/脚本小子

### Phase 4: 恢复
- [ ] 从已知良好的工程文件重新加载 PLC
- [ ] 对比 I/O 配置基线
- [ ] 逐步恢复网络连接
- [ ] 持续监控 72 小时
```

---

## 参考资源

- [ICS-CERT (CISA) 威胁狩猎指南](https://www.cisa.gov/ics)
- [MITRE ATT&CK for ICS](https://collaborate.mitre.org/attackics/)
- [SANS ICS515: ICS Active Defense and Incident Response](https://www.sans.org/cyber-security-courses/ics-active-defense-incident-response/)

---

*上一篇：[工控协议深度解析](./03-ics-protocols-deep-dive.md)*

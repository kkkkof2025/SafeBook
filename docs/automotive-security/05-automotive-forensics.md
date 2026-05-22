# 车载系统数字取证

## 概述

联网汽车是"车轮上的数据中心"——每辆车包含超过 100 个 ECU (电子控制单元)，每天产生 TB 级数据。当发生安全事故或交通事故时，车载电子数据是关键的法庭证据。

---

## 1. 车载数据源

### 1.1 关键证据模块

| 模块 | 数据 | 取证价值 |
|------|------|----------|
| **EDR (Event Data Recorder)** | 碰撞前 5 秒数据 | 事故重建 |
| **TCU (Telematics Control Unit)** | GPS、远程操作日志 | 轨迹追踪 |
| **IVI (In-Vehicle Infotainment)** | 通话、消息、导航 | 行为时间线 |
| **Gateway** | CAN 总线流量日志 | 网络级攻击证据 |
| **ADAS (高级驾驶辅助)** | 传感器数据、决策日志 | 事故原因 |
| **T-Box** | 蜂窝通信记录 | C2 通信溯源 |

### 1.2 Bosch CDR (碰撞数据记录器)

```bash
# Bosch CDR 读取工具
# 通过 OBD-II 接口读取 EDR 数据

# 可提取数据:
# - 速度 (碰撞前 -5.0 到 0s, 0.5s 间隔)
# - 刹车状态
# - 油门开度
# - 转向角度
# - 安全带状态
# - 气囊展开时间
# - Delta-V (速度变化)

# CDR 报告示例
{
  "event": "CRASH_DETECTED",
  "timestamp": "2024-01-15T14:32:05.123Z",
  "vehicle_speed": {
    "-5.0s": 120,  # km/h
    "-4.5s": 118,
    "-4.0s": 110,
    "-3.5s": 95,
    "-3.0s": 75,
    "-2.5s": 50,
    "-2.0s": 30,
    "-1.5s": 15,
    "-1.0s": 5,
    "-0.5s": 0
  },
  "brake_engaged": "-3.0s",
  "airbag_deployed": true,
  "max_delta_v": 45.2  # km/h
}
```

---

## 2. CAN 总线取证

### 2.1 CAN 流量捕获

```python
import can
import struct
from datetime import datetime, timedelta

class CANForensicCapture:
    """CAN 总线取证数据捕获"""

    def __init__(self, interface='can0'):
        self.bus = can.interface.Bus(
            channel=interface,
            bustype='socketcan'
        )
        self.packets = []

    def capture_traffic(self, duration_seconds=300):
        """捕获指定时长的 CAN 流量"""
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=duration_seconds)

        while datetime.now() < end_time:
            message = self.bus.recv(timeout=1.0)
            if message:
                self.packets.append({
                    'timestamp': datetime.now().isoformat(),
                    'arbitration_id': hex(message.arbitration_id),
                    'data': message.data.hex(),
                    'dlc': message.dlc,
                    'is_extended': message.is_extended_id
                })

        return self.packets

    def detect_unusual_ids(self):
        """检测非标准 CAN ID"""
        # 已知的正常 CAN ID 范围
        known_ranges = {
            'engine': range(0x100, 0x1FF),
            'transmission': range(0x200, 0x2FF),
            'body': range(0x300, 0x3FF),
            'chassis': range(0x400, 0x4FF),
            'hvac': range(0x500, 0x5FF),
        }

        unusual = []
        for pkt in self.packets:
            can_id = int(pkt['arbitration_id'], 16)

            # 检查是否在任何已知范围内
            in_known_range = False
            for component, id_range in known_ranges.items():
                if can_id in id_range:
                    in_known_range = True
                    break

            if not in_known_range and pkt['arbitration_id'] not in unusual:
                unusual.append(pkt)

        return unusual

    def detect_frame_injection(self):
        """检测帧注入攻击"""
        # 正常系统：每个 CAN ID 的发送频率是固定的
        # 攻击：可能高频率发送伪造帧

        freq_map = {}
        for pkt in self.packets:
            can_id = pkt['arbitration_id']
            if can_id not in freq_map:
                freq_map[can_id] = []
            freq_map[can_id].append(pkt['timestamp'])

        anomalies = []
        for can_id, timestamps in freq_map.items():
            if len(timestamps) < 2:
                continue

            # 计算帧间间隔
            intervals = []
            for i in range(1, len(timestamps)):
                t1 = datetime.fromisoformat(timestamps[i-1])
                t2 = datetime.fromisoformat(timestamps[i])
                intervals.append((t2 - t1).total_seconds() * 1000)  # ms

            avg_interval = sum(intervals) / len(intervals)

            # 检测异常高频率 (远低于正常间隔)
            min_interval = min(intervals)
            if min_interval < avg_interval * 0.1:  # 频率突然升高 10 倍
                anomalies.append({
                    'can_id': can_id,
                    'avg_interval_ms': avg_interval,
                    'min_interval_ms': min_interval,
                    'suspected_injection': True
                })

        return anomalies
```

### 2.2 时间线分析

```python
class CANEventTimeline:
    """CAN 事件时间线分析与可视化"""

    def __init__(self, can_logs):
        self.logs = can_logs
        self.events = []

    def build_timeline(self):
        """构建事件时间线"""

        for log in self.logs:
            can_id = log['arbitration_id']
            data = bytes.fromhex(log['data'])

            # 检测关键事件
            if can_id == '0x120':  # 刹车信号
                brake_pedal = data[0] & 0x01
                if brake_pedal:
                    self.events.append({
                        'timestamp': log['timestamp'],
                        'event': 'BRAKE_APPLIED',
                        'severity': 'INFO'
                    })

            elif can_id == '0x200':  # 速度信号
                speed = struct.unpack('>H', data[0:2])[0] * 0.01  # km/h
                self.events.append({
                    'timestamp': log['timestamp'],
                    'event': 'SPEED_UPDATE',
                    'value': speed,
                    'severity': 'INFO'
                })

            elif can_id == '0x400':  # 转向
                steering_angle = struct.unpack('>h', data[0:2])[0] * 0.1
                if abs(steering_angle) > 90:  # 急转弯
                    self.events.append({
                        'timestamp': log['timestamp'],
                        'event': 'SHARP_STEERING',
                        'angle': steering_angle,
                        'severity': 'WARNING'
                    })

        return sorted(self.events, key=lambda e: e['timestamp'])

    def find_anomalies(self):
        """查找时间线异常"""
        self.build_timeline()

        anomalies = []

        # 检测：无刹车日志但高级别减速度
        speeds = [e for e in self.events if e['event'] == 'SPEED_UPDATE']
        brakes = [e for e in self.events if e['event'] == 'BRAKE_APPLIED']

        for i in range(1, len(speeds)):
            speed_diff = speeds[i]['value'] - speeds[i-1]['value']
            time_diff = self._parse_time_diff(
                speeds[i]['timestamp'],
                speeds[i-1]['timestamp']
            )

            if time_diff > 0:
                decel = abs(speed_diff) / time_diff  # km/h/s

                if decel > 30:  # 剧烈减速
                    # 检查是否有对应刹车信号
                    has_brake = any(
                        abs(self._parse_time_diff(speeds[i]['timestamp'], b['timestamp'])) < 2
                        for b in brakes
                    )

                    if not has_brake:
                        anomalies.append({
                            'timestamp': speeds[i]['timestamp'],
                            'type': 'EMERGENCY_DECEL_NO_BRAKE',
                            'deceleration': decel,
                            'possible_cause': 'Brake-by-wire attack or EDR tampering'
                        })

        return anomalies
```

---

## 3. UDS (统一诊断服务) 取证

### 3.1 提取诊断数据

```python
import udsoncan
from udsoncan.client import Client
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.services import ReadDataByIdentifier

class UDSForensicExtractor:
    """通过 UDS 协议提取取证数据"""

    # 标准 UDS DID (Data Identifier)
    DID_MAP = {
        0xF190: "VIN (车辆识别码)",
        0xF197: "ECU 硬件版本",
        0xF198: "ECU 软件版本",
        0xF199: "ECU 序列号",
        0xF1A0: "ECU 编程日期",
        0xF19E: "故障码快照",
        0xFDC0: "安全日志",
        0xFDC1: "认证事件日志",
    }

    def __init__(self, isotp_interface):
        self.conn = PythonIsoTpConnection(isotp_interface)
        self.client = Client(
            self.conn, 
            request_timeout=2,
            config={'exception_on_negative_response': False}
        )

    def read_vin(self):
        """读取车辆识别码"""
        response = self.client.read_data_by_identifier([0xF190])
        return response.service_data.values[0xF190].hex()

    def extract_fault_codes(self):
        """提取故障码 (DTC)"""
        # 读取故障码
        response = self.client.read_dtc_information(
            udsoncan.services.ReadDTCInformation.Subfunction.reportDTCByStatusMask,
            status_mask=0xFF
        )

        dtcs = []
        if hasattr(response, 'service_data'):
            for dtc_record in response.service_data.dtc_list:
                dtcs.append({
                    'code': dtc_record.id,
                    'status': dtc_record.status.to_byte(),
                    'severity': 'CRITICAL' if dtc_record.status.test_failed else 'NORMAL'
                })

        return dtcs

    def extract_security_log(self):
        """提取安全事件日志"""
        try:
            response = self.client.read_data_by_identifier([0xFDC0])
            log_data = response.service_data.values[0xFDC0]

            events = []
            # 每 16 字节为一个事件记录
            for i in range(0, len(log_data), 16):
                record = log_data[i:i+16]
                events.append({
                    'timestamp': struct.unpack('>I', record[0:4])[0],
                    'event_type': record[4],
                    'source_ecu': record[5],
                    'data': record[6:16].hex()
                })

            return events
        except:
            return []
```

---

## 4. 取证工具链

| 工具 | 用途 | 平台 |
|------|------|------|
| **Bosch CDR Tool** | EDR 数据下载 | Windows |
| **Berla iVe** | IVI 系统取证 | Windows |
| **CANalyzer** | CAN 总线分析 | Windows |
| **Wireshark** | CAN 协议解析 | 跨平台 |
| **Autopsy** | 通用磁盘取证 | 跨平台 |
| **can-utils** | Linux CAN 工具集 | Linux |

```bash
# can-utils 取证常用命令
candump can0 -l              # 记录 CAN 流量
canplayer -I candump.log     # 回放 CAN 流量
cansniffer can0              # 实时监控 CAN 流量
cangen can0 -g 10            # 生成测试 CAN 帧
```

---

## 参考资源

- [SAE J1698 - EDR 数据规范](https://www.sae.org/standards/content/j1698/)
- [NISTIR 8058 - 车辆取证指南](https://www.nist.gov/publications/)
- [Car Hacker's Handbook](https://nostarch.com/carhacking)

---

*上一篇：[V2X 通信安全](./04-v2x-security.md)*

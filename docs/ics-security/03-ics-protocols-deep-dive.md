# 工控协议深度解析

## 工控协议概述

工业控制系统 (ICS) 使用多种专用协议进行通信。

### 主要协议

| 协议 | 用途 | 端口 | 安全风险 |
|------|------|------|----------|
| Modbus | PLC 通信 | TCP/502 | 无认证、明文 |
| DNP3 | 变电站 | TCP/20000 | 弱认证 |
| IEC 61850 | 变电站自动化 | TCP/102 | 复杂配置 |
| Profinet | 工业以太网 | UDP/34962-34964 | 实时性要求 |
| EtherNet/IP | 工业以太网 | UDP/2222 | 无加密 |
| OPC UA | 统一架构 | TCP/4840 | 配置错误 |

---

## Modbus 协议深度分析

### 协议基础

- **传输层：** TCP/502 (Modbus TCP) 或串口 (Modbus RTU)
- **功能码：** 读取/写入寄存器
- **数据模型：** Coil、Discrete Input、Input Register、Holding Register

### 安全风险

#### 风险1：无认证机制

**问题：** Modbus 协议本身无认证，任何设备均可读写

```python
# 使用 pymodbus 未授权访问
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('192.168.1.100')
client.connect()

# 读取 Holding Registers (未授权)
result = client.read_holding_registers(0, 10)
print(result.registers)

# 写入寄存器 (未授权，可能导致物理损害)
client.write_register(0, 9999)
```

#### 风险2：功能码滥用

**攻击：** 使用功能码 0x10 (Write Multiple Registers) 修改关键参数

```python
# 批量写入寄存器
client.write_registers(0, [1, 2, 3, 4, 5])
```

#### 风险3：异常数据注入

**攻击：** 发送异常数据导致 PLC 崩溃

```python
# 发送超长数据包
malicious_data = [0xFFFF] * 1000
client.write_registers(0, malicious_data)
```

### 防御措施

1. **部署 Modbus 防火墙** (如 Tofino)
2. **实施深度包检测 (DPI)**
3. **网络隔离** (DMZ + VLAN)
4. **启用 Modbus TCP Security (如果支持)**

---

## DNP3 协议安全

### 协议基础

- **应用层：** DNP3 Application Layer
- **传输层：** TCP/20000 或串口
- **功能：** 变电站自动化、SCADA 通信

### 安全机制

#### 1. 认证 (Authentication)

- **SLevel：** 预共享密钥 (Pre-Shared Key)
- **ASLevel：** 非对称加密 (证书)

#### 2. 授权 (Authorization)

- **Object Permissions：** 按对象授予权限

### 攻击向量

#### 攻击1：认证绕过

**原理：** 某些实现中，认证可被选配禁用

```python
# 使用 pydnp3 连接 (无认证)
from pydnp3 import opendnp3

manager = opendnp3.DNP3Manager()
channel = manager.AddTCPClient(...)
```

#### 攻击2：重放攻击

**原理：** 捕获认证数据包并重放

```python
# 使用 Scapy 重放 DNP3 数据包
from scapy.all import *

packets = rdpcap('dnp3_auth.pcap')
for pkt in packets:
    sendp(pkt, iface='eth0')
```

### 防御措施

1. **启用 ASLevel (证书认证)**
2. **实施序列号检查** (防止重放)
3. **加密通信** (IPsec VPN)
4. **定期更换密钥**

---

## IEC 61850 协议安全

### 协议基础

- **标准：** IEC 61850 (变电站自动化)
- **传输层：** MMS (Manufacturing Message Specification)
- **服务：** 数据集、报告、日志

### 安全风险

#### 风险1：复杂配置导致错误

**问题：** IEC 61850 配置复杂，容易引入安全漏洞

```
# SCL (Substation Configuration Language) 配置错误示例
<Communication>
  <SubNetwork type="8-MMS" name="S1">
    <ConnectedAP APName="AP1" IEDName="IED1">
      <Address>
        <P type="IP">192.168.1.100</P>  <!-- 硬编码 IP -->
      </Address>
    </ConnectedAP>
  </SubNetwork>
</Communication>
```

#### 风险2：MMS 服务暴露

**攻击：** 未授权访问 MMS 服务

```python
# 使用 pymms 连接 MMS 服务
from pymms import MMSClient

client = MMSClient('192.168.1.100', 102)
client.connect()

# 读取所有变量 (信息泄露)
variables = client.get_variable_list()
```

### 防御措施

1. **简化配置** (最小化攻击面)
2. **实施访问控制** (ACL + 防火墙)
3. **加密 MMS 通信** (TLS)
4. **定期审计配置**

---

## Profinet 协议安全

### 协议基础

- **实时性：** RT (Real-Time)、IRT (Isochronous Real-Time)
- **传输层：** UDP/34962-34964
- **用途：** 工业以太网通信

### 安全风险

#### 风险1：实时性要求导致安全让步

**问题：** 为满足实时性，某些安全机制被禁用

#### 风险2：设备发现协议 (DCP) 滥用

**攻击：** 使用 DCP 重置设备配置

```bash
# 使用 profinet-dcp-tool
dcp_tool -i eth0 -t AA:BB:CC:DD:EE:FF -r  # 重置设备
```

### 防御措施

1. **实施 VLAN 隔离**
2. **禁用未使用的 DCP 功能**
3. **监控异常流量**
4. **使用 Profinet Security Profile**

---

## OPC UA 协议安全

### 协议基础

- **架构：** 客户端-服务器
- **传输层：** TCP/4840 (二进制) 或 HTTPS/443 (JSON)
- **安全策略：** None、Basic128Rsa15、Basic256、Basic256Sha256、Aes128_Sha256

### 安全机制

#### 1. 认证 (Authentication)

- **匿名：** 无认证 (高风险)
- **用户名/密码：** 基本认证
- **证书：** X.509 证书 (推荐)

#### 2. 授权 (Authorization)

- **用户令牌：** UserIdentityToken
- **角色权限：** Role-Based Access Control

#### 3. 加密 (Encryption)

- **安全策略：** Basic256Sha256 (推荐)
- **消息签名：** Sign 或 SignAndEncrypt

### 攻击向量

#### 攻击1：匿名访问

**问题：** 默认配置允许匿名访问

```python
# 使用 opcua 连接 (匿名)
from opcua import Client

client = Client('opc.tcp://192.168.1.100:4840')
client.connect()  # 匿名连接成功

# 读取所有节点
root = client.get_root_node()
```

#### 攻击2：证书伪造

**攻击：** 自签名证书未被验证

```python
# 使用 opcua 忽略证书验证
from opcua import Client
import ssl

client = Client('opc.tcp://192.168.1.100:4840')
client.set_security_string('Basic256Sha256,SignAndEncrypt,my_cert.pem,my_key.pem')

# 忽略服务器证书验证
ssl._create_default_https_context = ssl._create_unverified_context
```

### 防御措施

1. **禁用匿名访问**
2. **强制证书认证**
3. **实施证书吊销列表 (CRL)**
4. **定期更新证书**

---

## 协议安全对比

| 协议 | 认证 | 加密 | 主要风险 | 防护难度 |
|------|------|------|----------|----------|
| Modbus | ❌ | ❌ | 无认证、明文 | 低 (加防火墙) |
| DNP3 | ✅ (可选) | ✅ (可选) | 认证绕过、重放 | 中 |
| IEC 61850 | ❌ | ❌ | 配置错误、MMS 暴露 | 高 |
| Profinet | ❌ | ❌ | DCP 滥用 | 中 |
| OPC UA | ✅ | ✅ | 匿名访问、证书伪造 | 中 |

---

## 安全加固清单

### Modbus
- [ ] 部署 Modbus 防火墙
- [ ] 实施 DPI
- [ ] 网络隔离 (DMZ)
- [ ] 启用 Modbus TCP Security

### DNP3
- [ ] 启用 ASLevel (证书认证)
- [ ] 实施序列号检查
- [ ] 加密通信 (IPsec)
- [ ] 定期更换密钥

### IEC 61850
- [ ] 简化配置
- [ ] 实施访问控制
- [ ] 加密 MMS 通信
- [ ] 定期审计配置

### Profinet
- [ ] 实施 VLAN 隔离
- [ ] 禁用未使用的 DCP 功能
- [ ] 监控异常流量

### OPC UA
- [ ] 禁用匿名访问
- [ ] 强制证书认证
- [ ] 实施 CRL
- [ ] 定期更新证书

---

## 延伸阅读

- [Modbus TCP Security](https://modbus地方)
- [DNP3 Secure Authentication](https://www.dnp.org/)
- [IEC 61850 Security](https://iec61850.com/)
- [OPC UA Security Model](https://reference.opcfoundation.org/)

---

**下一步：** 学习 响应)，掌握 ICS 应急响应流程。

*上一篇：[工控安全实战（上篇）](02-ics-security.md)*

*下一篇：[工控威胁狩猎](04-ics-threat-hunting.md)*

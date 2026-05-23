# IoT 安全全景

## 概述

IoT 设备数量预计在 2030 年突破 300 亿——但 98% 以上缺乏基本安全措施。IoT 安全的独特性在于：受限算力、长时间部署、物理可触碰性，以及最重要的是——它们控制现实世界中的物理组件。

---

## 1. IoT 威胁模型

```
IoT 攻击面（按层级）:

  L1 — 硬件层
    ├── JTAG/SWD 调试接口
    ├── UART 串口
    ├── SPI/I2C Flash 提取
    └── 侧信道 (功耗/电磁)

  L2 — 固件层
    ├── 固件提取与逆向
    ├── 加密密钥提取
    ├── 启动加载器 (Bootloader)
    └── 固件更新流程

  L3 — 网络通信层
    ├── WiFi/蓝牙/Zigbee 嗅探
    ├── MQTT/CoAP 协议攻击
    ├── API 不安全
    └── 中间人攻击

  L4 — 云端/App 层
    ├── Web 控制面板
    ├── 移动 App 逆向
    ├── 云端 API 滥用
    └── 账户劫持
```

---

## 2. 硬件接口利用

### 2.1 UART 串口识别

```bash
# UART 引脚识别（万用表法）
# 1. 找到 GND: 通断测试到电路板大面积铜箔
# 2. 找到 VCC: 通电后测量电压（通常 3.3V 或 5V）
# 3. 找到 TX: 通电后电压波动（通常是 3.3V 在发送数据时下降）
# 4. 找到 RX: 通电后电压稳定（等待接收）

# 连接 UART
screen /dev/ttyUSB0 115200
# 常见波特率: 9600, 19200, 38400, 57600, 115200

# 如果输出乱码 → 换波特率
# 如果可以输入但无输出 → TX/RX 反接
```

### 2.2 JTAG/SWD

```bash
# JTAG 引脚识别
# JTAGulator 或逻辑分析仪扫描
openocd -f /usr/share/openocd/scripts/interface/jlink.cfg -f /usr/share/openocd/scripts/target/stm32f1x.cfg

# 连接后: 读取 Flash, 断点调试, 修改寄存器
# 关键: 许多 IoT 设备未禁用 JTAG（严重安全漏洞）
```

---

## 3. 固件分析

### 3.1 固件提取

```bash
# 方法 1: SPI Flash 直接读取
# 使用 flashrom + 编程器夹子
flashrom -p ch341a_spi -r firmware.bin

# 方法 2: U-Boot 中断
# 启动时按键进入 U-Boot 控制台
# U-Boot> md 0x8000000  # 内存 dump

# 方法 3: 通过已知漏洞提取
# 例: 路由器管理页面命令注入
curl -X POST "http://192.168.1.1/cgi-bin/backup.cgi" \
  -d "action=download&file=../../../../../dev/mtdblock0"
```

### 3.2 固件解包

```bash
# binwalk 固件分析
binwalk -Me firmware.bin

# 常见输出:
# 0         0x0        uImage header
# 64        0x40       LZMA compressed data
# 1048576   0x100000   SquashFS filesystem
# 2097152   0x200002   JFFS2 filesystem

# 提取文件系统
unsquashfs -d /tmp/extracted 100000.squashfs

# 查找硬编码密钥
grep -ri "password\|secret\|api_key\|private_key" /tmp/extracted/
grep -ri "BEGIN RSA PRIVATE KEY" /tmp/extracted/

# 查找硬编码 IP/URL
grep -roE 'https?://[^"'\'' ]+' /tmp/extracted/ | sort -u
```

---

## 4. IoT 通信协议安全

### 4.1 MQTT 攻击

```bash
# MQTT (物联网最常用协议) 攻击面

# 1. 未授权订阅
mosquitto_sub -h 192.168.1.100 -t "#" -v
# "#" 是通配符 = 订阅所有主题

# 2. MQTT 暴力破解
nmap -p 1883 --script mqtt-subscribe <target>

# 3. MQTT 消息注入
mosquitto_pub -h 192.168.1.100 -t "smarthome/lock/front" -m '{"cmd":"unlock"}'

# 安全配置:
# - 启用 TLS (MQTT over TLS, port 8883)
# - 启用认证 (用户名+密码 或 客户端证书)
# - ACL 控制（每个客户端只能发布/订阅特定主题）
```

### 4.2 Zigbee 嗅探

```bash
# Zigbee 安全分析
# 硬件: CC2531 USB Dongle + zigbee2mqtt 固件

# 信道扫描
python3 zigpy_znp/tools/network_scan.py

# Zigbee 安全级别:
# Level 0: 无安全 → 可随意注入/重放
# Level 5: AES-128-CCM* + 网络密钥 → 理论上安全
# 常见问题: 默认/硬编码网络密钥
```

---

## 5. IoT 安全框架

```yaml
OWASP IoT Top 10 (2018):

  1. 弱/硬编码密码
  2. 不安全的网络服务
  3. 不安全的生态系统接口
  4. 缺乏安全更新机制
  5. 使用不安全的废弃组件
  6. 隐私保护不足
  7. 不安全的数据传输和存储
  8. 缺乏设备管理
  9. 不安全的默认设置
  10. 缺乏物理加固

物联网安全标准:
  - ETSI EN 303 645 (欧洲)
  - NIST IR 8259 (美国)
  - GB/T 36951-2018 (中国)
```

---

*上一篇：[车联网安全概述](../automotive-security/01-automotive-security.md)*

*下一篇：[IoT 固件分析与漏洞挖掘](02-iot-firmware.md)*

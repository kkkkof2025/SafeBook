# IoT 安全测试实战

## 概述

IoT 设备的攻击面跨越物理世界和数字世界——从硬件接口到云端 API，从固件到移动 App。本章提供系统化的 IoT 渗透测试方法论和工具链。

---

## 1. IoT 测试方法论

### 1.1 OWASP IoT Top 10 测试矩阵

```yaml
IoT 安全测试流程:

  Phase 1 — 侦察:
    - 设备拆解: 识别芯片、接口
    - 固件获取: SPI Flash/UART/OTA 抓包
    - 网络扫描: Nmap, discovery protocols
    - App 逆向: APK/IPA 分析

  Phase 2 — 固件分析:
    - 文件系统提取: binwalk, firmware-mod-kit
    - 硬编码凭证搜索: 密码/API Key/证书
    - 启动过程分析: Bootloader 安全性
    - 后门检测: 隐藏 Shell/SSH/Telnet

  Phase 3 — 通信安全:
    - 网络协议: MQTT/CoAP/Zigbee/BLE
    - TLS 检查: 证书验证, 中间人测试
    - RF 分析: SDR 信号捕获 (433MHz/Zigbee)

  Phase 4 — 接口测试:
    - UART: 获取 Shell
    - JTAG: 内存读写
    - SPI/I2C: 嗅探传感器数据
    - USB/OTG: HID 模拟, 调试

  Phase 5 — 云/App:
    - API 渗透测试
    - MQTT 主题授权
    - 会话管理
```

### 1.2 IoT 测试工具链

```bash
# IoT 测试工作站搭建 (Ubuntu)

# 1. 固件分析
sudo apt install binwalk jefferson firmware-mod-kit
pip install iaito  # Ghidra 开源替代

# 2. 硬件接口
sudo apt install minicom screen flashrom
pip install pyserial esptool

# 3. 网络分析
sudo apt install wireshark tcpdump bettercap mqtt-explorer

# 4. SDR
sudo apt install gnuradio gqrx-sdr rtl-sdr hackrf

# 5. Zigbee/BLE
sudo apt install bluez wpan-tools
pip install killerbee zigpy

# 下载常用工具
git clone https://github.com/devttys0/binwalk.git
git clone https://github.com/ReFirmLabs/binwalk.git
```

---

## 2. 网络协议安全测试

### 2.1 MQTT 测试

```python
import paho.mqtt.client as mqtt
import ssl
import time

class MQTTSecurityTester:
    """MQTT 协议安全测试"""

    def __init__(self, broker_host, port=1883):
        self.broker = broker_host
        self.port = port

    def test_anonymous_access(self):
        """测试匿名访问"""
        client = mqtt.Client()
        try:
            client.connect(self.broker, self.port, 5)
            # 尝试订阅所有主题
            client.subscribe('#')
            print("[CRITICAL] 匿名 MQTT 访问允许 — 可监听所有消息")
            return True
        except:
            print("[OK] 匿名访问已禁用")
            return False

    def test_topic_authorization(self):
        """测试主题授权"""

        # 尝试写入到不应授权的主题
        malicious_topics = [
            ('device/+/cmd', 'reboot'),       # 命令注入
            ('device/+/firmware/update', ''),  # 固件更新
            ('controller/shutdown', ''),       # 关闭控制器
        ]

        for topic, payload in malicious_topics:
            client = mqtt.Client()
            client.username_pw_set('guest', 'guest')
            client.connect(self.broker, self.port)

            result = client.publish(topic, payload)
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                print(f"[WARNING] 未授权主题可写入: {topic}")
            else:
                print(f"[OK] 主题写入受限: {topic}")

    def test_tls_config(self):
        """测试 TLS 配置"""
        client = mqtt.Client()
        client.tls_set(cert_reqs=ssl.CERT_NONE)  # 不验证证书

        try:
            client.connect(self.broker, 8883)
            print("[WARNING] MQTT over TLS 接受不验证证书的连接")
            print("          → 可被中间人攻击")
        except:
            pass

        # 检查证书
        try:
            client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
            client.connect(self.broker, 8883)
            cert = client.socket.getpeercert()
            print(f"[INFO] TLS 证书: {cert['subject']}")
            print(f"[INFO] 有效期: {cert['notAfter']}")
        except Exception as e:
            print(f"[WARNING] TLS 连接失败: {e}")

    def scan_sensitive_topics(self):
        """扫描敏感主题"""
        sensitive_patterns = [
            'password', 'token', 'key', 'secret',
            'admin', 'root', 'config', 'update', 'firmware',
            'cmd', 'command', 'exec', 'system',
            'health', 'sensor', 'camera',
        ]

        # 暴力扫描
        for pattern in sensitive_patterns:
            client = mqtt.Client()
            client.connect(self.broker, self.port)
            client.subscribe(f"+/+/+/+/{pattern}/#")
```

### 2.2 CoAP 测试

```python
import coapthon.client.helperclient as coap

class CoAPSecurityTester:
    """CoAP 协议安全测试"""

    def discover_resources(self, host, port=5683):
        """发现 CoAP 资源 (/.well-known/core)"""
        client = coap.HelperClient(server=(host, port))

        # GET /.well-known/core
        response = client.get('.well-known/core')
        print("发现 CoAP 资源:")
        for line in response.payload.decode().split(','):
            print(f"  {line.strip()}")

        return response.payload

    def test_coap_amplification(self, host, port=5683):
        """
        CoAP 放大攻击测试

        小请求 → 大响应
        放大系数: 可达 10-50x
        """
        client = coap.HelperClient(server=(host, port))

        # 发送小请求
        response = client.get('time', timeout=2)

        if response:
            request_size = 64  # 平均 CoAP GET 大小
            response_size = len(response.payload)

            amplification = response_size / request_size
            print(f"CoAP 放大系数: {amplification:.1f}x")
            if amplification > 10:
                print(f"[WARNING] CoAP 端点可用作 DDoS 放大器!")
```

---

## 3. BLE 安全测试

### 3.1 BLE 扫描与交互

```bash
# BLE 安全测试

# 1. 扫描 BLE 设备
sudo hcitool lescan
# LE Scan ...
# D4:3A:2C:XX:XX:XX Smart Lock Pro
# A1:B2:C3:XX:XX:XX IoT Sensor V2

# 2. 获取设备信息服务
sudo gatttool -b D4:3A:2C:XX:XX:XX --primary
# attr handle: 0x0001, end grp handle: 0x0005 uuid: 00001800-...
# attr handle: 0x0014, end grp handle: 0x001c uuid: 0000180a-...

# 3. 读取特征值
sudo gatttool -b D4:3A:2C:XX:XX:XX --char-read --uuid=2a00
# handle: 0x0003 value: 53 6d 61 72 74 20 4c 6f 63 6b
# → "Smart Lock"

# 4. 写入特征值 (解锁?)
sudo gatttool -b D4:3A:2C:XX:XX:XX --char-write-req \
    -a 0x0025 -n 0100
# 发送 0x0100 (解锁命令?)
# 测试: 不配对就向特征值写入
```

### 3.2 BLE 中间人攻击

```python
# BLE 中间人攻击概念

class BLEMITM:
    """
    BLE MITM 攻击

    前提: 需要设备在配对过程中 (Just Works/Legacy Pairing)

    步骤:
    1. 嗅探配对过程 → 获取 TK/PIN
    2. 破解 LTK (Long Term Key)
    3. 使用 LTK 解密后续通信
    """

    def exploit_just_works_pairing(self):
        """
        Just Works: TK = 000000 (6 个 0)
        → 任何嗅探器都可以计算相同的 LTK
        → 解密所有通信
        """
        tk = b'\x00\x00\x00\x00\x00\x00'

        # 嗅探配对数据
        peering_data = self.sniff_pairing()

        # 使用 TK 计算 LTK
        ltk = self.calculate_ltk(peering_data, tk)

        # 解密后续通信
        decrypted = self.decrypt_traffic(peering_data['encrypted'], ltk)
        return decrypted
```

---

## 4. IoT 固件后门分析

### 4.1 常见后门模式

```bash
# 搜索固件中的后门特征

# 1. Telnet 后门
grep -r "telnetd" extracted_firmware/
grep -r "/bin/sh" extracted_firmware/etc/inetd.conf

# 2. 硬编码密码
grep -r "password" --include="*.conf" --include="*.ini" --include="*.cfg"
grep -r "P@ssw0rd\|admin123\|root123" extracted_firmware/

# 3. 隐藏 SSH 密钥
find extracted_firmware/ -name "*.pem" -o -name "authorized_keys"

# 4. 后门端口
strings extracted_firmware/bin/* | grep -E "^(bind|listen).*:?[0-9]{2,5}"

# 5. 调试模式
grep -r "debug=1\|DEBUG=1\|enable_debug=1" extracted_firmware/

# 6. 远程命令执行
grep -r "system(\|popen(\|exec(" extracted_firmware/
```

### 4.2 固件仿真

```bash
# Firmware Analysis Toolkit (FAT) — 完整 IoT 设备仿真

# 1. 安装
git clone https://github.com/attify/firmware-analysis-toolkit.git
cd firmware-analysis-toolkit
./setup.sh

# 2. 提取固件
./fat.py /path/to/router_firmware.bin

# 3. FAT 自动:
#    - 提取文件系统
#    - 识别架构 (ARM/MIPS/x86)
#    - 创建 QEMU 仿真环境
#    - 启动固件模拟运行

# 4. 访问仿真的路由器
curl http://192.168.1.1        # 网页管理
nc -nv 192.168.1.1 23         # Telnet
nc -nv 192.168.1.1 22         # SSH
nmap -sV 192.168.1.1          # 扫描开放端口

# 5. 在仿真环境中测试漏洞
# (不影响真实设备)
```

---

## 参考资源

- [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/)
- [IoT Hacker's Handbook](https://nostarch.com/iot-hacking)
- [FCCID.io - IoT 设备资料](https://fccid.io/)
- [Shodan IoT 搜索](https://www.shodan.io/search?query=iot)

---

*上一篇：[IoT 云端安全](./04-iot-cloud-security.md)*

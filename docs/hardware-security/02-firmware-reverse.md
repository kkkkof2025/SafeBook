# 固件逆向分析

## 概述

固件逆向是 IoT 安全的核心技能——嵌入式设备的固件中隐藏着硬编码密码、调试后门、未修复的 N-day 漏洞。从路由器到智能门锁，掌握了固件分析就掌握了设备的控制权。

---

## 1. 固件获取方法

### 1.1 获取途径

| 方法 | 难度 | 成功率 | 风险 |
|------|------|--------|------|
| 官网下载 | ⭐ | 高 | 无 |
| OTA 抓包 | ⭐⭐ | 中 | 低 |
| SPI Flash 读 | ⭐⭐⭐ | 高 | 中 |
| UART 中断启动 | ⭐⭐⭐ | 高 | 低 |
| JTAG 读 Flash | ⭐⭐⭐⭐ | 高 | 中 |
| eMMC/NAND 拆焊 | ⭐⭐⭐⭐⭐ | 高 | 高 (可能损坏) |

### 1.2 OTA 固件更新抓包

```bash
# 通过中间人抓取 OTA 固件更新

# 1. ARP 欺骗 + 流量转发
echo 1 > /proc/sys/net/ipv4/ip_forward
bettercap -eval "net.probe on; net.sniff on; arp.spoof on"

# 2. 检测固件下载 (抓取大数据传输)
# 过滤 HTTP 请求 (OTA 通常走 HTTP/HTTPS)
tcpdump -i eth0 -A -s 0 \
    'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)'

# 3. 拦截 HTTPS OTA (需要代理证书)
# 设置 Burp Suite 透明代理
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
# Burp 中查看下载的固件文件

# 4. 从抓包中提取固件
# 找到最大的 POST/PUT 请求体 (通常 >1MB)
# Content-Type: application/octet-stream
tshark -r ota_capture.pcap -Y "http.request" -T fields \
    -e http.request.uri -e http.content_length | sort -t$'\t' -k2 -n

# 5. 下载后验证
curl -v https://firmware-update.vendor.com/v2.3.4.bin -o firmware.bin
file firmware.bin
# firmware.bin: uImage header, ...
md5sum firmware.bin
# 对比厂商公布的哈希
```

---

## 2. 固件解包与分析

### 2.1 多层解包

```bash
# IoT 固件解包流水线

# Step 1: 识别固件格式
file firmware.bin
# firmware.bin: u-boot legacy uImage, Linux kernel ARM

binwalk firmware.bin
# 0         0x0       uImage header
# 65536     0x10000   LZMA compressed data
# 1638400   0x190000  Squashfs filesystem
# 8388608   0x800000  JFFS2 filesystem
# 12582912  0xC00000  UBIFS image

# Step 2: 提取 uImage
dd if=firmware.bin of=kernel.uimage bs=1 skip=0 count=1638400

# Step 3: 解压内核
dd if=kernel.uimage of=kernel.lzma bs=1 skip=72  # 跳过 72 字节 header
unlzma kernel.lzma

# Step 4: 提取 Squashfs 文件系统
dd if=firmware.bin of=rootfs.squashfs bs=1 skip=1638400 count=6750208
unsquashfs rootfs.squashfs
# → squashfs-root/bin/  squashfs-root/etc/  squashfs-root/lib/

# Step 5: 从 Squashfs 根目录分析
cd squashfs-root/
ls -la etc/
cat etc/shadow                     # ← 密码哈希
cat etc/inittab                    # ← 启动进程
cat etc/init.d/rcS                 # ← 初始化脚本

# Step 6: 查看二进制文件
file bin/busybox
# bin/busybox: ELF 32-bit LSB executable, ARM, statically linked
# → ARM 架构
```

### 2.2 自动化搜索敏感信息

```bash
#!/bin/bash
# firmware_secrets_scan.sh
# 在提取的固件中自动搜索敏感信息

FIRMWARE_DIR="$1"
REPORT="secrets_report.txt"

echo "=== 固件安全扫描报告 ===" > $REPORT
echo "扫描目录: $FIRMWARE_DIR" >> $REPORT
echo "扫描时间: $(date)" >> $REPORT
echo "" >> $REPORT

# 1. 搜索密码和凭证
echo "=== 密码和凭证 ===" >> $REPORT
grep -rI "password\s*=" "$FIRMWARE_DIR/etc" --include="*.conf" --include="*.ini" \
    | sed 's/password=.*/password=***REDACTED***/' >> $REPORT 2>/dev/null
grep -rI "passwd" "$FIRMWARE_DIR/etc" >> $REPORT 2>/dev/null

# 2. 搜索私钥和证书
echo -e "\n=== 私钥和证书 ===" >> $REPORT
find "$FIRMWARE_DIR" -name "*.pem" -o -name "*.key" -o -name "*.crt" \
    -o -name "*.p12" -o -name "*.pfx" >> $REPORT 2>/dev/null
grep -rI "BEGIN.*PRIVATE KEY" "$FIRMWARE_DIR" >> $REPORT 2>/dev/null

# 3. 搜索 API Keys 和 Tokens
echo -e "\n=== API Keys 和 Tokens ===" >> $REPORT
grep -rI "api[_-]key\|api[_-]secret\|access[_-]token" "$FIRMWARE_DIR" \
    >> $REPORT 2>/dev/null

# 4. 搜索硬编码 URL 和 IP
echo -e "\n=== 硬编码 URL 和 IP ===" >> $REPORT
grep -roE "https?://[^\s\"']+" "$FIRMWARE_DIR" | sort -u >> $REPORT 2>/dev/null
grep -roE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$FIRMWARE_DIR" | sort -u \
    >> $REPORT 2>/dev/null

# 5. 搜索后门账户
echo -e "\n=== 后门账户 ===" >> $REPORT
grep -rI "admin\|root\|service\|support\|debug\|factory" \
    "$FIRMWARE_DIR/etc/passwd" "$FIRMWARE_DIR/etc/shadow" >> $REPORT 2>/dev/null

# 6. 搜索调试功能
echo -e "\n=== 调试/开发后门 ===" >> $REPORT
strings "$FIRMWARE_DIR/bin/"* "$FIRMWARE_DIR/sbin/"* 2>/dev/null | \
    grep -iE "telnetd\|dropbear\|sshd\|debug=1\|test_mode\|factory_mode" \
    >> $REPORT

# 7. 搜索已知的后门字符串
echo -e "\n=== 已知后门模式 ===" >> $REPORT
strings "$FIRMWARE_DIR/bin/"* "$FIRMWARE_DIR/sbin/"* 2>/dev/null | \
    grep -iE "backdoor\|master\|override\|emergency\|hidden\|secret" \
    >> $REPORT

# 8. 搜索弱加密
echo -e "\n=== 弱加密算法 ===" >> $REPORT
strings "$FIRMWARE_DIR/lib/"* 2>/dev/null | \
    grep -iE "DES\|MD2\|MD4\|RC2\|RC4\|SHA-0" \
    >> $REPORT

echo ""
echo "扫描完成! 报告已保存到 $REPORT"
cat $REPORT
```

### 2.3 常见固件结构

```yaml
IoT 固件常见结构:

  TP-Link / D-Link (路由器):
    ├── 0x000000: Bootloader (U-Boot/CFE)
    ├── 0x020000: Kernel (vmlinux.uImage)
    ├── 0x200000: Squashfs (只读根文件系统)
    └── 0x7C0000: JFFS2/UBIFS (读写覆盖层)

  ESP32 / ESP8266:
    ├── bootloader.bin   (0x1000)
    ├── partitions.bin   (0x8000)
    ├── app.bin          (0x10000)  ← 主固件
    └── spiffs.bin       (数据分区)

  Yocto-based (嵌入式 Linux):
    ├── zImage (内核)
    ├── devicetree.dtb (设备树)
    ├── rootfs.ext4 (EXT4 文件系统)
    └── modules.tar.gz (内核模块)

  Realtek / Mediatek (IP 摄像头):
    ├── cramfs/squashfs  (根文件系统)
    ├── romfs            (备用系统)
    └── data partition   (用户配置)
```

---

## 3. 符号恢复与反编译

### 3.1 Ghidra 固件分析

```bash
# Ghidra 分析 ARM/MIPS 固件

# 1. 创建 Ghidra 项目并导入固件
#   File → New Project → Import File → firmware.bin
#   选择架构: ARM v7 little-endian

# 2. 加载固件到正确地址
#   Memory Map → 添加段:
#   0x08000000 (Flash 基地址) + firmware.bin

# 3. 自动分析
#   Analysis → Auto Analyze → 全部启用

# 4. 搜索字符串
#   Search → For Strings → 过滤: "password\|admin\|backdoor"

# 5. 定义函数
#   选中代码区域 → D (反汇编) → F (创建函数)

# 6. Ghidra Headless (命令行批量分析)
/opt/ghidra/support/analyzeHeadless \
    /tmp/ghidra_project \
    FirmwareProject \
    -import firmware.bin \
    -processor ARM:LE:32:v7 \
    -postScript AnalyzeAll.java
```

### 3.2 关键函数定位

```python
# Ghidra Python 脚本 - 自动定位关键函数

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor

class FirmwareAnalyzer:
    """固件自动分析"""

    def find_crypto_functions(self):
        """定位加密函数"""

        # 搜索加密常量
        crypto_constants = {
            0x67452301: 'MD5_Init',
            0x6A09E667: 'SHA256_Init',
        }

        listing = currentProgram.getListing()
        memory = currentProgram.getMemory()

        for addr, name in crypto_constants.items():
            # 搜索 dword
            found = self.find_bytes(
                currentProgram.getMinAddress(),
                currentProgram.getMaxAddress(),
                struct.pack('<I', addr)
            )

            if found:
                # 创建标签
                for loc in found:
                    createLabel(loc, name + '_CONSTANT', True)
                    print(f"Found {name} at {loc}")

                    # 向前查找函数引用
                    refs = getReferencesTo(loc)
                    for ref in refs:
                        func = getFunctionContaining(ref.getFromAddress())
                        if func:
                            func.setName(name, SourceType.ANALYSIS)
                            print(f"  → Renamed {ref.getFromAddress()} to {name}")

    def find_backdoors(self):
        """定位后门函数"""

        # 特征: 用户输入直接传给 system()
        # 模式: gets() → system()

        functions = currentProgram.getFunctionManager().getFunctions(True)
        for func in functions:
            called = getCalledFunctions(func)
            called_names = [f.getName() for f in called]

            # 危险组合
            if 'system' in called_names or 'popen' in called_names:
                # 检查参数是否来自用户输入
                if any(n in called_names for n in ['recv', 'read', 'fgets', 'scanf']):
                    print(f"POTENTIAL BACKDOOR: {func.getName()} at {func.getEntryPoint()}")
                    setBackgroundColor(func.getEntryPoint(), Color.RED)
```

---

## 参考资源

- [Binwalk 文档](https://github.com/ReFirmLabs/binwalk)
- [Ghidra 固件分析](https://ghidra-sre.org/)
- [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [OWASP Firmware Security Testing](https://owasp.org/www-project-firmware-security-testing-methodology/)

---

*上一篇：[硬件安全入门](./01-hardware-hacking.md)*
*下一篇：[芯片安全攻击](03-chip-security.md)*

# IoT 设备固件安全分析

## 固件提取

### 硬件提取
```bash
# SPI Flash 读取（使用 Flashrom）
flashrom -p ch341a_spi -r firmware.bin

# UART 串口（默认 115200 8N1）
screen /dev/ttyUSB0 115200
# 启动时中断 U-Boot → 进入 uboot shell
# 在 uboot 中导出固件
tftp 0x82000000 firmware.bin; tftpboot
```

### 软件提取
```bash
# OTA 固件抓取（中间人代理设置）
mitmproxy -p 8080

# 分析更新 URL 模式
strings app.apk | grep -i "update\|firmware\|ota" | grep "http"
strings app.apk | grep -E "(https?://[^\s]+\.bin)"

# 从 App 提取
unzip -l app.apk | grep -i "bin\|img\|fw\|firmware"
```

## 固件分析流程

```bash
# 1. 识别文件系统
binwalk -Me firmware.bin

# 2. 文件系统解包
unsquashfs -d rootfs rootfs.squashfs

# 3. 架构识别
readelf -h rootfs/bin/busybox | grep Machine

# 4. 搜索敏感信息
grep -r "password\|admin\|root" etc/ lib/ --include="*.conf" --include="*.json"
grep -r "telnet\|ssh\|http" etc/init.d/

# 5. Web 漏洞扫描
# 在本地运行固件
chroot rootfs qemu-arm-static /usr/sbin/httpd
```

## 设备漏洞常见类型

| 漏洞类型 | 占比 | 典型案例 |
|---------|------|---------|
| 硬编码凭据 | 35% | 路由器 admin/admin |
| 命令注入 | 25% | ping/traceroute 参数 |
| 栈溢出 | 20% | CGI 参数过长 |
| 固件未签名 | 10% | OTA 中间人 |
| 信息泄露 | 10% | debug 接口未关闭 |

## 建议的安全配置

1. 出厂时随机化默认密码
2. 固件签名验证（RSA-4096 签名）
3. 禁用 telnet/ssh 非必要接口
4. Web 管理仅绑定本地接口
5. 定期安全审计（季度）
6. 漏洞赏金计划

# IoT 安全

## IoT 攻击面

### 常见入口
- Web 管理面板
- 固件更新机制
- 移动端 App
- 云平台 API
- 本地网络协议

### 典型漏洞
| 组件 | 漏洞 | 案例 |
|------|------|------|
| Web 面板 | 硬编码管理员凭据 | Mirai 僵尸网络 |
| 固件 | 未加密存储密钥 | SOHO 路由器后门 |
| 网络协议 | CoAP/ MQTT 无认证 | 智能家居入侵 |
| 移动 App | API Key 硬编码 | 云平台劫持 |
| OTA 更新 | 未签名固件 | 供应链投毒 |

## MQTT 安全
```bash
# ❌ 不安全的 MQTT 连接
mosquitto_pub -h broker.example.com -t "sensor/temp" -m "28.5"

# ✅ 带 TLS + 认证
mosquitto_pub -h broker.example.com -p 8883 \
  --cafile ca.crt --cert client.crt --key client.key \
  -t "sensor/temp" -m "28.5"
```

## 固件分析
```bash
# 提取固件
binwalk -e firmware.bin

# 文件系统分析（常见的 SquashFS）
unsquashfs -d extracted _firmware.extracted/squashfs-root/

# 硬编码凭据搜索
grep -r "password\|secret\|key" extracted/ --include="*.conf" --include="*.json"
grep -raP '(?<=[:\s])[A-Za-z0-9+/]{20,}={0,2}(?=["\s])' extracted/
```

## IoT 安全最佳实践

1. 每设备唯一凭据，禁止硬编码
2. 固件签名验证
3. 安全启动链（Secure Boot）
4. 物理防篡改检测
5. 最小化攻击面（禁用不必要服务）
6. OTA 更新机制
7. 安全通信（TLS/DTLS）
8. 日志审计和异常检测

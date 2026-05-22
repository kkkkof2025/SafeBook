# 5G 核心网安全

## 5G 核心网概述

5G 核心网 (5GC) 采用服务化架构 (SBA)，引入了新的安全挑战。

### 架构变化

| 特性 | 4G EPC | 5G Core |
|------|---------|----------|
| 架构 | 点对点 | 服务化架构 (SBA) |
| 接口 | 点对点 | HTTP/2 |
| 身份认证 | EAP-AKA' | EAP-AKA' / 5G AKA |
| 加密 | NAS + AS | 端到端 (可选) |
| 切片 | ❌ | ✅ (Network Slicing) |

---

## 5G 安全架构

### 安全域

```
+--------------+     +--------------+     +--------------+
|   UE         | <--> |   RAN        | <--> |   5GC        |
| (用户设备)   |     | (基站)      |     | (核心网)     |
+--------------+     +--------------+     +--------------+
      |                      |                      |
      v                      v                      v
[ME ID 认证]       [AS 安全]          [NA S 安全]
[用户身份认证]                             [服务化安全]
```

### 安全功能

1. **AUSF** - 认证服务器功能
2. **SEAF** - 安全锚点功能
3. **AMF** - 接入和移动性管理功能
4. **SMF** - 会话管理功能
5. **UPF** - 用户平面功能

---

## 5G AKA 认证

### 流程

```
UE <--> SEAF <--> AUSF <--> UDM
 |         |          |          |
 |<-------- SQN, RAND, AUTN ---->|
 |         |          |          |
 |--------> RES* (认证响应) ------>|
 |         |          |          |
 |<-------- 认证成功 <----------|
```

### 消息详解

#### 1. 认证请求 (Authentication Request)

```http
POST /nausf-auth/v1/ue-authentications HTTP/2
Content-Type: application/json

{
  "ueId": "imsi-460001234567890",
  "servingNetworkName": "5G:mnc001.mcc460.3gppnetwork.org",
  "resynchronizationInfo": {
    "rand": "00112233445566778899aabbccddeeff",
    "auts": "aabbccddeeff00112233445566778899"
  }
}
```

#### 2. 认证响应 (Authentication Response)

```http
HTTP/2 201 Created
Content-Type: application/json

{
  "authResult": "AUTHENTICATION_SUCCESS",
  "supi": "imsi-460001234567890",
  "kseaf": "aabbccddeeff00112233445566778899",
  "_links": {
    "self": { "href": "/nausf-auth/v1/ue-authentications/imsi-460001234567890" }
  }
}
```

### 安全增强

1. **归属网络控制** - HN (Home Network) 控制认证
2. **双向认证** - UE 认证网络，网络认证 UE
3. **防追踪** - SUPI (Subscription Permanent Identifier) 加密为 SUCI
4. **防重放** - SQN (Sequence Number) 防重放攻击

---

## 网络切片安全

### 切片隔离

**目标：** 防止切片间未授权访问

```
+------------+     +------------+     +------------+
| 切片1      |     | 切片2      |     | 切片3      |
| (eMBB)    | <X> | (uRLLC)   | <X> | (mMTC)    |
+------------+     +------------+     +------------+
      |                  |                  |
      v                  v                  v
  [隔离策略]       [隔离策略]       [隔离策略]
```

### 实施

#### 1. 切片认证

```yaml
# 切片配置
slices:
  - sst: 1  # eMBB
    sd: 0x111111
    authentication:
      primary: 5G-AKA
      secondary: EAP-TLS
    isolation: strict  # 严格隔离
```

#### 2. 切片访问控制

```python
# 切片访问控制策略
class SliceAccessControl:
    def check_access(self, ue, slice_id):
        # 检查 UE 是否有权访问该切片
        if ue.slice_policies.get(slice_id) != 'allowed':
            return False, 'Access denied: slice not allowed'

        # 检查切片负载
        if slice.load > 80:
            return False, 'Access denied: slice overloaded'

        return True, 'Access granted'
```

### 攻击向量

#### 攻击1：切片劫持

**原理：** 攻击者接入目标切片

**防御：**
- 强制切片认证
- 实施 RBAC (基于角色的访问控制)
- 监控异常切片流量

#### 攻击2：切片间侧信道

**原理：** 通过时序分析推断其他切片流量

**防御：**
- 实施流量隔离 (VLAN/VxLAN)
- 使用加密 (IPsec/TLS)
- 监控异常时延

---

## 服务化架构 (SBA) 安全

### 服务通信代理 (SCP)

**功能：** 服务间通信的中继

```
+--------+     +--------+     +--------+
| NF 1   | --> | SCP    | --> | NF 2   |
| (服务  |     | (代理) |     | (服务  |
|  消费者)|     |        |     |  生产者)|
+--------+     +--------+     +--------+
                      |
                      v
                 [安全策略]
                 [访问控制]
                 [流量监控]
```

### 安全机制

#### 1. 服务认证

```http
POST /nrf-nfmanagement/v1/nf-instances HTTP/2
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...

{
  "nfInstanceId": "aabbccdd-0011-2233-4455-66778899aabb",
  "nfType": "AMF",
  "nfStatus": "REGISTERED",
  "ipv4Addresses": ["192.168.1.100"],
  "nfServices": [
    {
      "serviceName": "namf-comm",
      "versions": [{"apiVersionInUri": "v1"}]
    }
  ]
}
```

#### 2. 服务授权

```python
# 服务授权策略
class ServiceAuthorization:
    def check_authorization(self, consumer_nf, producer_nf, service):
        # 检查 NF 类型是否允许调用该服务
        if (consumer_nf.type, producer_nf.type, service) not in POLICY_TABLE:
            return False, 'Service not allowed'

        # 检查 NF 实例是否注册
        if not self.nrf.is_registered(consumer_nf.id):
            return False, 'NF not registered'

        # 检查速率限制
        if self.rate_limiter.exceeded(consumer_nf.id, service):
            return False, 'Rate limit exceeded'

        return True, 'Authorized'
```

#### 3. 服务通信安全

**TLS 配置：**

```yaml
# NF 服务 TLS 配置
tls:
  enabled: true
  version: TLSv1.3
  cipher_suites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
  certificates:
    - type: x509
      path: /etc/5g/certs/nf-cert.pem
      key: /etc/5g/certs/nf-key.pem
      ca: /etc/5g/certs/ca-cert.pem
```

---

## 用户平面安全

### 用户平面功能 (UPF) 安全

**职责：**
1. 数据包转发
2. 策略执行 (PDR/FAR/QER)
3. 流量监控

### 安全策略

#### 1. 数据包检测规则 (PDR)

```json
{
  "pdrId": 1,
  "srcInterface": "ACCESS",
  "dstInterface": "CORE",
  "match": {
    "destinationIP": "10.0.0.0/8",
    "protocol": "TCP",
    "destinationPort": 443
  },
  "precedence": 255,
  "farId": 1,
  "qerId": [1]
}
```

#### 2. 转发动作规则 (FAR)

```json
{
  "farId": 1,
  "applyAction": "FORWARD",
  "forwardingParameters": {
    "destinationInterface": "CORE",
    "networkInstance": "core-net",
    "outerHeaderCreation": {
      "gtpUExtensions": true,
      "destinationIP": "192.168.2.100",
      "destinationPort": 2152
    }
  }
}
```

#### 3. QoS 执行规则 (QER)

```json
{
  "qerId": 1,
  "gateStatus": {
    "uplink": "OPEN",
    "downlink": "OPEN"
  },
  "maximumBitrate": {
    "uplink": "100000000",    // 100 Mbps
    "downlink": "500000000"    // 500 Mbps
  },
  "guaranteedBitrate": {
    "uplink": "10000000",     // 10 Mbps
    "downlink": "50000000"     // 50 Mbps
  }
}
```

### 攻击向量

#### 攻击1：UPF 旁路攻击

**原理：** 绕过 UPF 策略执行

**防御：**
- 实施严格 PDR/FAR/QER 验证
- 监控异常流量模式
- 定期审计 UPF 配置

#### 攻击2：用户平面泛洪

**原理：** 向 UPF 发送大量数据包

**防御：**
- 实施速率限制 (QER)
- 使用流量清洗 (DDoS 防护)
- 部署 UPF 集群 (负载均衡)

---

## 5G 安全监控

### 监控指标

| 指标 | 来源 | 告警阈值 |
|------|------|------------|
| 认证失败率 | AUSF | > 5% |
| 切片负载 | NSSF | > 80% |
| 服务调用延迟 | SCP | > 100ms |
| UPF 丢包率 | UPF | > 1% |

### 安全事件日志

```json
// 认证失败日志
{
  "timestamp": "2026-05-22T00:17:00Z",
  "eventType": "AUTHENTICATION_FAILURE",
  "ueId": "imsi-460001234567890",
  "failureCause": "MAC_FAILURE",
  "seafId": "seaf-001",
  "ausfId": "ausf-001"
}
```

```json
// 切片异常日志
{
  "timestamp": "2026-05-22T00:17:30Z",
  "eventType": "SLICE_ACCESS_VIOLATION",
  "ueId": "imsi-460009876543210",
  "sliceId": "slice-urllc-001",
  "violationType": "UNAUTHORIZED_ACCESS",
  "severity": "HIGH"
}
```

---

## 5G 安全加固清单

### 核心网

- [ ] 启用 5G AKA 双向认证
- [ ] 实施 SUPI 加密 (SUCI)
- [ ] 启用服务化架构认证 (OAuth 2.0/JWT)
- [ ] 实施网络切片隔离
- [ ] 启用用户平面加密 (UPF)
- [ ] 部署 5G 安全监控 (SIEM)

### RAN (基站)

- [ ] 启用 AS 安全 (RRC/UP 加密)
- [ ] 实施基站认证 (Xn/RM/C/F1 接口)
- [ ] 启用干扰检测 (Jamming 防护)
- [ ] 部署 RAN 切片隔离

### UE (用户设备)

- [ ] 启用 ME ID 认证
- [ ] 实施 SUCI 生成 (保护 SUPI)
- [ ] 启用 5G AKA 认证
- [ ] 禁用弱加密算法 (GPRS/T-EA0)

---

## 延伸阅读

- [3GPP TS 33.501](https://www.3gpp.org/ftp/Specs/latest/Rel-17/33501-h0.zip) - 5G 安全架构
- [O-RAN Security](https://www.o-ran.org/security) - 开放 RAN 安全
- [5G PPP Security](https://5g-ppp.eu/security/) - 5G 安全白皮书

---



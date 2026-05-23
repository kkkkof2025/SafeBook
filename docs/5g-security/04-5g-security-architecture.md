# 5G 安全架构深度

> 3GPP 5G 安全标准与实践

---

## 1. 5G 安全架构演进

```
4G→5G 安全改进:
┌─────────────────┐        ┌─────────────────────────┐
│       4G        │        │          5G             │
├─────────────────┤        ├─────────────────────────┤
│ AKA 认证        │   →    │ 5G AKA + EAP-AKA'       │
│ 明文 IMSI       │   →    │ 加密 SUCI               │
│ 无完整性保护    │   →    │ 用户面完整性 (可选)      │
│ SS7 信令攻击    │   →    │ SEPP + IPX 保护          │
│ 无 SBA         │   →    │ 基于服务的架构 (SBA)     │
│ 单一认证框架    │   →    │ 统一认证框架             │
└─────────────────┘        └─────────────────────────┘
```

---

## 2. 5G 认证与密钥管理

### SUCI (Subscription Concealed Identifier)
```
IMSI → SUCI 加密:
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  IMSI    │ ──→ │ ECIES 加密│ ──→ │  SUCI    │
  │(永久标识) │     │(公钥加密) │     │(隐藏标识) │
  └──────────┘     └──────────┘     └──────────┘

  作用: 防止 IMSI Catcher (Stingray) 攻击
  仅在归属网络解密 (UDM/ARPF)
```

### 5G AKA 流程
```
UE ←→ SEAF ←→ AUSF ←→ UDM/ARPF

1. UE → SEAF: SUCI (或 5G-GUTI)
2. SEAF → AUSF: Nausf_UEAuthentication_Authenticate Request
3. AUSF → UDM: Nudm_UEAuthentication_Get Request
4. UDM → AUSF: 5G AV (RAND, AUTN, HXRES*, KSEAF)
5. AUSF → SEAF: 5G SE AV (HXRES*, KSEAF)
6. SEAF → UE: RAND, AUTN (认证挑战)
7. UE 验证 AUTN + 计算 RES*
8. SEAF 验证 RES* == HXRES*
```

---

## 3. 网络切片安全

```yaml
网络切片安全隔离:
  切片类型:
    - eMBB: 增强移动宽带 (视频/AR/VR)
    - uRLLC: 超可靠低延迟 (自动驾驶/远程手术)
    - mMTC: 大规模物联网 (传感器/智能电表)

  安全挑战:
    - 切片间隔离: 防止跨切片攻击
    - 切片认证: NSSAI (网络切片选择辅助信息)
    - 切片 QoS: DoS 攻击导致资源耗尽
    - 切片编排: NFVO/SDN 控制器的安全

  防护措施:
    - NSSF: 网络切片选择功能,认证切片请求
    - NSSAAF: 切片专用认证和授权
    - 切片级加密: 不同切片独立加密密钥
    - SBA 令牌: 服务访问授权 (OAuth 2.0)
```

---

## 4. SBA 安全 (Service-Based Architecture)

```yaml
5G 核心网 SBA 安全:
  组件:
    - NRF (Network Repository Function): 服务注册/发现
    - NEF (Network Exposure Function): API 暴露
    - SEPP (Security Edge Protection Proxy): 漫游安全

  API 安全:
    - NRF OAuth 2.0 令牌: 服务间认证
    - TLS 1.3: 传输加密
    - NEF API 安全: 
      - 双向 TLS
      - OAuth 2.0 客户端凭证
      - API 速率限制

  SEPP (5G 漫游安全):
    - IPX 网络保护 (取代 SS7)
    - 应用层安全 (TLS + N32-f)
    - 端到端加密
    
  SEPP → SEPP 通信:
    Native IP: 未受保护
    TLS 1.3: 传输层保护
    PRINS (PRotocol for N32 INterconnect Security): 
    应用层修改保护 (JWE 加密 + JWS 签名)
```

---

## 5. 5G 安全威胁与对策

| 威胁 | 描述 | 对策 |
|------|------|------|
| 伪基站 (Fake gNB) | 假冒基站截获通信 | SUCI 加密 + 基站认证 |
| SIM 卡克隆 | 克隆 SIM 接入网络 | 5G AKA + SUPI 保护 |
| SBA API 攻击 | NRF/NEF API 未授权访问 | OAuth 2.0 + 双向 TLS |
| 网络切片 DoS | 耗尽特定切片资源 | 切片级 QoS 隔离 |
| 漫游拦截 | SEPP 通信明文传输 | PRINS + 端到端加密 |
| IoT 大规模攻击 | 海量 IoT 设备形成僵尸网络 | NSSAAF 认证 + 行为分析 |

---

*上一篇：[5G 核心网安全](03-5g-core-security.md)*

*下一篇：[物联网安全深度](04-iot-security-depth.md)*

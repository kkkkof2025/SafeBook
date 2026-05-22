# 5G 网络安全

## 5G 安全架构概述

5G 网络在架构上相比 4G LTE 有重大变化，引入了服务化架构（SBA）、网络切片、MEC 边缘计算等新特性，同时也带来了新的攻击面。

## 5G 安全架构模型

### 3GPP 安全架构

```yaml
5G 安全域（3GPP TS 33.501）:
  - 网络接入安全（I）: 
    - UE ↔ 接入网认证 (5G-AKA / EAP-AKA')
    - 空口加密和完整性保护
  - 网络域安全（II）: 
    - 网元间通信 (N32/N32-c 接口)
    - SEPP（安全边缘保护代理）
  - 用户域安全（III）:
    - USIM 卡安全
    - ME 移动设备安全
  - 应用域安全（IV）:
    - 应用层端到端安全
  - SBA 安全（V）:
    - 服务化架构内 NF 间通信
    - OAuth 2.0 授权框架
```

### 5G 认证流程（5G-AKA）

```
UE → gNB → AMF → AUSF → UDM
│       │      │      │      │
1. UE 发起注册请求
2. AMF 请求 AUSF 进行认证
3. AUSF 从 UDM 获取认证向量
4. 鉴权五元组 (RAND, AUTN, HXRES*, KSEAF, MAC)
5. UE 验证 AUTN（网络认证）
6. AUSF 验证 RES*（用户认证）→ 双向认证
```

## 5G 攻击面

### 空口攻击

```yaml
攻击类型:
  - IMSI 捕获:
    - 虽然 5G 使用 SUCI（加密的 SUPI），但初始接入仍可能暴露
    - 攻击者部署伪基站，强制降级到 4G/LTE
  - 降级攻击:
    - 通过干扰 5G NR 频段，迫使 UE 回落 4G
    - 在 4G 模式下利用旧协议的漏洞
  - 重放攻击:
    - 捕获并重放认证过程中的消息
```

### 核心网攻击

```yaml
核心网攻击路径:
  - N32 接口（SEPP↔SEPP）:
    - HTTP/2 协议攻击（请求走私、溢出）
    - TLS 配置弱点
    - JSON/Protobuf 解析漏洞
  - SBI（服务化接口）:
    - OAuth 令牌伪造
    - API 滥用（NF 仿冒）
    - 服务注册/发现攻击
  - NFs（网络功能）:
    - AMF/SMF/UPF 边界绕过
    - HTTP/2 多路复用攻击
```

### 网络切片安全

```yaml
切片隔离失效风险:
  - 控制面注入:
    从 eMBB 切片攻击 URLLC 切片的控制面
  - 数据面泄露:
    错误配置的 NSSF 导致切片间流量混淆
  - 资源耗尽:
    恶意切片占用大量计算/网络资源
  - 跨越攻击:
    从公共切片通过共享组件攻击企业切片
```

## 5G 安全测试工具

```bash
# 5G 协议测试工具
# Open5GS - 开源 5G 核心网实现
git clone https://github.com/open5gs/open5gs
cd open5gs && meson build && ninja -C build

# srsRAN - 开源 5G gNB 实现
git clone https://github.com/srsran/srsRAN_Project
cd srsRAN_Project && mkdir build && cd build && cmake .. && make

# 5G-NFV - 基于 fs 的测试框架
# 使用 Scapy 自定义 5G NAS 消息
from scapy.contrib.threeGPP5G import *
pkt = NAS5G(NAS5GMMHeader(msg_type=0x41))  # Registration Request
```

## 5G 安全合规

### 3GPP 安全要求

```yaml
要求（TS 33.501 Release 17+）:
  - 所有控制面信令必须完整性保护
  - 用户面加密可选（取决于网络配置）
  - SEAF/AUSF/UDM/ARPF 必须支持 5G-AKA 或 EAP-AKA'
  - 网络切片间严格隔离
  - 支持 SUCI 加密（ECC P-256）
  - NF 间通信通过 TLS 1.3+ 或 NDS/IP
```

## 总结

5G 安全远不止于无线加密。服务化架构、网络切片和 MEC 带来了全新的攻击面。5G 安全测试需要结合协议模糊测试、核心网渗透测试和切片隔离验证三大方向。

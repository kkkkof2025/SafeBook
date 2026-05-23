# 网络安全架构与零信任网络设计

## 零信任网络架构原则

零信任（Zero Trust）的核心假设：网络内不再被视为安全区，所有流量都必须经过认证和授权。

### NIST SP 800-207 零信任架构

```
基本原则:
1. 所有数据源和计算资源都被视为资源
2. 所有通信都应进行安全保护，无论网络位置
3. 对每个资源的访问都基于会话级别进行授权
4. 访问策略基于"需要知道"原则和属性评估
5. 持续监控和评估所有资源的安全性
6. 尽可能动态地收集和使用策略所需的数据
```

## 网络微隔离技术

### 基于主机的微隔离

```yaml
微隔离实现方式:
  - 云原生: AWS Security Groups / Azure NSG / GCP Firewall Rules
  - 容器级: Calico Network Policies / Cilium Network Policies / Istio AuthorizationPolicy
  - 主机级: Windows Defender Firewall / iptables / nftables / eBPF
  - Service Mesh: Istio / Linkerd / Consul Connect
```

### Cilium 网络策略示例

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-server-isolation
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "8443"
        protocol: TCP
  egress:
  - toEndpoints:
    - matchLabels:
        app: database
    toPorts:
    - ports:
      - port: "5432"
        protocol: TCP
```

## 网络分段设计模式

### 传统 VLAN 分段

```yaml
VLAN 设计:
  - VLAN 10: Management (10.10.0.0/16)
  - VLAN 20: User Access (10.20.0.0/16)
  - VLAN 30: Server Farm (10.30.0.0/16)
  - VLAN 40: DMZ (10.40.0.0/16)
  - VLAN 50: Guest (10.50.0.0/16)
  - VLAN 60: IoT/OT (10.60.0.0/16)
  - VLAN 70: Security Monitoring (10.70.0.0/16)
  - VLAN 100-199: Network Infrastructure (point-to-point)
```

### VRF（虚拟路由转发）隔离

```text
VRF 划分:
  - VRF Management: 管理流量
  - VRF Production: 生产环境
  - VRF Development: 开发测试
  - VRF Guest: 访客网络
  - VRF IoT: 物联网设备
  - VRF Storage: 存储网络（iSCSI/NFS）
```

## 下一代防火墙策略设计

### 应用层控制

```bash
# Palo Alto 应用防火墙策略示例
# 仅允许特定的应用流量
set rulebase security rules "Allow-Slack"
  set application [ "slack-base" "slack-files" ]
  set service [ "application-default" ]
  set action allow

# 使用 SSL 解密进行深度包检查
set rulebase security rules "SSL-Decrypt"
  set profile-setting group "strict-ssl-inbound"
  set action allow
```

## 零信任网络访问（ZTNA）

```yaml
ZTNA 对比:
  产品: Cloudflare Access | Zscaler ZPA | Tailscale | OpenZiti
  实现原理:
    - Cloudflare: 全球网络边界 + Tunnel
    - Zscaler: Broker 模型 + 应用分段
    - Tailscale: WireGuard Mesh + 基于身份的路由
    - OpenZiti: 开源零信任 Overlay 网络
  
  核心特性:
    - 不暴露公网 IP
    - 按用户+设备+上下文授权
    - 应用级隧道（非网络层 VPN）
    - 持续身份验证
```

### Cloudflare Tunnel 部署

```yaml
# cloudflared 隧道配置
tunnel: my-corp-tunnel
credentials-file: /root/.cloudflared/my-corp-tunnel.json

ingress:
  - hostname: wiki.example.com
    service: http://internal-wiki:8080
  - hostname: git.example.com
    service: http://gitlab:80
  - service: http_status:404
```

## 安全访问服务边缘（SASE）

SASE 整合了网络和安全功能：

```yaml
SASE 组件:
  网络功能:
    - SD-WAN (Software-Defined WAN)
    - WAN Optimization
    - 路由和 QoS
  安全功能:
    - SWG (Secure Web Gateway)
    - CASB (Cloud Access Security Broker)
    - ZTNA
    - FWaaS (Firewall as a Service)
    - RBI (Remote Browser Isolation)
```

## 总结

零信任网络架构已经从理论走向落地。从 DNSSEC/加密 DNS 开始，到网络微分段、ZTNA、SASE，逐步演进才能建立真正的零信任网络。

*上一篇：[网络架构安全](01-network-architecture-security.md)*

*下一篇：[微分段与零信任网络](03-microsegmentation.md)*

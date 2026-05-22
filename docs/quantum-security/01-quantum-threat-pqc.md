# 量子计算对密码学的威胁

## 概述

量子计算将在 2030 年代淘汰 RSA、ECC 等广泛使用的公钥密码体系。Shor 算法可在多项式时间内分解大整数和求解离散对数。NIST 已在 2024 年发布首批后量子密码学标准（FIPS 203-205），迁移窗口正在关闭。

---

## 1. 量子威胁时间线

### 1.1 威胁模型

```
量子计算里程碑与密码学影响:

现在 (2024-2026):
  - 量子计算机: ~1000 物理量子比特
  - 逻辑量子比特: 0 (错误率太高)
  - 威胁: Harvest Now, Decrypt Later (HNDL)
    → 攻击者现在收集加密数据
    → 等待量子计算机成熟后解密

2028-2030:
  - 逻辑量子比特: ~100-200
  - 威胁: 开始能分解小型 RSA (512-bit)
  - 影响: 早期密码迁移必须完成

2030-2035:
  - 逻辑量子比特: ~4000+
  - 威胁: RSA-2048 被破解 (Shor)
  - 影响: 所有经典非对称加密不再安全

2035+:
  - 量子优势: 全面
  - 威胁: 所有 PKI / TLS / 区块链 私有密钥可恢复
  - 影响: 必须完成后量子迁移
```

### 1.2 受影响的算法

| 算法 | 量子攻击 | 安全量子比特需求 | 后果 |
|------|----------|------------------|------|
| RSA-2048 | Shor | ~4000 逻辑量子比特 | 私钥可在秒级恢复 |
| ECDSA P-256 | Shor | ~2300 逻辑量子比特 | 签名可被伪造 |
| ECDH | Shor | ~2300 逻辑量子比特 | 会话密钥可恢复 |
| DSA / ElGamal | Shor | ~4000 逻辑量子比特 | 签名伪造 |
| AES-128 | Grover | 2^64 (平方根加速) | 安全性减半 |
| AES-256 | Grover | 2^128 (仍安全) | 足够安全 |
| SHA-256 | Grover | 2^128 (碰撞) | 哈希原像仍安全 |
| SHA3-512 | Grover | 2^256 (仍安全) | 长期安全 |

---

## 2. 后量子密码学 (PQC)

### 2.1 NIST PQC 标准 (2024)

```yaml
NIST FIPS 203 ~ 205 (2024年8月发布):

  FIPS 203 — ML-KEM (Kyber) — 密钥封装:
    类型: 基于格的 KEM
    安全级别:
      - ML-KEM-512: 等同于 AES-128
      - ML-KEM-768: 等同于 AES-192
      - ML-KEM-1024: 等同于 AES-256
    公私钥大小: 800-3168 字节
    密文大小: 768-1568 字节

  FIPS 204 — ML-DSA (Dilithium) — 数字签名:
    类型: 基于格的签名
    安全级别:
      - ML-DSA-44: 等同于 AES-128
      - ML-DSA-65: 等同于 AES-192
      - ML-DSA-87: 等同于 AES-256
    签名大小: 2420-4627 字节

  FIPS 205 — SLH-DSA (SPHINCS+) — 有状态签名:
    类型: 基于哈希的签名
    优势: 最保守的安全保证 (仅依赖哈希函数安全性)
    劣势: 签名大 (7-49KB), 有状态 (签名次数有限)
```

### 2.2 Kyber 密钥交换

```python
from pqcrystals import Kyber

# ML-KEM (Kyber) 密钥封装示例

# 1. 接收方生成密钥对
public_key, secret_key = Kyber.keypair()

# 2. 发送方使用接收方的公钥进行密钥封装
ciphertext, shared_secret_sender = Kyber.encapsulate(public_key)

# 3. 接收方使用私钥解封装
shared_secret_receiver = Kyber.decapsulate(ciphertext, secret_key)

# 4. 双方得到相同的 256-bit 共享密钥
assert shared_secret_sender == shared_secret_receiver

# 混合模式 (Hybrid): 同时使用 Kyber + ECDH
# 如果 Kyber 被破解 → ECDH 仍然保护密钥
# 如果 ECDH 被破解 → Kyber 仍然保护密钥
import hashlib

def hybrid_kem(ecdh_private_key, recipient_ecdh_pubkey, recipient_kyber_pubkey):
    # Classical: ECDH
    classical_shared = ecdh(ecdh_private_key, recipient_ecdh_pubkey)

    # Post-Quantum: Kyber
    ciphertext, pq_shared = Kyber.encapsulate(recipient_kyber_pubkey)

    # Combine: SHA3-256(classical || pq)
    combined_secret = hashlib.sha3_256(
        classical_shared + pq_shared
    ).digest()

    return ciphertext, combined_secret
```

### 2.3 TLS 后量子握手

```
TLS 1.3 with Post-Quantum (Hybrid Key Exchange):

Client                                              Server
  │                                                   │
  │ ClientHello                                       │
  │ - key_share:                                       │
  │   - X25519 (Classical)                            │
  │   - Kyber512 (Post-Quantum)                       │
  │──────────────────────────────────────────────────→│
  │                                                   │
  │   ServerHello                                     │
  │   - key_share: X25519 + Kyber512                 │
  │←─────────────────────────────────────────────────│
  │                                                   │
  │ 计算: secrets = HKDF(                             │
  │   classical_shared_secret ||                      │
  │   pq_shared_secret                                │
  │ )                                                 │
  │                                                   │
  │ 如果 Kyber 被量子破解 → X25519 仍然保护 TLS       │
  │ 如果 X25519 被古典破解 → Kyber 仍然保护 TLS       │
```

---

## 3. HNDL 攻击 (收割现在，解密以后)

### 3.1 风险评估

```python
class HNDLRiskAssessment:
    """Harvest Now, Decrypt Later 风险评估"""

    def __init__(self):
        self.sensitive_data_categories = {
            'state_secrets': {
                'shelf_life': '50+ years',
                'risk': 'CRITICAL',
                'action': '切换到 PQC + 对称加密回退'
            },
            'long_term_keys': {
                'shelf_life': '20+ years',
                'risk': 'CRITICAL',
                'action': '密钥轮换 + PQC 支持'
            },
            'financial_records': {
                'shelf_life': '10+ years',
                'risk': 'HIGH',
                'action': 'PQC 迁移 + 加密备份'
            },
            'personal_data': {
                'shelf_life': '5+ years',
                'risk': 'MEDIUM',
                'action': '加密升级 + 数据最小化'
            },
            'session_data': {
                'shelf_life': '< 1 day',
                'risk': 'LOW',
                'action': '继续用传统加密'
            }
        }

    def assess_hndl_risk(self):
        """评估 HNDL 风险"""

        # 1. 盘点: 哪些数据用非对称加密保护？
        risk_assessment = {
            'tls_sessions': [],      # 所有 TLS 会话历史
            'email': [],             # S/MIME / PGP 加密邮件
            'vpn_traffic': [],       # IPsec / WireGuard 流量
            'backups': [],           # 加密备份
            'code_signing': [],      # 签名过的二进制
            'blockchain_txns': [],   # 区块链签名
        }

        # 2. 评估: 哪些 TLS 会话包含长期价值的敏感数据？
        # 如果 NSA 记录了今天所有的 TLS 流量
        # 10 年后用量子计算机解密 → 哪些仍然有情报价值？

        # 3. 优先: 先保护高价值/长寿命数据
        priority = [
            ('Root CA 密钥', 'PQC 迁移 + 短期证书'),
            ('TLS 会话密钥', 'PQC 混合密钥交换'),
            ('VPN 隧道', 'PQC 支持的 VPN'),
            ('代码签名', 'PQC 签名算法'),
        ]

        return risk_assessment
```

### 3.2 迁移路线图

```yaml
后量子密码迁移路线图:
  
  第 0 阶段 (现在): 盘点
    - 列出所有使用非对称加密的系统
    - 识别 5 年以上寿命的密钥/证书
    - 评估 HNDL 风险等级

  第 1 阶段 (2025-2026): 混合模式
    - TLS: 启用 X25519 + Kyber 混合密钥交换
    - SSH: 启用 ssh-ed25519 + kyber512 混合
    - 测试环境: 全 PQC 试点

  第 2 阶段 (2027-2028): 全面 PQC
    - 所有公钥基础设施切换到 PQC
    - 签发 PQC 证书 (ML-DSA)
    - 代码签名使用 PQC
    - 软件更新签名使用 SLH-DSA

  第 3 阶段 (2029-2030): 完成迁移
    - 撤销所有 RSA/ECC 根证书
    - 移除对传统算法的支持
    - 定期重新评估 PQC 算法安全

  持续: 加密敏捷性 (Crypto Agility)
    - 所有系统必须支持算法切换
    - 密钥生命周期管理
    - 紧急算法 SHAKE 流程
```

---

## 4. 实战：Cloudflare PQC

```bash
# Cloudflare 2024: 后量子 TLS 已默认启用

# 检查到 Cloudflare 的 TLS 连接是否使用 PQC
curl -v https://blog.cloudflare.com 2>&1 | grep "TLSv1.3"

# Chrome 124+ 默认启用 Kyber (TLS 1.3 hybrid)
# chrome://flags > #enable-tls13-kyber

# 查看 TLS 握手中的 PQC 算法
openssl s_client -connect cloudflare.com:443 -tls1_3 \
    -curves X25519Kyber768 2>&1 | grep -A5 "Server Temp Key"

# 输出示例:
# Server Temp Key: X25519+Kyber768, 253 bits (混合)
```

---

## 参考资源

- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203/204/205](https://csrc.nist.gov/pubs/fips/203/ipd)
- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/)
- [Cloudflare PQC 部署](https://blog.cloudflare.com/pq-2024/)

---

*下一篇：[后量子迁移实践](./02-pqc-migration.md)*

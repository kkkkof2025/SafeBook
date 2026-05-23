# 后量子密码迁移实战

> NIST PQC 标准化与迁移路线

---

## 1. 量子威胁

```
量子计算对密码学的威胁:

  Shor 算法 (1994):
    ↳ 多项式时间分解大数
    ↳ 攻破: RSA, ECC, Diffie-Hellman, DSA
    ↳ 影响的协议: TLS, SSH, PGP, VPN, 区块链

  Grover 算法 (1996):
    ↳ 平方根加速搜索
    ↳ 减弱: AES-256 → AES-128 安全强度
    ↳ 防御: 密钥长度加倍

  当前量子比特 (2024):
    - IBM: 1121 qubits (Condor)
    - Google: 105 qubits (Willow)
    - 破解 RSA-2048 需要: ~4000 逻辑 qubit
    - 预计时间线: 2035-2050 (专家中位预测)
```

---

## 2. NIST PQC 标准化

### 入选算法 (2024)
```yaml
NIST PQC 标准化算法:

  KEM (密钥封装):
    ML-KEM (FIPS 203): 基于 Module-Lattice
      原名: CRYSTALS-Kyber
      特点: 密钥小 (800B), 性能最优
      安全: IND-CCA2

  签名:
    ML-DSA (FIPS 204): 基于 Module-Lattice
      原名: CRYSTALS-Dilithium
      特点: 签名较大 (~2.4KB)
    
    SLH-DSA (FIPS 205): 基于 Hash
      原名: SPHINCS+
      特点: 最保守安全, 但签名巨大 (~17KB)
      适用: 证书签名等高价值场景

    FN-DSA (FIPS 206): 基于 Lattice
      原名: FALCON
      特点: 签名小但浮点运算复杂
```

---

## 3. 混合模式迁移

### TLS 1.3 + PQ 混合密钥交换
```python
# 混合 Key Exchange: X25519 + Kyber-768
# 优点: 即使其中一个被攻破, 另一个仍保护通信

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from kyber import Kyber768

class HybridKeyExchange:
    """传统 + 后量子: 双密钥交换"""

    def __init__(self):
        # 传统: X25519
        self.traditional_key = X25519PrivateKey.generate()

        # 后量子: Kyber-768
        self.pq_public_key, self.pq_secret_key = Kyber768.keygen()

    def encapsulate(self):
        """客户端: 生成混合共享密钥"""
        # 传统: X25519 ECDH
        server_pub = self.traditional_key.public_key()

        # PQ: Kyber 封装
        pq_ciphertext, pq_shared = Kyber768.enc(self.pq_public_key)

        return {
            'traditional_pub': server_pub,
            'pq_ciphertext': pq_ciphertext,
            'mode': 'hybrid_x25519+kyber768'
        }

    def decapsulate(self, traditional_peer_pub, pq_ciphertext):
        """服务端: 解密混合共享密钥"""
        # 传统 ECDH
        shared_1 = self.traditional_key.exchange(traditional_peer_pub)

        # PQ Kyber 解封
        shared_2 = Kyber768.dec(pq_ciphertext, self.pq_secret_key)

        # HKDF 组合双密钥
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        combined = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=b"hybrid_key_agreement"
        ).derive(shared_1 + shared_2)

        return combined
```

---

## 4. 证书迁移

```bash
# OpenSSL 3.x + PQC 支持 (OQS Provider)
# 安装
git clone https://github.com/open-quantum-safe/oqs-provider
cd oqs-provider && ./build.sh

# 生成 PQ 混合证书
openssl req -x509 -new -newkey dilithium3 \
  -keyout pq.key -out pq.crt -days 365 \
  -subj "/CN=example.com"

# 混合证书 (RSA 签名 + PQ 签名)
openssl req -x509 -new \
  -newkey rsa:2048 \
  -newkey dilithium3 \
  -keyout hybrid.key -out hybrid.crt
```

---

## 5. 迁移路线图

```yaml
后量子迁移四阶段:

  Phase 1: 评估 (2024-2025)
    - 盘点所有密码学资产 (证书/密钥/协议)
    - 识别依赖 RSA/ECC 的系统
    - 评估迁移优先级 (TLS 优先, IoT 次之)

  Phase 2: 混合模式 (2025-2027)
    - TLS: 部署 X25519+Kyber 混合
    - 代码签名: 双签名 (RSA/EC + Dilithium)
    - VPN: 混合密钥交换
    - 测试互操作性

  Phase 3: 原生 PQ (2027-2030)
    - 纯 PQ 证书 (Dilithium 主签)
    - 纯 Kyber KEM
    - 废弃 RSA-2048

  Phase 4: 敏捷密码学 (2030+)
    - 多算法支持 (快速切换)
    - 持续监控量子计算进展
    - 定期重新评估安全参数
```

| 系统 | 当前 | 混合阶段 | 纯 PQ 阶段 |
|------|------|---------|-----------|
| TLS | ECDHE | ECDHE + Kyber | Kyber |
| 代码签名 | RSA-2048 | RSA + Dilithium | Dilithium |
| VPN | DH-2048 | DH + Kyber | Kyber |
| SSH | Ed25519 | Ed25519 + Dilithium | Dilithium |
| PKI | RSA CA | 混合 CA | NIST PQC CA |

---

*上一篇：[量子密码学基础](02-quantum-crypto.md)*

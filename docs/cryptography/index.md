# 密码学基础

## 概述

密码学是信息安全的基石——从 HTTPS 到区块链，从密码哈希到数字签名，每个安全工程师都必须理解其核心概念。本章从实践角度介绍常用算法及其在安全领域中的应用。

---

## 密码学发展简史

```
古典密码 (古代→19世纪):
  Caesar密码 → Vigenère → Enigma
  特点: 替换/置换，手工操作

近代密码 (20世纪):
  DES (1977) → 3DES → AES (2001)
  特点: 标准化，计算机执行

现代密码 (21世纪):
  RSA (1977) → ECC (1985) → 后量子密码 (NIST 2024)
  特点: 公钥体系，量子抗性
```

---

## 密码学三大支柱

```
                    ┌──────────────────┐
                    │     密码学        │
                    └────────┬─────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
    ┌─────┴─────┐      ┌────┴────┐      ┌──────┴──────┐
    │ 哈希函数   │      │ 对称加密 │      │ 非对称加密   │
    │ (Hash)    │      │(Symmetric)│    │(Asymmetric) │
    └─────┬─────┘      └────┬────┘      └──────┬──────┘
          │                  │                  │
    完整性验证          数据机密性          密钥交换/签名
    - SHA-256          - AES-256-GCM       - RSA-2048
    - BLAKE3           - ChaCha20          - ECDSA P-256
    - SHA-3            - SM4 (国密)        - Ed25519
                                          - SM2 (国密)
```

---

## 常见误区澄清

| 误区 | 真相 |
|------|------|
| "MD5 还能用吗？" | ❌ 不能。MD5 碰撞已被实际演示。用 SHA-256 或 BLAKE3。 |
| "加密 = 签名？" | ❌ 完全不同。加密用公钥→保密性，签名用私钥→身份认证。 |
| "SHA-1 还安全？" | ❌ 不安全。2017 年 SHAttered 攻击实际生成了 SHA-1 碰撞。 |
| "AES-ECB 够用了" | ❌ 永远不要用 ECB 模式。相同明文产生相同密文（企鹅问题）。 |
| "自建加密算法更安全" | ❌ 这是密码学第一大谎言。用标准算法，别自己发明。 |
| "HTTPS = 绝对安全" | ⚠️ HTTPS 保护传输，不保护应用层漏洞（SQLi/XSS 仍存在）。 |
| "密码哈希用一次就行" | ❌ 需要迭代。BCrypt 默认 10 轮，Argon2 是当前最佳选择。 |
| "RSA 永远安全" | ⚠️ 量子计算机到来后不再安全。正在向 PQC 迁移。 |

---

## 本章内容

| 章节 | 内容 | 核心知识 |
|------|------|----------|
| [哈希算法](01-hash-algorithms.md) | MD5/SHA/BLAKE3 | 完整性验证、密码存储、文件校验 |
| [对称加密](02-symmetric-encryption.md) | AES/ChaCha20/SM4 | 数据加密、TLS 密码套件、块密码模式 |
| [TLS/HTTPS](03-tls-https.md) | SSL/TLS 1.3 | 证书链、握手过程、Forward Secrecy |
| [非对称加密与签名](04-asymmetric-signatures.md) | RSA/ECDSA/Ed25519 | 密钥交换、数字签名、证书体系 |
| [零知识证明](04-zkp-zero-knowledge.md) | ZK-SNARK/STARK | 隐私计算、区块链 L2、身份认证 |

---

## 学完本章你能够

- [x] 理解哈希、对称加密、非对称加密的区别和适用场景
- [x] 识别弱加密算法（MD5/SHA1/DES/RC4）并替换为安全算法
- [x] 正确使用 BCrypt/Argon2 存储密码
- [x] 理解 TLS 1.3 握手过程和 Forward Secrecy
- [x] 评估系统的密码学安全性
- [x] 为系统选择合适的加密方案

---

## 延伸阅读

- [Crypto 101 (免费电子书)](https://www.crypto101.io/)
- [Cryptopals 密码学挑战](https://cryptopals.com/)
- [NIST PQC 后量子密码标准](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [OWASP 密码存储 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

*下一篇：[哈希算法与完整性校验](01-hash-algorithms.md)*

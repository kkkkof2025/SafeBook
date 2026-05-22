# 零知识证明与隐私计算

## 概述

零知识证明 (ZKP) 是密码学的前沿——证明者向验证者证明"我知道某个秘密"而不泄露秘密本身。这项技术正在从理论走向实践：Zcash 的隐私交易、Ethereum L2 的 zk-Rollup、数字身份中的 zk-Proof。

---

## 1. ZKP 核心概念

### 1.1 阿里巴巴洞穴 (经典解释)

```
证明者 (Peggy) 知道洞穴深处的魔法门密码。
验证者 (Victor) 站在洞口外。

协议:
1. Peggy 随机选择 A 或 B 出口进入
2. Victor 随机喊 "从 A 出来" 或 "从 B 出来"
3. 如果 Peggy 知道密码 → 总能从正确的出口出来
4. 重复 N 次 → 作弊概率 = (1/2)^N

结果:
  Victor 确信 Peggy 知道密码
  但 Victor 对密码本身仍然一无所知
```

### 1.2 ZKP 三大特性

```
完备性 (Completeness):  诚实证明者总能让验证者信服
可靠性 (Soundness):     不知道秘密的人无法伪造证明
零知识 (Zero-Knowledge): 验证者除了"证明者知道秘密"外一无所获
```

---

## 2. zk-SNARKs

### 2.1 原理与流程

```yaml
zk-SNARK 生成过程:
  设置阶段 (Trusted Setup):
    1. 生成公共参考字符串 (CRS)
    2. α, β, γ, δ (有毒废弃物 → 销毁)

  证明生成:
    1. 将计算转换为 R1CS (Rank-1 Constraint System)
    2. R1CS → QAP (Quadratic Arithmetic Program)
    3. 使用椭圆曲线密码学生成证明

  验证:
    1. 验证配对 (Pairing Check)
    2. e(π_A, π_B) == e(π_C, g²) · e(π_H, γ⁻¹)
    3. 常量时间验证 (无论计算多复杂)
```

### 2.2 Circom + SnarkJS 实践

```circom
// multiplier.circom - 一个简单的零知识乘法证明

pragma circom 2.0.0;

// 公开信号: 乘积 c
// 私有信号: 因子 a, b (不泄露)
template Multiplier() {
    // 私有输入
    signal input a;
    signal input b;

    // 公开输出
    signal output c;

    // 约束: c = a * b
    c <== a * b;
}

component main = Multiplier();
```

```bash
# 1. 编译电路
circom multiplier.circom --r1cs --wasm --sym

# 2. 可信设置 (Powers of Tau)
snarkjs powersoftau new bn128 12 pot12_0000.ptau
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First Contribution"
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau

# 3. 生成证明密钥和验证密钥
snarkjs groth16 setup multiplier.r1cs pot12_final.ptau multiplier_0000.zkey
snarkjs zkey contribute multiplier_0000.zkey multiplier_0001.zkey --name="Second"
snarkjs zkey export verificationkey multiplier_0001.zkey verification_key.json

# 4. 生成证明
cat > input.json << EOF
{"a": 3, "b": 11}
EOF

node multiplier_js/generate_witness.js multiplier_js/multiplier.wasm input.json witness.wtns
snarkjs groth16 prove multiplier_0001.zkey witness.wtns proof.json public.json

# 5. 验证
snarkjs groth16 verify verification_key.json public.json proof.json
# → [INFO] snarkJS: OK!
```

---

## 3. zk-STARKs

### 3.1 STARK vs SNARK

| 特性 | zk-SNARK | zk-STARK |
|------|----------|----------|
| 可信设置 | 需要 (有毒废弃物) | 不需要 ✅ |
| 量子安全 | ❌ (基于椭圆曲线) | ✅ (基于哈希) |
| 证明大小 | 小 (~200B) | 大 (~100KB) |
| 验证时间 | 极快 (~10ms) | 快 (~50ms) |
| 通用性 | Groth16 最通用 | 原生通用 |
| 成熟度 | 高 (Zcash 2016) | 中 (StarkWare 2020) |

### 3.2 StarkNet (Cairo 语言)

```rust
// Cairo - StarkNet 上的零知识证明合约

#[starknet::contract]
mod PrivateVoting {
    #[storage]
    struct Storage {
        votes: LegacyMap<u256, u256>,  // proposal_id → encrypted_votes
        has_voted: LegacyMap<ContractAddress, bool>,
    }

    #[external]
    fn cast_vote(
        proposal_id: u256,
        // ZK Proof 证明了:
        // 1. 投票者是合法的 (在注册表中)
        // 2. 投票者没有投过票
        // 3. vote_value 在允许范围内 (0 或 1)
        proof: Array<felt252>,
        vote_commitment: felt252  // 投票值承诺 (不暴露实际值)
    ) {
        // 验证 ZK 证明 (STARK)
        let is_valid = zk_verifier::verify_proof(
            proof,
            vote_commitment,
            proposal_id
        );
        assert(is_valid, 'Invalid proof');

        // 存储加密投票
        votes::write(proposal_id, votes::read(proposal_id) + 1);
    }
}
```

---

## 4. 应用场景

### 4.1 zk-Rollup (Ethereum L2)

```
zk-Rollup 工作流:

  L2 (zkSync/StarkNet):
    1. 处理 N 笔交易
    2. 计算状态根更新
    3. 生成 ZK 证明 (证明这 N 笔交易有效)

  L1 (Ethereum):
    4. 提交: [新状态根] + [ZK 证明] + [压缩交易数据]
    5. 验证 ZK 证明 (常量时间)
    6. 更新 L1 状态根

  关键优势:
    - 数据可用性: 交易数据仍在 L1 (压缩)
    - 安全性: 继承 Ethereum L1 安全性
    - 吞吐量: 2000+ TPS (vs Ethereum L1 ~15 TPS)
```

### 4.2 隐私身份认证

```python
# 零知识证明: "我年满 18 岁" 但不泄露生日

class ZKAgeVerification:
    """零知识年龄验证"""

    def __init__(self):
        self.trusted_issuers = []  # 可信的发证机构 (政府等)

    def issue_credential(self, user_dob):
        """
        发证机构 (如政府) 签发数字凭证
        """
        # 1. 计算: age = current_date - dob
        age = self._calculate_age(user_dob)

        # 2. 签发凭证: Sign(age ≥ 18, user_pubkey)
        credential = {
            'user_pubkey': user_pubkey,
            'claim': 'age ≥ 18',
            'issued_by': 'government_ca',
            'signature': sign_credential(claim, government_key)
        }
        return credential

    def generate_age_proof(self, credential):
        """
        用户生成 ZK 证明: "我 ≥ 18岁" (不泄露生日/姓名)
        """
        # 构造电路:
        # 输入: birthday (private), 验证签名 (private)
        # 约束: verify_signature(credential) == True
        # 约束: age_from_birthday >= 18
        # 输出: proof (零知识)

        proof = create_zkp({
            'private': {
                'birthday': credential.birthday,
                'signature': credential.signature
            },
            'public': {
                'issuer_pubkey': government_pubkey,
                'threshold_age': 18
            },
            'statement': 'Age is at least 18'
        })

        return proof

    def verify_age_proof(self, proof):
        """
        服务提供商验证年龄 (不了解任何个人信息)
        """
        return verify_zkp(proof)

# 使用示例
user_proof = generate_age_proof(my_credential)
is_adult = verify_age_proof(user_proof)
# → True (验证者知道用户 ≥ 18岁，但不知道具体年龄、生日或姓名)
```

### 4.3 zk-KYC (隐私 KYC)

```solidity
// zk-KYC 智能合约
contract ZKKYCVerifier {
    using Pairing for *;

    struct VerificationKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }

    VerificationKey public vk;
    mapping(address => bool) public verified;

    function submitProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[2] memory input  // 公开输入: 空 (隐私保护)
    ) public {
        // 验证 ZK 证明: 用户已完成 KYC
        require(
            verifyProof(a, b, c, input),
            "Invalid KYC proof"
        );

        verified[msg.sender] = true;
        emit KYCVerified(msg.sender);
    }
}
```

---

## 5. 实战工具

| 工具 | 用途 | 语言 |
|------|------|------|
| **Circom** | 电路编写语言 | Circom |
| **SnarkJS** | ZK 证明生成/验证 | JavaScript |
| **Groth16** | 最紧凑的 ZK-SNARK | 库 |
| **Plonky2** | 递归 ZK 证明 | Rust |
| **Halo2** | 无需可信设置的 ZK | Rust |
| **Noir** | ZK 编程语言 | Noir |
| **ZoKrates** | 以太坊集成 ZK | Python/Rust |

---

## 参考资源

- [ZK Hack - 零知识学习平台](https://zkhack.dev/)
- [Awesome Zero Knowledge Proofs](https://github.com/matter-labs/awesome-zero-knowledge-proofs)
- [ZKP MOOC (Stanford/UC Berkeley)](https://zk-learning.org/)

---

*上一篇：[密码学算法与应用](./03-crypto-algorithms-deep-dive.md)*

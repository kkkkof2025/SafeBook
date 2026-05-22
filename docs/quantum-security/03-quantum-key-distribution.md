# 量子密钥分发 (QKD)

## 概述

量子密钥分发 (QKD) 是首个商业化的量子安全技术——利用量子力学原理在双方之间安全地建立共享密钥，任何窃听都会被立即检测到。

---

## 1. QKD 基本原理

### 1.1 BB84 协议

```
BB84 协议流程:

  1. Alice 准备:
     → 随机选择比特 (0/1) 和基 (⊕/⊗)
     → 发送单光子

     基 ⊕ (水平/垂直):  0 → → (水平)   1 → ↑ (垂直)
     基 ⊗ (对角线):    0 → ↗           1 → ↘

  2. Bob 测量:
     → 随机选择测量基 (⊕/⊗)
     → 如果用错基 → 随机结果
     → 如果用对基 → 正确结果

  3. 筛选 (Sifting):
     Alice 和 Bob 公开比较所用基 (不公开比特值)
     → 保留使用相同基的比特
     → 丢弃使用不同基的比特
     → 筛选后密钥 ≈ 原始比特的 50%

  4. 窃听检测:
     如果 Eve 窃听:
     → 必须测量光子 → 破坏量子态
     → 导致 Bob 的错误率升高
     → Alice/Bob 比较部分密钥 → 检测到窃听

  5. 错误校正 + 隐私放大:
     → 纠正传输错误
     → 压缩密钥以限制 Eve 可能的信息
```

### 1.2 安全性证明

```python
import numpy as np

class BB84Simulator:
    """BB84 协议模拟器"""

    def __init__(self, num_photons=1000):
        self.n = num_photons

    def simulate(self, eavesdropper=False):
        """模拟 BB84 协议"""

        # Alice 准备
        alice_bits = np.random.randint(0, 2, self.n)  # 0/1
        alice_bases = np.random.randint(0, 2, self.n)  # 0: ⊕, 1: ⊗

        # Bob 测量
        bob_bases = np.random.randint(0, 2, self.n)

        # 理想传输 (无窃听)
        if not eavesdropper:
            bob_bits = np.where(alice_bases == bob_bases, alice_bits,
                              np.random.randint(0, 2, self.n))
        else:
            # Eve 截获 + 重发
            eve_bases = np.random.randint(0, 2, self.n)
            eve_bits = np.where(alice_bases == eve_bases, alice_bits,
                              np.random.randint(0, 2, self.n))
            bob_bits = np.where(eve_bases == bob_bases, eve_bits,
                              np.random.randint(0, 2, self.n))

        # 筛选
        matching = alice_bases == bob_bases
        key_alice = alice_bits[matching]
        key_bob = bob_bits[matching]

        # QBER (量子比特错误率)
        qber = np.mean(key_alice != key_bob) if len(key_alice) > 0 else 0

        return {
            'raw_bits': self.n,
            'sifted_bits': len(key_alice),
            'qber': qber,
            'secure': qber < 0.11,  # BB84 安全阈值 ≈ 11%
            'key_rate': len(key_alice) / self.n
        }

# 运行模拟
sim = BB84Simulator(1000)

result_no_eve = sim.simulate(eavesdropper=False)
print(f"无窃听: QBER={result_no_eve['qber']:.3f}, "
      f"密钥率={result_no_eve['key_rate']:.2f}")

result_eve = sim.simulate(eavesdropper=True)
print(f"有窃听: QBER={result_eve['qber']:.3f}, "
      f"密钥率={result_eve['key_rate']:.2f}, "
      f"安全={result_eve['secure']}")
# 输出: QBER ≈ 0.25 (Eve 引入 25% 错误)
```

---

## 2. QKD 协议对比

| 协议 | 发明 | 编码方式 | 特点 |
|------|------|----------|------|
| **BB84** | 1984 | 偏振 | 最经典，最广泛实现 |
| **E91** | 1991 | 纠缠 | 基于贝尔不等式 |
| **BBM92** | 1992 | 纠缠 | 简化 E91 |
| **COW** | 2004 | 时间槽 | 相干单向 |
| **MDI-QKD** | 2012 | 测量设备无关 | 抗探测器攻击 |

---

## 3. 实际部署

### 3.1 QKD 网络架构

```
QKD 网络拓扑:

         Alice ──── [量子信道] ──── Bob
           │                       │
           └─── [经典信道] ────────┘
                      │
                密钥管理 (KMS)
                      │
                ┌─────┼─────┐
                │     │     │
             路由器  VPN  数据库
```

### 3.2 实际项目

```yaml
全球 QKD 网络:

  中国:
    - 京沪干线 (2000 km): 世界最长 QKD 骨干网
    - 墨子号卫星: 星地量子密钥分发 (1200 km)
    - 济南量子通信试验网

  欧洲:
    - SECOQC (2008): 维也纳 QKD 网络
    - OpenQKD (2019-2022): 多国测试平台

  美国:
    - DARPA Quantum Network (2003-2007)
    - Q-NEXT (DOE 量子研究中心)
    - Chicago Quantum Network
```

---

## 4. QKD 的局限性

```yaml
QKD 实际限制:

  1. 距离限制:
     - 光纤: ~100 km (无中继)
     - 可信中继: 可达 2000 km (京沪干线)
     - 星地: 可达 1200 km (墨子号)

  2. 密钥率:
     - 100 km 光纤: ~10 kbps
     - 距离越远, 衰减越快

  3. 成本:
     - 专用硬件 ($10K-$100K+)
     - 需要暗光纤或专用信道
     - 不可能通过互联网传输

  4. 认证:
     - 量子信道本身不提供认证
     - 需要预共享密钥或经典 PKI
     - QKD + 经典认证 = 完整方案

  5. 后量子密码 (PQC) 替代:
     - PQC 不需要专用硬件
     - PQC 可在现有网络上部署
     - 很多人认为 PQC 足够 → QKD 是否必要?
```

---

## 参考资源

- [BB84 原始论文](https://doi.org/10.1016/0304-3975(84)90070-7)
- [量子京沪干线](https://www.quantum-info.com/)
- [ETSI QKD 标准](https://www.etsi.org/technologies/quantum-key-distribution)

---

*上一篇：[PQC 迁移实践](02-pqc-migration.md)*

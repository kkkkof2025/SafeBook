# 芯片安全攻击

## 概述

芯片（SoC/微控制器/安全元件）是现代设备的信任根。攻击芯片意味着绕过所有上层安全机制——从故障注入到侧信道，本章深入硬件安全的"终极关卡"。

---

## 1. 芯片攻击面

```
芯片攻击向量:

  非侵入式 (Non-Invasive):
    ├── 侧信道分析 (功耗/电磁/时序)
    ├── 故障注入 (电压/时钟 Glitch)
    └── 光分析 (激光/光子发射)

  半侵入式 (Semi-Invasive):
    ├── 芯片开封 (Decapsulation)
    ├── 背面成像
    └── 激光故障注入

  侵入式 (Invasive):
    ├── FIB (聚焦离子束)
    ├── 微探针 (Probing)
    └── ROM 直接读取
```

---

## 2. 侧信道攻击

### 2.1 功耗分析 (SPA/DPA)

```python
import numpy as np
import matplotlib.pyplot as plt

class PowerAnalysisAttack:
    """
    简单功耗分析 (SPA) 和差分功耗分析 (DPA)
    """

    def spa_attack(self, traces, known_operations):
        """
        简单功耗分析
        - 直接从单条功耗曲线推断操作
        """
        for i, trace in enumerate(traces):
            # 检测高功耗段 (可能是 AES S-Box 操作)
            high_power = np.where(trace > np.mean(trace) * 1.5)[0]
            if len(high_power) > 0:
                print(f"Trace {i}: 高功耗区域在 {high_power[0]}-{high_power[-1]}")

    def dpa_attack(self, traces, plaintexts, key_guess_range=(0, 256)):
        """
        差分功耗分析
        - 使用统计方法从多条曲线中提取密钥
        """
        num_traces = len(traces)
        trace_len = len(traces[0])

        max_correlation = 0
        best_key = 0

        for key_guess in range(*key_guess_range):
            # 选择函数: 基于猜测密钥预测比特值
            predictions = np.zeros(num_traces)
            for i in range(num_traces):
                # 加密第一个字节 (S-Box 输出 bit 0)
                sbox_out = self._aes_sbox(plaintexts[i] ^ key_guess)
                predictions[i] = sbox_out & 1

            # 计算差分
            group0 = np.mean(traces[predictions == 0], axis=0)
            group1 = np.mean(traces[predictions == 1], axis=0)
            difference = group1 - group0

            correlation = np.max(np.abs(difference))
            if correlation > max_correlation:
                max_correlation = correlation
                best_key = key_guess

        return best_key, max_correlation

    def _aes_sbox(self, byte_val):
        """AES S-Box 查找表 (简化)"""
        sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            # ... (完整 256 字节)
        ]
        return sbox[byte_val % len(sbox)]
```

### 2.2 对策

```yaml
侧信道防护层次:

  算法层:
    - 掩码 (Masking): 随机化中间值
    - 隐藏 (Hiding): 恒定时间/功耗

  逻辑层:
    - WDDL (Wave Dynamic Differential Logic)
    - Dual-Rail 逻辑

  架构层:
    - 随机时钟
    - 随机电源
```

---

## 3. 故障注入

### 3.1 电压/时钟 Glitch

```python
# 故障注入工具: ChipWhisperer

# 电压 Glitch 攻击
class VoltageGlitch:
    """电压故障注入"""

    def __init__(self, target_device):
        self.target = target_device

    def voltage_glitch(self, voltage=3.3, glitch_point=0.5, glitch_width=10):
        """
        在关键操作时短时降低电压
        目标: 跳过指令 (如: 跳过认证检查)
        """
        # 设置正常电压
        self.target.set_voltage(voltage)

        # 在特定时钟周期注入 Glitch
        self.target.trigger_at(glitch_point)

        # 短时降低电压
        self.target.glitch_voltage(0.5, glitch_width)  # 0.5V, 10ns

        return self.target.read_response()

    def clock_glitch(self, glitch_point, glitch_width=5):
        """
        时钟故障注入
        通过短时抬高时钟频率, 导致时序违反
        """
        self.target.inject_clock_glitch(glitch_point, glitch_width)
        return self.target.read_response()
```

### 3.2 典型攻击场景

```yaml
故障注入常见目标:

  1. 跳过认证:
     固件: if (!verify_signature(fw)) fail();
     攻击: Glitch 在 verify_signature 返回值读取时
     → verify_signature 返回 0 (成功) → 绕过签名验证

  2. 提取密钥:
     固件: AES_Encrypt(plaintext, key);
     攻击: 在 AES_Encrypt 特定轮数注入故障
     → DFA (差分故障分析) → 恢复密钥

  3. 解锁调试接口:
     固件: if (JTAG_LOCKED) return;
     攻击: Glitch 在条件判断时
     → JTAG 保持解锁状态
```

---

## 4. 物理攻击工具链

| 工具 | 功能 | 难度 | 成本 |
|------|------|------|------|
| **ChipWhisperer** | 功耗分析 + 故障注入 | ⭐⭐⭐ | ~$3000 |
| **NewAE CW-Lite** | 入门级 SCA 平台 | ⭐⭐ | ~$500 |
| **Riscure Inspector** | 专业侧信道 | ⭐⭐⭐⭐⭐ | ~$50K+ |
| **FIB 工作站** | 芯片修改 | ⭐⭐⭐⭐⭐ | ~$1M+ |
| **逻辑分析仪** | 信号采集 | ⭐⭐⭐ | ~$200-$5000 |
| **显微镜** | 芯片检查 | ⭐⭐ | ~$500-$5000 |

---

## 参考资源

- [ChipWhisperer](https://chipwhisperer.com/)
- [Side Channel Attacks (NIST)](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- [Paul Kocher's DPA Paper (1999)](https://paulkocher.com/)

---

*上一篇：[固件逆向](02-firmware-reverse.md)*

# 硬件安全模块 (HSM) 实践

> 物理安全与加密密钥的终极防线

---

## 1. 硬件安全全景

```
硬件安全分层:
┌──────────────────────────────────────┐
│         HSM (硬件安全模块)            │
│    FIPS 140-2 Level 3/4 认证        │
│    物理防篡改 + 密钥仅在 HSM 内操作   │
├──────────────────────────────────────┤
│         TPM (可信平台模块)            │
│    平台完整性 + 密封存储             │
│    远程证明 (Remote Attestation)     │
├──────────────────────────────────────┤
│         Secure Enclave / TEE         │
│    Intel SGX / AMD SEV / ARM TrustZone│
│    可信执行环境                      │
└──────────────────────────────────────┘
```

---

## 2. TPM 应用

### TPM 远程证明
```python
# TPM 2.0 远程证明流程
class TPMAttestation:
    """
    证明: 验证远程平台的完整性状态
    1. Attestor (TPM) 响应挑战
    2. 签名 PCR 值 (平台配置寄存器) 的引用
    3. Verifier 验证: PCR 值是否匹配已知良好状态
    """

    def verify_quote(self, quote, signature, public_key):
        """验证 TPM Quote"""
        from cryptography.hazmat.primitives.asymmetric import ec

        # 验证 TPM 签名
        public_key.verify(signature, quote, ec.ECDSA(hashes.SHA256()))

        # 验证 PCR 值
        pcr_values = self.parse_pcr_values(quote)

        # 对比已知良好值
        known_good = {
            0: "SHA256:abc123...",  # BIOS/UEFI
            7: "SHA256:def456...",  # Secure Boot 状态
        }

        for pcr_id, expected in known_good.items():
            if pcr_values[pcr_id] != expected:
                return False, f"PCR {pcr_id} mismatch!"

        return True, "Platform integrity verified"
```

### TPM 密钥密封
```bash
# TPM 2.0 工具
tpm2_createprimary -C o -c primary.ctx

# 创建密封密钥 (绑定 PCR 状态)
tpm2_create -C primary.ctx -u key.pub -r key.priv \
  -i secret.txt -a "fixedtpm|fixedparent|sensitivedataorigin"

# 加载密钥
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx

# 密封到特定 PCR 值 (解锁条件)
tpm2_unseal -c key.ctx -p pcr:sha256:0,1,2,3,7
# 只有当 PCR 0,1,2,3,7 的值匹配时才可解密
```

---

## 3. 侧信道攻击

### 攻击分类
| 攻击类型 | 原理 | 目标 | 难度 |
|---------|------|------|------|
| 时序攻击 | 操作时间差异泄露密钥 | 密码算法 | ⭐⭐ |
| 功耗分析 (SPA/DPA) | 测量芯片功耗波形 | 加密密钥 | ⭐⭐⭐⭐ |
| 电磁分析 (EMA) | 测量电磁辐射 | 加密操作 | ⭐⭐⭐⭐ |
| 故障注入 | 电压/时钟/激光干扰 | 跳过安全检查 | ⭐⭐⭐ |
| Rowhammer | DRAM 位翻转 | 内存隔离 | ⭐⭐⭐ |
| Spectre/Meltdown | CPU 推测执行 | 任意内存 | ⭐⭐⭐⭐⭐ |

### 时序攻击示例
```python
import time

def timing_attack_example(target_func):
    """
    利用不同输入导致不同执行时间,推断密钥
    防御: 恒定时间实现
    """
    samples = []
    for guess in range(256):
        start = time.perf_counter_ns()
        target_func(guess)
        elapsed = time.perf_counter_ns() - start
        samples.append((guess, elapsed))

    # 分析: 错误猜测导致提前返回 (时间短)
    # 正确猜测继续计算 (时间长)
    return max(samples, key=lambda x: x[1])[0]

# ✅ 恒定时间比较
def constant_time_compare(a, b):
    """防止时序攻击的字符串比较"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0
```

---

## 4. 安全启动链

```
安全启动流程:
  ROM (不可篡改)
    ↓ (验证签名)
  UEFI/BIOS
    ↓ (验证签名)
  Bootloader (GRUB2 + shim)
    ↓ (验证签名)
  Linux Kernel
    ↓ (验证签名)
  Initramfs
    ↓ (dm-verity / fs-verity)
  Root Filesystem (只读)
    ↓
  应用程序

  UEFI Secure Boot:
    - 平台密钥 (PK): 顶层信任根
    - 密钥交换密钥 (KEK): 管理签名数据库
    - 签名数据库 (db/dbx): 允许/禁止的执行代码
```

### dm-verity 文件系统完整性
```bash
# 创建 dm-verity 哈希树
veritysetup format /dev/sda2 /dev/sda3 \
  --hash=sha256 --data-block-size=4096

# 挂载时验证
veritysetup open /dev/sda2 root /dev/sda3 <ROOT_HASH>
mount /dev/mapper/root /mnt/secure-root
# 任何文件修改 = 读取时 I/O 错误
```

---

## 5. JTAG/UART 安全

```yaml
硬件调试接口防护:

  JTAG (Joint Test Action Group):
    - 风险: 完全内存访问 + 调试控制
    - 防护:
      - 生产熔断 (eFuse): 永久禁用 JTAG
      - JTAG 密码保护
      - 仅开发板保留 JTAG

  UART (Universal Async Receiver-Transmitter):
    - 风险: 串口控制台获取 root shell
    - 防护:
      - U-boot: 禁用自动启动中断
      - 密码保护串口控制台
      - init=/sbin/init 固化内核参数

  闪存读取:
    - 风险: 拆焊 Flash 芯片直接读取固件
    - 防护:
      - 固件加密 (AES-XTS)
      - Secure Boot 链验证
      - 仅存储加密固件
```

---

*上一篇：[芯片安全深度](02-chip-security.md)*

*下一篇：[物联网设备硬件安全](03-iot-hardware.md)*

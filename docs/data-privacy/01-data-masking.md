# 数据脱敏与隐私保护技术

> 保护数据隐私的核心技术手段——从脱敏到差分隐私

---

## 数据脱敏方法论

### 脱敏类型

```text
数据脱敏分为以下几种方式：

静态脱敏（SDM）：
  在数据存储层进行脱敏
  适用：测试环境、开发环境、数据分析
  方法：创建脱敏副本

动态脱敏（DDM）：
  在数据访问时实时脱敏
  适用：生产环境的查询接口
  方法：代理层拦截处理
```

### 常用脱敏策略

```python
import re
import hashlib
import uuid
from typing import Any

class DataMasker:
    """多策略数据脱敏器"""
    
    @staticmethod
    def mask_email(email: str) -> str:
        """邮箱脱敏: user@example.com → u***@example.com"""
        parts = email.split('@')
        if len(parts) != 2:
            return email
        local, domain = parts
        if len(local) <= 2:
            masked_local = local[0] + '***'
        else:
            masked_local = local[0] + '***' + local[-1]
        return f'{masked_local}@{domain}'
    
    @staticmethod
    def mask_phone(phone: str) -> str:
        """手机号脱敏: 13800138000 → 138****8000"""
        if len(phone) != 11:
            return phone
        return phone[:3] + '****' + phone[-4:]
    
    @staticmethod
    def mask_id_card(id_card: str) -> str:
        """身份证脱敏: 110101199001011234 → 1101**********1234"""
        if len(id_card) < 8:
            return id_card
        return id_card[:4] + '*' * (len(id_card) - 8) + id_card[-4:]
    
    @staticmethod
    def mask_name(name: str) -> str:
        """姓名脱敏: 张三 → 张*，李小明 → 李**"""
        if len(name) <= 1:
            return name
        return name[0] + '*' * (len(name) - 1)
    
    @staticmethod
    def pseudonymize(value: str, salt: str = '') -> str:
        """假名化（可逆：使用相同 salt 生成相同假名）"""
        import hashlib
        raw = f'{value}{salt}'.encode('utf-8')
        return hashlib.sha256(raw).hexdigest()[:16]
    
    @staticmethod
    def generalize(value: int, granularity: int = 1000) -> str:
        """泛化（数据降精度）
        Example: salary 8500 → 8K-9K range
        """
        lower = (value // granularity) * granularity
        upper = lower + granularity
        return f'{lower}-{upper}'
    
    @staticmethod
    def mask_numeric(value: float, variance: float = 0.1) -> float:
        """数值扰动（加随机噪声）
        Example: age 28 → 29 (add ~10% noise)
        """
        import random
        noise = value * random.uniform(-variance, variance)
        return round(value + noise, 2)

# 使用示例
masker = DataMasker()
print(masker.mask_email("alice@example.com"))      # a***e@example.com
print(masker.mask_phone("13800138000"))             # 138****8000
print(masker.mask_name("张小明"))                    # 张**
print(masker.generalize(8500, 1000))                # 8000-9000
```

---

## 差分隐私（Differential Privacy）

### 核心概念

```
差分隐私保证：
  在数据集中添加或删除一条记录，
  查询结果的概率分布变化不超过 e^ε

数学定义：
  Pr[K(D) ∈ S] ≤ e^ε × Pr[K(D') ∈ S]

其中：
  ε (epsilon) = 隐私预算（越小越安全）
  D = 原始数据集
  D' = 相差一条记录的数据集
```

### Python 实现

```python
import random
import numpy as np

class DifferentialPrivacy:
    """差分隐私实现"""
    
    def __init__(self, epsilon: float = 1.0):
        """
        Args:
            epsilon: 隐私预算，越小隐私保护越强
                     0.1 = 强隐私，10 = 弱隐私
        """
        self.epsilon = epsilon
    
    def laplace_noise(self, sensitivity: float, size: int = 1) -> float:
        """拉普拉斯机制：添加拉普拉斯噪声"""
        scale = sensitivity / self.epsilon
        return np.random.laplace(0, scale, size)
    
    def gaussian_noise(self, sensitivity: float, delta: float = 1e-5, size: int = 1) -> float:
        """高斯机制：添加高斯噪声"""
        sigma = sensitivity * np.sqrt(2 * np.log(1.25 / delta)) / self.epsilon
        return np.random.normal(0, sigma, size)
    
    def noisy_count(self, true_count: int) -> int:
        """加噪计数"""
        noise = self.laplace_noise(sensitivity=1)
        return max(0, int(true_count + noise))
    
    def noisy_mean(self, data: list[float]) -> float:
        """加噪均值"""
        true_mean = np.mean(data)
        sensitivity = (max(data) - min(data)) / len(data)
        noise = self.laplace_noise(sensitivity)
        return true_mean + noise[0]

# 示例：保护用户年龄数据
dp = DifferentialPrivacy(epsilon=0.5)

ages = [25, 32, 28, 45, 31, 29, 38, 42, 27, 33]
true_mean = np.mean(ages)
noisy_mean = dp.noisy_mean(ages)

print(f"真实平均年龄: {true_mean:.1f}")
print(f"差分隐私平均年龄: {noisy_mean:.1f}")
print(f"隐私预算 ε = {dp.epsilon}（值越小越安全）")
```

### 隐私预算管理

```yaml
隐私预算分配策略:

总预算 ε = 1.0（一年用量）
├── 月度统计查询: 0.05 × 12 = 0.6
├── 季度深度报告: 0.1 × 2 = 0.2
└── 临时查询: 0.2

规则:
  - 每次查询消耗预算
  - 预算耗尽后停止查询
  - 可以"购买"额外预算（业务审批）
```

---

## AI 训练中的隐私保护

### 联合学习（Federated Learning）

```text
原理：数据不动模型动

流程：
1. 中央服务器分发模型到客户端
2. 客户端用本地数据训练模型
3. 只上传模型更新（梯度），不上传数据
4. 中央服务器聚合更新

隐私保护：
  - 原始数据不出本地
  - 可以叠加差分隐私（DP-FL）
  - 可以使用安全聚合（Secure Aggregation）
```

### DP-SGD（差分隐私训练）

```python
import torch

class DPSGD(torch.optim.SGD):
    """带差分隐私的 SGD 优化器"""
    
    def __init__(self, params, lr, batch_size, **kwargs):
        super().__init__(params, lr=lr, **kwargs)
        self.batch_size = batch_size
        self.max_grad_norm = 1.0  # 梯度裁剪阈值
        self.noise_multiplier = 0.1  # 噪声乘数
    
    def step(self, closure=None):
        for group in self.param_groups:
            for p in group['params']:
                if p.grad is None:
                    continue
                
                # 1. 梯度裁剪：限制梯度大小
                grad_norm = p.grad.data.norm(2)
                clip_coef = min(1, self.max_grad_norm / (grad_norm + 1e-8))
                p.grad.data.mul_(clip_coef)
                
                # 2. 添加高斯噪声：实现差分隐私
                noise = torch.normal(
                    0,
                    self.noise_multiplier * self.max_grad_norm / self.batch_size,
                    p.grad.shape
                )
                p.grad.data.add_(noise)
        
        super().step(closure)
```

---

## 数据生命周期保护

```
数据生命周期:

收集 → 传输 → 存储 → 使用 → 共享 → 删除

各阶段的保护措施:

收集:
  - 明确告知用途并获取同意
  - 最小化收集

传输:
  - TLS 1.3 加密
  - VPN 或专线

存储:
  - AES-256 列级加密
  - 行级访问控制

使用:
  - 动态脱敏
  - 审计日志

共享:
  - 差分隐私
  - 去标识化

删除:
  - 加密擦除
  - 碎片化覆写
```

---

## 安全检查清单

- [ ] PII 数据在存储和传输中加密
- [ ] 生产环境用动态脱敏
- [ ] 测试环境用静态脱敏
- [ ] AI 训练前数据进行脱敏/匿名化
- [ ] 差分隐私预算有管理和审计
- [ ] 数据删除支持完全擦除
- [ ] 密钥管理系统 KMS 已部署
- [ ] 数据访问有审计日志
- [ ] 定期做隐私影响评估（PIA）
- [ ] 数据分类分级制度已实施

---

## 延伸阅读

1. [《差分隐私》Cynthia Dwork 原书](https://www.cis.upenn.edu/~aaroth/privacybook.html)
2. [Google Differential Privacy Library](https://github.com/google/differential-privacy)
3. [TensorFlow Privacy](https://github.com/tensorflow/privacy)
4. [NIST 隐私框架](https://www.nist.gov/privacy-framework)
5. [OWASP 数据保护 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Data_Protection_Cheat_Sheet.html)
6. [中国信通院 — 数据脱敏白皮书](http://www.caict.ac.cn/)

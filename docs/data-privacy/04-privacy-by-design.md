# Privacy by Design（隐私设计）

## 七大基本原则

1. **主动而非被动**：预防而非补救
2. **默认隐私**：默认设置即最大隐私保护
3. **嵌入设计**：隐私是核心功能，非附加
4. **全功能而非零和**：隐私与功能可兼得
5. **全生命周期保护**：从采集到销毁全程保护
6. **可见与透明**：对利益相关者透明
7. **以用户为中心**：尊重用户隐私偏好

## 技术实现

### 数据最小化
```python
# 反模式：收集全部
user_data = request.form  # 勿用

# 正模式：仅收集必要
user_data = {
    'email': request.form.get('email'),
    'nickname': request.form.get('nickname')
}
```

### 差分隐私
```python
import random

def add_laplace_noise(value, epsilon=1.0, sensitivity=1.0):
    scale = sensitivity / epsilon
    noise = random.laplace(0, scale)
    return value + noise
```

### 数据脱敏策略
| 类型 | 方法 | 示例 |
|------|------|------|
| 姓名 | 替换 | 张** |
| 身份证 | 掩码 | 110***********0012 |
| 手机 | 掩码 | 138****1234 |
| 邮箱 | 替换 | u***@example.com |

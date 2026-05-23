# 安全编码实践（Web/JavaScript）

> 前端安全并非无关紧要——XSS/CSP/CSRF 是通往服务端后门的钥匙。

---

## XSS 防护

```javascript
// ❌ 不安全：直接插入用户内容
document.getElementById('output').innerHTML = userInput;

// ✅ 安全：textContent 自动转义
document.getElementById('output').textContent = userInput;

// ✅ 或使用 DOMPurify 净化
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
});

// ✅ React 自动转义（默认 safe）
function UserProfile({ username }) {
    return <div>{username}</div>; // 自动转义
}
// ⚠️ 危险用法（显式注入 HTML）
function Unsafe({ html }) {
    return <div dangerouslySetInnerHTML={{ __html: sanitize(html) }} />;
}
```

## CSP 配置

```html
<!-- 严格的 CSP -->
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' https://cdn.example.com;
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self' https://api.example.com;
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
">

<!-- 非严格模式（仅阻止 XSS，未阻断数据外泄） -->
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```

## CSRF 防护

```javascript
// 1. CSRF Token
// 服务端生成 → 嵌入页面 → 提交时验证
function addCsrfToken(form) {
    const token = document.querySelector('meta[name="csrf-token"]').content;
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = '_csrf';
    input.value = token;
    form.appendChild(input);
}

// 2. SameSite Cookie（推荐，不需要额外代码）
// 服务端设置
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly

// 3. 自定义请求头（API 接口）
// 前端在 API 调用中添加自定义头
fetch('/api/transfer', {
    method: 'POST',
    headers: {
        'X-Requested-With': 'XMLHttpRequest', // 浏览器跨域不允许自定义头
        'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify({ amount: 100 })
});
```

## 依赖安全

```json
{
  "scripts": {
    "audit": "npm audit --audit-level=high",
    "outdated": "npm outdated"
  },
  "overrides": {
    "minimatch": "^3.1.2",        // 修复已知漏洞子依赖
    "json5": "^2.2.3",
    "semver": "^7.5.2"
  }
}
```

```bash
# 常规安全扫描
npm audit --production
npx snyk test
npx socket scan

# 锁定具体版本（防止自动升级引入破坏性变更）
npm ci  # 使用 package-lock.json 精确安装
```

## 环境变量安全

```javascript
// ❌ 不安全：前端配置中硬编码敏感信息
const API_KEY = 'sk-xxxxxxxxxxxxxxxxxxxx'; // 前端完全可见

// ✅ 安全：通过后端代理
// 前端 → 后端 API 代理 → 第三方服务
// 后端添加 API Key（对前端透明）
fetch('/api/proxy/chat', {
    method: 'POST',
    body: JSON.stringify({ message: userInput })
});

// ✅ 构建时注入（Build-time env）
// Vite/Webpack
const apiUrl = import.meta.env.VITE_API_URL; // 前缀 VITE_ 的变量

// ✅ 运行时注入（更安全）
// 服务端渲染时注入配置
res.render('index', {
    nonce: crypto.randomBytes(16).toString('base64'),
    publicConfig: {
        apiEndpoint: process.env.API_ENDPOINT
    }
});
```

## 输入验证（前端+后端双验证）

```javascript
// 前端验证（用户体验，不依赖它防御）
function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// 后端验证（真正安全边界）
// 使用 zod 验证库
import { z } from 'zod';

const TransferSchema = z.object({
    fromAccount: z.string().regex(/^ACC\d{10}$/),
    toAccount: z.string().regex(/^ACC\d{10}$/),
    amount: z.number().positive().max(999999.99),
    note: z.string().max(200).optional()
});

// 验证
try {
    const data = TransferSchema.parse(req.body);
    // 安全类型推断的数据
} catch (err) {
    return res.status(400).json({ error: err.errors });
}
```

## 安全响应头

```javascript
// Express.js 配置
const helmet = require('helmet');

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.example.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://api.example.com"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// 手动设置
res.setHeader('X-Content-Type-Options', 'nosniff');
res.setHeader('X-Frame-Options', 'DENY');
res.setHeader('X-XSS-Protection', '0'); // 废弃，用 CSP 替代
```

*上一篇：[安全编码实践（Python）](01-secure-coding-python.md)*

*下一篇：[安全代码审查实战](03-code-review.md)*

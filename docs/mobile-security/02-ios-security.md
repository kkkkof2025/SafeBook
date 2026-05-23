# iOS 安全测试与加固

> iOS 应用的逆向分析与安全防护机制

---

## iOS 应用架构

```
IPA 包（实质是 ZIP）
├── Payload/
│   └── AppName.app/
│       ├── AppName              ← Mach-O 可执行文件
│       ├── Info.plist           ← 应用配置
│       ├── embedded.mobileprovision ← 配置文件
│       └── _CodeSignature/     ← 代码签名
└── iTunesMetadata.plist

iOS 安全机制：
- 沙箱（Sandbox）：每个应用独立目录
- 代码签名：所有应用必须签名
- 数据保护：文件级加密
- ASLR：地址空间随机化
- 越狱检测：应用可检测设备是否越狱
```

---

## 逆向分析工具链

```bash
# 1. 砸壳（解密 App Store 下载的应用）
# 越狱设备上使用
frida-ios-dump -u -o AppName.ipa AppName
# 或使用 dumpdecrypted

# 2. 查看 Mach-O 信息
otool -l AppName/Payload/AppName.app/AppName
otool -L AppName  # 查看链接的库

# 3. 反编译 Mach-O
class-dump AppName  # 导出 Objective-C 头文件
# 使用 Hopper Disassembler 或 IDA Pro 分析

# 4. 查看 Info.plist
plutil -p Info.plist
```

---

## 常见 iOS 漏洞测试

### 1. API 密钥硬编码

```bash
# 在 Mach-O 中搜索字符串
strings AppName | grep -iE "api.?key|secret|token|password|sk-"

# 使用 Hopper/IDA 查看字符串引用
# 关注：Base64 编码、加密算法常数、硬编码 URL
```

### 2. Keychain 测试

```bash
# 越狱设备上查看 Keychain 内容
# 安装 Keychain-Dumper
scp keychain_dumper root@<device-ip>:/tmp/
ssh root@<device-ip> /tmp/keychain_dumper

# 检查：
# - API Token 是否存储在 Keychain 中
# - Keychain 的 access group 是否设置过宽
```

### 3. NSUserDefaults 检查

```bash
# SSH 到越狱设备
ssh root@<device-ip>

# 查看应用沙箱
cd /var/mobile/Containers/Data/Application/<app-uuid>/
cat Library/Preferences/com.example.app.plist | plutil -p -

# 常见不安全存储：
# - API Token
# - 用户密码
# - 认证 Cookie
```

### 4. ATS（App Transport Security）绕过

```bash
# 解压 IPA 后查看 Info.plist
plutil -p Info.plist | grep -A 20 NSAppTransportSecurity

# ❌ 不安全的配置（允许所有 HTTP）：
# NSAllowsArbitraryLoads = true

# ✅ 安全的配置：
# NSAllowsArbitraryLoads = false
# NSExceptionDomains = { api.trusted.com = { NSExceptionAllowsInsecureHTTPLoads = false } }
```

### 5. 证书固定测试

```bash
# 设置 Burp Suite 代理（iOS 设置 → Wi-Fi → HTTP 代理）

# 如果没有证书固定 → 抓包成功
# 如果有证书固定 → SSL 握手失败

# 绕过：使用 SSL Kill Switch 2（越狱设备）
# 安装 SSLKillSwitch2（Cydia）
# 重启后尝试抓包
```

---

## Frida 在 iOS 上的应用

```bash
# 1. 启动 Frida 服务（越狱设备）
frida-server &

# 2. 列出进程
frida-ps -U

# 3. Hook 应用
frida -U -f com.example.app -l ios_hook.js
```

### 常用 Hook 脚本

```javascript
// Hook NSUserDefaults
ObjC.classes.NSUserDefaults['- objectForKey:'].implementation = function(key) {
    var value = this.super.objectForKey_(key);
    console.log('[NSUserDefaults] ' + key + ' = ' + value);
    return value;
};

// Hook URL 请求
var NSURL = ObjC.classes.NSURL;
var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

// Hook NSURLSession 请求
var NSURLSession = ObjC.classes.NSURLSession;
NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation = function(request, handler) {
    var url = request.URL().absoluteString();
    console.log('[URL Request] ' + url);
    return this.super.dataTaskWithRequest_completionHandler_(request, handler);
};
```

---

## iOS 数据保护

```swift
// 正确的 Keychain 使用方式
import Security

class KeychainManager {
    
    enum KeychainError: Error {
        case saveFailed
        case readFailed
        case deleteFailed
    }
    
    static func save(key: String, data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrAccessGroup as String: "com.example.shared" // 限制访问组
        ]
        
        // 先删除已有
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed
        }
    }
    
    static func read(key: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw KeychainError.readFailed
        }
        
        return result as? Data
    }
}
```

---

## iOS 安全加固清单

### 应用层

- [ ] 所有网络请求使用 HTTPS（强制 ATS）
- [ ] 敏感 API 实现证书固定
- [ ] 密钥存储在 Keychain 而非 UserDefaults
- [ ] Keychain access group 限制到最小范围
- [ ] 本地缓存数据加密存储
- [ ] 实现越狱检测（至少做基本检测）
- [ ] 反调试保护（`ptrace(PT_DENY_ATTACH, ...)`）
- [ ] 代码混淆（编译时符号混淆）
- [ ] URL Scheme 验证来源

### 数据保护

- [ ] Keychain 使用合适的 accesibility 级别
- [ ] 日志中不输出敏感数据
- [ ] NSUserDefaults 不存储 Token
- [ ] 本地 SQLite 数据库加密（SQLCipher）
- [ ] 剪贴板清空（敏感数据离开应用后）

### 逆向防护

- [ ] 代码使用 Swift（比 ObjC 更难以逆向）
- [ ] 关键逻辑在服务端实现
- [ ] 不使用的功能在 Release 版本移除
- [ ] 使用 iOS App Store 的 FairPlay 保护

---

## 延伸阅读

1. [iOS Security Guide (Apple)](https://www.apple.com/business/docs/site/iOS_Security_Guide.pdf)
2. [OWASP iOS 测试指南](https://owasp.org/www-project-mobile-security-testing-guide/)
3. [Frida iOS 文档](https://frida.re/docs/ios/)
4. [HackTricks iOS](https://book.hacktricks.xyz/mobile-apps/ios-pentesting)
5. [iOS 应用安全评估 (NSC)](https://developer.apple.com/documentation/security)

*上一篇：[Android 安全测试与逆向](01-android-security.md)*

*下一篇：[Android 应用安全加固](03-android-hardening.md)*

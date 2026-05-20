# 移动安全概述

> 手机才是大多数人真正的"个人电脑"——移动应用安全不可忽视

---

## 为什么移动安全对 AI 重要

```
AI 应用的客户端：
├── 移动端 AI 助手（ChatGPT App/文心一言 App/通义千问 App）
├── 移动端模型推理（端侧 AI）
├── 移动端数据采集（训练数据来源）
└── 移动端 API 调用（AI API 的客户端认证）
```

移动端是 AI 应用与用户的直接接触面，也是认证、数据传输、本地存储的攻击面。

---

## Android 安全

### Android 应用架构

```
APK 安装包
├── AndroidManifest.xml  ← 权限声明
├── classes.dex          ← DEX 字节码
├── res/                  ← 资源文件
└── META-INF/            ← 签名信息

Android 安全模型
├── 沙箱隔离：每个应用有自己的 UID
├── 权限系统：应用间权限隔离
├── 签名验证：APK 必须有开发者签名
└── SELinux：强制访问控制
```

### 常见 Android 漏洞

#### 1. 权限过度申请

```xml
<!-- ❌ 错误：申请不必要的权限 -->
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.READ_SMS" />

<!-- 权限应该遵循最小必要原则 -->
<!-- 一个计算器应用要读取通讯录？显然不合理 -->
```

#### 2. 不安全的数据存储

```java
// ❌ 错误：明文存储敏感数据
SharedPreferences prefs = getSharedPreferences("user_data", MODE_PRIVATE);
prefs.edit().putString("api_key", "sk-xxxxxxxxxxxx").apply();
prefs.edit().putString("token", "user_jwt_token").apply();

// ✅ 正确：使用 Android Keystore
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);

// 或使用 EncryptedSharedPreferences
EncryptedSharedPreferences.create(
    "secure_prefs",
    MasterKey.DEFAULT_MASTER_KEY_ALIAS,
    context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);
```

#### 3. WebView 漏洞

```java
// ❌ 错误：不安全的 WebView 配置
WebView webView = findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(true);
webView.addJavascriptInterface(new Bridge(), "bridge");

// ✅ 正确：安全的 WebView 配置
WebView webView = findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(false);           // 禁止文件访问
webView.getSettings().setAllowContentAccess(false);        // 禁止内容访问
webView.getSettings().setAllowFileAccessFromFileURLs(false); // 禁止跨域文件访问
webView.removeJavascriptInterface("searchBoxJavaBridge_");  // 移除 bridge
```

#### 4. 不安全的反编译保护

```java
// ❌ 错误：混淆不等于安全
// 混淆后的代码：

public class a {
    public String a(String b, String c) {
        // 反编译后仍然可以看到密钥
        String d = "aGVsbG8=";
        byte[] e = Base64.decode(d, 0);
        // ...
    }
}

// 正确的做法：密钥不在客户端！
// 使用 OAuth 获取临时令牌
// 或使用 Android SafetyNet/Play Integrity API 验证客户端完整性
```

---

## iOS 安全

### iOS 安全架构

```
iOS 安全模型
├── Secure Enclave：硬件安全模块
├── App Sandbox：应用沙箱
├── Code Signing：强制代码签名
├── Data Protection：文件级加密
├── Keychain：安全密钥存储
└── App Transport Security：强制 HTTPS
```

### 常见 iOS 漏洞

#### 1. 不安全的数据存储（Keychain）

```swift
// ❌ 错误：UserDefaults 存敏感信息
UserDefaults.standard.set("sk-xxxxxxxx", forKey: "api_key")

// ✅ 正确：使用 Keychain
import Security

func saveAPIKey(_ key: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "api_key",
        kSecValueData as String: key.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemAdd(query as CFDictionary, nil)
}
```

#### 2. ATS（App Transport Security）绕过

```xml
<!-- ❌ 错误：禁用 ATS，允许 HTTP -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>

<!-- ✅ 正确：只为特定域设置例外 -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
        </dict>
    </dict>
</dict>
```

#### 3. 不安全的 URL Scheme

```swift
// ❌ 错误：未验证 URL Scheme 来源
func application(_ app: UIApplication, 
                 open url: URL, 
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    // 直接处理传入的 URL，不验证来源
    handleDeepLink(url)
    return true
}

// ✅ 正确：验证来源和参数
func application(_ app: UIApplication, 
                 open url: URL, 
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    guard let sourceApp = options[.sourceApplication] as? String,
          sourceApp == "com.trusted.app" else {
        return false
    }
    guard validateParameters(url) else {
        return false
    }
    handleDeepLink(url)
    return true
}
```

---

## 移动端 API 安全

### 通用问题

| 漏洞 | Android | iOS |
|------|---------|-----|
| API Key 硬编码 | ❌ 反编译可获取 | ❌ 反编译可获取 |
| 未加密传输 | ❌ 中间人攻击 | ❌ 中间人攻击 |
| Token 存储不当 | ❌ SharedPreferences | ❌ UserDefaults |
| 证书固定缺失 | ❌ 代理可抓包 | ❌ 代理可抓包 |

### 证书固定（Certificate Pinning）

```java
// Android 证书固定
// 使用 OkHttp 库
OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(new CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAA=")
        .build())
    .build();
```

```swift
// iOS 证书固定（使用 TrustKit）
class URLSessionPinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, 
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let policies = [SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)]
        SecTrustSetPolicies(serverTrust, policies as CFTypeRef)
        
        var result: SecTrustResultType = .invalid
        SecTrustEvaluate(serverTrust, &result)
        
        completionHandler((result == .proceed || result == .unspecified) ? 
            .performDefaultHandling : .cancelAuthenticationChallenge, nil)
    }
}
```

---

## 移动安全检测工具

```bash
# 静态分析
# Android
jadx-gui app.apk             # 反编译
apktool d app.apk             # 解包
qark --apk app.apk            # 漏洞扫描

# iOS
class-dump AppName.app        # 类信息提取
objection -g AppName explore   # 运行时分析

# 动态分析
# Android
frida -U -f com.example.app   # Hook 分析
drozer console connect         # 攻击面测试

# iOS
frida -U -f com.example.app
needle --target com.example.app --bundle-id
```

---

## 移动安全检查清单

- [ ] 敏感数据（API Key、Token）不使用明文存储
- [ ] 网络传输强制 HTTPS，配置了证书固定
- [ ] 不申请不必要的权限
- [ ] WebView 配置安全
- [ ] 代码中不硬编码密钥
- [ ] 本地数据存储使用了平台安全组件（Keychain/Keystore）
- [ ] URL Scheme 验证了来源
- [ ] 应用有反调试/反篡改机制
- [ ] 定期做安全测试（静态+动态分析）

---

## 延伸阅读

1. [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
2. [Android 安全最佳实践](https://developer.android.com/privacy-and-security)
3. [iOS 安全指南](https://developer.apple.com/documentation/security)
4. [MSTG — Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
5. [Android Security Bulletins](https://source.android.com/docs/security/bulletin)
6. [Frida — 动态 Instrumentation 工具](https://frida.re/)
7. [jadx — Android 反编译工具](https://github.com/skylot/jadx)

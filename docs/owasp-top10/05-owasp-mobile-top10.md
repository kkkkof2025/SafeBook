# OWASP Mobile Top 10 实战

## 概述

移动应用安全有其独特的攻击面：不安全的数据存储、不安全的网络通信、客户端注入。OWASP Mobile Top 10 (2024) 覆盖了移动 App 最常见的安全风险。

---

## 1. OWASP Mobile Top 10 (2024)

| 排名 | 风险 | CVSS 平均 | 关键检测方式 |
|------|------|-----------|-------------|
| M1 | 不当的凭证使用 | 7.5 | 硬编码密钥扫描 |
| M2 | 不安全的供应链 | 8.1 | 第三方 SDK 审计 |
| M3 | 不安全的认证/授权 | 8.5 | JWT/Token 安全测试 |
| M4 | 输入验证不足 | 7.8 | Deep Link 注入 |
| M5 | 不安全的通信 | 7.2 | 证书固定 (Pinning) |
| M6 | 隐私控制不足 | 6.5 | 敏感数据泄露 |
| M7 | 代码完整性不足 | 7.0 | 应用篡改检测 |
| M8 | 配置错误 | 7.5 | 调试标志/日志泄露 |
| M9 | 不安全的数据存储 | 8.0 | 本地存储审计 |
| M10 | 加密不足 | 8.2 | 加密算法审计 |

---

## 2. M1: 不当的凭证使用

### 2.1 硬编码凭证检测

```python
# 移动 App 凭证扫描脚本

import re
import os
import zipfile
from pathlib import Path

class MobileCredentialScanner:
    """移动应用硬编码凭证扫描"""

    # 高风险模式
    PATTERNS = {
        'api_key': r'(?i)(api[_-]?key|api[_-]?secret|api[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9+/=_-]{20,})["\']',
        'aws_key': r'(?i)(AKIA|ASIA)[A-Z0-9]{16}',
        'private_key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']',
        'connection_string': r'(?i)(jdbc|mongodb|mysql|postgresql)://[^/\s]+:[^@\s]+@',
        'google_api': r'(?i)AIza[0-9A-Za-z\-_]{35}',
        'firebase_url': r'(?i)https://[a-z0-9-]+\.firebaseio\.com',
        'oauth_secret': r'(?i)(client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{10,}["\']',
    }

    def scan_apk(self, apk_path):
        """扫描 APK 文件"""
        findings = []

        with zipfile.ZipFile(apk_path, 'r') as apk:
            # 扫描 classes.dex
            for dex_file in [f for f in apk.namelist() if f.endswith('.dex')]:
                dex_content = apk.read(dex_file).decode('latin-1', errors='ignore')
                findings.extend(self._scan_content(dex_content, dex_file))

            # 扫描资源文件
            for res_file in apk.namelist():
                if any(res_file.endswith(ext) for ext in ['.xml', '.json', '.properties', '.plist', '.js']):
                    content = apk.read(res_file).decode('utf-8', errors='ignore')
                    findings.extend(self._scan_content(content, res_file))

        return findings

    def scan_ipa(self, ipa_path):
        """扫描 IPA 文件"""
        findings = []

        with zipfile.ZipFile(ipa_path, 'r') as ipa:
            for file in ipa.namelist():
                if file.endswith('.nib') or file.endswith('.storyboardc'):
                    continue

                try:
                    content = ipa.read(file).decode('utf-8', errors='ignore')
                    findings.extend(self._scan_content(content, file))
                except:
                    pass

        return findings

    def _scan_content(self, content, source):
        findings = []
        for pattern_name, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'source': source,
                    'type': pattern_name,
                    'match': self._mask_secret(match.group()),
                    'severity': 'CRITICAL' if pattern_name in ['api_key', 'aws_key', 'private_key']
                                else 'HIGH'
                })
        return findings

    def _mask_secret(self, secret):
        """脱敏显示"""
        if len(secret) > 15:
            return secret[:8] + '***' + secret[-4:]
        return secret[:4] + '***'
```

### 2.2 安全存储方案

```kotlin
// Android - 使用 EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

encryptedPrefs.edit()
    .putString("api_key", "super_secret_key")
    .apply()

// ❌ 不要这样
// SharedPreferences.getDefault().edit()
//     .putString("token", "plaintext_token")
//     .apply()
```

```swift
// iOS - 使用 Keychain
import Security

func secureStore(key: String, value: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: value.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]

    SecItemDelete(query as CFDictionary)
    return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
}

// ❌ 不要这样
// UserDefaults.standard.set("token", forKey: "auth_token")
```

---

## 3. M5: 不安全的通信

### 3.1 SSL Pinning 实现

```kotlin
// Android - Certificate Pinning (OkHttp)
val hostname = "api.example.com"
val certificatePinner = CertificatePinner.Builder()
    .add(hostname, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add(hostname, "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")  // 备份证书
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()

// 检测 SSL Pinning 是否被绕过
class PinningDetector : X509TrustManager {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        // 检查证书链
        val expectedHash = "EXPECTED_CERT_HASH"
        val actualHash = hashCert(chain[0])

        if (expectedHash != actualHash) {
            // 可能被 MITM/Frida 绕过
            reportTampering()
            throw CertificateException("Certificate pinning violation")
        }
    }
}
```

### 3.2 Frida 绕过 SSL Pinning

```javascript
// 用 Frida 测试 App 的 SSL Pinning 是否健壮

// 绕过 OkHttp CertificatePinner
Java.perform(function() {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function(hostname, peerCertificates) {
        console.log("[+] Bypassed OkHttp SSL Pinning for " + hostname);
        return;
    };

    // 绕过 TrustManager
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function() {
        console.log("[+] Bypassed TrustManager check");
        return;
    };
});

// 如果 App 仍然拒绝连接 → SSL Pinning 实现良好
// 如果绕过成功 → 需要加固 SSL Pinning
```

---

## 4. M8: 配置错误

### 4.1 Android 安全检查清单

```xml
<!-- AndroidManifest.xml 安全检查 -->

<!-- ✅ 禁止调试 -->
<application
    android:debuggable="false"
    android:allowBackup="false"
    android:usesCleartextTraffic="false">

<!-- ✅ 安全导出控制 -->
<activity
    android:name=".PrivateActivity"
    android:exported="false">

<receiver
    android:name=".PrivateReceiver"
    android:exported="false">

<provider
    android:name=".FileProvider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths" />
</provider>
```

### 4.2 自动化配置审计

```bash
# 使用 MobSF 进行自动化安全审计
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# 或使用 APKTool 手动检查
apktool d target.apk -o decompiled/
grep -r "android:debuggable=\"true\"" decompiled/
grep -r "android:allowBackup=\"true\"" decompiled/
grep -r "android:usesCleartextTraffic=\"true\"" decompiled/
grep -r "android:exported=\"true\"" decompiled/
```

---

## 5. M9: 不安全的数据存储

```bash
# Android 本地存储审计

# 1. SharedPreferences
adb shell run-as com.example.app
cat shared_prefs/*.xml

# 2. SQLite 数据库
adb shell run-as com.example.app
ls databases/
sqlite3 databases/app.db .dump

# 3. 内部存储
adb shell run-as com.example.app
find . -type f -exec grep -l "token\|password\|secret\|key\|api" {} \;

# 4. SD 卡 (公开可读)
adb shell ls /sdcard/Android/data/com.example.app/
```

---

## 参考资源

- [OWASP Mobile Top 10 (2024)](https://owasp.org/www-project-mobile-top-10/)
- [OWASP Mobile Security Testing Guide (MSTG)](https://github.com/OWASP/owasp-mstg)
- [MobSF 移动安全框架](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

---

*上一篇：[OWASP ASVS 标准解析](./04-owasp-asvs.md)*

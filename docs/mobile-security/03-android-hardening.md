# Android 安全加固

## 防护体系

### ProGuard/R8 混淆
```gradle
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}
```

### 完整性校验
```java
// APK 签名校验
public static boolean verifySignature(Context ctx) {
    try {
        PackageInfo pkg = ctx.getPackageManager()
            .getPackageInfo(ctx.getPackageName(), PackageManager.GET_SIGNATURES);
        String signature = pkg.signatures[0].toCharsString();
        return KNOWN_HASH.equals(sha256(signature));
    } catch (Exception e) { return false; }
}
```

## 常见漏洞

| 漏洞类型 | 风险 | 防护 |
|---------|------|------|
| WebView RCE | setJavaScriptEnabled + addJavascriptInterface | 禁用 JS 接口 |
| Intent 劫持 | 隐式 Intent 被恶意 App 接收 | 显式 Intent + 签名校验 |
| 数据存储泄露 | SharedPreferences 明文 | EncryptedSharedPreferences |
| SSL 未校验 | 中间人攻击 | Certificate Pinning |

## 反调试技术

```java
// 检测调试器
if (android.os.Debug.isDebuggerConnected()) {
    System.exit(1);
}

// 检测模拟器
public static boolean isEmulator() {
    return Build.FINGERPRINT.contains("generic")
        || Build.MODEL.contains("sdk")
        || Build.PRODUCT.contains("sdk");
}

// 检测 root
public static boolean isRooted() {
    File[] paths = {
        new File("/system/app/Superuser.apk"),
        new File("/sbin/su"),
        new File("/system/bin/su")
    };
    for (File f : paths) if (f.exists()) return true;
    return false;
}
```

## Hook 检测

- Xposed 框架检测：检查 `de.robv.android.xposed.XposedBridge`
- Frida 检测：检查端口 27042，检查 `frida-server` 进程
- 动态调试检测：`android.os.Debug.waitingForDebugger()`

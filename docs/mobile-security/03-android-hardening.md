# Android 应用安全加固

## 概述

Android 安全面临独特的挑战——APK 可以被解包、逆向、篡改后重新签名。加固（Hardening）通过混淆、完整性校验和反调试技术，大幅提高逆向和重打包的难度。

---

## 1. 代码混淆

### 1.1 ProGuard/R8 配置

```proguard
# proguard-rules.pro (推荐生产配置)

# 保留模型类（避免 JSON 反序列化失败）
-keep class com.example.app.model.** { *; }

# 移除日志（防止敏感信息泄露）
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# 保留 Retrofit 接口
-keep,allowobfuscation interface com.example.app.api.** { *; }

# 保留加密/签名相关类（防止功能失效）
-keep class com.example.app.security.** { *; }

# 高级混淆: 重打包检测类绝对不能混淆
-keep class com.example.app.IntegrityCheck { *; }

# 字符串加密（使用 DexGuard 等商业方案）
# 开源替代: StringFog
```

### 1.2 额外混淆工具

```bash
# 1. DexGuard (商业) — 控制流混淆 + 字符串加密 + 反射混淆

# 2. StringFog (开源): 自动 AES 加密所有字符串
# build.gradle 配置
stringFog {
    implementation 'com.github.megatronking.stringfog:xor:4.0.0'
    enable true
    debug false
    fogPackages = ['com.example.app']
}

# 3. native 层混淆 (O-LLVM)
# 编译时启用混淆:
# -mllvm -fla: 控制流平坦化
# -mllvm -sub: 指令替换
# -mllvm -bcf: 虚假控制流
```

---

## 2. 完整性保护

### 2.1 APK 签名校验

```java
public class IntegrityChecker {
    private static final String EXPECTED_SIGNATURE =
        "308204a830820390...";  // 你的证书指纹

    public static boolean isSignatureValid(Context context) {
        try {
            PackageInfo pkgInfo = context.getPackageManager()
                .getPackageInfo(
                    context.getPackageName(),
                    PackageManager.GET_SIGNING_CERTIFICATES
                );

            // Android P+ 支持多签名方案
            SigningInfo signingInfo = pkgInfo.signingInfo;
            if (signingInfo.hasMultipleSigners()) {
                return false;  // 多签名 = 可能被篡改
            }

            Signature[] signatures = pkgInfo.signingInfo
                .getApkContentsSigners();

            for (Signature sig : signatures) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(sig.toByteArray());
                String currentSig = bytesToHex(digest);

                Log.d("Integrity", "Signature: " + currentSig);

                if (EXPECTED_SIGNATURE.equals(currentSig)) {
                    return true;
                }
            }

            return false;
        } catch (Exception e) {
            // 异常可能来自 Hook (Xposed/Frida 修改了 PackageManager)
            return false;
        }
    }

    // Native 校验（更难绕过）
    static {
        System.loadLibrary("integrity-check");
    }
    public static native boolean nativeCheckSignature();
}
```

### 2.2 Native 签名校验（C/C++）

```c
// integrity_check.c
#include <jni.h>
#include <sys/stat.h>

JNIEXPORT jboolean JNICALL
Java_com_example_app_IntegrityChecker_nativeCheckSignature(
    JNIEnv *env, jclass clazz) {

    // 方法 1: 读取 /proc/self/maps 检查异常库
    // 检测 Xposed/Frida 的 .so 注入
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "xposed") ||
                strstr(line, "frida") ||
                strstr(line, "substrate")) {
                fclose(fp);
                return JNI_FALSE;
            }
        }
        fclose(fp);
    }

    // 方法 2: 检查 APK 文件哈希
    // getPackageCodePath → stat → 对比哈希

    return JNI_TRUE;
}
```

---

## 3. Root/调试检测

### 3.1 综合 Root 检测

```kotlin
object RootDetector {
    // 多层检测
    fun isRooted(): Boolean {
        return checkBuildTags()
            || checkSuExists()
            || checkSuperUserApk()
            || checkDangerousProps()
            || checkRootCloakingApps()
            || checkMagisk()
    }

    private fun checkBuildTags(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkSuExists(): Boolean {
        val paths = arrayOf(
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su"
        )
        return paths.any { File(it).exists() }
    }

    private fun checkDangerousProps(): Boolean {
        val dangerousProps = mapOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0"
        )
        return dangerousProps.any { (prop, value) ->
            try {
                val process = Runtime.getRuntime().exec("getprop $prop")
                val result = process.inputStream.bufferedReader().readText()
                result.contains(value)
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun checkMagisk(): Boolean {
        val paths = arrayOf(
            "/sbin/magisk", "/data/adb/magisk",
            "/data/adb/modules"
        )
        return paths.any { File(it).exists() }
    }

    // 反检测绕过: Magisk Hide 和 Shamiko 模块可隐藏上述特征
    // 高级检测: 使用 SafetyNet / Play Integrity API
}
```

### 3.2 反调试

```java
public class AntiDebug {
    static { System.loadLibrary("anti-debug"); }

    // Native: 检测 ptrace (TracerPid)
    public static native boolean isBeingDebugged();

    // Java: 检测调试器连接
    public static boolean isDebuggerConnected() {
        return Debug.isDebuggerConnected() ||
               Debug.waitingForDebugger();
    }

    // 检测 Frida (跨进程端口扫描)
    public static boolean isFridaRunning() {
        try {
            // Frida 默认端口 27042
            String[] ports = {"27042", "27043"};
            for (String port : ports) {
                Process p = Runtime.getRuntime().exec(
                    "cat /proc/net/tcp | grep " + port
                );
                String result = new BufferedReader(
                    new InputStreamReader(p.getInputStream())
                ).readLine();
                if (result != null && !result.isEmpty()) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }
}
```

---

## 4. 数据存储安全

```kotlin
// EncryptedSharedPreferences
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

// Android Keystore (硬件级密钥保护)
val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
    load(null)
}

val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder(
        "secure_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)  // 需要设备解锁
    .setKeySize(256)
    .build()
)
keyGenerator.generateKey()
```

---

## 5. Android 加固清单

```yaml
Android 安全加固分级:

  P0 (必须):
    - [ ] HTTPS + Certificate Pinning
    - [ ] ProGuard/R8 启用
    - [ ] EncryptedSharedPreferences
    - [ ] Android Keystore（生物识别绑定）
    - [ ] debuggable = false (release)
    - [ ] usesCleartextTraffic = false

  P1 (推荐):
    - [ ] APK 签名校验（Native 层）
    - [ ] Root 检测 + 运行退出
    - [ ] 模拟器检测
    - [ ] 调试器/Frida 检测
    - [ ] SafetyNet / Play Integrity

  P2 (高级):
    - [ ] Native 层核心逻辑（.so 文件）
    - [ ] 控制流混淆 (O-LLVM)
    - [ ] 字符串加密 (StringFog)
    - [ ] Dex 加固（DexGuard/iXGuard）
    - [ ] 反动态分析（时间检测、断点检测）
```

---

*上一篇：[iOS 安全](04-ios-security.md)*

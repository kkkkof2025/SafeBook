# Android 逆向与 Hook

> Android 逆向：APK → DEX → Smali → Java → Native Hook

---

## APK 结构

```
app.apk
├── AndroidManifest.xml       # 清单文件（二进制AXML格式）
├── classes.dex               # DEX字节码（Java代码编译结果）
├── classes2.dex              # 多DEX（64K方法数限制）
├── lib/
│   ├── armeabi-v7a/         # ARM 32位 Native库
│   ├── arm64-v8a/           # ARM 64位 Native库
│   └── x86/                 # x86模拟器库
├── res/                     # 资源文件
├── assets/                  # 原始资产文件
├── META-INF/                # 签名信息
└── resources.arsc           # 编译后的资源索引
```

## 反编译流程

```bash
# 1. APK → JAR（反编译DEX）
d2j-dex2jar.sh app.apk -o app.jar

# 2. JAR → Java 源码（JD-GUI / JADX）
jadx -d output_dir app.apk

# 3. 直接查看 Smali
apktool d app.apk -o output_dir

# 4. 查看 AndroidManifest
# Application / Activity / Service / BroadcastReceiver / Permission
# 重点关注 exported=true 的组件
```

## Frida Android 实战

### 环境配置
```bash
pip install frida-tools
# 手机端
adb push frida-server-16.0.1-android-arm64 /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server-16.0.1-android-arm64
adb shell /data/local/tmp/frida-server-16.0.1-android-arm64 &
```

### 常用 Hook 脚本

```javascript
// 1. 绕过 SSL Pinning
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.TrustManager');
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustAllManager = Java.registerClass({
        name: 'com.example.TrustAllManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    SSLContext.init(
        [TrustAllManager.$new()],
        null,
        null
    );
});

// 2. 枚举 Activity（了解应用功能）
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            if (name.indexOf('activity') != -1 ||
                name.indexOf('Activity') != -1) {
                console.log(name);
            }
        },
        onComplete: function() { console.log('Done!'); }
    });
});

// 3. 动态查看加密参数
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('Cipher.doFinal called');
        send('Input: ' + bytesToHex(input));
        var result = this.doFinal(input);
        send('Output: ' + bytesToHex(result));
        return result;
    };
});

// 辅助函数
function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
    }
    return hex.join('');
}

// 4. 绕过 Root 检测
Java.perform(function() {
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getPath();
        if (path.indexOf('su') != -1 ||
            path.indexOf('supersu') != -1) {
            console.log('Blocked root check: ' + path);
            return false;
        }
        return this.exists();
    };
});
```

## Objection（Frida GUI 封装）

```bash
# 安装
pip install objection

# 注入应用
objection -g com.example.app explore

# 常用命令
android hooking list activities        # 列出所有 Activity
android hooking list services           # 列出所有 Service
android sslpinning disable              # 一键关闭 SSL Pinning
android root disable                    # 一键绕过 Root 检测
android intent launch_activity [ACT]    # 直接启动 Activity
memory list modules                     # 列出加载的 Native 库
android keystore list                   # 列出 Keystore 密钥
```

## APK 工具链速查

```bash
# 重打包 + 签名
apktool b output_dir -o mod.apk
jarsigner -keystore my.keystore -storepass 123456 mod.apk alias
# 或使用 uber-apk-signer
java -jar uber-apk-signer.jar --apk mod.apk

# 提取加固壳分析
# 腾讯加固/360加固/娜迦加固
# 内存Dump（Frida Dump）
frida-dexdump -U -n com.example.app

# 查看签名信息
keytool -printcert -jarfile app.apk
```

## 安全建议

| 威胁 | 防御措施 |
|------|---------|
| APK 反编译 | 代码混淆（ProGuard/DexGuard） |
| Frida Hook | 反 Frida 检测 + SSL Pinning |
| 抓包 | 证书校验 + 双向认证 |
| 重打包 | 签名校验 + 完整性校验 |
| 动态调试 | 反调试 + 时间戳校验 |

*上一篇：[逆向工程基础](01-reverse-basics.md)*

*下一篇：[Frida 高级使用与脱壳](03-frida-advanced.md)*

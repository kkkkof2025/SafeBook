# Android 安全测试与逆向

> Android 应用的反编译、Hook 与安全评估方法论

---

## APK 结构与分析

```
APK = ZIP 文件
├── AndroidManifest.xml   ← 二进制 XML（需要用工具解析）
├── classes.dex           ← DEX 字节码
├── classes2.dex          ← 多 DEX 分割
├── res/                  ← 资源文件
├── lib/                  ← Native 库 (.so)
└── META-INF/             ← 签名和证书
```

### 反编译工具链

```bash
# 1. 解包 APK
apktool d app.apk -o app_decompiled/
# 得到: AndroidManifest.xml（明文）+ smali 代码 + 资源文件

# 2. 反编译为 Java
jadx app.apk
# GUI 工具，直接转换为可读的 Java 代码

# 3. 查看 DEX
dexdump -d classes.dex | head -50

# 4. 查看 Manifest (adertool)
aapt dump badging app.apk
```

### 自动化安全扫描

```bash
# 安装 MobSF（移动安全框架）
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# 上传 APK 到 http://localhost:8000 进行自动分析
# 包含：权限分析、证书分析、硬编码密钥、不安全存储等
```

---

## 常见漏洞测试

### 1. 检测硬编码密钥

```bash
# 在反编译的代码中搜索常见密钥模式
grep -r "api.key\|apikey\|API_KEY\|secret\|password" app_decompiled/smali/ --include="*.smali"

# 使用 jadx-gui 的 "Text Search" 功能更高效
# 常见搜索词：sk- | AKIA | -----BEGIN | jwt | token
```

### 2. 不安全的数据存储测试

```bash
# 在已 root 设备上检查应用数据
adb shell
su
cd /data/data/com.example.app/

# 检查 SharedPreferences
cat shared_prefs/*.xml

# 检查数据库
sqlite3 databases/app.db ".tables"
sqlite3 databases/app.db "SELECT * FROM user_data;"

# 检查文件权限
ls -la files/
```

### 3. HTTPS 检查

```bash
# 使用 Burp Suite 代理抓包
adb shell settings put global http_proxy 192.168.1.100:8080

# 检查证书固定
# 如果使用了证书固定，Burp 会报 SSL 错误

# 绕过证书固定（有 root 权限）
# 使用 Xposed 模块：JustTrustMe
# 或使用 Frida 脚本：frida -U -l ssl-pinning-bypass.js -f com.example.app
```

### 4. Intent 组件暴露测试

```bash
# 列出所有暴露的组件
aapt dump xmltree app.apk AndroidManifest.xml | grep -A 2 "activity\|service\|receiver\|provider" | grep -i "exported=true"

# 测试 Activity 越权访问
adb shell am start -n com.example.app/.secret.SettingsActivity

# 测试 Content Provider 越权
adb shell content query --uri content://com.example.app.provider/users/
```

---

## Frida Hook 实战

```bash
# 安装 Frida
pip install frida-tools

# 确认设备上的 Frida server
adb push frida-server-16.5.9-android-arm64 /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server-16.5.9-android-arm64
adb shell /data/local/tmp/frida-server-16.5.9-android-arm64 &

# 列出进程
frida-ps -U

# Hook 指定应用
frida -U -f com.example.app -l script.js
```

### Frida 脚本示例

```javascript
// Hook SSL 证书固定
Java.perform(function() {
    var ArrayList = Java.use('java.util.ArrayList');
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    
    TrustManagerImpl.verifyChain.implementation = function(untrusted, trustAnchor, used, 
        untrustedAnchor, ocspData, tlsSession) {
        return ArrayList.$new();  // 返回空列表，信任所有证书
    };
});

// Hook SharedPreferences
Java.perform(function() {
    var SharedPreferences = Java.use('android.content.SharedPreferences');
    SharedPreferences.getString.overload('java.lang.String', 'java.lang.String')
        .implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log('[SharedPref] ' + key + ' = ' + value);
        return value;
    };
});
```

---

## ProGuard/R8 混淆绕过

```bash
# 识别混淆映射文件
find app_decompiled/ -name "mapping.txt" -o -name "proguard*"

# 没有映射文件时的应对策略
# 1. 使用 jadx 的"重复代码分析"功能
# 2. 通过字符串引用来推断变量用途
# 3. 运行时 Hook 获取字段名

# jadx 反混淆
# 在 jadx-gui 中启用 "Deobfuscation" 选项
# Tools → Deobfuscation → 启用
```

---

## 安全检查清单

- [ ] 反编译后能找到敏感数据（密钥/Token/密码）？
- [ ] APK 中没有硬编码的 API 端点？
- [ ] 数据库文件没有明文存储敏感数据？
- [ ] SharedPreferences 没有存储密码/Token？
- [ ] 网络流量可以被抓包解密？
- [ ] Activity 可以被外部恶意应用启动？
- [ ] Content Provider 没有权限校验？
- [ ] 代码混淆生效（ProGuard/R8）？
- [ ] 有反调试/反模拟器检测？
- [ ] WebView 配置安全？

---

## 延伸阅读

1. [MobSF — 移动安全框架](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
2. [Frida 中文文档](https://frida.re/docs/home/)
3. [jadx — Android 反编译](https://github.com/skylot/jadx)
4. [APKTool](https://apktool.org/)
5. [Android Security Testing Guide (MSTG)](https://owasp.org/www-project-mobile-security-testing-guide/)
6. [HackTricks Android](https://book.hacktricks.xyz/mobile-apps/android-pentesting)

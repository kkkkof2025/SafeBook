# iOS 应用安全深度

## 概述

iOS 安全模型自诩为"安全堡垒"——但堡垒也会被攻破。本章深入 iOS 安全机制、越狱检测、应用完整性验证和 Keychain 保护。

---

## 1. iOS 安全架构

```
iOS 安全层次:

  应用层 (App)
    ├── App Sandbox（每个应用独立沙箱）
    ├── Data Protection (文件级加密)
    ├── Keychain (密钥存储)
    └── App Transport Security (ATS)

  系统层 (OS)
    ├── SEP (Secure Enclave Processor)
    ├── Code Signing (所有代码必须签名)
    ├── ASLR/KASLR
    └── Non-Executable Memory (XN)

  内核层 (Kernel)
    ├── PAC (Pointer Authentication)
    ├── KTRR (Kernel Text Read-only Region)
    └── Watchdog Monitoring
```

---

## 2. 应用安全分析

### 2.1 ATS 绕过检测

```bash
# 检查 App 是否启用了 ATS
# 方法 1: 查看 Info.plist
plutil -p Payload/App.app/Info.plist | grep NSAppTransportSecurity

# 危险配置示例:
# <key>NSAllowsArbitraryLoads</key><true/>  ← 允许所有 HTTP
# <key>NSExceptionDomains</key>             ← 域名级例外

# 检测: 使用 mitmproxy 中间人
mitmproxy -p 8080
# iPhone: 设置 → WiFi → HTTP 代理 → 192.168.1.x:8080

# 如果 App 信任 MITM 证书 → 可查看/修改所有通信
```

### 2.2 SSL Pinning 绕过

```bash
# 方法 1: Objection (Frida 框架)
objection -g com.target.app explore
# 进入 objection 后:
ios sslpinning disable

# 方法 2: Frida 手动 Hook
frida -U -l bypass_ssl.js -f com.target.app

# bypass_ssl.js:
/*
if (ObjC.available) {
    var hook = ObjC.classes.AFSecurityPolicy["-setAllowInvalidCertificates:"];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            args[2] = ptr(1);  // 强制允许无效证书
        }
    });
}
*/
```

---

## 3. 越狱检测与绕过

### 3.1 越狱检测方法

```objc
// iOS 越狱检测常见方法

// 1. 文件系统检测
- (BOOL)isJailbroken {
    NSArray *paths = @[
        @"/Applications/Cydia.app",
        @"/usr/sbin/sshd",
        @"/bin/bash",
        @"/etc/apt",
        @"/Library/MobileSubstrate"
    ];
    for (NSString *path in paths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            return YES;
        }
    }
    return NO;
}

// 2. fork() 检测（沙箱应用不能 fork）
- (BOOL)canFork {
    pid_t pid = fork();
    if (pid >= 0) {
        if (pid == 0) exit(0);  // 子进程
        return YES;  // 能 fork → 越狱
    }
    return NO;
}

// 3. 沙箱检测（访问越狱设备才能访问的路径）
- (BOOL)canWriteToRestricted {
    NSError *error;
    [@"test" writeToFile:@"/private/test.txt"
              atomically:YES
                encoding:NSUTF8StringEncoding
                   error:&error];
    [[NSFileManager defaultManager] removeItemAtPath:@"/private/test.txt" error:nil];
    return (error == nil);
}

// 4. dyld 注入检测
- (BOOL)hasSuspiciousDyld {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        NSString *name = [NSString stringWithUTF8String:_dyld_get_image_name(i)];
        if ([name containsString:@"Substrate"] ||
            [name containsString:@"Frida"]) {
            return YES;
        }
    }
    return NO;
}
```

### 3.2 绕过越狱检测

```bash
# Frida Hook 绕过
frida -U -l bypass_jb.js -f com.target.app

# bypass_jb.js (简单版)
/*
var fileExistsAtPath = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
Interceptor.attach(fileExistsAtPath.implementation, {
    onLeave: function(retval) {
        var path = ObjC.Object(args[2]);
        if (path.toString().includes("Cydia") ||
            path.toString().includes("apt")) {
            retval.replace(ptr(0));  // 返回 false
        }
    }
});
*/
```

---

## 4. Keychain 安全

```swift
// Keychain 安全存储（正确方式）

// 1. 使用 kSecAttrAccessibleWhenUnlockedThisDeviceOnly
// 防止迁移到其他设备，仅在解锁时可用
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "userToken",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAttrSynchronizable as String: false  // 不同步到 iCloud
]

// 2. 使用 Secure Enclave (SEP) 生成的密钥
let access = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet],  // FaceID/TouchID 绑定
    nil
)

// 3. 检测 Keychain dump
// 越狱设备 Keychain 可被 Keychain-Dumper 提取
// 防御: 应用级密钥派生 (PBKDF2) + SEP 绑定
```

---

## 5. iOS 安全检测清单

```yaml
iOS 应用安全检测清单:

  静态分析:
    - [ ] ATS 配置（Info.plist）
    - [ ] 硬编码密钥/URL (strings 命令)
    - [ ] 不安全第三方库 (CocoaPods/Carthage 版本)
    - [ ] PIE / ASLR 启用 (otool -hv)
    - [ ] ARC 适用 (检查 manual retain/release)

  动态分析:
    - [ ] SSL Pinning 是否存在
    - [ ] 越狱检测功能
    - [ ] Keychain 访问控制
    - [ ] 本地数据存储（SQLite/Realm/UserDefaults）
    - [ ] 后台任务数据泄漏

  工具:
    - objection (Frida)
    - MobSF (移动安全框架)
    - otool / class-dump (静态)
    - Needle (iOS 安全测试框架)
```

---

*上一篇：[Android 加固](03-android-hardening.md)*

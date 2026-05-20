# iOS 安全测试

## IPA 逆向分析

### 砸壳（Decrypt）
```bash
# 使用 frida-ios-dump
iproxy 2222 22
python3 dump.py com.example.app

# 手动砸壳
otool -l Payload/App.app/App | grep -A 4 LC_ENCRYPTION_INFO
```

### 静态分析
```bash
# 查看二进制的保护措施
otool -arch arm64 -l App | grep -E "PIE|STACK|NX|RPATH"

# 解析 Mach-O 结构
jtool2 -l App
class-dump -H App -o headers/
```

## 常见安全风险

### 越狱检测绕过
```objective-c
// 常见的越狱检测
BOOL isJailbroken() {
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"])
        return YES;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/private/var/lib/apt/"])
        return YES;
    return NO;
}
```

### Keychain 安全
```objective-c
// 安全存储
NSMutableDictionary *query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService: @"com.example.service",
    (__bridge id)kSecAttrAccount: username,
    (__bridge id)kSecValueData: [password dataUsingEncoding:NSUTF8StringEncoding],
    (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly
};
SecItemAdd((__bridge CFDictionaryRef)query, NULL);
```

## HTTPS 证书绑定
```objective-c
// TrustKit 证书固定
TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:@{
    kTSKSwizzleNetworkDelegates: @YES,
    kTSKPinnedDomains: @{
        @"api.example.com": @{
            kTSKEnforcePinning: @YES,
            kTSKIncludeSubdomains: @YES,
            kTSKPublicKeyHashes: @[
                @"HXXQgxueCXU7lM3FsR3sTNh3U=",
                @"iCh4b2wM9zFLwHc="
            ]
        }
    }
}];
```

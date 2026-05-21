# 逆向工程基础

> 逆向工程（Reverse Engineering）—— 从二进制代码还原逻辑，理解程序如何运作。

---

## 逆向分析流程

```
程序/固件/APK
    ↓
文件类型识别（file / Detect It Easy）
    ↓
静态分析（IDA / Ghidra / JADX）
    ↓
动态调试（GDB / Frida / x64dbg）
    ↓
算法还原 / Key 提取 / 漏洞发现
    ↓
编写脚本 / 生成报告
```

## 必备工具链

| 类别 | 工具 | 用途 |
|------|------|------|
| **文件识别** | file / DIE(Detect It Easy) / PEiD | 确定文件类型和编译器 |
| **反汇编** | IDA Pro / Ghidra / Binary Ninja | 将机器码转为汇编 |
| **反编译** | Ghidra / IDA Hex-Rays / JADX | 将汇编转为伪代码 |
| **调试器** | GDB / x64dbg / WinDbg / LLDB | 动态跟踪执行流程 |
| **Hook** | Frida / Xposed / DLL 注入 | 运行时修改行为 |
| **十六进制** | HxD / 010 Editor / ImHex | 直接编辑二进制数据 |
| **脱壳** | x64dbg + ScyllaHide / Unpacker | 去除软件保护壳 |
| **网络分析** | Wireshark / Fiddler / Proxifier | 分析网络通信协议 |

## Ghidra 入门

```java
// Ghidra 脚本示例：搜索字符串并交叉引用
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;

public class FindSensitiveStrings extends GhidraScript {
    public void run() throws Exception {
        String[] keywords = {"password", "secret", "key", "token", "admin"};
        for (String keyword : keywords) {
            // 搜索字符串
            Address addr = findBytes(
                currentProgram.getMinAddress(),
                keyword.getBytes()
            );
            if (addr != null) {
                println("Found: " + keyword + " at " + addr);
                // 交叉引用查看使用位置
                Reference[] refs = getReferencesTo(addr);
                for (Reference r : refs) {
                    println("  Referenced by: " + r.getFromAddress());
                }
            }
        }
    }
}
```

## Frida Hook 实战

```javascript
// 1. Hook Java 方法（Android）
Java.perform(function() {
    var MainActivity = Java.use('com.example.MainActivity');
    MainActivity.checkPassword.implementation = function(password) {
        console.log('[+] intercepting checkPassword: ' + password);
        var result = this.checkPassword(password);
        console.log('[+] result: ' + result);
        return true; // 总是返回 true
    };
});

// 2. Hook Native 函数
Interceptor.attach(Module.findExportByName('libnative.so', 'verify_key'), {
    onEnter: function(args) {
        console.log('verify_key args: ' + hexdump(args[0]));
    },
    onLeave: function(retval) {
        console.log('verify_key result: ' + retval);
        retval.replace(1); // 修改返回值
    }
});
```

## 常见算法识别

| 算法特征 | 识别方法 | 工具 |
|---------|---------|------|
| Base64 | 0x40行号+特定常数表 | 手动搜索 |
| AES | S盒常数 0x63,0x7c,0x77... | findcrypt |
| MD5 | 初始化常数 0x67452301 | findcrypt |
| SHA256 | 常数 0x6a09e667 | findcrypt |
| RSA | 大数运算 + powmod | 行为分析 |
| CRC32 | 多项式表 0xEDB88320 | findcrypt |
| XOR | 特征不明显 | 手动逆向 |

## 脱壳基础

```bash
# UPX 脱壳
upx -d packed.exe -o unpacked.exe

# ASPack 脱壳
# 手动 ESP 定律法（最常见的脱壳技巧）
# 1. OD/x64dbg 加载程序
# 2. F8 单步到第一个 JMP/CALL
# 3. 下硬件断点 HW ESP
# 4. F9 运行 → 断在 OEP
# 5. Dump → importRE 修复 IAT

# VMProtect/Themida 等强壳
# 需要使用专业工具或手动分析虚拟机入口
```

## 实战练习资源

| 平台 | 难度 | 特点 |
|------|------|------|
| **Crackmes.one** | ⭐~⭐⭐⭐⭐⭐ | 纯逆向挑战 |
| **Reversing.kr** | ⭐⭐~⭐⭐⭐⭐ | 韩国逆向站 |
| **PwnableKr** | ⭐⭐~⭐⭐⭐⭐ | 包含逆向 |
| **Root-Me** | ⭐~⭐⭐⭐⭐⭐ | 分级体系明确 |
| **Flare-On** | ⭐⭐⭐~⭐⭐⭐⭐⭐ | 年度挑战赛 |

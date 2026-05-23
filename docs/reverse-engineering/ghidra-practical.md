# Ghidra 逆向工程实战

> NSA 开源逆向工具从入门到精通

---

## 1. Ghidra 快速上手

```bash
# 安装 (需 JDK 17+)
# 下载: https://github.com/NationalSecurityAgency/ghidra/releases
unzip ghidra_11.0_PUBLIC_20240101.zip
cd ghidra_11.0_PUBLIC
./ghidraRun

# 基本工作流:
# File → New Project → Import File → Double-click to open
# Analysis → Auto Analyze (默认选项)
# Window → Decompile → 查看 C 伪代码
```

---

## 2. 分析 C 程序

```c
// 示例: 认证函数逆向
// 原始代码:
bool authenticate(char *password) {
    return strcmp(password, "SuperSecret123") == 0;
}

// Ghidra 反编译结果:
undefined8 authenticate(char *password) {
    int result;
    result = strcmp(password, "SuperSecret123");
    return (ulong)(result == 0);
}

// 发现: 明文硬编码密码!
```

### 重命名与注释
```
逆向分析步骤:
1. 找到关键函数: Symbol Tree → Functions → authenticate
2. 重命名变量: 右键变量 → Rename Variable
3. 添加注释: 右键行号 → Set Comment
4. 标记数据类型: 右键 → Retype Variable → char*
5. 修补常量: 修改硬编码值 (不推荐用于真实逆向)
```

---

## 3. 恶意软件分析实践

### 检测反调试
```c
// 识别反调试代码 (Ghidra 反编译)
BOOL CheckDebugger() {
    // IsDebuggerPresent → 反调试
    if (IsDebuggerPresent() != 0) {
        return 1;
    }

    // NtGlobalFlag → 检测调试器标志
    int NtGlobalFlag = *(int *)(0x7FFE02D0);
    if ((NtGlobalFlag & 0x70) != 0) {
        return 1;
    }

    // CheckRemoteDebuggerPresent
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &flag) && flag) {
        return 1;
    }
    return 0;
}

// Ghidra 分析:
// 1. 找到此函数
// 2. 查看调用图: Window → Function Call Graph
// 3. 找到调用处 → 可能的分支: if(CheckDebugger()) ExitProcess(0)
// 4. Patch: 修改条件跳转为无条件跳转 (绕过)
```

### API 哈希解析
```python
# Ghidra Script: 解析 API 哈希
# Window → Script Manager → New Python Script

from ghidra.program.model.symbol import SymbolUtilities

def resolve_api_hash(hash_function_addr, api_hashes):
    """解析通过哈希调用的 API 函数名"""
    listing = currentProgram.getListing()
    function = getFunctionAt(toAddr(hash_function_addr))

    # 常见 API 哈希算法: ROR13
    def ror13_hash(name):
        hash_val = 0
        for c in name:
            hash_val = ((hash_val >> 13) | (hash_val << 19)) & 0xFFFFFFFF
            hash_val = (hash_val + ord(c)) & 0xFFFFFFFF
        return hash_val

    # 暴力匹配常见 DLL 导出函数
    resolved = {}
    for dll in ['kernel32.dll', 'ntdll.dll', 'advapi32.dll']:
        for api in get_dll_exports(dll):
            h = ror13_hash(api)
            if h in api_hashes:
                resolved[h] = f'{dll}!{api}'

    return resolved

# 使用:
# hashes = [0x12345678, 0x9ABCDEF0]
# result = resolve_api_hash(0x401000, hashes)
# → {0x12345678: 'kernel32.dll!VirtualAlloc', ...}
```

---

## 4. Ghidra 脚本自动化

```python
# 自动查找危险 API 调用
# Window → Script Manager → New Python Script
# 保存到 ~/ghidra_scripts/FindDangerousAPIs.py

DANGEROUS_APIS = [
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect',
    'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx',
    'OpenProcess', 'ReadProcessMemory', 'QueueUserAPC',
    'CryptEncrypt', 'CryptDecrypt', 'WinHttpOpen',
    'URLDownloadToFile', 'WinExec', 'CreateProcess',
    'RegCreateKey', 'RegSetValue', 'CreateService',
    'StartService', 'DeleteFile', 'MoveFile',
]

def find_dangerous_calls():
    listing = currentProgram.getListing()
    symbol_table = currentProgram.getSymbolTable()

    findings = []
    for api_name in DANGEROUS_APIS:
        symbols = symbol_table.getSymbols(api_name)
        for symbol in symbols:
            references = getReferencesTo(symbol.getAddress())
            for ref in references:
                func = getFunctionContaining(ref.getFromAddress())
                findings.append({
                    'api': api_name,
                    'caller': func.getName() if func else 'Unknown',
                    'address': ref.getFromAddress(),
                })

    # 输出到控制台
    for f in sorted(findings, key=lambda x: x['address']):
        print(f"  {f['address']}: {f['api']} ← {f['caller']}")

find_dangerous_calls()
```

---

## 5. Ghidra 高级功能

| 功能 | 快捷键 | 用途 |
|------|--------|------|
| 反编译 | Ctrl+E | 查看 C 伪代码 |
| 交叉引用 | 右键→References→Show References To | 谁调用了此地址 |
| 数据类型编辑 | T | 修改数据类型 |
| 搜索内存 | S | Search Memory (字符串/字节) |
| 修补指令 | Ctrl+Shift+G | Patch Instruction |
| 函数图 | 右键→Graph→Function Call Graph | 可视化调用关系 |
| 字符串搜索 | Search→For Strings | 查找硬编码字符串 |
| 字节搜索 | Search→Memory | 搜索字节模式 |
| 版本跟踪 | Tools→Version Tracking | 比较两个二进制文件 |
| 导出程序 | File→Export Program | 导出为 C/XML/Binary |

---

*上一篇：[反汇编基础](02-reverse-engineering-basics.md)*

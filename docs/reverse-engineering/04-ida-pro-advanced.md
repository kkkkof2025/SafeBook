# IDA Pro 高级逆向技术

## 概述

IDA Pro 是二进制逆向工程的行业标准。从基础的静态分析到复杂的脚本自动化、插件开发和处理器模块编写——掌握 IDA Pro 的高级功能是理解恶意软件和漏洞利用的关键。

---

## 1. IDA Python 自动化

### 1.1 基础脚本框架

```python
# ida_analyzer.py - IDA Python 自动化脚本

import idaapi
import idautils
import idc
import ida_bytes
import ida_name
import ida_funcs
import ida_xref

class BinaryAnalyzer:
    """二进制自动化分析器"""

    def __init__(self):
        self.findings = []

    def rename_crypto_functions(self):
        """自动识别和重命名加密函数"""

        # 加密算法特征常量
        crypto_constants = {
            'md5': [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
            'sha1': [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            'sha256': [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                       0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19],
            'aes_sbox': [0x637C777B, 0xF26B6FC5, 0x3001672B, 0xFED7AB76],
            'rc4': [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
        }

        for segment in idautils.Segments():
            seg_start = idc.get_segm_start(segment)
            seg_end = idc.get_segm_end(segment)

            for algo, constants in crypto_constants.items():
                # 在数据段搜索常量
                for ea in range(seg_start, seg_end - len(constants) * 4, 4):
                    match = True
                    for i, const in enumerate(constants):
                        if ida_bytes.get_dword(ea + i * 4) != const:
                            match = False
                            break

                    if match and algo == 'aes_sbox':
                        # 找到 AES S-Box → 查找引用
                        for xref in idautils.XrefsTo(ea):
                            func = ida_funcs.get_func(xref.frm)
                            if func:
                                name = f'aes_encrypt_{algo}'
                                ida_name.set_name(func.start_ea, name)
                                self.findings.append({
                                    'type': 'crypto',
                                    'address': hex(func.start_ea),
                                    'algorithm': 'AES',
                                    'renamed_to': name
                                })

    def find_obfuscated_strings(self):
        """检测混淆字符串（栈字符串构造）"""

        stack_string_patterns = [
            # mov dword ptr [ebp-XX], 'part'  (栈字符串)
            'stack_string_xor',  # XOR 解码
            'stack_string_sub',  # SUB 运算解码
            'stack_string_add',  # ADD 运算解码
        ]

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)

            # 分析基本块
            flow_chart = idaapi.FlowChart(func)
            for block in flow_chart:
                consecutive_moves = 0
                for head in idautils.Heads(block.start_ea, block.end_ea):
                    mnem = idc.print_insn_mnem(head)

                    if mnem == 'mov':
                        # 检测: mov [ebp-XX], imm32 (四字节)
                        op2 = idc.print_operand(head, 1)
                        if op2.startswith('0x') and len(op2) == 10:
                            # 检查是否是可打印 ASCII
                            imm_val = idc.get_operand_value(head, 1)
                            chars = [
                                (imm_val >> 0) & 0xFF,
                                (imm_val >> 8) & 0xFF,
                                (imm_val >> 16) & 0xFF,
                                (imm_val >> 24) & 0xFF,
                            ]
                            if all(0x20 <= c <= 0x7E for c in chars):
                                consecutive_moves += 1

                if consecutive_moves >= 3:
                    # 可能的栈字符串构造
                    self.findings.append({
                        'type': 'stack_string',
                        'function': hex(func_ea),
                        'block': hex(block.start_ea),
                        'consecutive_moves': consecutive_moves
                    })

    def detect_anti_analysis(self):
        """检测反分析技术"""

        anti_debug_apis = [
            'IsDebuggerPresent',
            'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess',
            'OutputDebugStringA',
            'NtSetInformationThread',
        ]

        anti_vm_apis = [
            # VM 检测
            'Rdtsc',  # 时间检测
            'cpuid',  # CPU 特性检测
        ]

        for func_ea in idautils.Functions():
            func_name = ida_name.get_name(func_ea)

            # 检查导入函数
            if any(api in func_name for api in anti_debug_apis):
                self.findings.append({
                    'type': 'anti_debug',
                    'function': hex(func_ea),
                    'api': func_name
                })

    def export_report(self, filepath='analysis_report.json'):
        """导出分析报告"""
        self.rename_crypto_functions()
        self.find_obfuscated_strings()
        self.detect_anti_analysis()

        with open(filepath, 'w') as f:
            json.dump({
                'binary': idc.get_input_file_path(),
                'md5': idautils.GetInputFileMD5(),
                'findings': self.findings,
                'stats': {
                    'functions': len(list(idautils.Functions())),
                    'strings': len(list(idautils.Strings())),
                    'imports': len(list(idautils.Entries())),
                }
            }, f, indent=2)

        print(f"Report saved to {filepath}")

# 运行
analyzer = BinaryAnalyzer()
analyzer.export_report()
```

### 1.2 污点追踪

```python
# IDA Python 污点追踪

class TaintTracker:
    """数据流污点追踪"""

    def __init__(self):
        self.tainted = set()
        self.sources = set()  # 污点源 (recv/read/fgets)
        self.sinks = set()    # 危险操作 (system/exec/strcpy)

    def find_user_input_sources(self):
        """查找用户输入源"""
        source_apis = [
            'recv', 'recvfrom', 'read', 'fread',
            'fgets', 'scanf', 'gets',
            'recvmsg', 'WSARecv'
        ]

        for func_ea in idautils.Functions():
            name = ida_name.get_name(func_ea)
            if any(api in name.lower() for api in source_apis):
                # 找到调用源 API 的地方
                for xref in idautils.XrefsTo(func_ea):
                    self.sources.add(xref.frm)

    def find_dangerous_sinks(self):
        """查找危险操作"""
        sink_apis = [
            'system', 'execve', 'popen',
            'strcpy', 'strcat', 'sprintf', 'vsprintf',
            'memcpy', 'memmove',
            'CreateProcess', 'WinExec'
        ]

        for func_ea in idautils.Functions():
            name = ida_name.get_name(func_ea)
            if any(api in name for api in sink_apis):
                for xref in idautils.XrefsTo(func_ea):
                    self.sinks.add(xref.frm)

    def trace_taint(self, source_ea):
        """从源开始追踪数据流"""
        visited = set()
        queue = [source_ea]

        while queue:
            ea = queue.pop(0)
            if ea in visited:
                continue
            visited.add(ea)

            self.tainted.add(ea)

            # 检查是否到达危险 sink
            if ea in self.sinks:
                self.findings.append({
                    'type': 'taint_reach_sink',
                    'source': hex(source_ea),
                    'sink': hex(ea),
                    'severity': 'HIGH'
                })

            # 查找数据引用 (mov, lea, etc.)
            for xref in idautils.XrefsFrom(ea):
                if xref.type in [ida_xref.fl_F, ida_xref.fl_CN]:
                    continue  # 跳过控制流引用

                queue.append(xref.to)

    def full_taint_analysis(self):
        """完整污点分析"""
        self.find_user_input_sources()
        self.find_dangerous_sinks()

        for source in self.sources:
            self.trace_taint(source)

        return self.findings
```

---

## 2. IDA 插件开发

### 2.1 反反调试插件

```python
# ida_anti_anti_debug_plugin.py

import idaapi
import idc

class AntiAntiDebugPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "反反调试分析插件"
    help = "自动检测和标记反调试代码"
    wanted_name = "Anti-Anti-Debug"
    wanted_hotkey = "Ctrl-Shift-A"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        """分析当前二进制中的反调试技术"""

        anti_debug_patterns = {
            'PEB.BeingDebugged': [
                'mov eax, fs:[30h]',
                'movzx eax, byte ptr [eax+2]'
            ],
            'NtGlobalFlag': [
                'mov eax, fs:[30h]',
                'mov eax, [eax+68h]'
            ],
            'HeapFlags': [
                'mov eax, fs:[30h]',
                'mov eax, [eax+18h]',
                'mov eax, [eax+40h]'
            ],
            'CheckRemoteDebuggerPresent': [
                'call CheckRemoteDebuggerPresent'
            ],
            'TLS Callback': [
                'TlsCallback'
            ],
            'Timing Check': [
                'rdtsc'
            ]
        }

        findings = []
        for func_ea in idautils.Functions():
            func_bytes = ida_bytes.get_bytes(
                func_ea,
                ida_funcs.get_func(func_ea).size()
            )

            for pattern_name, instructions in anti_debug_patterns.items():
                if all(
                    self._find_instruction(func_bytes, instr)
                    for instr in instructions
                ):
                    findings.append({
                        'function': hex(func_ea),
                        'name': ida_name.get_name(func_ea),
                        'anti_debug_technique': pattern_name
                    })

                    # 在 IDA 中添加注释
                    idc.set_cmt(func_ea, f"ANTI-DEBUG: {pattern_name}", True)

                    # 设置标签颜色
                    idaapi.set_item_color(func_ea, 0xFFAAAA)  # 浅红色

        print(f"找到 {len(findings)} 个反调试技术:")
        for f in findings:
            print(f"  {f['function']} - {f['anti_debug_technique']}")

    def _find_instruction(self, func_bytes, pattern):
        """在函数字节中查找指令模式"""
        return pattern.encode() in func_bytes

    def term(self):
        pass

def PLUGIN_ENTRY():
    return AntiAntiDebugPlugin()
```

---

## 3. 高级调试技巧

### 3.1 条件断点脚本

```python
# IDA Python 条件断点

class ConditionalBreakpoint:
    """高级条件断点"""

    @staticmethod
    def break_on_specific_arg(func_name, arg_index, magic_value):
        """
        当函数被特定参数调用时断下
        """
        func_ea = ida_name.get_name_ea(idaapi.BADADDR, func_name)

        class ConditionalBP(idaapi.DBG_Hooks):
            def dbg_bpt(self, tid, ea):
                if ea == func_ea:
                    # x64: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4
                    registers = {
                        0: idc.get_reg_value('rcx'),
                        1: idc.get_reg_value('rdx'),
                        2: idc.get_reg_value('r8'),
                        3: idc.get_reg_value('r9')
                    }

                    if registers.get(arg_index) == magic_value:
                        print(f"Hit! {func_name}(arg{arg_index}=0x{magic_value:X})")
                        return 1  # 暂停
                return 0  # 继续

        bp = ConditionalBP()
        bp.hook()
        idc.add_bpt(func_ea)
```

### 3.2 动态解混淆

```python
# 运行时解密字符串

def decrypt_runtime_strings(decrypt_func_ea, call_sites):
    """
    动态解密混淆字符串
    """
    import ida_dbg

    decrypted = {}

    for call_ea in call_sites:
        # 在调用解密函数前设置断点
        idc.add_bpt(call_ea)

        # 继续运行到断点
        ida_dbg.continue_process()

        # 进入解密函数
        ida_dbg.step_into()

        # 运行到函数返回
        ida_dbg.run_until_ret()

        # 读取返回值 (x64: rax = 字符串指针)
        str_ptr = idc.get_reg_value('rax')

        # 读取字符串
        string = ida_bytes.get_strlit_contents(
            str_ptr, -1, ida_bytes.STRTYPE_C
        )
        decrypted[call_ea] = string.decode()

        # 在 IDA 中添加注释
        idc.set_cmt(call_ea, f'Decrypted: "{string.decode()}"', False)

        # 移除断点
        idc.del_bpt(call_ea)

    return decrypted
```

---

## 4. 实战：勒索软件分析工作流

```yaml
勒索软件逆向分析流程:

  1. 静态分析 (IDA Pro):
    - 识别编译器/加壳 → diec/detect-it-easy
    - 导入表分析 (CryptAPI → 加密, DeleteFile → 收尾)
    - 字符串分析 (勒索信内容, C2 域名, 文件扩展名)
    - 反分析代码标记

  2. 动态分析 (x64dbg + IDA):
    - 断在加密 API (CryptEncrypt/BCryptEncrypt)
    - 观察加密算法和密钥生成
    - 断在文件操作 (FindFirstFile/FindNextFile)
    - 观察目标文件扩展名列表

  3. 密钥恢复尝试:
    - 分析密钥生成算法
    - 查找密钥派生中的弱点 (时间戳/机器名)
    - 搜索内存中的明文密钥

  4. 编写解密器:
    - 如果发现密钥算法弱点 → 编写解密工具
    - 如果无弱点 → 为受害者提取加密配置
```

---

## 参考资源

- [IDA Pro Book (Chris Eagle)](https://nostarch.com/idapro2.htm)
- [Hex-Rays SDK 文档](https://hex-rays.com/products/decompiler/manual/sdk/)
- [Practical Binary Analysis](https://practicalbinaryanalysis.com/)

---

*上一篇：[二进制静态分析](./02-binary-static-analysis.md)*
*下一篇：[Ghidra 逆向实践](./05-ghidra-reverse.md)*

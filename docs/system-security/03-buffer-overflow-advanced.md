# 缓冲区溢出进阶

## Shellcode 开发

### 基于 Linux x86_64 的 execve Shellcode

```
BITS 64
global _start
_start:
    xor rsi, rsi
    xor rdx, rdx
    mov rdi, 0x68732f6e69622f  ; "/bin/sh"
    push rsi
    push rdi
    mov rdi, rsp
    mov rax, 59                ; execve syscall
    syscall
```

### 编码与规避

| 技术 | 说明 | 绕过对象 |
|------|------|---------|
| NOP Sled | 大量 0x90 填充 | 栈随机化 |
| Alpha-numeric | 仅字母数字 Shellcode | WAF/输入过滤 |
| Polymorphic | 自解密编码 | 签名检测 |
| Egg Hunter | 小缓冲区搜索大 Shellcode | 有限空间 |

## 现代缓解措施

### ASLR（地址空间布局随机化）
- 栈/堆/库基址随机化
- 暴力绕过：32 位系统约 2^16 种排列
- 信息泄露辅助：利用内存泄漏获取基址

### DEP/NX（数据执行保护）
- 栈和堆不可执行
- ROP/JOP：复用现有代码段
- ROP 链构造：`ret` 指令串联

### Stack Canary
- 函数入口写入随机值，出口校验
- 绕过方法：
  - 信息泄露读取 Canary 值
  - 覆写 `__stack_chk_fail` GOT 表
  - 一次性覆盖（非 __stack_chk_fail 路径）

## 真实 CVE 实例

### CVE-2021-3156（sudo 堆溢出）
- 利用 sudo 的 `-s` 和 `-i` 参数组合
- 堆溢出导致任意代码执行
- 影响几乎所有 Linux 发行版
- PoC 长度仅 15 行

### CVE-2017-0263（Windows Win32k 提权）
- 内核模式驱动 win32k.sys 释放后使用
- 配合系统调用的条件竞争
- 成功获得 SYSTEM 权限

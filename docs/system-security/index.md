# 系统安全基础

> 操作系统层面的安全——缓冲区溢出、提权、内存保护

---

## 为什么系统安全重要

```
AI 工作负载的底层：
├── 训练节点操作系统（Linux）
├── 推理服务器操作系统
├── GPU 驱动（可能有漏洞）
└── 内核安全模块（SELinux/AppArmor）
```

系统漏洞可以让攻击者：
- 从普通用户提权到 root → 控制整台服务器
- 绕过安全机制 → 执行任意代码
- 突破容器隔离 → 访问宿主机

---

## 缓冲区溢出（Buffer Overflow）

### 原理

```
内存中的栈结构（从高地址到低地址）：

高地址
┌──────────────────┐
│     返回地址      │  ← 攻击者想改写这里 → 跳转到恶意代码
├──────────────────┤
│     EBP 基址      │
├──────────────────┤
│     局部变量      │  ← 这里存着 buffer[64]
├──────────────────┤
│     buffer[64]   │  ← 输入写入这里
└──────────────────┘
低地址

正常情况：写入 64 字节以内
攻击情况：写入超过 64 字节 → 覆盖返回地址
```

### 简单 POC

```c
#include <stdio.h>
#include <string.h>

void vulnerable() {
    char buffer[64];
    printf("Enter text: ");
    gets(buffer);  // ❌ gets() 不检查长度！永远不要使用
    printf("You entered: %s\n", buffer);
}

int main() {
    vulnerable();
    return 0;
}
```

**编译和测试**：

```bash
# 关闭保护以便演示
gcc -fno-stack-protector -z execstack -o vuln vuln.c

# 测试溢出
python3 -c "print('A' * 72)" | ./vuln
# 预期：Segmentation fault（返回地址被覆盖）
```

### 防御

| 防御机制 | 说明 | 使用方法 |
|---------|------|---------|
| Stack Canary | 在返回地址前放金丝雀值 | `-fstack-protector`（默认开启） |
| ASLR | 地址空间随机化 | 操作系统特性 |
| NX | 栈不可执行 | `-z noexecstack`（默认） |
| PIE | 位置无关可执行文件 | `-fpie -pie` |

```bash
# 安全的编译方式
gcc -fstack-protector-strong -pie -fpie -D_FORTIFY_SOURCE=2 -O2 -o safe safe.c
```

---

## 提权（Privilege Escalation）

### 提权类型

```
提权
├── 水平提权：访问同级用户的数据
│   └── 例如：用户 A 访问用户 B 的信息
└── 垂直提权：获取更高级别的权限
    ├── 普通用户 → root
    ├── 普通用户 → 管理员
    └── 容器内 → 宿主机
```

### Linux 提权常见路径

#### 1. SUID 二进制文件

```bash
# 查找设置了 SUID 位的文件
find / -perm -4000 -type f 2>/dev/null

# 危险的 SUID 程序
# - 如果某个 SUID 程序有漏洞，可以提权到 root
# - 例如：过时的 screen、pkexec、sudo

# 检查已知的 SUID 提权
./GTFOBins/search.sh pkexec  # 已修复
python3 -c 'import pty; pty.spawn("/bin/sh")'  # CVE-2021-4034 PwnKit
```

#### 2. 内核漏洞

```bash
# 查看内核版本
uname -a

# 检查是否有已知漏洞
# 脏牛 (Dirty Cow) — CVE-2016-5195
# 脏管道 (Dirty Pipe) — CVE-2022-0847
# OverlayFS — CVE-2021-3493
```

#### 3. Sudo 配置错误

```bash
# 查看当前用户可以以 root 执行什么
sudo -l

# ❌ 危险的 sudo 配置：
# user ALL=(ALL) NOPASSWD: ALL  → 无密码 root
# user ALL=(ALL) /bin/vim        → vim 可以执行 shell

# 如果 /etc/sudoers 允许以 root 执行 vim：
sudo vim -c '!sh'
# 实际上获得了 root shell
```

#### 4. Docker 组提权

```bash
# 如果用户在 docker 组中
docker run -v /:/host -it ubuntu chroot /host

# 这就相当于 root 权限
# 可以在宿主机上执行任何操作
```

### Windows 提权

```powershell
# 常见 Windows 提权路径
# 1. 未打补丁的系统
# 2. 服务权限配置错误
# 3. DLL 劫持
# 4. AlwaysInstallElevated 注册表

# 使用工具枚举
whoami /priv
# 查看 SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
# 如果有 → 可以使用 JuicyPotato 提权
```

---

## 内存安全

### 常见内存漏洞

| 漏洞 | 说明 | 影响 |
|------|------|------|
| Use-After-Free | 释放后使用 | 执行任意代码 |
| Double Free | 重复释放 | 程序崩溃/RCE |
| Heap Overflow | 堆溢出 | 覆盖堆元数据 |
| Integer Overflow | 整数溢出 | 绕过长度检查 → 溢出 |

### 使用 Rust 的内存安全

```rust
// Rust 通过所有权系统消除内存安全问题

fn main() {
    // ✅ 安全的数组访问——编译时检查
    let v = vec![1, 2, 3];
    println!("{}", v[0]);  // 安全
    
    // let x = v[10];  // ❌ 编译错误或 panic（不会越界）
    
    // ✅ 安全的字符串处理
    let name = String::from("Alice");
    // 不会缓冲区溢出
}
```

### 现代防御技术

```bash
# Linux 内核安全功能检查
cat /proc/sys/kernel/randomize_va_space
# 2 = 完全 ASLR

# SELinux 状态
getenforce
# Enforcing

# AppArmor 状态
aa-status

# 内核保护
# - KASLR: 内核地址空间随机化
# - SMAP/SMEP: 禁止内核访问用户空间
# - KPTI: 内核页表隔离
```

---

## AI 场景中的系统安全问题

### GPU 驱动漏洞

```bash
# NVIDIA 驱动中的潜在安全问题
# CVE-2023-25516 — NVIDIA 驱动提权漏洞
# CVE-2024-0070 — GPU 内存泄露

# 检查 GPU 驱动版本
nvidia-smi

# 保持驱动更新
# 定期检查 NVIDIA 安全公告
```

### 训练服务器加固

```bash
# AI 训练服务器的系统安全配置

# 1. 最小化安装
# 只安装必要的软件包和驱动

# 2. 内核加固
# 开启 SELinux/AppArmor
# 开启内核安全模块
grubby --update-kernel=ALL --args="slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on"

# 3. 网络隔离
# 训练节点只开放必要端口
iptables -P INPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT

# 4. 审计日志
auditctl -w /var/log/audit/ -k audit-log
```

---

## 安全检查清单

- [ ] 系统内核是最新稳定版本
- [ ] 安全模块已启用（SELinux/AppArmor）
- [ ] ASLR 已开启
- [ ] 不使用的服务和端口已关闭
- [ ] SUID 程序最少化
- [ ] sudo 配置遵循最小权限
- [ ] 没有用户在 docker 组中（除非需要）
- [ ] GPU 驱动是最新安全版本
- [ ] 审计日志已开启

---

## 延伸阅读

1. [OWASP Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
2. [GTFOBins — Linux 提权大全](https://gtfobins.github.io/)
3. [LOLBAS — Windows 提权](https://lolbas-project.github.io/)
4. [PentestMonkey — Linux 提权 Cheatsheet](https://pentestmonkey.net/category/cheat-sheet)
5. [CIS 基准](https://www.cisecurity.org/cis-benchmarks)
6. [NVIDIA 安全公告](https://www.nvidia.com/en-us/security/)
7. [Kernel Self-Protection](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)

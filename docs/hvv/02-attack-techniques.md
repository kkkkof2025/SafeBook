# HVV 红队攻击技术实战

## 信息收集阶段

### 目标测绘技术
- **子域名枚举**：Subfinder + Amass + Ffuf 多源枚举
- **端口扫描**：Masscan 全端口（1600/s）+ Nmap 精细化
- **Web 指纹识别**：Wappalyzer + WhatWeb 自动识别
- **暴露面发现**：FOFA/Shodan/Censys 三引擎交叉

### 社工钓鱼
- **定制化钓鱼**：基于公开信息的针对性邮件
- **水坑攻击**：投毒目标常用站点
- **电话钓鱼**：冒充 IT 支持或供应商

## 漏洞利用阶段

### Web 应用突破
`http
# SQL 注入绕过 WAF
GET /api/users?id=1/**/UNION/**/SELECT/**/1,2,3
X-Forwarded-For: 127.0.0.1
Cookie: session=../../../etc/passwd
`

### 横向移动技术
- **Pass-the-Hash**：Mimikatz 提取 NTLM hash 后直接认证
- **Kerberos 黄金票据**：伪造 KRBTGT 票据
- **SSH 密钥劫持**：~/.ssh/authorized_keys 植入

## 权限维持

### WebShell 隐藏
- **内存马**：Java Agent/Servlet API 注入，无文件落地
- **图片马**：EXIF/SVG 文件隐写 Webshell
- **Log 马**：写入 access.log 通过 User-Agent 触发执行

### C2 通信隐藏
- **域名前置**：CDN/CloudFront 作为中转
- **随机心跳**：致敬正态分布避免规律检测
- **DNS over HTTPS**：DoH 隧道加密通信
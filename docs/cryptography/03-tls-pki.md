# TLS/SSL 与 PKI 证书体系

## TLS 握手协议

### 1.3 简化握手（1-RTT）
```
Client: ClientHello (支持的密码套件)
Server: ServerHello + 证书 + KeyShare
Client: 验证证书 + 计算共享密钥
        → Finished（加密）
Server: → Finished（加密）
        ↔ 加密应用数据
```

### 证书验证链
```
Root CA (自签名)
  └─ Intermediate CA
       └─ 服务器证书 ← 浏览器验证这个
```

## 常见 TLS 漏洞

| 漏洞 | 影响 | 修复 |
|------|------|------|
| POODLE | SSLv3 填充预言机 | 禁用 SSL 3.0 |
| Heartbleed | OpenSSL 1.0.1 内存泄漏 | 升级 OpenSSL |
| ROBOT | RSA 填充预言机 | 禁用 RSA 密钥交换 |
| Logjam | DH 参数降级 | 使用 >= 2048 位 DH |
| CRIME/BREACH | 压缩率侧信道 | 禁用 TLS 压缩 |

## 证书类型

| 类型 | 验证级别 | 适用场景 |
|------|---------|---------|
| DV（域名验证） | 低 | 个人博客、测试 |
| OV（组织验证） | 中 | 企业官网 |
| EV（扩展验证） | 高 | 金融、电商 |

## 证书部署检查

```bash
# 使用 OpenSSL
openssl s_client -connect example.com:443 -servername example.com

# 证书链检查
openssl s_client -showcerts -connect example.com:443

# 查看证书详情
openssl x509 -in cert.pem -text -noout

# 在线测试工具
# https://www.ssllabs.com/ssltest/
```

## Let's Encrypt 自动化

```bash
# 使用 Certbot 获取证书
certbot certonly --webroot -w /var/www/html -d example.com

# 自动续期
certbot renew --dry-run
# Certbot 自动添加 systemd timer

# DNS-01 挑战（通配符证书）
certbot certonly --manual --preferred-challenges dns -d *.example.com
```

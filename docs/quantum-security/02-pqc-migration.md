# 后量子密码迁移实践

## 概述

从传统加密算法迁移到后量子密码学 (PQC) 不是一次性项目——而是一个持续多年的系统性工程。NIST 2024 年标准发布后，美国政府要求在 2030 年前完成所有非安全系统的 PQC 迁移。本章提供可操作的迁移路线。

---

## 1. 迁移第一步：密码学盘点

### 1.1 自动化密码审计

```python
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
import subprocess
import json

class CryptographicInventory:
    """自动化密码学资产盘点"""

    def __init__(self):
        self.inventory = {
            'tls_certificates': [],
            'ssh_keys': [],
            'code_signing_certs': [],
            'database_encryption': [],
            'application_crypto': [],
        }

    def scan_tls_endpoints(self, endpoints):
        """扫描 TLS 端点使用的算法"""

        for endpoint in endpoints:
            host, port = endpoint.split(':')
            port = int(port)

            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        cipher = ssock.cipher()

                        cert_obj = x509.load_der_x509_certificate(cert)

                        # 提取算法信息
                        algo_info = {
                            'endpoint': endpoint,
                            'cert_algorithm': type(cert_obj.public_key()).__name__,
                            'cert_key_size': cert_obj.public_key().key_size,
                            'signature_algorithm': str(cert_obj.signature_algorithm_oid),
                            'tls_cipher': cipher[0],
                            'pq_ready': False,
                            'migration_deadline': '2030'
                        }

                        # 判断量子安全性
                        if 'X25519Kyber768' in cipher[0]:
                            algo_info['pq_ready'] = True

                        self.inventory['tls_certificates'].append(algo_info)

            except Exception as e:
                print(f"Error scanning {endpoint}: {e}")

    def scan_ssh_keys(self, hosts):
        """扫描 SSH 密钥算法"""

        for host in hosts:
            try:
                result = subprocess.run([
                    'ssh-keyscan', '-t', 'ed25519,rsa,ecdsa', host
                ], capture_output=True, text=True, timeout=10)

                for line in result.stdout.split('\n'):
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2:
                            key_type = parts[1]
                            self.inventory['ssh_keys'].append({
                                'host': host,
                                'key_type': key_type,
                                'pq_safe': key_type in [
                                    'ssh-ed25519', 'ecdsa-sha2-nistp521'
                                ],
                                'recommended': 'ssh-ed25519 + sntrup761x25519'
                            })

            except Exception as e:
                print(f"Error scanning {host}: {e}")

    def generate_report(self):
        """生成密码学盘点报告"""

        total = sum(len(v) for v in self.inventory.values())
        pq_safe_tls = sum(
            1 for c in self.inventory['tls_certificates']
            if c['pq_ready']
        )

        return {
            'total_assets': total,
            'tls_pq_ready_pct': f'{pq_safe_tls / max(1, len(self.inventory["tls_certificates"])) * 100:.1f}%',
            'risk_score': self._calculate_risk(),
            'high_priority_items': self._get_high_priority(),
            'inventory': self.inventory
        }

    def _calculate_risk(self):
        """
        风险评分:
        - RSA-1024 或更小: CRITICAL (容易量子破解)
        - RSA-2048: HIGH (Shor 算法目标)
        - ECDSA P-256: HIGH (2314 qubits)
        - Ed25519: MEDIUM (仍暴露签名伪造风险)
        """
        risk = 0
        for cert in self.inventory['tls_certificates']:
            if 'rsa' in cert['cert_algorithm'].lower():
                if cert['cert_key_size'] <= 1024:
                    risk += 100  # CRITICAL
                else:
                    risk += 50   # HIGH
            elif 'elliptic' in cert['cert_algorithm'].lower():
                risk += 40

        return risk / max(1, len(self.inventory['tls_certificates']))

    def _get_high_priority(self):
        """需要优先迁移的项目"""
        return [
            {
                'priority': 1,
                'system': '外部 TLS 证书 (面向用户)',
                'action': '启用 X25519 + Kyber-768 混合密钥交换',
                'timeline': '2024-2025'
            },
            {
                'priority': 2,
                'system': '内部 PKI / Root CA',
                'action': '签发 ML-DSA-65 证书',
                'timeline': '2025-2026'
            },
            {
                'priority': 3,
                'system': '代码签名证书',
                'action': '迁移到 SLH-DSA',
                'timeline': '2026-2027'
            },
            {
                'priority': 4,
                'system': '数据库加密密钥',
                'action': '加密密钥轮换 + PQC 备份',
                'timeline': '2025-2028'
            },
            {
                'priority': 5,
                'system': 'SSH Host Keys',
                'action': '启用 hybrid SSH (ed25519 + kyber512)',
                'timeline': '2025-2026'
            }
        ]
```

### 1.2 SSH PQC 迁移

```bash
# OpenSSH 9.0+ 支持后量子密钥交换

# 1. 生成混合密钥
ssh-keygen -t ed25519-sk -f ~/.ssh/id_hybrid
# 同时生成 sntrup761x25519-sha512@openssh.com 密钥

# 2. 配置 sshd
cat >> /etc/ssh/sshd_config << EOF
# 后量子密钥交换
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256

# PQC Host Keys
HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com

# 混合签名
PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com
EOF

systemctl restart sshd

# 3. 验证
ssh -v -o KexAlgorithms=sntrup761x25519-sha512@openssh.com user@host
# 输出:
# debug1: kex: algorithm: sntrup761x25519-sha512@openssh.com
# debug1: kex: host key algorithm: ssh-ed25519
```

---

## 2. 混合模式部署

### 2.1 Nginx PQC TLS

```nginx
# nginx.conf - PQC 混合 TLS 配置
# 需要 OpenSSL 3.3+ 或 BoringSSL 或 liboqs

server {
    listen 443 ssl http2;
    server_name example.com;

    # 传统证书 (RSA 2048)
    ssl_certificate     /etc/nginx/certs/rsa_2048.crt;
    ssl_certificate_key /etc/nginx/certs/rsa_2048.key;

    # 后量子证书 (ML-DSA-65)
    ssl_certificate     /etc/nginx/certs/ml_dsa_65.crt;
    ssl_certificate_key /etc/nginx/certs/ml_dsa_65.key;

    # 密码套件顺序: PQC 优先
    ssl_prefer_server_ciphers on;

    # PQC 混合密码套件
    ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256';

    # PQC 支持的签名算法
    ssl_conf_command Options SignAlgorithms 'ml_dsa_65,rsa_pkcs1_sha256';
}
```

### 2.2 证书迁移脚本

```bash
#!/bin/bash
# 批量证书迁移: RSA → PQC

# 生成 ML-DSA-65 密钥和证书 (使用 liboqs)
for domain in api.example.com app.example.com admin.example.com; do
    echo "===== 迁移 $domain ====="

    # 1. 生成 ML-DSA-65 密钥
    openssl req -x509 -newkey ml_dsa_65 \
        -keyout ${domain}_pq.key \
        -out ${domain}_pq.crt \
        -days 365 \
        -subj "/CN=$domain" \
        -addext "basicConstraints=CA:FALSE"

    # 2. 验证
    openssl x509 -in ${domain}_pq.crt -text -noout | grep "Public Key Algorithm"

    # 3. 部署
    cp ${domain}_pq.crt /etc/nginx/certs/
    cp ${domain}_pq.key /etc/nginx/certs/

    echo "✅ $domain PQC 证书已生成"
done

# 重载 Nginx
nginx -t && nginx -s reload
```

---

## 3. Crypto Agility

### 3.1 设计原则

```yaml
密码敏捷性 — 架构设计原则:

  1. 抽象密码层:
    所有加密操作通过统一接口
    不允许直接调用 OpenSSL/bcrypt API

  2. 算法可配置:
    密码算法通过配置文件选择
    支持运行时切换

  3. 多算法支持:
    每个加密操作支持至少 2 种算法
    1 个当前算法 + 1 个备用算法

  4. 密钥生命周期管理:
    密钥生成/轮换/吊销/归档自动化
    每个密钥标注算法类型和有效期

  5. 测试与演练:
    定期"密码日演练"
    在测试环境中切换算法
    验证所有系统正常工作
```

### 3.2 实现示例

```python
class CryptoAgilityManager:
    """
    密码敏捷性管理器
    支持运行时算法切换
    """

    def __init__(self, config):
        self.algorithms = {
            'kem': ['kyber-1024', 'rsa-2048'],       # 密钥封装
            'signature': ['ml-dsa-65', 'ed25519'],    # 签名
            'hash': ['sha3-512', 'sha-256'],          # 哈希
            'symmetric': ['aes-256-gcm', 'chacha20-poly1305'],  # 对称加密
        }
        self.active_algo = config['active_algorithms']
        self.fallback_algo = config['fallback_algorithms']

    def encrypt(self, plaintext, public_key, algorithm=None):
        """
        加密: 使用当前算法 + 回退算法
        如果当前算法被破解 → 切换回退算法
        """
        algo = algorithm or self.active_algo['kem']

        # 主算法加密
        primary_ciphertext = self._encrypt_with(
            plaintext, public_key, algo
        )

        # 备用算法加密 (作为冗余)
        backup_ciphertext = self._encrypt_with(
            plaintext, public_key, self.fallback_algo['kem']
        )

        return {
            'algorithm': algo,
            'ciphertext': primary_ciphertext,
            'backup_algorithm': self.fallback_algo['kem'],
            'backup_ciphertext': backup_ciphertext,
        }

    def rotate_algorithms(self, new_active, reason):
        """
        算法轮换:
        - 紧急: 算法被破解 → 立即切换
        - 计划: 定期轮换 → 按计划执行
        """
        old_active = self.active_algo.copy()

        # 1. 验证新算法可用
        self._validate_algorithms(new_active)

        # 2. 更新活动算法
        self.active_algo.update(new_active)

        # 3. 通知所有依赖方
        self._notify_algorithm_change(old_active, new_active, reason)

        # 4. 记录审计日志
        self._audit_log(old_active, new_active, reason)

        return {
            'status': 'rotated',
            'old': old_active,
            'new': self.active_algo,
            'reason': reason
        }
```

---

## 参考资源

- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe](https://openquantumsafe.org/)
- [BoringSSL PQC](https://boringssl.googlesource.com/boringssl)
- [IETF TLS PQC Draft](https://datatracker.ietf.org/wg/pquip/)

---

*上一篇：[量子计算对密码学的威胁](./01-quantum-threat-pqc.md)*

*下一篇：[量子密钥分发 (QKD)](03-quantum-key-distribution.md)*

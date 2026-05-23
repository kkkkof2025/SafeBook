# 国密证书与 PKI 体系

## 概述

国密 PKI 体系是中国商用密码基础设施的核心，基于 SM2/SM3/SM4/SM9 算法族构建。随着《密码法》的实施和信创工程的推进，国密证书在政府和关键行业的应用正快速普及。

---

## 1. 国密 PKI 体系架构

### 1.1 与 X.509 PKI 的对比

```
国际 PKI (X.509):              国密 PKI (GM/T 0015):
┌──────────────────┐          ┌──────────────────┐
│  Root CA         │          │  根CA (SM2-512)   │
│  (RSA-4096)      │          │  GM/T 0010 格式   │
└────────┬─────────┘          └────────┬─────────┘
         │                             │
┌────────┴─────────┐          ┌────────┴─────────┐
│  子 CA           │          │  子CA (SM2-256)   │
│  (RSA-2048)      │          │  GM/T 0010 格式   │
└────────┬─────────┘          └────────┬─────────┘
         │                             │
┌────────┴─────────┐          ┌────────┴─────────┐
│  终端实体证书     │          │  终端实体证书      │
│  (RSA/ECDSA)     │          │  (SM2)           │
└──────────────────┘          └──────────────────┘
```

### 1.2 GM/T 0010 证书格式

```python
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import struct
import hashlib

class GMT0010Certificate:
    """
    GM/T 0010 标准数字证书格式
    基于 X.509v3 的扩展
    """

    # 国密 OID 定义
    OID_SM2 = "1.2.156.10197.1.301"         # SM2 椭圆曲线公钥密码算法
    OID_SM3_SM2 = "1.2.156.10197.1.501"     # SM3WithSM2 签名算法
    OID_SM2_256 = "1.2.156.10197.1.301.1"   # SM2-256 推荐曲线

    def __init__(self):
        self.cert_extensions = []

    def add_sm2_key_usage(self, key_usage_bits):
        """
        GM/T 0010 定义的密钥用法:
        - digitalSignature (0)
        - nonRepudiation (1)
        - keyEncipherment (2)
        - dataEncipherment (3)
        - keyAgreement (4)        # SM2 密钥交换
        - keyCertSign (5)
        - cRLSign (6)
        - encipherOnly (7)
        - decipherOnly (8)
        """
        return self._build_key_usage_extension(key_usage_bits)

    def add_sm2_certificate_policies(self, policy_oids):
        """
        证书策略 OID:
        - 1.2.156.10268.1.1: 个人身份证书
        - 1.2.156.10268.1.2: 企业身份证书
        - 1.2.156.10268.1.3: 设备证书
        - 1.2.156.10268.1.4: 代码签名证书
        - 1.2.156.10268.1.5: 时间戳证书
        """
        return x509.CertificatePolicies([
            x509.PolicyInformation(
                policy_identifier=x509.ObjectIdentifier(oid),
                policy_qualifiers=None
            )
            for oid in policy_oids
        ])

    def to_pem(self, certificate, private_key=None):
        """导出为 PEM 格式 (含国密标记)"""
        cert_pem = certificate.public_bytes(
            serialization.Encoding.PEM
        )

        if private_key:
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            return cert_pem, key_pem

        return cert_pem
```

---

## 2. 双证书体系

### 2.1 签名证书 vs 加密证书

```yaml
国密双证书体系:
  签名证书:
    用途: 身份认证、数字签名
    密钥: SM2 (签名模式)
    证书策略: 1.2.156.10268.1.1
    有效期: 个人 5 年，企业 10 年
    密钥用法: digitalSignature, nonRepudiation
    私钥保护: USB Key / 加密机 / TEE

  加密证书:
    用途: 数据加密、密钥协商
    密钥: SM2 (加密模式)
    证书策略: 1.2.156.10268.1.2
    有效期: 个人 5 年，企业 10 年
    密钥用法: keyEncipherment, keyAgreement
    私钥保存: 同时保存加密私钥 (用于解密历史数据)
```

### 2.2 证书申请流程

```python
import requests
from gmssl import sm2, sm3

class SM2CertificateEnrollment:
    """SM2 证书注册 (基于 CMPv2/GM/T 0092)"""

    def __init__(self, ca_url, ra_operator):
        self.ca_url = ca_url
        self.ra_operator = ra_operator

    def generate_sm2_keypair(self):
        """生成 SM2 密钥对"""
        # SM2 使用 256 位曲线
        cryptosystem = sm2.CryptSM2(private_key=None, public_key=None)

        # 生成密钥对
        private_key = cryptosystem.generate_private_key()
        public_key = cryptosystem.get_public_key(private_key)

        return {
            'private_key': private_key,
            'public_key': public_key,
            'curve': 'sm2p256v1',
            'key_size': 256
        }

    def create_csr(self, subject_dn, keypair, cert_type='signature'):
        """
        生成 SM2 CSR (PKCS#10)
        GM/T 0092 规范
        """
        csr = {
            'version': 0,
            'subject': subject_dn,  # CN=XXX,O=XXX,C=CN
            'public_key_info': {
                'algorithm': '1.2.156.10197.1.301',  # SM2 OID
                'public_key': keypair['public_key'],
                'curve': '1.2.156.10197.1.301.1'     # sm2p256v1
            },
            'attributes': [
                {
                    'type': 'extensionRequest',
                    'extensions': {
                        'keyUsage': self._get_key_usage(cert_type),
                        'certificatePolicies': self._get_policy_oid(cert_type)
                    }
                }
            ]
        }

        # SM3WithSM2 签名 CSR
        signature = sm3_sign(
            data=csr_to_der(csr),
            private_key=keypair['private_key']
        )

        csr['signature'] = signature
        csr['signature_algorithm'] = '1.2.156.10197.1.501'

        return csr

    def submit_enrollment(self, csr, auth_data):
        """
        提交证书注册请求
        """
        # 封装 RA 认证信息
        enrollment_request = {
            'csr': csr,
            'auth': {
                'method': 'face_to_face',  # 或 enterprise_seal
                'operator_id': self.ra_operator,
                'verification_documents': auth_data
            }
        }

        response = requests.post(
            f'{self.ca_url}/enroll/sm2',
            json=enrollment_request,
            headers={'Content-Type': 'application/json'}
        )

        return response.json()
```

---

## 3. 国密 PKI 安全加固

### 3.1 HSM 密钥管理

```python
# 使用国密 HSM (硬件加密机) 进行密钥管理
# PKCS#11 接口示例

class GMHSMKeyManager:
    """国密 HSM 密钥管理"""

    def generate_sm2_key_hsm(self, key_label):
        """
        在 HSM 内部生成 SM2 密钥对
        私钥永不离开 HSM
        """
        return self.hsm.generate_key_pair(
            mechanism='CKM_SM2_KEY_PAIR_GEN',
            template={
                'CKA_LABEL': key_label,
                'CKA_TOKEN': True,
                'CKA_PRIVATE': True,
                'CKA_SIGN': True,
                'CKA_DECRYPT': True,
                'CKA_EXTRACTABLE': False,  # 不可导出
                'CKA_MODIFIABLE': False
            }
        )

    def sm2_sign_hsm(self, key_handle, data):
        """
        使用 HSM 内部密钥进行 SM2 签名
        数据进 HSM，签名出 HSM
        """
        # 先计算 SM3 哈希
        digest = sm3_hash(data)

        # 在 HSM 内签名 (使用 SM2)
        return self.hsm.sign(
            key=key_handle,
            mechanism='CKM_SM2_SM3',
            data=digest
        )

    def sm2_verify_hsm(self, key_handle, data, signature):
        """在 HSM 内验证 SM2 签名"""
        digest = sm3_hash(data)
        return self.hsm.verify(
            key=key_handle,
            mechanism='CKM_SM2_SM3',
            data=digest,
            signature=signature
        )
```

### 3.2 证书吊销管理

```yaml
GM CRL (GM/T 0011):
  CRL 格式:
    - 基于 X.509 CRL v2
    - 签名算法: SM3WithSM2
    - 发布周期: 24 小时

  OCSP (GM/T 0012):
    - 在线证书状态查询
    - 实时获取证书状态
    - 支持 SM2 签名验证

  吊销原因:
    - keyCompromise: 密钥泄露
    - cACompromise: CA 密钥泄露
    - affiliationChanged: 隶属关系变更
    - superseded: 证书被替代
    - cessationOfOperation: 停止运营
    - certificateHold: 证书暂停
```

---

## 4. 国密与国际双模 PKI

### 4.1 双模架构设计

```yaml
双模 PKI 策略:
  证书签发:
    - 同一 CA 签发 RSA/SM2 双证书
    - 使用 ACME (RFC 8555) + GM/T 0092 双协议

  TLS 握手:
    - Client Hello 中包含国密密码套件:
      - ECC_SM2_SM4_SM3 (0xE013)
      - ECDHE_SM2_SM4_SM3 (0xE015)
    - 服务器根据客户端能力选择套件

  密码套件优先级:
    国产环境:
      1. ECDHE_SM2_SM4_SM3     # 国密优先
      2. ECDHE_RSA_AES128_GCM   # 国际兼容

    国际环境:
      1. ECDHE_RSA_AES256_GCM   # 国际优先
      2. ECDHE_SM2_SM4_SM3      # 国密兼容
```

### 4.2 Nginx 国密双证书配置

```nginx
# /etc/nginx/conf.d/gm_ssl.conf

server {
    listen 443 ssl;
    server_name example.cn;

    # 国际证书
    ssl_certificate     /etc/nginx/certs/rsa_server.crt;
    ssl_certificate_key /etc/nginx/certs/rsa_server.key;

    # 国密证书 (使用 TongSuo/BabaSSL)
    ssl_certificate     /etc/nginx/certs/sm2_sign.crt;
    ssl_certificate_key /etc/nginx/certs/sm2_sign.key;

    # 国密加密证书 (双证书)
    ssl_certificate     /etc/nginx/certs/sm2_encrypt.crt;
    ssl_certificate_key /etc/nginx/certs/sm2_encrypt.key;

    # 密码套件优先级
    ssl_ciphers 'ECC_SM4_SM3:ECDHE_SM4_SM3:ECDHE-RSA-AES128-GCM-SHA256';

    # 国密签名证书验证
    ssl_verify_client optional;
    ssl_client_certificate /etc/nginx/certs/sm2_ca.pem;
    ssl_verify_depth 2;
}
```

---

## 5. 合规审计

```yaml
密码应用安全性评估 (密评) 要求:

  物理与环境安全:
    - [ ] 密钥存储在通过认证的 HSM 中
    - [ ] HSM 通过 GM/T 0028 三级认证
    - [ ] 机房符合 GB 50174 标准

  网络与通信安全:
    - [ ] 传输加密使用 SM4 (GM/T 0002)
    - [ ] 身份认证使用 SM2 (GM/T 0003)
    - [ ] 完整性校验使用 SM3 (GM/T 0004)

  设备与计算安全:
    - [ ] 使用国密算法实现 HTTPS
    - [ ] 数据库加密使用 SM4
    - [ ] 日志签名使用 SM2

  应用与数据安全:
    - [ ] 用户口令使用 SM3 哈希
    - [ ] 数字签名使用 SM2
    - [ ] 数据存储加密 SM4-CBC

  密钥管理周期:
    - [ ] 签名密钥: 1-3 年生命周期
    - [ ] 加密密钥: 1 年生命周期
    - [ ] 会话密钥: 单次使用
    - [ ] 密钥备份: 3-2-1 规则
```

---

## 参考资源

- [GM/T 0015 - 数字证书格式](https://www.gmbz.org.cn/)
- [GM/T 0010 - SM2 密码算法使用规范](https://www.sca.gov.cn/)
- [TongSuo (铜锁) - 国密 TLS 实现](https://github.com/Tongsuo-Project/Tongsuo)

---

*上一篇：[SM 系列算法实现](./03-sm-crypto-implementation.md)*

*下一篇：[国密算法应用指南](04-sm-application-guide.md)*

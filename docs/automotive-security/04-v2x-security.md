# V2X 车联网通信安全

## 概述

V2X (Vehicle-to-Everything) 是智能网联汽车的核心通信技术，包括 V2V (车-车)、V2I (车-基础设施)、V2P (车-行人)、V2N (车-网络)。任何通信链路的安全漏洞都可能导致交通事故和生命危险。

---

## 1. V2X 通信架构

### 1.1 通信类型与安全需求

| 通信类型 | 延迟要求 | 通信范围 | 安全等级 | 主要威胁 |
|----------|----------|----------|----------|----------|
| V2V (车-车) | <20ms | 300m | 极高 | 伪造BSM, Sybil攻击 |
| V2I (车-基础设施) | <100ms | 1000m | 高 | 伪造信号灯消息 |
| V2P (车-行人) | <100ms | 100m | 高 | 位置隐私泄露 |
| V2N (车-网络) | <1s | 不限 | 中 | 云端API攻击 |

### 1.2 DSRC vs C-V2X

```
DSRC (IEEE 802.11p):
  优点: 成熟稳定，低延迟
  缺点: 覆盖有限，演进空间小
  安全: IEEE 1609.2 证书体系

C-V2X (LTE-V2X / NR-V2X):
  优点: 5G演进路线，覆盖广
  缺点: 依赖基站，部署成本高
  安全: 3GPP 33.185 安全框架
```

---

## 2. V2X PKI 安全体系

### 2.1 SCMS (Security Credential Management System)

```yaml
SCMS 证书体系:
  角色:
    - Root CA: 根证书机构
    - Enrollment CA: 注册证书颁发
    - Pseudonym CA: 假名证书颁发 (隐私保护)
    - Linkage Authority: 关联值生成 (可追溯)
    - Misbehavior Authority: 异常行为检测与吊销
    - Registration Authority: 注册机构

  证书类型:
    注册证书 (Enrollment Certificate):
      - 终身有效
      - 标识车辆合法身份
      - 类似 "身份证"

    假名证书 (Pseudonym Certificate):
      - 短期有效 (1周)
      - 用于签署BSM消息
      - 定期轮换防止追踪
      - 类似 "一次性口罩"

    应用证书 (Application Certificate):
      - 用于非安全应用 (信息娱乐)
      - 不需要假名保护
```

### 2.2 证书生命周期

```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import uuid
from datetime import datetime, timedelta

class V2XCertificateManager:
    def __init__(self, enrollment_cert, private_key):
        self.enrollment_cert = enrollment_cert
        self.private_key = private_key

    def request_pseudonym_certs(self, count=20):
        """
        请求假名证书批次
        - 一次请求获取 20 个证书 (供一周使用)
        - 每个证书包含不同的假名
        """
        certs = []
        for _ in range(count):
            pseudonym = self._generate_pseudonym()
            cert = self._create_pseudonym_cert(pseudonym)
            certs.append(cert)
        return certs

    def _generate_pseudonym(self):
        """生成一次性假名"""
        return hashlib.sha256(
            uuid.uuid4().bytes + str(datetime.now().timestamp()).encode()
        ).hexdigest()[:16]

    def _create_pseudonym_cert(self, pseudonym):
        """创建短期假名证书"""
        # ECDSA P-256 (V2X 标准)
        priv_key = ec.generate_private_key(ec.SECP256R1())

        cert = x509.CertificateBuilder()
        cert = cert.subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, pseudonym)
        ]))
        cert = cert.issuer_name(self.enrollment_cert.subject)
        cert = cert.public_key(priv_key.public_key())
        cert = cert.serial_number(int.from_bytes(os.urandom(20), 'big'))
        cert = cert.not_valid_before(datetime.utcnow())
        cert = cert.not_valid_after(datetime.utcnow() + timedelta(days=7))
        cert = cert.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )

        return {
            'cert': cert,
            'private_key': priv_key,
            'pseudonym': pseudonym,
            'valid_until': datetime.utcnow() + timedelta(days=7)
        }

    def rotate_pseudonym(self):
        """
        假名轮换策略:
        - 启动后随机延迟 0-60s 使用首个证书
        - 每次停车后更换证书
        - 连续行驶超过 5 分钟后随机更换
        """
        delay = random.uniform(0, 60)
        time.sleep(delay)
        return self.get_next_cert()
```

---

## 3. BSM 消息安全

### 3.1 基本安全消息结构

```python
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

class BSMMessage:
    """Basic Safety Message (SAE J2735)"""

    def __init__(self, vehicle_id, lat, lon, speed, heading):
        self.msg_id = os.urandom(4)
        self.timestamp = int(time.time() * 1000)
        self.vehicle_id = vehicle_id
        self.latitude = lat
        self.longitude = lon
        self.speed = speed  # m/s
        self.heading = heading  # degrees

    def serialize(self) -> bytes:
        """序列化为字节流"""
        payload = struct.pack(
            '!Iddff',
            self.timestamp,
            self.latitude,
            self.longitude,
            self.speed,
            self.heading
        )
        return payload

    def sign(self, private_key, certificate):
        """ECDSA 签名 BSM"""
        payload = self.serialize()
        # 附加证书链 (隐式证书可省略)
        to_sign = payload + certificate.public_bytes(serialization.Encoding.DER)

        signature = private_key.sign(
            to_sign,
            ec.ECDSA(hashes.SHA256())
        )

        return {
            'payload': payload,
            'certificate': certificate,
            'signature': signature
        }

    @staticmethod
    def verify(signed_message):
        """验证 BSM 签名"""
        to_verify = (
            signed_message['payload'] +
            signed_message['certificate'].public_bytes(serialization.Encoding.DER)
        )

        cert = x509.load_der_x509_certificate(
            signed_message['certificate'].public_bytes(serialization.Encoding.DER)
        )
        public_key = cert.public_key()

        try:
            public_key.verify(
                signed_message['signature'],
                to_verify,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False
```

### 3.2 BSM 攻击检测

```python
class BSMAnomalyDetector:
    """BSM 消息异常检测"""

    def __init__(self):
        self.vehicle_states = {}

    def check_message(self, bsm):
        alerts = []

        # 1. Sybil 攻击检测：同一物理位置的多辆车
        key = f"{bsm.latitude:.6f},{bsm.longitude:.6f}"
        vehicles_at_pos = self._get_vehicles_at(key)
        if len(vehicles_at_pos) > 5:  # 不可能 5 辆车在同一坐标
            alerts.append({
                'type': 'SYBIL_ATTACK',
                'position': (bsm.latitude, bsm.longitude),
                'vehicle_count': len(vehicles_at_pos)
            })

        # 2. 速度突变检测
        last = self.vehicle_states.get(bsm.vehicle_id)
        if last:
            delta_v = abs(bsm.speed - last['speed'])
            delta_t = bsm.timestamp - last['timestamp']
            if delta_t > 0:
                accel = delta_v / (delta_t / 1000)  # m/s^2
                if accel > 10:  # 不可能 > 1G 加速度
                    alerts.append({
                        'type': 'SPEED_ANOMALY',
                        'acceleration': accel
                    })

        # 3. 位置跳跃检测
        if last:
            distance = self._haversine(
                last['lat'], last['lon'],
                bsm.latitude, bsm.longitude
            )
            delta_t = bsm.timestamp - last['timestamp']
            if distance / (delta_t/1000) > 100:  # >100m/s
                alerts.append({
                    'type': 'POSITION_JUMP',
                    'distance': distance
                })

        self.vehicle_states[bsm.vehicle_id] = {
            'lat': bsm.latitude,
            'lon': bsm.longitude,
            'speed': bsm.speed,
            'timestamp': bsm.timestamp
        }

        return alerts
```

---

## 4. 隐私保护

### 4.1 混合区域 (Mix-Zone) 策略

```python
class MixZoneStrategy:
    """
    在交叉口等位置引入混合区域
    所有车辆同时更换假名，无法关联新旧假名
    """

    def __init__(self, mixzone_locations):
        self.mixzones = mixzone_locations  # [(lat, lon, radius), ...]

    def should_change_pseudonym(self, current_position):
        """判断是否进入混合区域"""
        lat, lon = current_position

        for mz_lat, mz_lon, radius in self.mixzones:
            distance = self._haversine(lat, lon, mz_lat, mz_lon)
            if distance < radius:
                # 在混合区域内随机延迟后更换
                delay = random.uniform(0, 3)  # 0-3秒
                time.sleep(delay)
                return True

        return False
```

### 4.2 k-匿名位置隐私

```python
def k_anonymize_location(lat, lon, k=5):
    """
    k-匿名: 位置模糊化到包含至少 k 辆车的区域
    """
    # 将经纬度截断到一定精度
    precision = 4  # ~11m at equator
    truncated_lat = round(lat, precision)
    truncated_lon = round(lon, precision)

    # 查询该区域内的车辆数
    vehicle_count = query_vehicle_density(
        truncated_lat - 0.00005,
        truncated_lon - 0.00005,
        truncated_lat + 0.00005,
        truncated_lon + 0.00005
    )

    if vehicle_count < k:
        # 扩大匿名区域
        precision -= 1
        truncated_lat = round(lat, precision)
        truncated_lon = round(lon, precision)

    return truncated_lat, truncated_lon
```

---

## 5. 安全测试

### 5.1 V2X 渗透测试工具

```bash
# OpenC2X - 开源 V2X 仿真平台
git clone https://github.com/floriankaltenberger/openC2X
cd openC2X
docker-compose up

# 伪造 BSM 消息
python3 tools/fake_bsm.py \
  --lat 37.7749 --lon -122.4194 \
  --speed 80 --heading 90 \
  --frequency 10  # 10Hz

# Vanetza - V2X 协议栈安全测试
git clone https://github.com/riebl/vanetza
cd vanetza/build && cmake .. && make
```

### 5.2 V2X 威胁建模

```yaml
V2X 威胁矩阵 (STRIDE):

  Spoofing (欺骗):
    - 伪造紧急车辆 BSM (迫使车辆让路)
    - 伪造信号灯 SPaT 消息
    缓解: ECDSA 签名 + SCMS 证书验证

  Tampering (篡改):
    - 修改 BSM 中的位置/速度数据
    - 重放旧的安全消息
    缓解: 签名 + 时间戳 + 新鲜度验证

  Repudiation (否认):
    - 车辆否认发送过错误消息
    缓解: 不可否认签名 + 异常行为报告

  Information Disclosure (信息泄露):
    - 长期追踪车辆位置
    - 获取驾驶员身份
    缓解: 假名证书 + Mix-Zone + k-匿名

  Denial of Service (拒绝服务):
    - 信道拥塞 (大量伪造消息)
    - 证书验证过载
    缓解: 速率限制 + 拥塞控制 + 高效验证

  Elevation of Privilege (权限提升):
    - 获取 MA (Misbehavior Authority) 权限
    - 签发伪造吊销列表
    缓解: 严格 SCMS 权限分离
```

---

## 参考资源

- [IEEE 1609.2 - V2X 安全服务](https://standards.ieee.org/standard/1609_2-2020.html)
- [SAE J2735 - V2X 消息集](https://www.sae.org/standards/content/j2735/)
- [3GPP TS 33.185 - LTE V2X 安全](https://www.3gpp.org/ftp/Specs/archive/33_series/33.185/)

---

*上一篇：[车辆黑客攻击技术](./03-vehicle-hacking.md)*

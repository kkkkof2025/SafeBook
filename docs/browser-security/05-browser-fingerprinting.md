# 浏览器指纹与反追踪

> 现代浏览器追踪技术与隐私防护

---

## 1. 浏览器指纹技术

```
指纹维度:
┌──────────────────────────────────────┐
│           浏览器指纹向量             │
├────────────┬────────────┬───────────┤
│  User Agent│ Canvas     │ WebGL     │
│  屏幕分辨率 │ 字体列表   │ AudioContext│
│  时区       │ 语言列表    │ WebRTC    │
│  Cookie    │ localStorage│ IndexedDB │
│  Plugins   │ 硬件并发    │ 内存      │
└────────────┴────────────┴───────────┘
```

### Canvas 指纹
```javascript
// Canvas 指纹提取
function getCanvasFingerprint() {
    const canvas = document.createElement('canvas');
    canvas.width = 280;
    canvas.height = 60;

    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Browser Fingerprint 👆', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Security Matters', 4, 35);

    return canvas.toDataURL();
    // 不同 GPU/OS/驱动/字体 → 不同的 hash!
}
```

### WebGL 指纹
```javascript
function getWebGLFingerprint() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl');

    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
    const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    // 例: "Intel Inc." / "Intel(R) UHD Graphics 620"
    // → 精确识别 GPU 型号!

    return {vendor, renderer};
}
```

---

## 2. 指纹唯一性评估

```python
from dataclasses import dataclass
from typing import Dict
import hashlib

@dataclass
class Fingerprint:
    user_agent: str
    screen: str          # "1920x1080x24"
    timezone: str        # "Asia/Shanghai"
    languages: list      # ["zh-CN", "en-US", "zh"]
    canvas_hash: str
    webgl_vendor: str
    webgl_renderer: str
    platform: str
    hardware_concurrency: int
    device_memory: int

    def entropy_bits(self) -> float:
        """估算指纹的信息熵"""
        bits = 0
        bits += len(self.user_agent) * 0.5     # ~5 bits
        bits += math.log2(10000)                # screen: ~13 bits
        bits += math.log2(600)                  # timezone: ~9 bits
        bits += self.canvas_hash_count * 0.9   # canvas: ~15 bits
        bits += math.log2(500)                  # webgl: ~9 bits
        bits += math.log2(self.hardware_concurrency)  # ~2 bits
        return bits
    # 总计: ~53 bits — 可唯一标识 2^53 约 9×10^15 台设备!
```

### 测试效果
```python
class FingerprintTester:
    """测试指纹唯一性"""

    def __init__(self):
        self.fingerprints = {}  # hash → {fingerprint, count}

    def add(self, fp):
        fp_hash = hashlib.sha256(
            f"{fp.user_agent}|{fp.canvas_hash}|{fp.webgl_renderer}".encode()
        ).hexdigest()

        if fp_hash in self.fingerprints:
            self.fingerprints[fp_hash]['count'] += 1
        else:
            self.fingerprints[fp_hash] = {'fp': fp, 'count': 1}

    def uniqueness_rate(self):
        """计算唯一率: 独特的指纹数 / 总数"""
        total = sum(v['count'] for v in self.fingerprints.values())
        unique = sum(1 for v in self.fingerprints.values() if v['count'] == 1)
        return unique / total if total else 0
```

---

## 3. 反指纹技术

### Brave 浏览器反指纹
```yaml
Brave 防指纹措施:
  - Canvas: 添加随机噪声 (farbling)
  - WebGL: 返回伪造的 vendor/renderer
  - AudioContext: 添加极微小的随机偏移
  - Fonts: 仅暴露标准字体
  - WebRTC: 阻止私有 IP 泄露
  - Battery API: 完全禁用
```

### Tor 浏览器
```yaml
Tor 浏览器策略: "所有人都一样"
  - 统一窗口大小: 1000×900 (letterboxing)
  - 固定 User Agent
  - 固定时区: UTC
  - 禁用 Canvas/WebGL
  - 禁用 WebRTC
  - 仅允许标准字体
```

### 企业反指纹检测
```python
class AntiFingerprintDetector:
    """检测网站是否在进行指纹采集"""

    DETECTION_HOOKS = {
        'canvas': """
            const orig = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function(...args) {
                console.warn('[Fingerprint] Canvas toDataURL called');
                return orig.apply(this, args);
            };
        """,
        'webgl': """
            const origGetParam = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(param) {
                if (param === 37445 || param === 37446) {
                    console.warn('[Fingerprint] WebGL vendor/renderer queried');
                }
                return origGetParam.call(this, param);
            };
        """,
        'fonts': """
            const origMeasure = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(...args) {
                if (args[0] === 'mmmmmmmmmmmmmmmmmmmmmmmmmmmmmm') {
                    console.warn('[Fingerprint] Font enumeration suspected');
                }
                return origMeasure.apply(this, args);
            };
        """
    }
```

---

## 4. 防御清单

```yaml
浏览器反指纹最佳实践:

  用户端:
    - 使用 Brave/Tor 浏览器
    - 启用隐私模式 (降低持久性)
    - 禁用第三方 Cookie
    - 安装 uBlock Origin + Privacy Badger

  企业端:
    - 部署 Browser Isolation (远程浏览器)
    - Web Application Firewall: 检测异常指纹
    - 登录异常检测: 新指纹 = MFA 挑战
    - 不依赖浏览器指纹做安全控制

  指纹 vs 合法安全:
    ❌ 不要: 用浏览器指纹替代认证
    ✅ 可以: 用指纹作为辅助信号 (设备识别)
    ✅ 可以: 检测异常指纹触发 MFA
```

---

*上一篇：[浏览器扩展安全](04-browser-extensions-security.md)*

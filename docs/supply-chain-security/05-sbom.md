# 软件物料清单 (SBOM)

## 概述

软件物料清单 (Software Bill of Materials) 是软件的"成分表"——列出构成软件的每个组件、库和依赖。Biden 14028 号行政令和欧盟 CRA 法案都将 SBOM 作为强制性合规要求。当 Log4Shell 爆发时，有 SBOM 的团队在几分钟内定位影响，没有的团队花了数周。

---

## 1. SBOM 标准

### 1.1 三大格式

| 格式 | 创建者 | 文件格式 | 适用场景 |
|------|--------|----------|----------|
| **SPDX** | Linux Foundation | JSON/YAML/Tag-Value | 开源合规、许可证 |
| **CycloneDX** | OWASP | JSON/XML | 安全分析、漏洞管理 |
| **SWID** | ISO/IEC 19770-2 | XML | 软件资产管理 |

### 1.2 SBOM 最小元素 (NTIA)

```yaml
SBOM 最小必需元素 (NTIA 2021):

  1. 供应商信息:
    - Supplier Name
    - Component Name
    - Version String

  2. 唯一标识:
    - Package URL (purl)
    - CPE (Common Platform Enumeration)
    - SWHID (Software Heritage ID)

  3. 依赖关系:
    - 上游/下游关系
    - 直接依赖 vs 传递依赖

  4. 作者:
    - SBOM 创建者
    - 创建时间戳

  5. 其他:
    - 许可证信息
    - 组件哈希 (SHA256)
    - 漏洞报告地址
```

---

## 2. SBOM 生成

### 2.1 Syft (Anchore)

```bash
# 安装 Syft
brew install syft

# 生成容器镜像 SBOM
syft nginx:latest -o cyclonedx-json > nginx.sbom.json

# 生成源码目录 SBOM
syft dir:./src/ -o spdx-json > source.sbom.json

# 查看 SBOM 内容
syft nginx:latest
# NAME                VERSION             TYPE
# adduser             3.118               deb
# apt                 1.8.2.3             deb
# libssl1.1           1.1.1n-0+deb11u3    deb
# nginx               1.25.3              binary
# ...

# 导出多种格式
syft myapp:latest \
    -o cyclonedx-json=app.cyclonedx.json \
    -o spdx-json=app.spdx.json \
    -o table=app.table.txt
```

### 2.2 自动化 CI/CD

```yaml
# .github/workflows/sbom.yml
name: Generate SBOM

on:
  push:
    branches: [main, release/*]
    tags: ['v*']

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: 构建容器镜像
        run: docker build -t myapp:${{ github.sha }} .

      - name: 生成 SBOM (CycloneDX)
        uses: anchore/sbom-action@v0
        with:
          image: myapp:${{ github.sha }}
          format: cyclonedx-json
          output-file: myapp-${{ github.ref_name }}.cdx.json

      - name: 生成 SBOM (SPDX)
        uses: anchore/sbom-action@v0
        with:
          image: myapp:${{ github.sha }}
          format: spdx-json
          output-file: myapp-${{ github.ref_name }}.spdx.json

      - name: 上传 SBOM 作为 Artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom-${{ github.sha }}
          path: '*.{cdx,spdx}.json'

      - name: 检查 SBOM 中的已知漏洞
        uses: anchore/scan-action@v3
        with:
          image: myapp:${{ github.sha }}
          fail-build: true
          severity-cutoff: high
```

---

## 3. SBOM 安全分析

### 3.1 Grype 漏洞扫描

```bash
# 基于 SBOM 扫描漏洞
grype sbom:app.cyclonedx.json

# 输出示例:
# NAME          INSTALLED  FIXED-IN  TYPE       VULNERABILITY        SEVERITY
# libssl1.1     1.1.1n     1.1.1t    deb        CVE-2023-0286        High
# libssl1.1     1.1.1n               deb        CVE-2022-4450        Medium
# curl          7.74.0     7.74.0-1  deb        CVE-2023-23916       Medium
# zlib          1.2.11     1.2.13    deb        CVE-2022-37434       Critical

# 生成 JSON 报告
grype sbom:app.cyclonedx.json -o json > vulnerabilities.json

# 集成 VEX (Vulnerability Exploitability eXchange)
grype sbom:app.cyclonedx.json \
    --vex vex-statement.json \
    -o table
```

### 3.2 持续监控

```python
import json
import requests
from datetime import datetime, timedelta
from typing import List, Dict

class SBOMVulnerabilityMonitor:
    """SBOM 漏洞持续监控"""

    def __init__(self, sbom_path, nvd_api_key=None):
        with open(sbom_path) as f:
            self.sbom = json.load(f)
        self.components = self._extract_components()
        self.nvd_api_key = nvd_api_key

    def _extract_components(self):
        """从 CycloneDX SBOM 提取组件列表"""
        components = []

        for comp in self.sbom.get('components', []):
            components.append({
                'name': comp['name'],
                'version': comp.get('version', 'unknown'),
                'purl': comp.get('purl', ''),
                'cpe': comp.get('cpe', ''),
                'type': comp.get('type', 'library'),
                'bom-ref': comp.get('bom-ref', ''),
                'licenses': [l['license']['id']
                            for l in comp.get('licenses', [])
                            if 'license' in l]
            })

        return components

    def check_osv_dev(self):
        """
        使用 Google OSV API 检查组件漏洞
        https://osv.dev/
        """
        findings = []

        for comp in self.components:
            if not comp['purl']:
                continue

            response = requests.post(
                'https://api.osv.dev/v1/query',
                json={
                    'package': {'purl': comp['purl']},
                    'version': comp['version']
                }
            )

            if response.status_code == 200:
                vulns = response.json().get('vulns', [])
                for vuln in vulns:
                    findings.append({
                        'component': f"{comp['name']}@{comp['version']}",
                        'vulnerability': vuln['id'],
                        'summary': vuln.get('summary', ''),
                        'severity': self._get_osv_severity(vuln),
                        'fixed_version': self._get_fixed_version(vuln),
                        'published': vuln.get('published', '')
                    })

        return findings

    def generate_alert(self, findings):
        """生成高优先级告警"""
        critical_vulns = [f for f in findings
                         if f['severity'] in ('CRITICAL', 'HIGH')]
        if critical_vulns:
            print(f"🚨 {len(critical_vulns)} 高危组件漏洞!")
            for vuln in critical_vulns:
                print(f"   {vuln['component']}: {vuln['vulnerability']} "
                      f"({vuln['severity']})")
                if vuln['fixed_version']:
                    print(f"   → 修复版本: {vuln['fixed_version']}")

    def _get_osv_severity(self, vuln):
        severities = []
        for db_specific in vuln.get('database_specific', {}):
            if 'severity' in db_specific:
                severities.append(db_specific['severity'])

        cvss_scores = []
        for severity in vuln.get('severity', []):
            if severity['type'] == 'CVSS_V3':
                score = float(severity['score'])
                cvss_scores.append(score)

        if cvss_scores:
            max_score = max(cvss_scores)
            if max_score >= 9.0: return 'CRITICAL'
            if max_score >= 7.0: return 'HIGH'
            if max_score >= 4.0: return 'MEDIUM'
            return 'LOW'

        return 'UNKNOWN'

    def _get_fixed_version(self, vuln):
        for affected in vuln.get('affected', []):
            for range_event in affected.get('ranges', []):
                events = range_event.get('events', [])
                for event in events:
                    if 'fixed' in event:
                        return event['fixed']
        return None
```

---

## 4. VEX (漏洞可利用性交换)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "name": "myapp",
      "version": "2.3.1"
    },
    "timestamp": "2024-03-15T14:30:00Z"
  },
  "vulnerabilities": [
    {
      "id": "CVE-2023-44487",
      "analysis": {
        "state": "not_affected",
        "detail": "本应用不使用 HTTP/2 (只使用 HTTP/1.1)，因此不受 Rapid Reset 攻击影响",
        "justification": "code_not_reachable"
      }
    },
    {
      "id": "CVE-2023-38545",
      "analysis": {
        "state": "resolved",
        "detail": "libcurl 已通过内部 patch 修复，版本 7.88.1+p1",
        "justification": "code_not_reachable"
      },
      "affects": [
        {
          "ref": "pkg:deb/debian/libcurl4@7.88.1-10"
        }
      ]
    }
  ]
}
```

---

## 参考资源

- [NTIA SBOM 最小元素](https://www.ntia.gov/sbom)
- [CycloneDX 规范](https://cyclonedx.org/)
- [SPDX 规范](https://spdx.dev/)
- [Anchore Syft](https://github.com/anchore/syft)
- [Google OSV](https://osv.dev/)

---

*上一篇：[CI/CD 安全加固](./01-cicd-security.md)*

*下一篇：[软件签名与验证深度](05-signing-verification.md)*

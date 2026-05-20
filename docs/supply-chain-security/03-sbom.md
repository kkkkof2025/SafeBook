# SBOM（软件物料清单）

## 什么是 SBOM

SBOM（Software Bill of Materials）是软件的成分清单，列出所有直接和传递依赖。

## SBOM 格式

### SPDX（ISO/IEC 5962）
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
PackageName: my-app
PackageVersion: 1.0.0

### CycloneDX（OWASP）
```xml
<component type="library" bom-ref="pkg:npm/lodash@4.17.21">
  <name>lodash</name>
  <version>4.17.21</version>
</component>
```

## 生成工具

| 语言/平台 | 工具 | 输出格式 |
|-----------|------|---------|
| JavaScript | CycloneDX-Node | CycloneDX |
| Python | cyclonedx-bom | CycloneDX |
| Java | cyclonedx-maven-plugin | CycloneDX |
| 通用 | Syft | SPDX/CycloneDX |
| 容器 | Trivy | CycloneDX |

## SBOM 在安全中的应用

1. 漏洞扫描：SBOM 到 CVE 的自动映射
2. 合规审计：许可证合规性检查
3. 供应链风险管理：已知漏洞组件识别
4. 应急响应：Log4Shell 快速确认是否受影响

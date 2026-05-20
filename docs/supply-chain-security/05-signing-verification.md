# 软件签名与验证

## 为什么要签名

- 防止软件被篡改
- 确保来源可信
- 满足供应链安全合规

## Sigstore 生态

### Cosign 签名
```bash
cosign generate-key-pair
cosign sign --key cosign.key ghcr.io/org/my-app:v1.0
cosign verify --key cosign.pub ghcr.io/org/my-app:v1.0
```

### Keyless 签名（推荐）
```bash
cosign sign ghcr.io/org/my-app:v1.0
cosign verify ghcr.io/org/my-app:v1.0 --certificate-identity user@example.com
```

## 供应链安全最佳实践

1. 依赖锁定：使用 lock 文件锁定传递依赖版本
2. 自动更新：Dependabot/Renovate 周级别更新
3. 签名验证：CI/CD 中验证所有第三方包签名
4. 最小依赖：定期评审并移除未使用依赖
5. 镜像缓存：内部镜像仓库缓存可信镜像

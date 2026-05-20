# 依赖管理与投毒防御

> 你的项目引用的每一个第三方包，都可能成为攻击入口

---

## 依赖投毒攻击链

```
攻击者视角：
1. 选择一个流行的开源包
2. 通过社会工程或凭证泄露获得维护者权限
3. 提交包含后门的代码（精简版）
4. 发布新版本
5. 自动更新的项目自动拉取恶意版本
6. 后门被执行
```

---

## 真实案例

### event-stream (npm, 2018)

```text
攻击者成为流行包 event-stream 的维护者
→ 注入 flatmap-stream 作为依赖
→ flatmap-stream 包含加密货币窃取代码
→ 影响：数千个项目，包括 Copay 钱包
→ 损失：数百万美元加密货币

教训：即使维护良好的包也可能被攻陷
```

### PyTorch 依赖链 (2022)

```text
攻击者注册了与 PyPi 流行包相似的名称
→ 在 PyTorch 项目的 CI 中依赖被混淆
→ 恶意包收集环境变量和密钥
→ 影响：CI 中构建的项目

教训：依赖解析优先级可能导致混淆攻击
```

### Colors 库 (npm, 2024)

```text
colors.js 维护者故意引入死循环
→ 导致依赖该库的所有项目崩溃
→ 影响：数千个 Node.js 项目

教训：即使是"维护者不满"也可能成为供应链攻击
```

---

## 依赖混淆攻击

### 原理

```text
企业私有包名： @company/internal-lib
攻击者注册：   internal-lib（在 PyPI/npm 上）

如果包管理器的解析顺序是：
  1. 先查公有仓库
  2. 再查私有仓库

→ 公有仓库的 malicious internal-lib 被优先安装
```

### 防御

```bash
# Python: 配置私有索引为优先源
pip config set global.index-url https://private.pypi.org/simple/
pip config set global.extra-index-url https://pypi.org/simple

# Node.js: 使用 scope 隔离
npm config set @company:registry https://private.registry.com/
```

---

## 防御策略

### 1. 锁定依赖版本

```bash
# Python
pip freeze > requirements.txt

# Node.js - 自动创建
npm install  # 生成 package-lock.json
yarn install # 生成 yarn.lock

# 强制使用 lockfile
npm ci       # 使用 lockfile 精确安装
pip install --require-hashes -r requirements.txt
```

### 2. 依赖扫描

```bash
# Python
pip-audit -r requirements.txt
safety check -r requirements.txt

# Node.js
npm audit
npm audit --audit-level=high

# 容器
trivy image my-app:latest
grype my-app:latest
```

### 3. 版本钉选（Pin）

```python
# requirements.txt — 不推荐的做法
requests  # ❌ 每次安装可能不同版本

# ✅ 推荐：锁定精确版本 + 哈希
requests==2.31.0 --hash=sha256:abc123...
urllib3==2.1.0 --hash=sha256:def456...
```

### 4. 最小依赖原则

```text
引入一个新依赖之前问自己：
  □ 这个功能有多复杂？能不能自己写？
  □ 这个包的维护状态如何？
  □ 它依赖了多少传递依赖？
  □ 有没有更轻量的替代方案？

经验法则：
  - 简单功能（URL 解析、编码转换）→ 自己实现
  - 复杂功能（加密、协议）→ 使用成熟库
  - AI 项目 → 使用官方镜像、固定版本
```

---

## AI 项目的依赖风险

```text
AI 项目的高风险依赖：
  - PyTorch / TensorFlow (大型二进制文件)
  - transformers (运行时下载模型)
  - tokenizers (C 扩展)
  - onnxruntime (多平台适配)
  - CUDA 驱动 (系统级安装)

特殊风险：
  1. Pickle 序列化 → 模型文件可包含任意代码
  2. Hugging Face Hub → 自动下载权重
  3. Jupyter Notebook → 运行环境中的恶意代码
```

---

## 安全检查清单

- [ ] 所有依赖版本已锁定（lockfile 已提交）
- [ ] CI 中使用 `npm ci` 或 `pip install --require-hashes`
- [ ] 依赖漏洞扫描集成到 CI
- [ ] 配置了私有仓库优先（防止依赖混淆）
- [ ] 最小化依赖引入
- [ ] AI 模型只从可信来源下载
- [ ] 有 SBOM 生成机制
- [ ] 定期更新依赖并审查变更

---

## 延伸阅读

1. [OpenSSF Scorecard — 开源包安全评分](https://securityscorecards.dev/)
2. [RLS — 依赖投毒案例库](https://github.com/ossf/package-analysis)
3. [npm audit 官方文档](https://docs.npmjs.com/cli/v10/commands/npm-audit)
4. [pip-audit 工具](https://github.com/pypa/pip-audit)
5. [Dependency Confusion 攻击详解](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)

# 安全认证完全指南

> 从入门到专家的安全认证路线图

---

## 认证分类

```
    入门级              中级              高级              专家级
  ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
  │Security+│ ──→ │  eJPT   │ ──→ │  OSCP   │ ──→ │  OSEP   │
  │Network+ │     │  CEH    │     │  GPEN   │     │  OSED   │
  │CySA+   │     │  BTL1   │     │  CISSP  │     │  GSE    │
  └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

---

## 渗透测试路线

| 认证 | 机构 | 价格 | 难度 | 考试 | 适合 |
|------|------|------|------|------|------|
| eJPT | INE | $200 | ⭐⭐ | 48h 实操 | 零基础入门 |
| PNPT | TCM | $299 | ⭐⭐⭐ | 5天 AD 环境 | 性价比之选 |
| OSCP | OffSec | $1599 | ⭐⭐⭐⭐ | 24h 夺旗+报告 | 行业金标准 |
| GPEN | SANS | $8000+ | ⭐⭐⭐⭐ | 机考 | 企业员工 |
| OSEP | OffSec | $1299 | ⭐⭐⭐⭐⭐ | 48h 综合 | 高级红队 |
| CRTP | Altered | $249 | ⭐⭐⭐ | 24h AD | AD 专项 |

### OSCP 备考路径
```bash
# Phase 1: 基础巩固 (2 周)
# - PortSwigger Academy Labs (至少做完 SQL + XSS)
# - TryHackMe: OffSec 路径

# Phase 2: 靶场练习 (4-6 周)
# - PWK Labs: 30-60 台机器
# - Proving Grounds Practice: Linux + Windows
# - Hack The Box: Easy-Medium

# Phase 3: 模拟冲刺 (2 周)
# - 官方模拟考试
# - AD 专项: CRTP 实验室
# - 报告模板准备
```

---

## 蓝队/防御路线

| 认证 | 方向 | 难度 |
|------|------|------|
| BTL1 | 蓝队入门 | ⭐⭐ |
| CySA+ | 安全分析 | ⭐⭐ |
| BTL2 | 高级蓝队 | ⭐⭐⭐ |
| GCFA | 取证分析 | ⭐⭐⭐⭐ |
| GNFA | 网络取证 | ⭐⭐⭐⭐⭐ |
| GCIH | 事件响应 | ⭐⭐⭐ |

---

## 云安全路线

| 认证 | 平台 | 适合 |
|------|------|------|
| AWS Security Specialty | AWS | AWS 安全工程师 |
| Azure Security Engineer | Azure | Azure 安全工程师 |
| GCP Professional Security | GCP | GCP 安全架构师 |
| CCSK | 通用 | 云安全基础 |
| CCSP | 通用 | 云安全专家 |

---

## 管理路线

| 认证 | 要求 | 薪资参考 |
|------|------|---------|
| CISSP | 5年经验 + 背书 | $120K-180K |
| CISM | 5年经验 | $110K-160K |
| CRISC | 3年经验 | $100K-140K |
| CISA | 5年经验 | $90K-130K |

---

## 选证建议

```yaml
零基础入门: eJPT → OSCP
  - 理由: 实战导向，直接提升技能
  - 预算: ~$1800

性价比路线: PNPT → CRTP → OSCP  
  - 理由: 低价高质，AD 专项深入
  - 预算: ~$2000

科班路线: Security+ → CySA+ → CISSP
  - 理由: 体系完整，雇主认可度高
  - 预算: ~$1300

云安全: AWS-SCS → CCSP
  - 理由: 云安全人才缺口大
  - 预算: ~$900
```

---

*上一篇：[安全职业发展路径](03-career.md)*

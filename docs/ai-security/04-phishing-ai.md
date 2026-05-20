# AI 辅助钓鱼与防护

> AI 降低了钓鱼攻击的门槛，也让防御变得更加复杂

---

## AI 如何改变钓鱼攻击

### 传统钓鱼 vs AI 辅助钓鱼

| 维度 | 传统钓鱼 | AI 辅助钓鱼 |
|------|----------|-------------|
| 邮件质量 | 语法错误多、格式粗糙 | 自然流畅、无语法错误 |
| 个性化程度 | 通用模板 | 可针对个人定制 |
| 规模化 | 需要人工创建 | AI 批量生成 |
| 多语言 | 翻译质量差 | 天然多语言支持 |
| A/B测试 | 手动 | AI 自动优化 |

### AI 钓鱼攻击的典型流程

```mermaid
graph LR
    A[收集目标信息] --> B[AI 生成钓鱼内容]
    B --> C[个性化定制]
    C --> D[自动发送]
    D --> E[收集响应]
    E --> F[AI 自动跟进]
    F --> G[最终攻击]
    
    style A fill:#ff6b6b
    style G fill:#ff0000
```

### AI 生成的钓鱼邮件示例

```text
发件人: 技术支持 <support@company-secure.com>
主题: 紧急：您的账户存在异常登录

尊敬的张三，

我们检测到您的企业邮箱在今天凌晨 03:17 有一次来自
IP 203.113.x.x（北京）的异常登录。

如确认是您本人的操作，请忽略此邮件。
如非本人操作，请立即点击以下链接验证身份：
https://company-secure-verify.com/check

此链接 30 分钟内有效。

此致
IT 安全团队

------------------------------------------------------
[分析] 与传统钓鱼相比：
✓ 收件人姓名准确（张三）
✓ 语法完全正确
✓ 语气和格式专业
✓ 制造紧迫感（30分钟）
✓ 没有明显的拼写错误
```

---

## 识别 AI 生成的钓鱼内容

### 信号检测

```python
import re
from typing import List, Dict

class AIPhishingDetector:
    """AI 钓鱼邮件检测器"""
    
    def __init__(self):
        self.signals = {
            'urgency': r'(立即|紧急|限时|最后通知|逾期|30分钟|24小时内)',
            'personalization': r'(尊敬的.{1,4}[，,]\s*$)',
            'perfect_format': r'^(尊敬的|尊敬的.{1,10}：\n\n)',
            'suspicious_domain': r'https?://[\w.-]*?(secure|verify|confirm|protect|login)[\w.-]*\.\w+/',
            'no_greeting_variant': r'(尊敬的.{1,10}：?\n\n)',
        }
    
    def analyze_email(self, email_text: str) -> Dict:
        """分析邮件中的钓鱼信号"""
        results = {}
        
        for signal_name, pattern in self.signals.items():
            matches = re.findall(pattern, email_text)
            results[signal_name] = {
                'detected': len(matches) > 0,
                'count': len(matches),
                'matches': matches[:3]
            }
        
        # 综合评分
        total_signals = sum(1 for v in results.values() if v['detected'])
        phishing_score = total_signals / len(self.signals)
        
        results['phishing_score'] = phishing_score
        
        if phishing_score >= 0.6:
            results['verdict'] = '高危 - 建议标记为钓鱼'
        elif phishing_score >= 0.3:
            results['verdict'] = '可疑 - 需要人工审核'
        else:
            results['verdict'] = '低风险'
        
        return results
```

### 人工识别技巧

1. **检查发件人地址**：显示名可以伪造，但邮件地址不能
2. **悬停查看链接**：鼠标悬停在链接上（不要点击），查看真正的地址
3. **核对语气**：AI 生成的邮件通常过于"完美"，缺少人类书写的自然感
4. **寻找异常**：任何要求你"立即操作"的消息都值得警惕
5. **独立验证**：不要通过邮件中的链接登录，而是手动打开官方网站

---

## Agent 平台如何防御钓鱼

### OpenClaw 中的防御机制

```python
class PhishingDefense:
    """Agent 钓鱼防御模块"""
    
    def __init__(self):
        self.known_malicious_domains = set()
        self.suspicious_patterns = []
        
    def check_url(self, url: str) -> Dict:
        """检查 URL 是否安全"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        domain = parsed.hostname
        
        issues = []
        
        # 1. 检查域名相似度（防止 typosquatting）
        similar = self._check_typosquatting(domain)
        if similar:
            issues.append(f"域名 {domain} 与已知合法域名 {similar} 相似")
        
        # 2. 检查是否为已知恶意域名
        if domain in self.known_malicious_domains:
            issues.append(f"域名 {domain} 在已知恶意域名列表中")
        
        # 3. 检查 URL 中的可疑关键词
        suspicious_keywords = ['login', 'verify', 'secure', 'update', 'confirm']
        path_lower = parsed.path.lower()
        for kw in suspicious_keywords:
            if kw in path_lower:
                issues.append(f"URL 路径包含可疑关键词: {kw}")
        
        # 4. 检查短链接
        short_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.cn', 'url.cn']
        if domain in short_domains:
            issues.append("短链接无法直接判断，建议还原后检查")
        
        return {
            'safe': len(issues) == 0,
            'issues': issues,
            'domain': domain
        }
    
    def _check_typosquatting(self, domain: str) -> str:
        """检查域名是否与知名品牌相似"""
        known_domains = [
            'google.com', 'facebook.com', 'twitter.com', 
            'microsoft.com', 'apple.com', 'amazon.com',
            'alibaba.com', 'tencent.com', 'baidu.com'
        ]
        
        for known in known_domains:
            if self._levenshtein_distance(domain, known) <= 2:
                return known
        
        return None
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """计算编辑距离"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]


# 使用示例
def agent_before_access_url(url: str) -> bool:
    """Agent 访问 URL 前的安全检查"""
    defense = PhishingDefense()
    result = defense.check_url(url)
    
    if not result['safe']:
        # 记录安全事件
        log_security_event('phishing_url_detected', {
            'url': url,
            'issues': result['issues'],
            'timestamp': datetime.now().isoformat()
        })
        
        print(f"⚠️ 安全警告：该链接可能不安全")
        for issue in result['issues']:
            print(f"  · {issue}")
        
        # 返回 False 阻止自动访问
        return False
    
    return True
```

---

## 防御的最佳实践

### 用户层面

1. **不轻信链接**：即使是 AI 助手发来的链接也要核实
2. **启用双因素**：所有账户启用 2FA（尤其是邮箱和金融账户）
3. **验证来源**：收到异常消息时，通过其他渠道独立验证
4. **教育训练**：定期参加钓鱼演练，保持警觉

### Agent 平台层面

1. **URL 检查**：访问链接前进行安全检测
2. **域名验证**：对疑似钓鱼域名自动告警
3. **操作确认**：高风险操作需要用户二次确认
4. **访问日志**：记录所有网络访问便于回溯

### 组织层面

1. **定期演练**：模拟钓鱼测试员工
2. **报告机制**：方便员工报告可疑邮件
3. **技术防御**：DMARC、SPF、DKIM 邮件验证
4. **即时响应**：发现钓鱼后的快速响应流程

---

## 延伸阅读

1. [APWG 钓鱼活动趋势报告](https://apwg.org/)
2. [OpenClaw 安全最佳实践](https://openclaw.ai/docs/security)
3. [AI 钓鱼防御指南 — OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Phishing_Cheat_Sheet.html)
4. [Google Safe Browsing API](https://developers.google.com/safe-browsing)
5. [DMARC 配置指南](https://dmarc.org/)

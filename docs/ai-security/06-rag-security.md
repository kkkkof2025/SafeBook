# RAG 安全模式与架构

> 检索增强生成系统的纵深防御

---

## 1. RAG 攻击面

```
RAG 架构攻击面:
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   用户输入    │───→│   查询改写    │───→│   向量检索    │
└──────┬───────┘    └──────────────┘    └──────┬───────┘
       │                                       │
  Prompt 注入                           ┌──────┴───────┐
  越狱攻击                               │   知识库文档  │ ← 文档投毒
       │                                  └──────┬───────┘
       │                                       │
       │                                  ┌──────┴───────┐
       └────────────────────────────────→│   LLM 生成    │
                                          └──────────────┘
                                                  │
                                            输出注入
                                            PII 泄露
```

---

## 2. 文档级投毒防御

```python
class DocumentTrustVerifier:
    """知识库文档可信度验证"""

    def __init__(self):
        self.trusted_sources = {'wikipedia.org', 'arxiv.org', '.gov'}
        self.blocked_patterns = [
            r'(?i)ignore\s+(previous|all)\s+instructions',
            r'(?i)you\s+are\s+now\s+(DAN|unrestricted)',
            r'(?i)system\s*prompt\s*:',
            r'<!--\s*system\s*-->',
        ]

    def verify_document(self, doc_content, source_url):
        """文档加入知识库前的安全检查"""

        # 1. 来源白名单
        parsed = urlparse(source_url)
        if not any(parsed.netloc.endswith(s) for s in self.trusted_sources):
            return {'trusted': False, 'reason': f'Untrusted source: {source_url}'}

        # 2. 注入检测
        for pattern in self.blocked_patterns:
            if re.search(pattern, doc_content, re.IGNORECASE):
                return {
                    'trusted': False,
                    'reason': f'Injection pattern detected: {pattern}'
                }

        # 3. 隐藏文本检测 (白色文字/极小字体/零宽字符)
        hidden_patterns = [
            r'[\u200b-\u200f\u2028-\u202f\u2060-\u206f]',  # 零宽字符
            r'font-size\s*:\s*0',                          # 隐藏文本
            r'color\s*:\s*transparent',                    # 透明文本
        ]
        for pattern in hidden_patterns:
            matches = re.findall(pattern, doc_content, re.IGNORECASE)
            if matches:
                return {
                    'trusted': False,
                    'reason': f'Hidden text detected: {len(matches)} matches'
                }

        # 4. 内容签名
        doc_hash = hashlib.sha256(doc_content.encode()).hexdigest()
        return {
            'trusted': True,
            'hash': doc_hash,
            'source': source_url
        }
```

---

## 3. 检索层安全

```python
class SecureRetriever:
    """安全增强的向量检索器"""

    def __init__(self, vector_store, trust_db):
        self.vector_store = vector_store
        self.trust_db = trust_db

    def retrieve(self, query, k=5):
        docs = self.vector_store.similarity_search(query, k=k)

        filtered = []
        for doc in docs:
            trust_score = self.trust_db.get(doc.metadata['doc_id'], 1.0)

            # 投毒检测: 异常高的相似度
            if doc.metadata.get('score', 0) > 0.99 and trust_score < 0.5:
                log.warning(f"Suspicious high-similarity doc: {doc.metadata['doc_id']}")
                continue

            # 来源交叉验证
            sources = doc.metadata.get('cross_references', [])
            for ref in sources:
                ref_trust = self.trust_db.get(ref, 0)
                trust_score = max(trust_score, ref_trust * 0.5)

            if trust_score >= 0.3:  # 最低可信度阈值
                doc.metadata['trust_score'] = trust_score
                filtered.append(doc)

        # 按可信度排序
        filtered.sort(key=lambda d: d.metadata['trust_score'], reverse=True)
        return filtered[:k]
```

---

## 4. 生成层防御

```python
class RAGOutputGuard:
    """RAG 输出安全护栏"""

    SENSITIVE_PATTERNS = {
        'api_key': r'(sk-|api_key[=:])\s*[a-zA-Z0-9_-]{32,}',
        'password': r'(password|passwd)\s*[=:]\s*\S+',
        'internal_ip': r'\b(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',
        'system_prompt': r'(?i)(system\s*prompt|you are a helpful|you are an AI)',
    }

    def sanitize_output(self, response, retrieved_docs):
        # 1. 敏感信息过滤
        for key, pattern in self.SENSITIVE_PATTERNS.items():
            response = re.sub(pattern, f'[REDACTED:{key}]', response)

        # 2. 来源引用验证
        cited_sources = self.extract_citations(response)
        for source in cited_sources:
            if source not in retrieved_docs:
                response = response.replace(source, '[UNVERIFIED]')

        # 3. Prompt 注入反射检测
        if any(p in response.lower() for p in [
            'system prompt', 'you are now', 'ignore instructions'
        ]):
            return "I cannot process this request. Please rephrase."

        return response
```

---

## 5. RAG 安全矩阵

| 层级 | 攻击 | 防御 | 成熟度 |
|------|------|------|--------|
| 文档层 | 知识库投毒 | 来源白名单 + 签名验证 | ★★★ |
| 检索层 | 相似度操纵 | 信任评分 + 交叉验证 | ★★☆ |
| 生成层 | 提示反射 | 输出过滤 + 注入检测 | ★★★ |
| 用户层 | Prompt 注入 | 输入消毒 + 上下文隔离 | ★★★ |
| 运营层 | 数据投毒 | 差分隐私 + 审计日志 | ★★☆ |
| 监控层 | 模型窃取 | 频率限制 + 行为基线 | ★★★ |

---

*上一篇：[AI 安全实战指南](../ai-security/ai-security-toolkit.md)*

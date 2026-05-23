# REST API 安全测试自动化

> CI/CD 管道中的 API 安全扫描

---

## 1. API 安全测试工具链

```
CI/CD 管道中的 API 安全:
  ┌──────┐   ┌──────┐   ┌───────┐   ┌──────┐   ┌───────┐
  │ Code │ → │ SAST │ → │ Build │ → │ DAST │ → │ Deploy│
  │ Push │   │Semgrep│   │       │   │ZAP   │   │       │
  └──────┘   └──────┘   └───────┘   └──────┘   └───────┘
                                          │
                                    ┌─────┴─────┐
                                    │ API 测试   │
                                    │ Postman   │
                                    │ Schemathesis│
                                    │ fuzz-light│
                                    └───────────┘
```

---

## 2. OpenAPI Schema 测试

```python
import schemathesis

# Schemathesis: 基于 OpenAPI Schema 的自动模糊测试
schema = schemathesis.from_uri("https://api.example.com/openapi.json")

# 自动发现所有端点 → 生成测试用例 → 执行
@schema.parametrize()
def test_api(case):
    """每个 API 端点的自动安全测试"""
    response = case.call()

    # 验证:
    # 1. 响应状态码是否符合规范
    case.validate_response(response)

    # 2. 安全头检查
    security_headers = [
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Content-Security-Policy'
    ]
    for header in security_headers:
        assert header in response.headers, f"Missing: {header}"

    # 3. 不泄露敏感信息
    sensitive_fields = ['password', 'secret', 'token', 'api_key']
    for field in sensitive_fields:
        assert field not in response.text.lower()

# 运行
# schemathesis run https://api.example.com/openapi.json
```

---

## 3. API Fuzzer

```python
class APIFuzzer:
    """API 模糊测试引擎"""

    def __init__(self, openapi_spec):
        self.spec = openapi_spec
        self.endpoints = self.parse_endpoints()

    def parse_endpoints(self):
        """解析 OpenAPI → 端点列表"""
        endpoints = []
        for path, methods in self.spec['paths'].items():
            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    endpoints.append({
                        'path': path,
                        'method': method.upper(),
                        'params': details.get('parameters', []),
                        'request_body': details.get('requestBody', {}),
                        'responses': details.get('responses', {}),
                        'security': details.get('security', [])
                    })
        return endpoints

    def fuzz_injection(self, endpoint):
        """注入攻击测试"""
        payloads = {
            'sql_injection': ["' OR '1'='1", "1; DROP TABLE users--",
                             "1' UNION SELECT NULL--"],
            'xss': ['<script>alert(1)</script>',
                   '<img src=x onerror=alert(1)>'],
            'nosql_injection': ['{"$gt": ""}',
                               '{"$ne": null}'],
            'command_injection': ['; ls -la', '| cat /etc/passwd',
                                 '`whoami`', '$(id)'],
            'path_traversal': ['../../etc/passwd',
                              '..\\..\\windows\\system32\\config\\sam'],
        }

        findings = []
        for attack_type, payload_list in payloads.items():
            for payload in payload_list:
                response = self.send_request(endpoint, payload)

                if self.detect_vulnerability(response, attack_type):
                    findings.append({
                        'endpoint': endpoint['path'],
                        'method': endpoint['method'],
                        'type': attack_type,
                        'payload': payload,
                        'response_code': response.status_code,
                        'evidence': response.text[:200]
                    })

        return findings

    def fuzz_authorization(self, endpoint):
        """授权绕过测试"""
        responses = []

        # 1. 无认证
        responses.append(('no_auth', self.call(endpoint, auth=None)))

        # 2. 低权角色访问高权端点
        if endpoint.get('security'):
            responses.append(
                ('low_privilege',
                 self.call(endpoint, role='viewer'))
            )

            # 3. 修改资源 ID 访问他人数据
            if '{id}' in endpoint['path']:
                other_path = endpoint['path'].replace(
                    '{id}', 'OTHER_USER_ID'
                )
                responses.append(
                    ('idor_test',
                     self.call({**endpoint, 'path': other_path},
                              role='user'))
                )

        findings = []
        for test_name, resp in responses:
            if resp.status_code == 200 and test_name in ['no_auth', 'low_privilege']:
                findings.append({
                    'type': 'MISSING_AUTHORIZATION',
                    'test': test_name,
                    'endpoint': endpoint['path'],
                    'severity': 'HIGH'
                })

        return findings
```

---

## 4. CI/CD 集成

```yaml
# GitHub Actions: API 安全扫描
name: API Security Scan
on:
  pull_request:
    paths:
      - 'api/**'
      - 'openapi.yaml'

jobs:
  api-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start API Server
        run: |
          docker-compose up -d api
          sleep 15

      - name: ZAP API Scan
        uses: zaproxy/action-api-scan@v0.7.0
        with:
          target: 'http://localhost:8000/openapi.json'
          format: 'openapi'
          rules_file_name: '.zap/rules.tsv'

      - name: Schemathesis Fuzz
        run: |
          pip install schemathesis
          st run http://localhost:8000/openapi.json \
            --checks all \
            --max-response-time=5000 \
            --hypothesis-max-examples=1000 \
            --junit-xml=report.xml

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: api-security-results
          path: report.xml

      - name: Fail on High Risk
        if: failure()
        run: |
          echo "API security scan failed! Blocking merge."
          exit 1
```

---

## 5. API 安全基线

```yaml
API 安全测试清单:

  认证测试:
    - [ ] 所有端点需要认证 (除 /health)
    - [ ] JWT 签名验证
    - [ ] Token 过期后正确拒绝
    - [ ] 算法混淆攻击测试

  授权测试:
    - [ ] BOLA (IDOR): 访问他人的资源 ID
    - [ ] BFLA: 普通用户执行管理员操作
    - [ ] 批量操作权限检查

  输入验证:
    - [ ] SQLi/NoSQLi 注入
    - [ ] XSS
    - [ ] Mass Assignment
    - [ ] 类型混淆 (string → int/array)

  速率限制:
    - [ ] 100 req/min 基准测试
    - [ ] 绕过测试 (不同 IP/Header)
    - [ ] GraphQL 深度限制

  安全头:
    - [ ] CORS (禁止 *)
    - [ ] HSTS
    - [ ] Content-Type 一致性
```

---

*上一篇：[GraphQL 深度攻击与防御](05-graphql-defense.md)*

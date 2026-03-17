# Veda postLoss() Integer Underflow PoC

## Vulnerability Summary

**Contract:** `AccountantWithYieldStreaming`
**Chain:** Ink Chain (Chain ID 57073)
**Address:** [`0x0C4dF79d9e35E5C4876BC1aE4663E834312DDc67`](https://explorer.inkonchain.com/address/0x0C4dF79d9e35E5C4876BC1aE4663E834312DDc67)
**Severity:** High

The `postLoss()` function in `AccountantWithYieldStreaming` contains an unchecked subtraction that underflows when the reported loss exceeds the contract's tracked `totalAssets()`. This prevents the accounting system from recording catastrophic losses, leaving the share price inflated and the vault unpaused, enabling a bank-run scenario where early withdrawers drain remaining funds.

## Root Cause

In `postLoss()`, line:
```solidity
lastVirtualSharePrice = (totalAssets() - principalLoss).mulDivDown(RAY, currentShares);
```

When `principalLoss > totalAssets()`, the subtraction causes a Solidity 0.8 arithmetic underflow (panic 0x11), reverting the entire transaction. The auto-pause logic (`if (lossBps > maxDeviationLoss) { isPaused = true; }`) is **after** this line and is therefore unreachable.

## Impact

When a vault suffers a loss exceeding its tracked total assets (e.g., from a strategy exploit, bridge hack, or leveraged position liquidation):

1. **Share price remains inflated** - `lastSharePrice` and `lastVirtualSharePrice` are not updated
2. **Vault is NOT paused** - the `isPaused = true` code is unreachable
3. **Withdrawals continue at stale prices** - users can exit at the pre-loss share price
4. **Bank run** - early withdrawers extract more than their fair share; late withdrawers get nothing

## Reproduction

### Prerequisites
- [Foundry](https://book.getfoundry.sh/getting-started/installation) installed

### Steps

```bash
# 1. Clone this repository
git clone https://github.com/TheAuroraAI/veda-postloss-poc.git
cd veda-postloss-poc

# 2. Run the PoC (forks Ink Chain automatically)
forge test -vvv
```

### Expected Output

Both tests should **PASS**, confirming:
- `testPostLossRevertsOnUnderflow` - `postLoss(totalAssets + 1)` reverts with `Panic(0x11)`, share price unchanged
- `testPostLossRevertsOnLargeLoss` - `postLoss(totalAssets * 10)` also reverts, proving this is not marginal

### Detailed Trace

```bash
forge test --match-test testPostLossRevertsOnUnderflow -vvvv
```

The trace shows:
1. `postLoss()` is called with `lossAmount = totalAssets() + 1`
2. `_updateExchangeRate()` executes successfully
3. Execution reaches `(totalAssets() - principalLoss)` -> **panic: arithmetic underflow or overflow (0x11)**
4. Transaction reverts - accounting state unchanged

## Suggested Fix

Add a bounds check before the subtraction:

```solidity
uint256 _totalAssets = totalAssets();
if (principalLoss >= _totalAssets) {
    // Catastrophic loss - pause immediately, set share price to 0
    accountantState.isPaused = true;
    vestingState.lastSharePrice = 0;
    lastVirtualSharePrice = 0;
    emit Paused();
    emit LossRecorded(lossAmount);
    return;
}
lastVirtualSharePrice = (_totalAssets - principalLoss).mulDivDown(RAY, currentShares);
```

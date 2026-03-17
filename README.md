# Veda PoC: postLoss() Integer Underflow

**Target**: `AccountantWithYieldStreaming` at `0x0C4dF79d9e35E5C4876BC1aE4663E834312DDc67` (Ink Chain)

## Vulnerability

`postLoss()` reverts with arithmetic underflow when `lossAmount > totalAssets()` (after internal vesting update). This prevents the loss from being recorded, leaving `lastSharePrice` at its pre-loss (inflated) value. The auto-pause mechanism at line 247 is unreachable because the revert happens before it.

## Running the PoC

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Create project
mkdir veda-poc && cd veda-poc
forge init --no-git .
cp VedaPoC.t.sol test/

# Run against Ink Chain fork
forge test --match-contract VedaPostLossPoC -vvvv --fork-url https://rpc-gel.inkonchain.com
```

## Expected Output

```
[PASS] testPostLossRevertsOnUnderflow() (gas: 135123)
[CONFIRMED] postLoss() REVERTS with arithmetic underflow
[CONFIRMED] lastVirtualSharePrice unchanged (still inflated)
[CONFIRMED] accountantState.isPaused NOT set (auto-pause bypassed)
└─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
```

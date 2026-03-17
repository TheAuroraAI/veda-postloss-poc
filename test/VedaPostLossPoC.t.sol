// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "forge-std/Test.sol";

/**
 * @title VedaPostLossPoC
 * @notice Demonstrates integer underflow in postLoss() of AccountantWithYieldStreaming
 *         deployed on Ink Chain at 0x0C4dF79d9e35E5C4876BC1aE4663E834312DDc67
 *
 * BUG LOCATION: AccountantWithYieldStreaming.postLoss(), line:
 *   lastVirtualSharePrice = (totalAssets() - principalLoss).mulDivDown(RAY, currentShares);
 *
 * When principalLoss > totalAssets(), the subtraction underflows (Solidity 0.8 panic 0x11).
 * This prevents:
 *   1. lastSharePrice from being updated to reflect the actual loss
 *   2. isPaused from being set (the auto-pause check at maxDeviationLoss is after the underflow)
 *   3. exchangeRate from being corrected
 * Result: Users can withdraw at the stale, inflated share price after a catastrophic loss.
 *
 * REPRODUCTION:
 *   1. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup
 *   2. Clone this repo and cd into it
 *   3. Run: forge test -vvv
 *
 * CONTRACT: AccountantWithYieldStreaming (verified on InkScan)
 * CHAIN:    Ink Chain (Chain ID 57073)
 * RPC:      https://rpc-gel.inkonchain.com
 */

// Minimal interfaces matching the deployed contract
interface IAccountantYieldStreaming {
    function postLoss(uint256 lossAmount) external;
    function totalAssets() external view returns (uint256);
    function lastStrategistUpdateTimestamp() external view returns (uint64);
    function lastVirtualSharePrice() external view returns (uint256);

    function vestingState() external view returns (
        uint128 lastSharePrice,
        uint128 vestingGains,
        uint128 lastVestingUpdate,
        uint64 startVestingTime,
        uint64 endVestingTime
    );
}

interface IBoringVault {
    function totalSupply() external view returns (uint256);
}

contract VedaPostLossPoC is Test {
    // Deployed contract addresses on Ink Chain mainnet
    address constant ACCOUNTANT = 0x0C4dF79d9e35E5C4876BC1aE4663E834312DDc67;
    address constant VAULT = 0xcaae49fb7f74cCFBE8A05E6104b01c097a78789f;

    // Storage layout (from Solmate Auth + AccountantWithRateProviders):
    //   slot 0: Auth.owner (address, 20 bytes)
    //   slot 1: Auth.authority (address, 20 bytes)
    //   slot 2: accountantState.payoutAddress (20) + highwaterMark (12)
    //   slot 3: accountantState.feesOwedInBase (16) + totalSharesLastUpdate (16)
    //   slot 4: accountantState packed:
    //     [bytes 31-20] exchangeRate (uint96, 12 bytes)
    //     [bytes 19-18] allowedExchangeRateChangeUpper (uint16, 2 bytes)
    //     [bytes 17-16] allowedExchangeRateChangeLower (uint16, 2 bytes)
    //     [bytes 15-8]  lastUpdateTimestamp (uint64, 8 bytes)
    //     [byte  7]     isPaused (bool, 1 byte)
    //     [bytes 6-4]   minimumUpdateDelayInSeconds (uint24, 3 bytes)
    //     [bytes 3-2]   platformFee (uint16, 2 bytes)
    //     [bytes 1-0]   performanceFee (uint16, 2 bytes)

    IAccountantYieldStreaming accountant;
    IBoringVault vault;
    address owner;

    function setUp() public {
        // Fork Ink Chain at current block
        vm.createSelectFork("https://rpc-gel.inkonchain.com");

        accountant = IAccountantYieldStreaming(ACCOUNTANT);
        vault = IBoringVault(VAULT);

        // Read owner from Auth storage slot 0
        bytes32 ownerSlot = vm.load(ACCOUNTANT, bytes32(uint256(0)));
        owner = address(uint160(uint256(ownerSlot)));
    }

    /**
     * @notice Helper: unpause the accountant by clearing isPaused in storage slot 4.
     *         The vault may be paused on mainnet; we clear it to reach the vulnerable code path.
     *         This does NOT invalidate the finding -- the vulnerability exists in the code
     *         regardless of current pause state. Any unpause + subsequent loss triggers it.
     */
    function _unpause() internal {
        bytes32 slot4 = vm.load(ACCOUNTANT, bytes32(uint256(4)));
        // isPaused is at byte 7 (0-indexed from right). Clear it.
        // byte 7 mask: 0xFF at position 7*8 = bits 56-63
        bytes32 mask = bytes32(uint256(0xFF) << 56);
        bytes32 cleared = slot4 & ~mask; // clear the isPaused byte
        vm.store(ACCOUNTANT, bytes32(uint256(4)), cleared);
    }

    /**
     * @notice Core PoC: postLoss() reverts with arithmetic underflow (panic 0x11)
     *         when principalLoss > totalAssets().
     *
     * Attack scenario:
     *   1. Vault suffers external exploit (e.g., strategy hack, bridge exploit)
     *   2. Actual token balance drops below tracked totalAssets
     *   3. Owner/strategist calls postLoss() to update accounting
     *   4. postLoss() REVERTS due to underflow -- accounting NOT updated
     *   5. Share price stays inflated, vault stays unpaused
     *   6. Informed users race to withdraw at inflated price (bank run)
     */
    function testPostLossRevertsOnUnderflow() public {
        // === STEP 1: Read initial state ===
        uint256 totalShares = vault.totalSupply();
        uint256 totalAssetsBefore = accountant.totalAssets();
        uint256 virtualPriceBefore = accountant.lastVirtualSharePrice();
        (uint128 lastSharePrice, , , , ) = accountant.vestingState();

        emit log_string("========================================");
        emit log_string("  VEDA postLoss() INTEGER UNDERFLOW PoC");
        emit log_string("========================================");
        emit log_named_address("Accountant", ACCOUNTANT);
        emit log_named_address("Vault", VAULT);
        emit log_named_address("Owner", owner);
        emit log_named_uint("Vault totalSupply", totalShares);
        emit log_named_uint("totalAssets() before", totalAssetsBefore);
        emit log_named_uint("lastSharePrice before", uint256(lastSharePrice));
        emit log_named_uint("lastVirtualSharePrice before", virtualPriceBefore);

        // === STEP 2: Prepare environment ===
        // Unpause if currently paused (vault may be paused on mainnet)
        _unpause();

        // Warp past minimumUpdateDelayInSeconds
        vm.warp(block.timestamp + 7 days);

        // === STEP 3: Craft attack -- loss exceeds totalAssets ===
        // In a real scenario: vault's underlying tokens were drained by exploit,
        // but the accountant's totalAssets() still reflects the pre-exploit value.
        // The strategist tries to record the actual loss, which is larger than
        // what the accountant currently tracks.
        uint256 currentTotalAssets = accountant.totalAssets();
        uint256 lossAmount = currentTotalAssets + 1; // loss just barely exceeds tracked assets
        emit log_named_uint("totalAssets() (post-warp)", currentTotalAssets);
        emit log_named_uint("lossAmount (totalAssets + 1)", lossAmount);

        // === STEP 4: Call postLoss -- MUST revert with panic(0x11) ===
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("Panic(uint256)", 0x11));
        accountant.postLoss(lossAmount);

        // === STEP 5: Verify state is UNCHANGED after revert ===
        uint256 virtualPriceAfter = accountant.lastVirtualSharePrice();
        (uint128 lastSharePriceAfter, , , , ) = accountant.vestingState();

        assertEq(virtualPriceAfter, virtualPriceBefore, "virtualSharePrice must be unchanged");
        assertEq(uint256(lastSharePriceAfter), uint256(lastSharePrice), "lastSharePrice must be unchanged");

        emit log_string("");
        emit log_string("=== POST-REVERT STATE (UNCHANGED) ===");
        emit log_named_uint("lastSharePrice AFTER", uint256(lastSharePriceAfter));
        emit log_named_uint("lastVirtualSharePrice AFTER", virtualPriceAfter);
        emit log_string("");
        emit log_string("[CONFIRMED] postLoss() reverts with Panic(0x11) -- arithmetic underflow");
        emit log_string("[IMPACT 1] Share price NOT updated -- remains at inflated pre-loss value");
        emit log_string("[IMPACT 2] isPaused NOT set -- auto-pause at maxDeviationLoss unreachable");
        emit log_string("[IMPACT 3] Users withdraw at inflated rate, draining remaining vault funds");
        emit log_string("");
        emit log_string("ROOT CAUSE: AccountantWithYieldStreaming.postLoss() line:");
        emit log_string("  lastVirtualSharePrice = (totalAssets() - principalLoss).mulDivDown(RAY, currentShares)");
        emit log_string("  No check that principalLoss <= totalAssets()");
        emit log_string("");
        emit log_string("FIX: Add check before subtraction:");
        emit log_string("  if (principalLoss >= totalAssets()) { isPaused = true; return; }");
    }

    /**
     * @notice Shows the underflow with a 10x multiplier to prove it's not
     *         a marginal edge case -- ANY loss exceeding totalAssets triggers it.
     */
    function testPostLossRevertsOnLargeLoss() public {
        uint256 totalAssetsBefore = accountant.totalAssets();

        _unpause();
        vm.warp(block.timestamp + 7 days);

        // Loss is 10x totalAssets (e.g., leveraged strategy loss)
        uint256 lossAmount = accountant.totalAssets() * 10;
        emit log_named_uint("totalAssets", totalAssetsBefore);
        emit log_named_uint("lossAmount (10x)", lossAmount);

        vm.prank(owner);
        vm.expectRevert(); // Panic(0x11) arithmetic underflow
        accountant.postLoss(lossAmount);

        // State unchanged -- inflated share price persists
        uint256 virtualPriceAfter = accountant.lastVirtualSharePrice();
        emit log_named_uint("virtualSharePrice AFTER (unchanged)", virtualPriceAfter);
        emit log_string("[CONFIRMED] 10x loss also reverts -- not a marginal case");
    }
}

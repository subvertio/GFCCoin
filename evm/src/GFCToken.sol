// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Pausable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {
    AccessControlDefaultAdminRules
} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {IGFCToken} from "./interfaces/IGFCToken.sol";

/// @title Galactic Federation Coin (wrapped)
/// @notice ERC-20 representation of GFC ledger credits. Every token in circulation should be
/// backed by GFC held in the ledger's bridge escrow wallet; the only intended minter is GFCBridge.
///
/// Roles:
/// - DEFAULT_ADMIN_ROLE ("treasury"): a multisig. Grants roles, raises/lowers the supply cap,
///   unpauses. Handover is two-step with a delay (AccessControlDefaultAdminRules).
/// - MINTER_ROLE: the bridge contract only. Never an EOA, never the ledger treasury key.
/// - BURNER_ROLE: the bridge contract only. There's no public burn: every burn is a
///   bridgeOut, which the bridge counts in cents and the ledger pays back. A burn the bridge
///   didn't count would leave supply and the bridge's books apart for good (audit F03: one
///   token-wei burned by anyone kept the bridge paused).
/// - PAUSER_ROLE: a fast-response guardian. Can pause, cannot unpause, so a leaked guardian
///   key can freeze the token but can't be used to resume it after the team has paused.
contract GFCToken is ERC20, ERC20Pausable, ERC20Permit, AccessControlDefaultAdminRules, IGFCToken {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    /// @notice Hard ceiling: the ledger premine (blockchain.PREMINE_CENTS = 100 trillion GFC).
    /// The wrapped supply can never exceed what the ledger could ever have issued.
    uint256 public constant MAX_SUPPLY = 100_000_000_000_000 * 1e18;

    /// @notice Current cap on totalSupply, set by the admin at or below MAX_SUPPLY.
    uint256 public supplyCap;

    event SupplyCapChanged(uint256 oldCap, uint256 newCap);

    error SupplyCapExceeded(uint256 newSupply, uint256 cap);
    error CapAboveMax(uint256 cap);
    error CapBelowSupply(uint256 cap, uint256 supply);

    constructor(address admin, uint48 adminTransferDelay, uint256 initialCap)
        ERC20("Galactic Federation Coin", "GFC")
        ERC20Permit("Galactic Federation Coin")
        AccessControlDefaultAdminRules(adminTransferDelay, admin)
    {
        _setSupplyCap(initialCap);
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        uint256 newSupply = totalSupply() + amount;
        if (newSupply > supplyCap) revert SupplyCapExceeded(newSupply, supplyCap);
        _mint(to, amount);
    }

    /// @notice Burns `amount` of `account`'s tokens, spending the allowance `account` gave the
    /// caller (as ERC20Burnable.burnFrom did). Only the bridge (BURNER_ROLE) may call it.
    function burnFrom(address account, uint256 amount) external onlyRole(BURNER_ROLE) {
        _spendAllowance(account, _msgSender(), amount);
        _burn(account, amount);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function setSupplyCap(uint256 newCap) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setSupplyCap(newCap);
    }

    function _setSupplyCap(uint256 newCap) internal {
        if (newCap > MAX_SUPPLY) revert CapAboveMax(newCap);
        if (newCap < totalSupply()) revert CapBelowSupply(newCap, totalSupply());
        emit SupplyCapChanged(supplyCap, newCap);
        supplyCap = newCap;
    }

    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Pausable) {
        super._update(from, to, value);
    }
}

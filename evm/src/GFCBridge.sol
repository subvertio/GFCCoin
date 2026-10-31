// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    AccessControlDefaultAdminRules
} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IGFCBridge} from "./interfaces/IGFCBridge.sol";
import {IGFCToken} from "./interfaces/IGFCToken.sol";

/// @title GFC ledger bridge (lock-and-mint)
/// @notice Mints wrapped GFC against escrow deposits on the GFC ledger, attested by a threshold
/// of independent attesters, and burns it on the way back. See IGFCBridge for the flow.
///
/// Limits on what a compromised attester set can do before someone pulls the pause:
/// - each ledger deposit mints once (`processed`), and only before its `deadline`;
/// - at most `maxMintCents` per mint and `windowLimitCents` per `windowDuration`;
/// - the token's own `supplyCap`.
contract GFCBridge is IGFCBridge, AccessControlDefaultAdminRules, Pausable, EIP712 {
    bytes32 public constant ATTESTER_ROLE = keccak256("ATTESTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice One ledger cent (0.01 GFC) in token units (18 decimals).
    uint256 public constant CENT = 1e16;

    bytes32 public constant MINT_TYPEHASH =
        keccak256("Mint(bytes32 ledgerTxHash,address to,uint256 amountCents,uint256 deadline)");

    IGFCToken public immutable token;

    uint256 public threshold;
    uint256 public maxMintCents;
    uint256 public windowLimitCents;
    uint256 public windowDuration;
    uint256 public minBridgeOutCents;

    uint256 public windowStart;
    uint256 public mintedInWindowCents;

    /// @notice Running totals, for the off-chain reconciler:
    /// token.totalSupply() == (totalMintedCents - totalBridgedOutCents) * CENT while this is the only minter.
    uint256 public totalMintedCents;
    uint256 public totalBridgedOutCents;
    uint256 public outNonce;

    mapping(bytes32 => bool) public processed;

    struct Limits {
        uint256 maxMintCents;
        uint256 windowLimitCents;
        uint256 windowDuration;
        uint256 minBridgeOutCents;
    }

    constructor(
        IGFCToken token_,
        address admin,
        uint48 adminTransferDelay,
        uint256 threshold_,
        Limits memory limits
    ) AccessControlDefaultAdminRules(adminTransferDelay, admin) EIP712("GFC Bridge", "1") {
        if (address(token_) == address(0)) revert ZeroAddress();
        token = token_;
        _setThreshold(threshold_);
        _setLimits(limits);
    }

    // ------------------------------------------------------------------ ledger -> chain

    /// @notice Anyone may relay; the attester signatures are the authorization.
    /// @param signatures one per attester, ordered by strictly increasing signer address.
    function mintFromLedger(MintRequest calldata req, bytes[] calldata signatures) external whenNotPaused {
        if (processed[req.ledgerTxHash]) revert AlreadyProcessed(req.ledgerTxHash);
        if (block.timestamp > req.deadline) revert Expired(req.deadline);
        if (req.to == address(0)) revert ZeroAddress();
        if (req.amountCents == 0) revert ZeroAmount();
        if (req.amountCents > maxMintCents) revert MintTooLarge(req.amountCents, maxMintCents);

        _checkSignatures(mintDigest(req), signatures);
        _consumeWindow(req.amountCents);

        processed[req.ledgerTxHash] = true;
        totalMintedCents += req.amountCents;
        emit MintedFromLedger(req.ledgerTxHash, req.to, req.amountCents);
        token.mint(req.to, req.amountCents * CENT);
    }

    function mintDigest(MintRequest calldata req) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(abi.encode(MINT_TYPEHASH, req.ledgerTxHash, req.to, req.amountCents, req.deadline))
        );
    }

    // ------------------------------------------------------------------ chain -> ledger

    /// @notice Burns `amount` of the caller's tokens (needs allowance to this bridge, or a permit)
    /// and records a payout owed from the ledger escrow to `ledgerWallet` (an Ed25519 public key).
    function bridgeOut(uint256 amount, bytes32 ledgerWallet) external whenNotPaused returns (uint256 nonce) {
        if (ledgerWallet == bytes32(0)) revert ZeroLedgerWallet();
        if (amount % CENT != 0) revert NotWholeCents(amount);
        uint256 cents = amount / CENT;
        if (cents == 0 || cents < minBridgeOutCents) revert BelowMinimum(cents, minBridgeOutCents);

        totalBridgedOutCents += cents;
        nonce = ++outNonce;
        emit BridgedOut(nonce, msg.sender, ledgerWallet, cents);
        token.burnFrom(msg.sender, amount); // reverts the whole call without allowance or balance
    }

    // ------------------------------------------------------------------ admin

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function setThreshold(uint256 newThreshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setThreshold(newThreshold);
    }

    function setLimits(Limits calldata limits) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setLimits(limits);
    }

    function remainingInWindowCents() external view returns (uint256) {
        if (block.timestamp >= windowStart + windowDuration) return windowLimitCents;
        return windowLimitCents - mintedInWindowCents;
    }

    // ------------------------------------------------------------------ internals

    function _checkSignatures(bytes32 digest, bytes[] calldata signatures) internal view {
        if (signatures.length < threshold) revert NotEnoughSignatures(signatures.length, threshold);
        address last = address(0);
        for (uint256 i; i < signatures.length; ++i) {
            address signer = ECDSA.recover(digest, signatures[i]);
            if (signer <= last) revert BadSignerOrder(); // also rules out duplicates
            if (!hasRole(ATTESTER_ROLE, signer)) revert NotAttester(signer);
            last = signer;
        }
    }

    function _consumeWindow(uint256 cents) internal {
        if (block.timestamp >= windowStart + windowDuration) {
            windowStart = block.timestamp;
            mintedInWindowCents = 0;
        }
        uint256 remaining = windowLimitCents - mintedInWindowCents;
        if (cents > remaining) revert WindowLimitExceeded(cents, remaining);
        mintedInWindowCents += cents;
    }

    function _setThreshold(uint256 newThreshold) internal {
        if (newThreshold == 0) revert BadThreshold();
        emit ThresholdChanged(threshold, newThreshold);
        threshold = newThreshold;
    }

    function _setLimits(Limits memory l) internal {
        if (l.windowDuration == 0 || l.maxMintCents > l.windowLimitCents) revert BadLimits();
        maxMintCents = l.maxMintCents;
        windowLimitCents = l.windowLimitCents;
        windowDuration = l.windowDuration;
        minBridgeOutCents = l.minBridgeOutCents;
        // A lowered limit applies to the current window too
        if (mintedInWindowCents > windowLimitCents) mintedInWindowCents = windowLimitCents;
        emit LimitsChanged(l.maxMintCents, l.windowLimitCents, l.windowDuration, l.minBridgeOutCents);
    }
}

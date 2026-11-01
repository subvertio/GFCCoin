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
/// - at most `maxMintCents` per mint, and never more than `windowLimitCents` in any span of
///   `windowDuration` (a rolling window, not a calendar day: see _consumeWindow);
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

    /// @notice The rolling window is kept in BUCKETS + 1 buckets of windowDuration / BUCKETS
    /// seconds (an hour, for a day). Usage is summed over all of them, so any true window of
    /// windowDuration seconds fits inside the counted span: no span of windowDuration ever
    /// mints more than windowLimitCents (it can be stricter by one bucket, never looser).
    uint256 public constant BUCKETS = 24;

    /// @notice Cents minted in the counted span (the last BUCKETS + 1 buckets). Recorded usage
    /// only ever expires with time: changing the limits never forgets it (audit F11).
    uint256 public mintedInWindowCents;
    uint256 public lastBucket; // index of the newest bucket, block.timestamp / bucketLength
    mapping(uint256 => uint256) private _bucketCents; // slot (bucket % (BUCKETS + 1)) -> cents

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
        uint256 used = _usageAfterExpiry();
        return used >= windowLimitCents ? 0 : windowLimitCents - used;
    }

    function bucketLength() public view returns (uint256) {
        return windowDuration / BUCKETS;
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
        _expireBuckets();
        uint256 remaining =
            mintedInWindowCents >= windowLimitCents ? 0 : windowLimitCents - mintedInWindowCents;
        if (cents > remaining) revert WindowLimitExceeded(cents, remaining);
        _bucketCents[lastBucket % (BUCKETS + 1)] += cents;
        mintedInWindowCents += cents;
    }

    /// @dev Moves the window to the current bucket, dropping buckets that fell out of it.
    function _expireBuckets() internal {
        uint256 current = block.timestamp / bucketLength();
        if (current == lastBucket) return;
        uint256 steps = current - lastBucket;
        if (steps > BUCKETS + 1) steps = BUCKETS + 1; // after a long quiet spell, all of them
        for (uint256 i = 1; i <= steps; ++i) {
            uint256 slot = (lastBucket + i) % (BUCKETS + 1);
            mintedInWindowCents -= _bucketCents[slot];
            _bucketCents[slot] = 0;
        }
        lastBucket = current;
    }

    /// @dev What _expireBuckets would leave in mintedInWindowCents, without writing.
    function _usageAfterExpiry() internal view returns (uint256 used) {
        used = mintedInWindowCents;
        uint256 current = block.timestamp / bucketLength();
        if (current == lastBucket) return used;
        uint256 steps = current - lastBucket;
        if (steps > BUCKETS + 1) steps = BUCKETS + 1;
        for (uint256 i = 1; i <= steps; ++i) {
            used -= _bucketCents[(lastBucket + i) % (BUCKETS + 1)];
        }
    }

    function _setThreshold(uint256 newThreshold) internal {
        if (newThreshold == 0) revert BadThreshold();
        emit ThresholdChanged(threshold, newThreshold);
        threshold = newThreshold;
    }

    function _setLimits(Limits memory l) internal {
        if (
            l.windowDuration < BUCKETS || l.windowDuration % BUCKETS != 0
                || l.maxMintCents > l.windowLimitCents
        ) {
            revert BadLimits();
        }
        if (windowDuration != 0) _expireBuckets();
        if (l.windowDuration != windowDuration) {
            // New bucket size: carry what's still counted into the current new bucket, so it
            // stays counted for a whole new window (stricter, never forgotten)
            uint256 carried = mintedInWindowCents;
            for (uint256 i; i <= BUCKETS; ++i) {
                _bucketCents[i] = 0;
            }
            windowDuration = l.windowDuration;
            lastBucket = block.timestamp / bucketLength();
            _bucketCents[lastBucket % (BUCKETS + 1)] = carried;
        }
        maxMintCents = l.maxMintCents;
        // A lowered limit applies at once: if more is already counted, nothing more until it expires
        windowLimitCents = l.windowLimitCents;
        minBridgeOutCents = l.minBridgeOutCents;
        emit LimitsChanged(l.maxMintCents, l.windowLimitCents, l.windowDuration, l.minBridgeOutCents);
    }
}

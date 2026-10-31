// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Lock-and-mint bridge between the GFC ledger (Ed25519, integer cents) and the ERC-20.
///
/// Ledger -> chain: a user signs a ledger TRANSFER to the bridge escrow wallet whose `reason`
/// names their EVM address. Once the deposit is final on the bridge node, `threshold` attesters
/// sign a MintRequest (EIP-712) and anyone may relay it to `mintFromLedger`.
///
/// Chain -> ledger: a user calls `bridgeOut`, which burns the tokens and emits `BridgedOut`.
/// The bridge service then signs a ledger TRANSFER from the escrow wallet to `ledgerWallet`,
/// keyed by `nonce` so it is paid at most once.
interface IGFCBridge {
    struct MintRequest {
        bytes32 ledgerTxHash; // blockchain.compute_tx_hash() of the escrow deposit
        address to;
        uint256 amountCents; // ledger amount_cents; minted as amountCents * CENT
        uint256 deadline; // unix seconds; stale attestations can't be replayed later
    }

    event MintedFromLedger(bytes32 indexed ledgerTxHash, address indexed to, uint256 amountCents);
    event BridgedOut(
        uint256 indexed nonce, address indexed from, bytes32 indexed ledgerWallet, uint256 amountCents
    );
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);
    event LimitsChanged(
        uint256 maxMintCents, uint256 windowLimitCents, uint256 windowDuration, uint256 minBridgeOutCents
    );

    error AlreadyProcessed(bytes32 ledgerTxHash);
    error Expired(uint256 deadline);
    error ZeroAddress();
    error ZeroAmount();
    error MintTooLarge(uint256 amountCents, uint256 maxMintCents);
    error WindowLimitExceeded(uint256 requestedCents, uint256 remainingCents);
    error NotEnoughSignatures(uint256 given, uint256 threshold);
    error BadSignerOrder();
    error NotAttester(address signer);
    error BadThreshold();
    error BadLimits();
    error NotWholeCents(uint256 amount);
    error BelowMinimum(uint256 amountCents, uint256 minCents);
    error ZeroLedgerWallet();

    function mintFromLedger(MintRequest calldata req, bytes[] calldata signatures) external;
    function bridgeOut(uint256 amount, bytes32 ledgerWallet) external returns (uint256 nonce);
    function mintDigest(MintRequest calldata req) external view returns (bytes32);
    function processed(bytes32 ledgerTxHash) external view returns (bool);
}

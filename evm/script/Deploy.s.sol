// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {GFCToken} from "../src/GFCToken.sol";
import {GFCBridge} from "../src/GFCBridge.sol";

/// @dev The two Safe reads the deploy checks (Safe v1.x).
interface ISafeLike {
    function getThreshold() external view returns (uint256);
    function getOwners() external view returns (address[] memory);
}

/// @notice Deploys GFCToken + GFCBridge, wires roles, and starts the admin handover to the
/// treasury multisig (which must call acceptDefaultAdminTransfer on both after the delay).
///
/// NOT run against any network yet. Testnet first, and only with the owner's go-ahead:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --account <keystore-name> --broadcast
/// Required env: GFC_MULTISIG, GFC_PAUSER, GFC_ATTESTERS (comma-separated), GFC_THRESHOLD.
/// Optional env (defaults below are placeholders, not a recommendation): GFC_SUPPLY_CAP_GFC,
/// GFC_MAX_MINT_GFC, GFC_WINDOW_LIMIT_GFC, GFC_WINDOW_SECONDS, GFC_MIN_OUT_GFC, GFC_ADMIN_DELAY.
contract Deploy is Script {
    struct Config {
        address multisig;
        address pauser;
        address[] attesters;
        uint256 threshold;
        uint48 adminDelay;
        uint256 supplyCap; // token units
        GFCBridge.Limits limits; // cents
    }

    /// @notice The least the admin may be: a Safe needing 2 of at least 3 owners (audit F15).
    uint256 public constant MIN_SAFE_THRESHOLD = 2;
    uint256 public constant MIN_SAFE_OWNERS = 3;
    /// @notice The fewest attester signatures a mint may need (audit F15: threshold 1 = one key mints).
    uint256 public constant MIN_ATTESTER_THRESHOLD = 2;

    function run() external returns (GFCToken token, GFCBridge bridge) {
        Config memory cfg = configFromEnv();
        checkSafe(cfg.multisig);
        vm.startBroadcast();
        (token, bridge) = deploy(cfg, msg.sender);
        vm.stopBroadcast();
    }

    function configFromEnv() public view returns (Config memory cfg) {
        cfg.multisig = vm.envAddress("GFC_MULTISIG");
        cfg.pauser = vm.envAddress("GFC_PAUSER");
        cfg.attesters = vm.envAddress("GFC_ATTESTERS", ",");
        cfg.threshold = vm.envUint("GFC_THRESHOLD");
        cfg.adminDelay = uint48(vm.envOr("GFC_ADMIN_DELAY", uint256(2 days)));
        cfg.supplyCap = vm.envOr("GFC_SUPPLY_CAP_GFC", uint256(1_000_000)) * 1e18;
        cfg.limits = GFCBridge.Limits({
            maxMintCents: vm.envOr("GFC_MAX_MINT_GFC", uint256(10_000)) * 100,
            windowLimitCents: vm.envOr("GFC_WINDOW_LIMIT_GFC", uint256(50_000)) * 100,
            windowDuration: vm.envOr("GFC_WINDOW_SECONDS", uint256(1 days)),
            minBridgeOutCents: vm.envOr("GFC_MIN_OUT_GFC", uint256(10)) * 100
        });
    }

    /// @notice Refuses an admin that isn't a real multisig: it must have code, need at least
    /// MIN_SAFE_THRESHOLD signatures, and have at least MIN_SAFE_OWNERS owners.
    function checkSafe(address multisig) public view {
        require(multisig.code.length > 0, "GFC_MULTISIG has no code: not a Safe on this chain");
        uint256 threshold = ISafeLike(multisig).getThreshold();
        uint256 owners = ISafeLike(multisig).getOwners().length;
        require(threshold >= MIN_SAFE_THRESHOLD, "the Safe must need at least 2 signatures");
        require(owners >= MIN_SAFE_OWNERS && threshold <= owners, "the Safe must have at least 3 owners");
    }

    /// @notice Refuses a weak or muddled role setup before anything is deployed (audit F15):
    /// threshold below 2 or above the attester count, zero or repeated attesters, and one
    /// address holding two jobs (attester, pauser, admin, deployer).
    function checkConfig(Config memory cfg, address deployer) public pure {
        require(cfg.multisig != address(0) && cfg.pauser != address(0), "zero address");
        require(cfg.threshold >= MIN_ATTESTER_THRESHOLD, "threshold must be at least 2");
        require(cfg.threshold <= cfg.attesters.length, "threshold above the number of attesters");
        require(
            cfg.pauser != cfg.multisig && cfg.pauser != deployer && cfg.multisig != deployer, "roles overlap"
        );
        for (uint256 i; i < cfg.attesters.length; ++i) {
            address a = cfg.attesters[i];
            require(a != address(0), "zero attester");
            require(a != cfg.multisig && a != cfg.pauser && a != deployer, "an attester holds another role");
            for (uint256 j = i + 1; j < cfg.attesters.length; ++j) {
                require(a != cfg.attesters[j], "attester listed twice");
            }
        }
    }

    /// @dev `deployer` is the temporary admin; it hands over to the multisig and keeps no roles.
    function deploy(Config memory cfg, address deployer) public returns (GFCToken token, GFCBridge bridge) {
        checkConfig(cfg, deployer);

        token = new GFCToken(deployer, cfg.adminDelay, cfg.supplyCap);
        bridge = new GFCBridge(token, deployer, cfg.adminDelay, cfg.threshold, cfg.limits);

        token.grantRole(token.MINTER_ROLE(), address(bridge));
        token.grantRole(token.BURNER_ROLE(), address(bridge));
        token.grantRole(token.PAUSER_ROLE(), cfg.pauser);
        bridge.grantRole(bridge.PAUSER_ROLE(), cfg.pauser);
        for (uint256 i; i < cfg.attesters.length; ++i) {
            bridge.grantRole(bridge.ATTESTER_ROLE(), cfg.attesters[i]);
        }

        token.beginDefaultAdminTransfer(cfg.multisig);
        bridge.beginDefaultAdminTransfer(cfg.multisig);
    }
}

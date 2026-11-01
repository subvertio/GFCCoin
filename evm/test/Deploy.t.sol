// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {GFCToken} from "../src/GFCToken.sol";
import {GFCBridge} from "../src/GFCBridge.sol";

/// Runs the deploy script's wiring inside the test EVM (no network) and checks the end state.
contract DeployTest is Test {
    function test_DeployWiresRolesAndHandsOver() public {
        Deploy script = new Deploy();
        address multisig = makeAddr("multisig");
        address pauser = makeAddr("pauser");
        address[] memory attesters = new address[](3);
        attesters[0] = makeAddr("a0");
        attesters[1] = makeAddr("a1");
        attesters[2] = makeAddr("a2");

        Deploy.Config memory cfg = Deploy.Config({
            multisig: multisig,
            pauser: pauser,
            attesters: attesters,
            threshold: 2,
            adminDelay: 2 days,
            supplyCap: 1_000_000e18,
            limits: GFCBridge.Limits(10_000_00, 50_000_00, 1 days, 10_00)
        });
        (GFCToken token, GFCBridge bridge) = script.deploy(cfg, address(script));

        assertTrue(token.hasRole(token.MINTER_ROLE(), address(bridge)));
        assertTrue(token.hasRole(token.BURNER_ROLE(), address(bridge)));
        assertTrue(token.hasRole(token.PAUSER_ROLE(), pauser));
        assertTrue(bridge.hasRole(bridge.PAUSER_ROLE(), pauser));
        for (uint256 i; i < 3; ++i) {
            assertTrue(bridge.hasRole(bridge.ATTESTER_ROLE(), attesters[i]));
        }
        assertEq(bridge.threshold(), 2);
        (address pendingT,) = token.pendingDefaultAdmin();
        (address pendingB,) = bridge.pendingDefaultAdmin();
        assertEq(pendingT, multisig);
        assertEq(pendingB, multisig);

        vm.warp(block.timestamp + 2 days + 1);
        vm.startPrank(multisig);
        token.acceptDefaultAdminTransfer();
        bridge.acceptDefaultAdminTransfer();
        vm.stopPrank();
        assertEq(token.defaultAdmin(), multisig);
        assertFalse(token.hasRole(token.DEFAULT_ADMIN_ROLE(), address(script)), "deployer keeps no admin");
        assertFalse(token.hasRole(token.MINTER_ROLE(), address(script)), "deployer never mints");
    }

    // ---- audit F15: weak setups are refused before anything is deployed ----

    function _cfg() internal returns (Deploy.Config memory cfg) {
        address[] memory attesters = new address[](3);
        attesters[0] = makeAddr("a0");
        attesters[1] = makeAddr("a1");
        attesters[2] = makeAddr("a2");
        cfg = Deploy.Config({
            multisig: makeAddr("multisig"),
            pauser: makeAddr("pauser"),
            attesters: attesters,
            threshold: 2,
            adminDelay: 2 days,
            supplyCap: 1_000_000e18,
            limits: GFCBridge.Limits(10_000_00, 50_000_00, 1 days, 10_00)
        });
    }

    function test_RefusesWeakConfigs() public {
        Deploy script = new Deploy();
        address deployer = makeAddr("deployer");
        Deploy.Config memory cfg = _cfg();
        script.checkConfig(cfg, deployer); // the good one passes

        cfg.threshold = 1;
        vm.expectRevert(bytes("threshold must be at least 2"));
        script.checkConfig(cfg, deployer);

        cfg = _cfg();
        cfg.threshold = 4;
        vm.expectRevert(bytes("threshold above the number of attesters"));
        script.checkConfig(cfg, deployer);

        cfg = _cfg();
        cfg.attesters[2] = cfg.attesters[0];
        vm.expectRevert(bytes("attester listed twice"));
        script.checkConfig(cfg, deployer);

        cfg = _cfg();
        cfg.attesters[1] = address(0);
        vm.expectRevert(bytes("zero attester"));
        script.checkConfig(cfg, deployer);

        cfg = _cfg();
        cfg.attesters[1] = cfg.pauser;
        vm.expectRevert(bytes("an attester holds another role"));
        script.checkConfig(cfg, deployer);

        cfg = _cfg();
        cfg.pauser = deployer;
        vm.expectRevert(bytes("roles overlap"));
        script.checkConfig(cfg, deployer);
    }

    function test_RefusesAnAdminThatIsntAStrongSafe() public {
        Deploy script = new Deploy();
        vm.expectRevert(bytes("GFC_MULTISIG has no code: not a Safe on this chain"));
        script.checkSafe(makeAddr("eoa"));

        FakeSafe weak = new FakeSafe(1, 3);
        vm.expectRevert(bytes("the Safe must need at least 2 signatures"));
        script.checkSafe(address(weak));

        FakeSafe few = new FakeSafe(2, 2);
        vm.expectRevert(bytes("the Safe must have at least 3 owners"));
        script.checkSafe(address(few));

        script.checkSafe(address(new FakeSafe(2, 3))); // like the testnet's GFC Testnet Admin
    }
}

contract FakeSafe {
    uint256 threshold;
    address[] owners;

    constructor(uint256 threshold_, uint256 ownerCount) {
        threshold = threshold_;
        for (uint256 i; i < ownerCount; ++i) {
            owners.push(address(uint160(i + 1)));
        }
    }

    function getThreshold() external view returns (uint256) {
        return threshold;
    }

    function getOwners() external view returns (address[] memory) {
        return owners;
    }
}

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
}

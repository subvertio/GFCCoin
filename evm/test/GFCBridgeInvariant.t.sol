// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IGFCBridge} from "../src/interfaces/IGFCBridge.sol";
import {BridgeFixture} from "./GFCBridge.t.sol";
import {GFCToken} from "../src/GFCToken.sol";
import {GFCBridge} from "../src/GFCBridge.sol";
import {Test} from "forge-std/Test.sol";

/// Random mints, bridge-outs, transfers and time jumps. The bridge's books must match the token.
contract BridgeHandler is Test {
    GFCToken token;
    GFCBridge bridge;
    uint256[3] keys;
    address[] users;
    uint256 public depositCount;

    constructor(GFCToken token_, GFCBridge bridge_, uint256[3] memory keys_) {
        token = token_;
        bridge = bridge_;
        keys = keys_;
        for (uint256 i; i < 4; ++i) {
            users.push(makeAddr(string(abi.encode("user", i))));
        }
    }

    function mint(uint256 userSeed, uint256 cents) external {
        cents = bound(cents, 1, bridge.maxMintCents());
        if (cents > bridge.remainingInWindowCents()) return;
        if (token.totalSupply() + cents * 1e16 > token.supplyCap()) return;
        IGFCBridge.MintRequest memory req = IGFCBridge.MintRequest({
            ledgerTxHash: keccak256(abi.encode("deposit", depositCount++)),
            to: users[userSeed % users.length],
            amountCents: cents,
            deadline: block.timestamp + 1 hours
        });
        bytes32 digest = bridge.mintDigest(req);
        bytes[] memory sigs = new bytes[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[0], digest);
        sigs[0] = abi.encodePacked(r, s, v);
        (v, r, s) = vm.sign(keys[2], digest);
        sigs[1] = abi.encodePacked(r, s, v);
        bridge.mintFromLedger(req, sigs);
    }

    function bridgeOut(uint256 userSeed, uint256 cents) external {
        address user = users[userSeed % users.length];
        uint256 maxCents = token.balanceOf(user) / 1e16;
        if (maxCents < bridge.minBridgeOutCents()) return;
        cents = bound(cents, bridge.minBridgeOutCents(), maxCents);
        vm.startPrank(user);
        token.approve(address(bridge), cents * 1e16);
        bridge.bridgeOut(cents * 1e16, bytes32(uint256(uint160(user))));
        vm.stopPrank();
    }

    function transfer(uint256 fromSeed, uint256 toSeed, uint256 amount) external {
        address from = users[fromSeed % users.length];
        amount = bound(amount, 0, token.balanceOf(from));
        vm.prank(from);
        token.transfer(users[toSeed % users.length], amount);
    }

    /// Holders and approved spenders try to burn outside the bridge (audit F03): never works.
    function burnDirectly(uint256 userSeed, uint256 amount) external {
        address user = users[userSeed % users.length];
        amount = bound(amount, 1, 1e18);
        vm.prank(user);
        (bool ok,) = address(token).call(abi.encodeWithSignature("burn(uint256)", amount));
        require(!ok, "public burn worked");
        vm.prank(user);
        token.approve(address(this), amount);
        try token.burnFrom(user, amount) {
            revert("an approved spender burned");
        } catch {}
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 2 days));
    }
}

contract GFCBridgeInvariantTest is BridgeFixture {
    BridgeHandler handler;

    function setUp() public override {
        super.setUp();
        handler = new BridgeHandler(token, bridge, [keys[0], keys[1], keys[2]]);
        targetContract(address(handler));
    }

    function invariant_SupplyEqualsBridgeBooks() public view {
        assertEq(token.totalSupply(), (bridge.totalMintedCents() - bridge.totalBridgedOutCents()) * 1e16);
    }

    function invariant_SupplyWithinCap() public view {
        assertLe(token.totalSupply(), token.supplyCap());
    }

    function invariant_WindowNeverOverspent() public view {
        assertLe(bridge.mintedInWindowCents(), bridge.windowLimitCents());
    }

    function invariant_NoBurnOutsideTheBridge() public view {
        // With burnDirectly in the mix, supply still matches the bridge's books to the wei
        assertEq(token.totalSupply() % 1e16, 0);
    }
}

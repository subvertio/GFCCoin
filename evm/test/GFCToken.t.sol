// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {GFCToken} from "../src/GFCToken.sol";

contract GFCTokenTest is Test {
    GFCToken token;
    address admin = makeAddr("treasuryMultisig");
    address minter = makeAddr("bridge");
    address pauser = makeAddr("guardian");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    uint256 constant CAP = 1_000_000e18;

    function setUp() public {
        token = new GFCToken(admin, 2 days, CAP);
        vm.startPrank(admin);
        token.grantRole(token.MINTER_ROLE(), minter);
        token.grantRole(token.PAUSER_ROLE(), pauser);
        vm.stopPrank();
    }

    function test_Metadata() public view {
        assertEq(token.name(), "Galactic Federation Coin");
        assertEq(token.symbol(), "GFC");
        assertEq(token.decimals(), 18);
        assertEq(token.totalSupply(), 0, "no premine on chain");
        assertEq(token.supplyCap(), CAP);
        assertEq(token.defaultAdmin(), admin);
    }

    function test_MinterMints() public {
        vm.prank(minter);
        token.mint(alice, 100e18);
        assertEq(token.balanceOf(alice), 100e18);
    }

    function test_RevertWhen_NonMinterMints() public {
        bytes32 role = token.MINTER_ROLE();
        for (uint256 i; i < 3; ++i) {
            address caller = [admin, pauser, alice][i];
            vm.prank(caller);
            vm.expectRevert(
                abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, caller, role)
            );
            token.mint(caller, 1);
        }
    }

    function test_RevertWhen_MintAboveCap() public {
        vm.startPrank(minter);
        token.mint(alice, CAP);
        vm.expectRevert(abi.encodeWithSelector(GFCToken.SupplyCapExceeded.selector, CAP + 1, CAP));
        token.mint(alice, 1);
        vm.stopPrank();
    }

    function testFuzz_SupplyNeverExceedsCap(uint256 a, uint256 b) public {
        a = bound(a, 0, CAP);
        b = bound(b, 0, CAP);
        vm.startPrank(minter);
        token.mint(alice, a);
        if (a + b > CAP) vm.expectRevert();
        token.mint(bob, b);
        vm.stopPrank();
        assertLe(token.totalSupply(), token.supplyCap());
    }

    function test_SetSupplyCapBounds() public {
        vm.prank(minter);
        token.mint(alice, 500e18);

        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(GFCToken.CapBelowSupply.selector, 499e18, 500e18));
        token.setSupplyCap(499e18);
        uint256 tooBig = token.MAX_SUPPLY() + 1;
        vm.expectRevert(abi.encodeWithSelector(GFCToken.CapAboveMax.selector, tooBig));
        token.setSupplyCap(tooBig);
        token.setSupplyCap(token.MAX_SUPPLY());
        vm.stopPrank();
        assertEq(token.supplyCap(), token.MAX_SUPPLY());

        vm.prank(alice);
        vm.expectRevert();
        token.setSupplyCap(1);
    }

    function test_MaxSupplyMatchesLedgerPremine() public view {
        // blockchain.PREMINE_CENTS = 100_000_000_000_000_00 cents; 1 cent = 1e16 token units
        assertEq(token.MAX_SUPPLY(), uint256(100_000_000_000_000_00) * 1e16);
    }

    function test_PauseStopsTransfersAndMints() public {
        vm.prank(minter);
        token.mint(alice, 10e18);

        vm.prank(pauser);
        token.pause();

        vm.prank(alice);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        token.transfer(bob, 1e18);

        vm.prank(minter);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        token.mint(alice, 1);
    }

    function test_PauserCannotUnpause_AdminCan() public {
        vm.prank(pauser);
        token.pause();

        vm.prank(pauser);
        vm.expectRevert();
        token.unpause();

        vm.prank(admin);
        token.unpause();
        assertFalse(token.paused());
    }

    function test_BurnFromNeedsAllowance() public {
        vm.prank(minter);
        token.mint(alice, 10e18);

        vm.prank(bob);
        vm.expectRevert();
        token.burnFrom(alice, 1e18);

        vm.prank(alice);
        token.approve(bob, 1e18);
        vm.prank(bob);
        token.burnFrom(alice, 1e18);
        assertEq(token.totalSupply(), 9e18);
    }

    function test_Permit() public {
        (address owner, uint256 key) = makeAddrAndKey("permitOwner");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                ),
                owner,
                bob,
                5e18,
                token.nonces(owner),
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        token.permit(owner, bob, 5e18, deadline, v, r, s);
        assertEq(token.allowance(owner, bob), 5e18);
    }

    function test_AdminHandoverIsDelayed() public {
        address newAdmin = makeAddr("newMultisig");
        vm.prank(admin);
        token.beginDefaultAdminTransfer(newAdmin);

        vm.prank(newAdmin);
        vm.expectRevert();
        token.acceptDefaultAdminTransfer();

        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(newAdmin);
        token.acceptDefaultAdminTransfer();
        assertEq(token.defaultAdmin(), newAdmin);
        assertFalse(token.hasRole(token.DEFAULT_ADMIN_ROLE(), admin));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {GFCToken} from "../src/GFCToken.sol";
import {GFCBridge} from "../src/GFCBridge.sol";
import {IGFCBridge} from "../src/interfaces/IGFCBridge.sol";

contract BridgeFixture is Test {
    GFCToken token;
    GFCBridge bridge;
    address admin = makeAddr("treasuryMultisig");
    address pauser = makeAddr("guardian");
    address alice = makeAddr("alice");
    address relayer = makeAddr("anyRelayer");

    // Attesters sorted by address, so tests can pick any subset in signing order
    uint256[3] keys;
    address[3] attesters;

    uint256 constant CENT = 1e16;
    uint256 constant MAX_MINT = 10_000_00; // 10,000 GFC
    uint256 constant WINDOW_LIMIT = 50_000_00; // 50,000 GFC
    uint256 constant WINDOW = 1 days;
    uint256 constant MIN_OUT = 10_00; // 10 GFC
    bytes32 constant LEDGER_WALLET = bytes32(uint256(0xed25519));

    function setUp() public virtual {
        token = new GFCToken(admin, 2 days, 1_000_000e18);
        bridge = new GFCBridge(
            token,
            admin,
            2 days,
            2,
            GFCBridge.Limits({
                maxMintCents: MAX_MINT,
                windowLimitCents: WINDOW_LIMIT,
                windowDuration: WINDOW,
                minBridgeOutCents: MIN_OUT
            })
        );

        (address a0, uint256 k0) = makeAddrAndKey("attester0");
        (address a1, uint256 k1) = makeAddrAndKey("attester1");
        (address a2, uint256 k2) = makeAddrAndKey("attester2");
        address[3] memory as_ = [a0, a1, a2];
        uint256[3] memory ks = [k0, k1, k2];
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (as_[j] < as_[i]) {
                    (as_[i], as_[j]) = (as_[j], as_[i]);
                    (ks[i], ks[j]) = (ks[j], ks[i]);
                }
            }
        }
        attesters = as_;
        keys = ks;

        vm.startPrank(admin);
        token.grantRole(token.MINTER_ROLE(), address(bridge));
        token.grantRole(token.BURNER_ROLE(), address(bridge));
        bridge.grantRole(bridge.PAUSER_ROLE(), pauser);
        for (uint256 i; i < 3; ++i) {
            bridge.grantRole(bridge.ATTESTER_ROLE(), attesters[i]);
        }
        vm.stopPrank();
    }

    function _req(bytes32 txHash, address to, uint256 cents)
        internal
        view
        returns (IGFCBridge.MintRequest memory)
    {
        return IGFCBridge.MintRequest({
            ledgerTxHash: txHash, to: to, amountCents: cents, deadline: block.timestamp + 1 hours
        });
    }

    function _sig(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sign(IGFCBridge.MintRequest memory req, uint256 i, uint256 j)
        internal
        view
        returns (bytes[] memory sigs)
    {
        bytes32 digest = bridge.mintDigest(req);
        sigs = new bytes[](2);
        sigs[0] = _sig(keys[i], digest);
        sigs[1] = _sig(keys[j], digest);
    }

    function _mint(bytes32 txHash, address to, uint256 cents) internal {
        IGFCBridge.MintRequest memory req = _req(txHash, to, cents);
        bridge.mintFromLedger(req, _sign(req, 0, 1));
    }
}

contract GFCBridgeTest is BridgeFixture {
    function test_MintWithTwoOfThree() public {
        IGFCBridge.MintRequest memory req = _req(keccak256("deposit-1"), alice, 123_45);
        bytes[] memory sigs = _sign(req, 0, 2);

        vm.expectEmit(address(bridge));
        emit IGFCBridge.MintedFromLedger(req.ledgerTxHash, alice, 123_45);
        vm.prank(relayer); // relaying is permissionless; signatures are the authorization
        bridge.mintFromLedger(req, sigs);

        assertEq(token.balanceOf(alice), 123_45 * CENT);
        assertEq(token.balanceOf(alice), 123.45e18);
        assertTrue(bridge.processed(req.ledgerTxHash));
        assertEq(bridge.totalMintedCents(), 123_45);
    }

    function test_RevertWhen_Replayed() public {
        IGFCBridge.MintRequest memory req = _req(keccak256("deposit-1"), alice, 100);
        bytes[] memory sigs = _sign(req, 0, 1);
        bridge.mintFromLedger(req, sigs);
        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.AlreadyProcessed.selector, req.ledgerTxHash));
        bridge.mintFromLedger(req, sigs);
    }

    function test_RevertWhen_SameDepositToAnotherAddress() public {
        _mint(keccak256("deposit-1"), alice, 100);
        IGFCBridge.MintRequest memory req = _req(keccak256("deposit-1"), relayer, 100);
        bytes[] memory sigs = _sign(req, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.AlreadyProcessed.selector, req.ledgerTxHash));
        bridge.mintFromLedger(req, sigs);
    }

    function test_RevertWhen_BelowThreshold() public {
        IGFCBridge.MintRequest memory req = _req(keccak256("d"), alice, 100);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sig(keys[0], bridge.mintDigest(req));
        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.NotEnoughSignatures.selector, 1, 2));
        bridge.mintFromLedger(req, sigs);
    }

    function test_RevertWhen_DuplicateSigner() public {
        IGFCBridge.MintRequest memory req = _req(keccak256("d"), alice, 100);
        bytes[] memory sigs = _sign(req, 1, 1);
        vm.expectRevert(IGFCBridge.BadSignerOrder.selector);
        bridge.mintFromLedger(req, sigs);
    }

    function test_RevertWhen_SignersUnsorted() public {
        IGFCBridge.MintRequest memory req = _req(keccak256("d"), alice, 100);
        bytes[] memory sigs = _sign(req, 2, 0);
        vm.expectRevert(IGFCBridge.BadSignerOrder.selector);
        bridge.mintFromLedger(req, sigs);
    }

    function test_RevertWhen_SignerNotAttester() public {
        (address outsider, uint256 outsiderKey) = makeAddrAndKey("outsider");
        IGFCBridge.MintRequest memory req = _req(keccak256("d"), alice, 100);
        bytes32 digest = bridge.mintDigest(req);
        bytes[] memory sigs = new bytes[](2);
        // order the pair by address so the failure is the role check, not ordering
        (uint256 k0, uint256 k1) = attesters[0] < outsider ? (keys[0], outsiderKey) : (outsiderKey, keys[0]);
        sigs[0] = _sig(k0, digest);
        sigs[1] = _sig(k1, digest);
        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.NotAttester.selector, outsider));
        bridge.mintFromLedger(req, sigs);
    }

    function test_RevertWhen_TamperedAmount() public {
        IGFCBridge.MintRequest memory req = _req(keccak256("d"), alice, 100);
        bytes[] memory sigs = _sign(req, 0, 1);
        req.amountCents = 9_999_00;
        vm.expectRevert(); // recovers to unrelated addresses
        bridge.mintFromLedger(req, sigs);
    }

    function test_RevertWhen_SignedForAnotherBridge() public {
        GFCBridge other =
            new GFCBridge(token, admin, 2 days, 2, GFCBridge.Limits(MAX_MINT, WINDOW_LIMIT, WINDOW, MIN_OUT));
        IGFCBridge.MintRequest memory req = _req(keccak256("d"), alice, 100);
        bytes32 digest = other.mintDigest(req);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sig(keys[0], digest);
        sigs[1] = _sig(keys[1], digest);
        vm.expectRevert();
        bridge.mintFromLedger(req, sigs);
    }

    function test_RevertWhen_Expired() public {
        IGFCBridge.MintRequest memory req = _req(keccak256("d"), alice, 100);
        bytes[] memory sigs = _sign(req, 0, 1);
        vm.warp(req.deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.Expired.selector, req.deadline));
        bridge.mintFromLedger(req, sigs);
    }

    function test_RevertWhen_MintTooLarge() public {
        IGFCBridge.MintRequest memory req = _req(keccak256("d"), alice, MAX_MINT + 1);
        bytes[] memory sigs = _sign(req, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.MintTooLarge.selector, MAX_MINT + 1, MAX_MINT));
        bridge.mintFromLedger(req, sigs);
    }

    function test_WindowLimitThenReset() public {
        for (uint256 i; i < 5; ++i) {
            _mint(keccak256(abi.encode("w", i)), alice, MAX_MINT);
        }
        assertEq(bridge.remainingInWindowCents(), 0);

        IGFCBridge.MintRequest memory req = _req(keccak256("over"), alice, 1);
        bytes[] memory sigs = _sign(req, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.WindowLimitExceeded.selector, 1, 0));
        bridge.mintFromLedger(req, sigs);

        // Rolling: a full window later, what was minted has expired (it's counted for a window
        // plus up to one bucket, never less)
        vm.warp(block.timestamp + WINDOW + bridge.bucketLength());
        req = _req(keccak256("over"), alice, 1);
        bridge.mintFromLedger(req, _sign(req, 0, 1));
        assertEq(bridge.remainingInWindowCents(), WINDOW_LIMIT - 1);
    }

    // ---- audit F11: no burst at a window boundary, and cap changes never forget usage ----

    function test_NoDoubleLimitAcrossAWindowBoundary() public {
        // The audit's scenario: anchor a window with 1 cent, fill it just before it ends, then
        // try again just after. A calendar window allowed ~2x the limit within a second.
        _mint(keccak256("anchor"), alice, 1);
        vm.warp(block.timestamp + WINDOW - 10);
        for (uint256 i; i < 4; ++i) {
            _mint(keccak256(abi.encode("late", i)), alice, MAX_MINT);
        }
        _mint(keccak256("late-rest"), alice, MAX_MINT - 1);
        assertEq(bridge.remainingInWindowCents(), 0);
        vm.warp(block.timestamp + 20); // a calendar window would have reset 10 seconds ago
        IGFCBridge.MintRequest memory req = _req(keccak256("burst"), alice, MAX_MINT);
        bytes[] memory sigs = _sign(req, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.WindowLimitExceeded.selector, MAX_MINT, 0));
        bridge.mintFromLedger(req, sigs);
        // The anchor cent expires a window (plus at most one bucket) after it was minted
        vm.warp(block.timestamp + bridge.bucketLength());
        assertEq(bridge.remainingInWindowCents(), 1, "only the 1-cent anchor has aged out");
    }

    function test_LoweringThenRaisingTheCapForgetsNothing() public {
        // The audit's scenario: mint 50,000, lower the cap to 10,000, put it back to 50,000 in the
        // same window. The old code rewrote usage to 10,000 and freed 40,000 more.
        for (uint256 i; i < 5; ++i) {
            _mint(keccak256(abi.encode("full", i)), alice, MAX_MINT);
        }
        vm.startPrank(admin);
        bridge.setLimits(GFCBridge.Limits(MAX_MINT, 10_000_00, WINDOW, MIN_OUT));
        assertEq(bridge.remainingInWindowCents(), 0);
        bridge.setLimits(GFCBridge.Limits(MAX_MINT, WINDOW_LIMIT, WINDOW, MIN_OUT));
        vm.stopPrank();
        assertEq(bridge.remainingInWindowCents(), 0, "usage survives cap changes");
        assertEq(bridge.mintedInWindowCents(), WINDOW_LIMIT);
    }

    function test_ChangingTheWindowLengthKeepsUsageCounted() public {
        _mint(keccak256("before"), alice, MAX_MINT);
        vm.prank(admin);
        bridge.setLimits(GFCBridge.Limits(MAX_MINT, WINDOW_LIMIT, 2 days, MIN_OUT));
        assertEq(bridge.remainingInWindowCents(), WINDOW_LIMIT - MAX_MINT);
        vm.warp(block.timestamp + 1 days + 2 hours); // the old window has passed, the new one hasn't
        assertEq(bridge.remainingInWindowCents(), WINDOW_LIMIT - MAX_MINT);
        vm.warp(block.timestamp + 1 days);
        assertEq(bridge.remainingInWindowCents(), WINDOW_LIMIT);
    }

    function testFuzz_NoSpanOfOneWindowExceedsTheLimit(uint256 seed) public {
        // Random mints at random times; every mint is checked against an independent history
        uint256[] memory times = new uint256[](40);
        uint256[] memory amounts = new uint256[](40);
        uint256 n;
        uint256 t = block.timestamp;
        for (uint256 i; i < 40; ++i) {
            seed = uint256(keccak256(abi.encode(seed, i)));
            t += seed % 3 hours;
            vm.warp(t);
            uint256 cents = 1 + (seed >> 32) % MAX_MINT;
            if (cents > bridge.remainingInWindowCents()) continue;
            _mint(keccak256(abi.encode("fz", seed, i)), alice, cents);
            times[n] = t;
            amounts[n] = cents;
            ++n;
            uint256 inSpan;
            for (uint256 j; j < n; ++j) {
                if (times[j] + WINDOW > t) inSpan += amounts[j];
            }
            assertLe(inSpan, WINDOW_LIMIT, "a 1-day span minted more than the limit");
        }
    }

    // ---- audit F03: nobody but the bridge can burn ----

    function test_HoldersCannotBurnOutsideTheBridge() public {
        _mint(keccak256("held"), alice, 100_00);
        vm.startPrank(alice);
        (bool ok,) = address(token).call(abi.encodeWithSignature("burn(uint256)", 1));
        assertFalse(ok, "there's no public burn()");
        token.approve(relayer, 1);
        vm.stopPrank();
        vm.prank(relayer); // an approved spender isn't a burner either
        vm.expectRevert();
        token.burnFrom(alice, 1);
        assertEq(token.totalSupply(), (bridge.totalMintedCents() - bridge.totalBridgedOutCents()) * CENT);
    }

    function test_PausedBridgeRefusesBothWays() public {
        _mint(keccak256("d"), alice, 100_00);
        vm.prank(pauser);
        bridge.pause();

        IGFCBridge.MintRequest memory req = _req(keccak256("d2"), alice, 100);
        bytes[] memory sigs = _sign(req, 0, 1);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        bridge.mintFromLedger(req, sigs);

        vm.prank(alice);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        bridge.bridgeOut(10e18, LEDGER_WALLET);

        vm.prank(pauser);
        vm.expectRevert();
        bridge.unpause();
        vm.prank(admin);
        bridge.unpause();
    }

    function test_BridgeOutBurnsAndEmits() public {
        _mint(keccak256("d"), alice, 100_00);
        vm.startPrank(alice);
        token.approve(address(bridge), 25e18);
        vm.expectEmit(address(bridge));
        emit IGFCBridge.BridgedOut(1, alice, LEDGER_WALLET, 25_00);
        uint256 nonce = bridge.bridgeOut(25e18, LEDGER_WALLET);
        vm.stopPrank();

        assertEq(nonce, 1);
        assertEq(token.balanceOf(alice), 75e18);
        assertEq(token.totalSupply(), 75e18);
        assertEq(bridge.totalBridgedOutCents(), 25_00);
    }

    function test_RevertWhen_BridgeOutBadInputs() public {
        _mint(keccak256("d"), alice, 100_00);
        vm.startPrank(alice);
        token.approve(address(bridge), type(uint256).max);

        vm.expectRevert(IGFCBridge.ZeroLedgerWallet.selector);
        bridge.bridgeOut(20e18, bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.NotWholeCents.selector, 20e18 + 1));
        bridge.bridgeOut(20e18 + 1, LEDGER_WALLET);

        vm.expectRevert(abi.encodeWithSelector(IGFCBridge.BelowMinimum.selector, 9_99, MIN_OUT));
        bridge.bridgeOut(9.99e18, LEDGER_WALLET);
        vm.stopPrank();
    }

    function test_RevertWhen_BridgeOutWithoutAllowance() public {
        _mint(keccak256("d"), alice, 100_00);
        vm.prank(alice);
        vm.expectRevert();
        bridge.bridgeOut(20e18, LEDGER_WALLET);
    }

    function test_AdminOnlySettings() public {
        vm.startPrank(alice);
        vm.expectRevert();
        bridge.setThreshold(1);
        vm.expectRevert();
        bridge.setLimits(GFCBridge.Limits(1, 1, 1, 1));
        vm.stopPrank();

        vm.startPrank(admin);
        vm.expectRevert(IGFCBridge.BadThreshold.selector);
        bridge.setThreshold(0);
        vm.expectRevert(IGFCBridge.BadLimits.selector);
        bridge.setLimits(GFCBridge.Limits(2, 1, 1, 0)); // per-mint above window
        bridge.setThreshold(3);
        vm.stopPrank();
        assertEq(bridge.threshold(), 3);
    }

    function test_TokenSupplyCapStillApplies() public {
        vm.prank(admin);
        token.setSupplyCap(50e18);
        IGFCBridge.MintRequest memory req = _req(keccak256("d"), alice, 51_00);
        bytes[] memory sigs = _sign(req, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(GFCToken.SupplyCapExceeded.selector, 51e18, 50e18));
        bridge.mintFromLedger(req, sigs);
        assertFalse(bridge.processed(req.ledgerTxHash), "failed mint must not consume the deposit");
    }
}

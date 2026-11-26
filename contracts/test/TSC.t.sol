// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
import {TSC} from "../src/TSC.sol";

interface Vm {
    function addr(uint256) external returns (address);
    function prank(address) external;
    function deal(address, uint256) external;
    function warp(uint256) external;
    function expectRevert() external;
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function assume(bool) external;
}

contract RejectingOwner {
    TSC public t;

    constructor(TSC value) {
        t = value;
    }

    function register(uint256 did, address buyer) external returns (uint256) {
        return t.registerTrade(did, bytes32(uint256(2)), bytes32(uint256(3)), buyer, 1 ether, 100);
    }

    function confirm(uint256 tid, address key) external {
        t.confirmKey(tid, key);
    }

    function withdraw() external {
        t.withdraw();
    }

    receive() external payable {
        revert("reject");
    }
}

contract ReenteringOwner {
    TSC public t;
    bool public blocked;

    constructor(TSC value) {
        t = value;
    }

    function register(uint256 did, address buyer) external returns (uint256) {
        return t.registerTrade(did, bytes32(uint256(2)), bytes32(uint256(3)), buyer, 1 ether, 100);
    }

    function confirm(uint256 tid, address key) external {
        t.confirmKey(tid, key);
    }

    function withdraw() external {
        t.withdraw();
    }

    receive() external payable {
        try t.withdraw() {
            revert("reentered");
        } catch {
            blocked = true;
        }
    }
}

contract TSCTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    TSC t;
    address owner;
    address buyer;
    address enclave;
    uint256 constant ENC = 0xE11;
    bytes32 constant COMMIT = bytes32(uint256(123));

    function setUp() public {
        t = new TSC(address(this));
        owner = vm.addr(1);
        buyer = vm.addr(2);
        enclave = vm.addr(ENC);
        vm.deal(buyer, 100 ether);
        vm.warp(1000);
    }

    function open(address who, uint64 limit) internal returns (uint256) {
        return t.openAudit(
            who,
            bytes32(uint256(10)),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            3,
            COMMIT,
            uint64(block.timestamp + 100),
            limit
        );
    }

    function certify(address who) internal returns (uint256) {
        uint256 a = open(who, 2);
        t.fixChallenge(a, bytes32(uint256(7)));
        return t.decideAudit(a, true);
    }

    function trade(uint256 did) internal returns (uint256) {
        vm.prank(owner);
        return t.registerTrade(did, bytes32(uint256(2)), bytes32(uint256(3)), buyer, 1 ether, 100);
    }

    function fund(uint256 id) internal {
        vm.prank(buyer);
        t.deposit{value: 1 ether}(id);
    }

    function ready(uint256 id) internal {
        fund(id);
        vm.prank(owner);
        t.confirmKey(id, enclave);
        vm.prank(buyer);
        t.confirmKey(id, enclave);
    }

    function sig(uint256 id, bytes32 commitment, bytes memory data) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ENC, t.receiptDigest(id, commitment, data));
        return abi.encodePacked(r, s, v);
    }

    function testNormalSettlementAndWithdrawal() public {
        uint256 id = trade(certify(owner));
        ready(id);
        bytes memory data = hex"aabbcc";
        t.settle(id, COMMIT, data, sig(id, COMMIT, data));
        require(t.balances(owner) == 1 ether);
        require(t.getTrade(id).status == TSC.TradeStatus.Settled);
        require(t.resultBlocks(id) == block.number);
        uint256 before = owner.balance;
        vm.prank(owner);
        t.withdraw();
        require(owner.balance == before + 1 ether && t.balances(owner) == 0);
        vm.warp(2000);
        vm.expectRevert();
        vm.prank(buyer);
        t.timeoutRefund(id);
    }

    function testCertificationReusedAcrossTrades() public {
        uint256 did = certify(owner);
        uint256 a = trade(did);
        uint256 b = trade(did);
        ready(a);
        ready(b);
        require(a != b && t.getTrade(a).commitment == t.getTrade(b).commitment);
    }

    function testOnlyRAAndOnlyOwner() public {
        vm.expectRevert();
        vm.prank(buyer);
        t.openAudit(owner, bytes32(uint256(1)), 0, 0, 0, 3, COMMIT, 1100, 2);
        uint256 a = open(owner, 2);
        vm.expectRevert();
        t.decideAudit(a, true);
        vm.expectRevert();
        vm.prank(owner);
        t.fixChallenge(a, bytes32(uint256(2)));
        t.fixChallenge(a, bytes32(uint256(2)));
        uint256 did = t.decideAudit(a, true);
        vm.expectRevert();
        vm.prank(buyer);
        t.registerTrade(did, bytes32(uint256(1)), bytes32(uint256(2)), owner, 1, 10);
    }

    function testChallengeBudgetPersistsAfterFailureAndTimeout() public {
        uint256 a = open(owner, 2);
        t.fixChallenge(a, bytes32(uint256(1)));
        t.decideAudit(a, false);
        uint256 b = open(owner, 2);
        t.fixChallenge(b, bytes32(uint256(2)));
        vm.warp(1101);
        t.expireAudit(b);
        uint256 c = open(owner, 2);
        vm.expectRevert();
        t.fixChallenge(c, bytes32(uint256(3)));
        vm.expectRevert();
        open(owner, 3);
        vm.expectRevert();
        t.decideAudit(a, true);
        vm.expectRevert();
        t.decideAudit(b, true);
    }

    function testAuditDeadlineBoundaryAndPendingTimeout() public {
        uint256 a = open(owner, 2);
        t.fixChallenge(a, bytes32(uint256(1)));
        vm.warp(1100);
        t.decideAudit(a, true);
        uint256 b = open(owner, 2);
        vm.warp(1200);
        vm.expectRevert();
        t.expireAudit(b);
        vm.warp(1201);
        t.expireAudit(b);
        vm.expectRevert();
        t.fixChallenge(b, bytes32(uint256(3)));
    }

    function testFundingAndKeyAccessControls() public {
        uint256 id = trade(certify(owner));
        vm.expectRevert();
        vm.prank(owner);
        t.deposit{value: 0}(id);
        vm.expectRevert();
        vm.prank(buyer);
        t.deposit{value: 2 ether}(id);
        fund(id);
        vm.expectRevert();
        fund(id);
        vm.expectRevert();
        t.confirmKey(id, enclave);
        vm.prank(owner);
        t.confirmKey(id, enclave);
        vm.expectRevert();
        vm.prank(owner);
        t.confirmKey(id, enclave);
        vm.prank(buyer);
        t.confirmKey(id, enclave);
        vm.expectRevert();
        vm.prank(owner);
        t.confirmKey(id, enclave);
    }

    function testMismatchedKeysRefundExactlyOnce() public {
        uint256 id = trade(certify(owner));
        fund(id);
        uint256 before = buyer.balance;
        vm.prank(owner);
        t.confirmKey(id, enclave);
        vm.prank(buyer);
        t.confirmKey(id, owner);
        require(buyer.balance == before + 1 ether && t.getTrade(id).status == TSC.TradeStatus.Refunded);
        vm.warp(2000);
        vm.expectRevert();
        vm.prank(buyer);
        t.timeoutRefund(id);
    }

    function testInvalidRequestsNeverRefundOrChangeState() public {
        uint256 id = trade(certify(owner));
        ready(id);
        bytes memory data = hex"aa";
        bytes memory valid = sig(id, COMMIT, data);
        vm.expectRevert();
        t.settle(id, COMMIT, data, hex"01");
        vm.expectRevert();
        t.settle(id, COMMIT, hex"bb", valid);
        bytes32 other = bytes32(uint256(321));
        bytes memory changed = sig(id, other, data);
        vm.expectRevert();
        t.settle(id, other, data, changed);
        require(
            t.getTrade(id).status == TSC.TradeStatus.Ready && address(t).balance == 1 ether && t.balances(owner) == 0
        );
        require(t.resultBlocks(id) == 0);
        t.settle(id, COMMIT, data, valid);
        vm.expectRevert();
        t.settle(id, COMMIT, data, valid);
    }

    function testCrossTradeReplayRejectedEvenWithSameKey() public {
        uint256 did = certify(owner);
        uint256 a = trade(did);
        uint256 b = trade(did);
        ready(a);
        ready(b);
        bytes memory data = hex"aa";
        bytes memory signature = sig(a, COMMIT, data);
        vm.expectRevert();
        t.settle(b, COMMIT, data, signature);
        require(t.getTrade(b).status == TSC.TradeStatus.Ready);
    }

    function testSettlementAtDeadlineAndRefundAfterDeadline() public {
        uint256 did = certify(owner);
        uint256 a = trade(did);
        uint256 b = trade(did);
        ready(a);
        fund(b);
        vm.warp(1100);
        vm.expectRevert();
        vm.prank(buyer);
        t.timeoutRefund(a);
        bytes memory data = hex"aa";
        t.settle(a, COMMIT, data, sig(a, COMMIT, data));
        vm.warp(1101);
        vm.prank(buyer);
        t.timeoutRefund(b);
        require(t.getTrade(b).status == TSC.TradeStatus.Refunded);
        require(t.resultBlocks(b) == 0);
    }

    function testLateSettlementRejectedWithoutReleasingFunds() public {
        uint256 id = trade(certify(owner));
        ready(id);
        bytes memory data = hex"aa";
        bytes memory signature = sig(id, COMMIT, data);
        vm.warp(1101);
        vm.expectRevert();
        t.settle(id, COMMIT, data, signature);
        require(t.getTrade(id).status == TSC.TradeStatus.Ready);
        vm.prank(buyer);
        t.timeoutRefund(id);
    }

    function testWithdrawalFailureKeepsCreditAndSettlement() public {
        RejectingOwner r = new RejectingOwner(t);
        uint256 did = certify(address(r));
        uint256 id = r.register(did, buyer);
        fund(id);
        r.confirm(id, enclave);
        vm.prank(buyer);
        t.confirmKey(id, enclave);
        bytes memory data = hex"aa";
        t.settle(id, COMMIT, data, sig(id, COMMIT, data));
        vm.expectRevert();
        r.withdraw();
        require(t.balances(address(r)) == 1 ether && t.getTrade(id).status == TSC.TradeStatus.Settled);
    }

    function testWithdrawalReentrancyBlocked() public {
        ReenteringOwner r = new ReenteringOwner(t);
        uint256 did = certify(address(r));
        uint256 id = r.register(did, buyer);
        fund(id);
        r.confirm(id, enclave);
        vm.prank(buyer);
        t.confirmKey(id, enclave);
        bytes memory data = hex"aa";
        t.settle(id, COMMIT, data, sig(id, COMMIT, data));
        r.withdraw();
        require(r.blocked() && t.balances(address(r)) == 0 && address(r).balance == 1 ether);
    }

    function testFuzzMutationCannotSettle(bytes32 wrong) public {
        vm.assume(wrong != COMMIT);
        uint256 id = trade(certify(owner));
        ready(id);
        bytes memory data = hex"aa";
        bytes memory signature = sig(id, wrong, data);
        vm.expectRevert();
        t.settle(id, wrong, data, signature);
        require(t.getTrade(id).status == TSC.TradeStatus.Ready);
    }
}

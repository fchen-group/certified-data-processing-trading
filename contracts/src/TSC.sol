// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Research prototype. Business and source-code reviews are off-chain.
contract TSC {
    enum AuditStatus {
        Missing,
        Pending,
        Challenged,
        Certified,
        Failed,
        Expired
    }
    enum TradeStatus {
        Missing,
        Registered,
        Funded,
        Ready,
        Settled,
        Refunded
    }

    struct Audit {
        address owner;
        bytes32 batch;
        bytes32 version;
        bytes32 description;
        bytes32 policy;
        uint64 records;
        bytes32 commitment;
        uint64 deadline;
        bytes32 challenge;
        AuditStatus status;
        uint256 did;
    }

    struct Budget {
        uint64 limit;
        uint64 used;
    }

    struct Trade {
        uint256 did;
        address owner;
        address buyer;
        bytes32 source;
        bytes32 measurement;
        bytes32 commitment;
        uint256 price;
        uint64 duration;
        uint64 deadline;
        address ownerKey;
        address buyerKey;
        address enclaveKey;
        TradeStatus status;
    }
    address public immutable auditor;
    uint256 public auditCount;
    uint256 public dataCount;
    uint256 public tradeCount;
    mapping(uint256 => Audit) private audits;
    mapping(uint256 => uint256) public certificate;
    mapping(bytes32 => Budget) public budgets;
    mapping(uint256 => Trade) private trades;
    mapping(address => uint256) public balances;
    // Locator only; the complete result remains in ResultDelivered.
    mapping(uint256 => uint256) public resultBlocks;
    bool private entered;

    event AuditOpened(uint256 indexed aid);
    event ChallengeFixed(uint256 indexed aid, bytes32 challenge);
    event AuditClosed(uint256 indexed aid, AuditStatus status, uint256 did);
    event TradeRegistered(uint256 indexed tid);
    event Funded(uint256 indexed tid, uint64 deadline);
    event KeyFixed(uint256 indexed tid, address key);
    event ResultDelivered(uint256 indexed tid, bytes ciphertext);
    event Refunded(uint256 indexed tid);
    event Withdrawn(address indexed owner, uint256 amount);

    modifier onlyRA() {
        require(msg.sender == auditor, "RA only");
        _;
    }
    modifier nonReentrant() {
        require(!entered, "reentrancy");
        entered = true;
        _;
        entered = false;
    }

    constructor(address ra) {
        require(ra != address(0), "zero RA");
        auditor = ra;
    }

    function getAudit(uint256 aid) external view returns (Audit memory) {
        return audits[aid];
    }

    function getTrade(uint256 tid) external view returns (Trade memory) {
        return trades[tid];
    }

    function openAudit(
        address owner,
        bytes32 batch,
        bytes32 version,
        bytes32 description,
        bytes32 policy,
        uint64 records,
        bytes32 commitment,
        uint64 deadline,
        uint64 limit
    ) external onlyRA returns (uint256 aid) {
        require(owner != address(0) && records > 0 && limit > 0, "invalid audit");
        require(batch != bytes32(0) && commitment != bytes32(0), "empty binding");
        require(deadline > block.timestamp, "expired audit");
        bytes32 b = keccak256(abi.encode(owner, batch));
        Budget storage budget = budgets[b];
        if (budget.limit == 0) {
            budget.limit = limit;
        } else {
            require(budget.limit == limit, "batch limit immutable");
        }
        aid = ++auditCount;
        audits[aid] =
            Audit(owner, batch, version, description, policy, records, commitment, deadline, 0, AuditStatus.Pending, 0);
        emit AuditOpened(aid);
    }

    function fixChallenge(uint256 aid, bytes32 challenge) external onlyRA {
        Audit storage a = audits[aid];
        require(a.status == AuditStatus.Pending && block.timestamp <= a.deadline, "audit not pending");
        require(challenge != bytes32(0), "empty challenge");
        Budget storage b = budgets[keccak256(abi.encode(a.owner, a.batch))];
        require(b.used < b.limit, "challenge limit");
        ++b.used;
        a.challenge = challenge;
        a.status = AuditStatus.Challenged;
        emit ChallengeFixed(aid, challenge);
    }

    function decideAudit(uint256 aid, bool accepted) external onlyRA returns (uint256 did) {
        Audit storage a = audits[aid];
        require(a.status == AuditStatus.Challenged && block.timestamp <= a.deadline, "audit not active");
        if (accepted) {
            a.status = AuditStatus.Certified;
            did = ++dataCount;
            a.did = did;
            certificate[did] = aid;
        } else {
            a.status = AuditStatus.Failed;
        }
        emit AuditClosed(aid, a.status, did);
    }

    function expireAudit(uint256 aid) external {
        Audit storage a = audits[aid];
        require(a.status == AuditStatus.Pending || a.status == AuditStatus.Challenged, "audit terminal");
        require(block.timestamp > a.deadline, "audit not expired");
        a.status = AuditStatus.Expired;
        emit AuditClosed(aid, a.status, 0);
    }

    function registerTrade(
        uint256 did,
        bytes32 source,
        bytes32 measurement,
        address buyer,
        uint256 price,
        uint64 duration
    ) external returns (uint256 tid) {
        Audit storage a = audits[certificate[did]];
        require(a.status == AuditStatus.Certified && a.owner == msg.sender, "uncertified or wrong owner");
        require(buyer != address(0) && buyer != msg.sender && price > 0 && duration > 0, "invalid trade");
        require(source != bytes32(0) && measurement != bytes32(0), "empty program");
        tid = ++tradeCount;
        Trade storage t = trades[tid];
        t.did = did;
        t.owner = msg.sender;
        t.buyer = buyer;
        t.source = source;
        t.measurement = measurement;
        t.commitment = a.commitment;
        t.price = price;
        t.duration = duration;
        t.status = TradeStatus.Registered;
        emit TradeRegistered(tid);
    }

    function deposit(uint256 tid) external payable {
        Trade storage t = trades[tid];
        require(t.status == TradeStatus.Registered && msg.sender == t.buyer, "deposit not allowed");
        require(msg.value == t.price, "wrong amount");
        require(block.timestamp + t.duration <= type(uint64).max, "deadline overflow");
        t.deadline = uint64(block.timestamp) + t.duration;
        t.status = TradeStatus.Funded;
        emit Funded(tid, t.deadline);
    }

    // Addresses are Ethereum representations of secp256k1 public keys.
    function confirmKey(uint256 tid, address key) external nonReentrant {
        Trade storage t = trades[tid];
        require(t.status == TradeStatus.Funded && block.timestamp <= t.deadline, "not accepting keys");
        require(key != address(0), "zero key");
        if (msg.sender == t.owner) {
            require(t.ownerKey == address(0), "owner already confirmed");
            t.ownerKey = key;
        } else {
            require(msg.sender == t.buyer && t.buyerKey == address(0), "buyer confirmation invalid");
            t.buyerKey = key;
        }
        if (t.ownerKey != address(0) && t.buyerKey != address(0)) {
            if (t.ownerKey != t.buyerKey) {
                _refund(tid, t);
            } else {
                t.enclaveKey = key;
                t.status = TradeStatus.Ready;
                emit KeyFixed(tid, key);
            }
        }
    }

    function receiptDigest(uint256 tid, bytes32 commitment, bytes memory ciphertext) public view returns (bytes32) {
        // Domain separation additionally prevents reuse across chains/contracts.
        return
            keccak256(
                abi.encode("WORK2_RECEIPT_V1", block.chainid, address(this), tid, commitment, keccak256(ciphertext))
            );
    }

    function settle(uint256 tid, bytes32 commitment, bytes calldata ciphertext, bytes calldata signature) external {
        Trade storage t = trades[tid];
        require(t.status == TradeStatus.Ready, "trade not ready");
        require(block.timestamp <= t.deadline && commitment == t.commitment, "settlement conditions");
        require(ciphertext.length > 0 && signature.length == 65, "invalid receipt");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        require(v == 27 || v == 28, "invalid v");
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "high s");
        address signer = ecrecover(receiptDigest(tid, commitment, ciphertext), v, r, s);
        require(signer != address(0) && signer == t.enclaveKey, "invalid signature");
        t.status = TradeStatus.Settled;
        balances[t.owner] += t.price;
        resultBlocks[tid] = block.number;
        emit ResultDelivered(tid, ciphertext);
    }

    function timeoutRefund(uint256 tid) external nonReentrant {
        Trade storage t = trades[tid];
        require(
            msg.sender == t.buyer && (t.status == TradeStatus.Funded || t.status == TradeStatus.Ready),
            "refund not allowed"
        );
        require(block.timestamp > t.deadline, "not expired");
        _refund(tid, t);
    }

    function _refund(uint256 tid, Trade storage t) private {
        t.status = TradeStatus.Refunded;
        (bool ok,) = payable(t.buyer).call{value: t.price}("");
        require(ok, "refund transfer failed");
        emit Refunded(tid);
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty balance");
        balances[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "withdraw transfer failed");
        emit Withdrawn(msg.sender, amount);
    }
}

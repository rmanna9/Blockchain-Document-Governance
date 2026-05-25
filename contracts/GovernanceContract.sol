// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./AuditLog.sol";
import "./DIDRegistry.sol";

/**
 * @title GovernanceContract
 * @notice Implements the five-stage governance workflow for the consortium.
 *         Membership-based voting: one authority = one vote.
 *         Manages authority admission/exclusion and collective enforcement (RF3).
 */
contract GovernanceContract {

    // ── Enums ────────────────────────────────────────────────────────────────

    enum ProposalStatus { Pending, Active, Succeeded, Defeated, Executed, Cancelled }

    enum ThresholdType { Majority, Supermajority }  // >1/2 or >2/3

    // ── Structs ──────────────────────────────────────────────────────────────

    struct Proposal {
        uint256        proposalId;
        address        proposer;
        string         description;
        address        targetContract;
        bytes          calldata_;
        ProposalStatus status;
        ThresholdType  thresholdType;
        uint256        votingStart;
        uint256        votingEnd;
        uint256        queuedAt;
        uint256        forVotes;
        uint256        againstVotes;
        uint256        abstainVotes;
        uint256        eligibleVoters;
    }

    // ── Constants ────────────────────────────────────────────────────────────

    uint256 public constant VOTING_DELAY  = 1 hours;
    uint256 public constant VOTING_PERIOD = 3 days;
    uint256 public constant TIMELOCK      = 1 days;

    // ── State ────────────────────────────────────────────────────────────────

    DIDRegistry public didRegistry;
    AuditLog    public auditLog;

    address[] private _authorities;
    mapping(address => bool)   public isAuthority;
    mapping(address => string) public authorityDID;

    uint256 private _nextProposalId;
    mapping(uint256 => Proposal)                 private _proposals;
    mapping(uint256 => mapping(address => bool)) private _hasVoted;

    // ── Events ───────────────────────────────────────────────────────────────

    event AuthorityAdded(address indexed authority, string did);
    event AuthorityRemoved(address indexed authority, string did);

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyAuthority() {
        require(isAuthority[msg.sender], "Governance: caller is not an authority");
        _;
    }

    modifier proposalExists(uint256 proposalId) {
        require(proposalId > 0 && proposalId < _nextProposalId, "Governance: proposal not found");
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor(
        address[]  memory foundingAuthorities,
        string[]   memory dids,
        address           didRegistry_,
        address           auditLog_
    ) {
        require(foundingAuthorities.length == dids.length, "Governance: array length mismatch");
        require(foundingAuthorities.length > 0,            "Governance: no founding authorities");

        didRegistry = DIDRegistry(didRegistry_);
        auditLog    = AuditLog(auditLog_);
        _nextProposalId = 1;

        for (uint256 i = 0; i < foundingAuthorities.length; i++) {
            _addAuthority(foundingAuthorities[i], dids[i]);
        }
    }

    // ── Authority management (called via proposals only) ──────────────────────

    /**
     * @notice Atomically register a new authority DID and add it to the
     *         consortium. Called by GovernanceContract itself via proposal
     *         execution. Supermajority required (WP2 §Authority Admission).
     */
    function admitAuthority(
        address         authority,
        string calldata did,
        string calldata activePublicKey,
        string calldata recoveryPublicKey
    ) external {
        require(msg.sender == address(this), "Governance: only via proposal");
        require(!isAuthority[authority],     "Governance: already an authority");

        // Register DID atomically with governance admission
        didRegistry.registerAuthority(did, activePublicKey, recoveryPublicKey, authority);
        _addAuthority(authority, did);

        auditLog.log(
            authority,
            AuditLog.ActionType.DIDRegistered,
            keccak256(bytes(did)),
            abi.encode(authority, did)
        );
    }

    /**
     * @notice Remove an authority from the consortium and deactivate its DID.
     *         Called by GovernanceContract itself via proposal execution.
     *         Supermajority required (WP2 §Authority Exclusion).
     *
     *         WP2: "The proposal calldata encodes both
     *         GovernanceContract.removeAuthorityAddress(address) and
     *         DIDRegistry.deactivate(did), executed atomically upon approval."
     */
    function removeAuthority(address authority) external {
        require(msg.sender == address(this), "Governance: only via proposal");
        require(isAuthority[authority],      "Governance: not an authority");

        string memory did = authorityDID[authority];
        _removeAuthority(authority);

        // WP2 §Authority Exclusion: deactivate DID atomically
        didRegistry.deactivate(did);

        auditLog.log(
            authority,
            AuditLog.ActionType.DIDDeactivated,
            keccak256(bytes(did)),
            abi.encode(authority, did)
        );
    }

    // ── Stage 2: Proposal submission ──────────────────────────────────────────

    /**
     * @notice Submit a governance proposal (Stage 2 of five-stage workflow).
     * @param description    Human-readable description.
     * @param targetContract Contract to call upon execution.
     * @param calldata_      Encoded function call to execute.
     * @param thresholdType  Majority (>1/2) or Supermajority (>2/3).
     */
    function propose(
        string    calldata description,
        address            targetContract,
        bytes     calldata calldata_,
        ThresholdType      thresholdType
    ) external onlyAuthority returns (uint256 proposalId) {
        proposalId = _nextProposalId++;

        uint256 votingStart = block.timestamp + VOTING_DELAY;

        _proposals[proposalId] = Proposal({
            proposalId:     proposalId,
            proposer:       msg.sender,
            description:    description,
            targetContract: targetContract,
            calldata_:      calldata_,
            status:         ProposalStatus.Pending,
            thresholdType:  thresholdType,
            votingStart:    votingStart,
            votingEnd:      votingStart + VOTING_PERIOD,
            queuedAt:       0,
            forVotes:       0,
            againstVotes:   0,
            abstainVotes:   0,
            eligibleVoters: _authorities.length
        });

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.ProposalSubmitted,
            bytes32(proposalId),
            abi.encode(proposalId, targetContract, thresholdType, description)
        );
    }

    // ── Stage 3: Voting ───────────────────────────────────────────────────────

    /**
     * @notice Cast a vote on an active proposal (Stage 3).
     * @param support  0 = Against, 1 = For, 2 = Abstain
     */
    function castVote(uint256 proposalId, uint8 support)
        external
        onlyAuthority
        proposalExists(proposalId)
    {
        require(support <= 2, "Governance: invalid support value");

        Proposal storage p = _proposals[proposalId];

        if (p.status == ProposalStatus.Pending && block.timestamp >= p.votingStart) {
            p.status = ProposalStatus.Active;
        }

        require(p.status == ProposalStatus.Active, "Governance: proposal not active");
        require(block.timestamp <= p.votingEnd,     "Governance: voting period ended");
        require(!_hasVoted[proposalId][msg.sender], "Governance: already voted");

        _hasVoted[proposalId][msg.sender] = true;

        if      (support == 1) p.forVotes++;
        else if (support == 0) p.againstVotes++;
        else                   p.abstainVotes++;

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.VoteCast,
            bytes32(proposalId),
            abi.encode(proposalId, support)
        );
    }

    // ── Stage 4: Timelock queue ───────────────────────────────────────────────

    /**
     * @notice Queue a succeeded proposal for the timelock delay (Stage 4).
     *         Anyone can call this after the voting period ends.
     */
    function queue(uint256 proposalId) external proposalExists(proposalId) {
        Proposal storage p = _proposals[proposalId];
        require(block.timestamp > p.votingEnd, "Governance: voting not ended");
        require(
            p.status == ProposalStatus.Active || p.status == ProposalStatus.Pending,
            "Governance: invalid status"
        );

        if (_quorumReached(p)) {
            p.status   = ProposalStatus.Succeeded;
            p.queuedAt = block.timestamp;
        } else {
            p.status = ProposalStatus.Defeated;
        }
    }

    // ── Stage 5: Execution ────────────────────────────────────────────────────

    /**
     * @notice Execute a queued proposal after the timelock has elapsed (Stage 5).
     */
    function execute(uint256 proposalId)
        external
        onlyAuthority
        proposalExists(proposalId)
    {
        Proposal storage p = _proposals[proposalId];
        require(p.status == ProposalStatus.Succeeded,     "Governance: not succeeded");
        require(block.timestamp >= p.queuedAt + TIMELOCK, "Governance: timelock not elapsed");

        p.status = ProposalStatus.Executed;

        (bool success, ) = p.targetContract.call(p.calldata_);
        require(success, "Governance: execution failed");

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.ProposalExecuted,
            bytes32(proposalId),
            abi.encode(proposalId)
        );
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    function getProposal(uint256 proposalId)
        external view proposalExists(proposalId)
        returns (Proposal memory)
    {
        return _proposals[proposalId];
    }

    function getAuthorities() external view returns (address[] memory) {
        return _authorities;
    }

    function authorityCount() external view returns (uint256) {
        return _authorities.length;
    }

    function hasVoted(uint256 proposalId, address authority) external view returns (bool) {
        return _hasVoted[proposalId][authority];
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _addAuthority(address authority, string memory did) internal {
        isAuthority[authority]  = true;
        authorityDID[authority] = did;
        _authorities.push(authority);
        emit AuthorityAdded(authority, did);
    }

    function _removeAuthority(address authority) internal {
        isAuthority[authority] = false;
        uint256 len = _authorities.length;
        for (uint256 i = 0; i < len; i++) {
            if (_authorities[i] == authority) {
                _authorities[i] = _authorities[len - 1];
                _authorities.pop();
                break;
            }
        }
        emit AuthorityRemoved(authority, authorityDID[authority]);
        delete authorityDID[authority];
    }

    function _quorumReached(Proposal storage p) internal view returns (bool) {
        uint256 total = p.eligibleVoters;
        if (total == 0) return false;
        if (p.thresholdType == ThresholdType.Majority) {
            return p.forVotes * 2 > total;
        } else {
            return p.forVotes * 3 > total * 2;
        }
    }
}
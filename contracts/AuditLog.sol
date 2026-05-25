// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title AuditLog
 * @notice Append-only, tamper-evident event log.
 *         All other contracts emit structured entries here.
 *         No entry is ever deleted or modified after emission.
 */
contract AuditLog {

    // ── Enums ────────────────────────────────────────────────────────────────

    enum ActionType {
        // Identity
        DIDRegistered,
        DIDDeactivated,
        // Document lifecycle
        CertificationRequested,
        DocumentCertified,
        DocumentRevoked,
        CIDStored,
        SharesStored,
        // Access control
        PermissionGranted,
        PermissionRevoked,
        DelegationIssued,
        DelegationRevoked,
        // Governance
        ProposalSubmitted,
        VoteCast,
        ProposalExecuted,
        // Audit
        AnomalyReported,
        // Retrieval
        ReadApproved
    }

    // ── Structs ──────────────────────────────────────────────────────────────

    struct LogEntry {
        uint256    entryId;
        address    emittedBy;    // originating contract
        address    actor;        // entity that triggered the operation
        ActionType actionType;
        bytes32    targetId;     // hash, DID hash, proposalId, delegationId …
        uint256    timestamp;
        uint256    blockNumber;
        bytes      payload;      // ABI-encoded action-specific data
    }

    // ── State ────────────────────────────────────────────────────────────────

    // Authorised contracts that may write to the log
    mapping(address => bool) public authorisedWriters;
    address public admin;        // deployer; used only to add writers at setup

    uint256 private _nextId;
    mapping(uint256 => LogEntry) private _entries;

    // ── Events ───────────────────────────────────────────────────────────────

    event EntryLogged(
        uint256 indexed entryId,
        address indexed actor,
        ActionType indexed actionType,
        bytes32 targetId,
        uint256 timestamp
    );

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyAuthorised() {
        require(authorisedWriters[msg.sender], "AuditLog: caller not authorised");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "AuditLog: caller is not admin");
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor() {
        admin    = msg.sender;
        _nextId  = 1;
    }

    // ── Writer management ────────────────────────────────────────────────────

    /**
     * @notice Authorise a contract to write log entries.
     *         Called by the deployer during setup, before renouncing admin.
     */
    function addWriter(address writer) external onlyAdmin {
        require(writer != address(0), "AuditLog: zero address");
        authorisedWriters[writer] = true;
    }

    /**
     * @notice Renounce admin rights after all writers have been registered.
     *         After this call the writer set is frozen.
     */
    function renounceAdmin() external onlyAdmin {
        admin = address(0);
    }

    // ── Logging ──────────────────────────────────────────────────────────────

    /**
     * @notice Append a new entry to the log.
     * @param actor       Blockchain address of the entity that triggered the op.
     * @param actionType  Categorises the operation.
     * @param targetId    Primary identifier of the affected object.
     * @param payload     ABI-encoded action-specific data.
     * @return entryId    The assigned sequential identifier.
     */
    function log(
        address    actor,
        ActionType actionType,
        bytes32    targetId,
        bytes calldata payload
    ) external onlyAuthorised returns (uint256 entryId) {
        entryId = _nextId++;

        _entries[entryId] = LogEntry({
            entryId:     entryId,
            emittedBy:   msg.sender,
            actor:       actor,
            actionType:  actionType,
            targetId:    targetId,
            timestamp:   block.timestamp,
            blockNumber: block.number,
            payload:     payload
        });

        emit EntryLogged(entryId, actor, actionType, targetId, block.timestamp);
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    function getEntry(uint256 entryId) external view returns (LogEntry memory) {
        require(entryId > 0 && entryId < _nextId, "AuditLog: entry not found");
        return _entries[entryId];
    }

    function totalEntries() external view returns (uint256) {
        return _nextId - 1;
    }
}
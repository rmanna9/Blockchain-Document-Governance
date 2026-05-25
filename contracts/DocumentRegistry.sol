// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./DIDRegistry.sol";
import "./AuditLog.sol";
import "./DocumentAccessControl.sol";

/**
 * @title DocumentRegistry
 * @notice Manages document metadata, lifecycle state, and version chains.
 *         Implements RF4 (Document Lifecycle) and RF5 (Access Control).
 */
contract DocumentRegistry {

    // ── Enums ────────────────────────────────────────────────────────────────

    enum DocumentStatus { Pending, Certified, Revoked }

    // ── Structs ──────────────────────────────────────────────────────────────

    struct DocumentRecord {
        bytes32        documentHash;
        string         cid;
        DocumentStatus status;
        string         creatorDID;
        string         ownerDID;
        address        certifiedBy;
        bytes          sigAuthority;
        uint256        version;
        bytes32        previousVersion;
        bytes32        followingVersion;
        uint256        certifiedAt;
        string         revocationReason;
    }

    // ── State ────────────────────────────────────────────────────────────────

    DIDRegistry public didRegistry;
    AuditLog    public auditLog;
    address     public accessControl;
    address     public governanceContract;

    mapping(bytes32 => DocumentRecord) private _records;

    // ── Events ───────────────────────────────────────────────────────────────

    event CertificationRequested(bytes32 indexed documentHash, string creatorDID, uint256 timestamp);
    event DocumentCertified(bytes32 indexed documentHash, address indexed certifiedBy, uint256 timestamp);
    event DocumentRevoked(bytes32 indexed documentHash, string reason, uint256 timestamp);
    event CIDStored(bytes32 indexed documentHash, string cid, uint256 timestamp);

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyAuthority() {
        string memory did = didRegistry.lookupDID(msg.sender);
        require(bytes(did).length > 0, "DocumentRegistry: caller not registered");
        DIDRegistry.DIDDocument memory doc = didRegistry.resolve(did);
        require(doc.entityType == DIDRegistry.EntityType.Authority, "DocumentRegistry: caller is not an authority");
        require(doc.isActive, "DocumentRegistry: authority not active");
        _;
    }

    modifier onlyGovernanceOrAuthority(bytes32 documentHash) {
        if (msg.sender != governanceContract) {
            string memory did = didRegistry.lookupDID(msg.sender);
            require(bytes(did).length > 0, "DocumentRegistry: caller not registered");
            DIDRegistry.DIDDocument memory doc = didRegistry.resolve(did);
            require(doc.entityType == DIDRegistry.EntityType.Authority, "DocumentRegistry: not an authority");
            require(doc.isActive, "DocumentRegistry: authority not active");
            require(
                _records[documentHash].certifiedBy == msg.sender,
                "DocumentRegistry: not the certifying authority"
            );
        }
        _;
    }

    modifier recordExists(bytes32 documentHash) {
        require(_records[documentHash].documentHash != 0, "DocumentRegistry: document not found");
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor(address didRegistry_, address auditLog_) {
        didRegistry = DIDRegistry(didRegistry_);
        auditLog    = AuditLog(auditLog_);
    }

    // ── Setup ────────────────────────────────────────────────────────────────

    function setAccessControl(address accessControl_) external {
        require(accessControl == address(0), "DocumentRegistry: already set");
        require(accessControl_ != address(0), "DocumentRegistry: zero address");
        accessControl = accessControl_;
    }

    function setGovernanceContract(address governance_) external {
        require(governanceContract == address(0), "DocumentRegistry: already set");
        require(governance_ != address(0), "DocumentRegistry: zero address");
        governanceContract = governance_;
    }

    // ── Phase 1: Hash commitment ──────────────────────────────────────────────

    /**
     * @notice User anchors the document hash on-chain before transferring
     *         the document to the authority (WP2 §Certification Phase 1).
     *
     *         Checks (RF5):
     *         - New document: caller must hold canCreate permission.
     *         - Update: caller must hold canUpdate scoped to previousHash.
     *
     *         ownerDID defaults:
     *         - New document: creatorDID.
     *         - Update: ownerDID of the previous version (WP2 §Certification Phase 1).
     */
    function requestCertification(
        bytes32         documentHash,
        bytes32         previousHash,
        string calldata ownerDID
    ) external {
        require(documentHash != 0,                        "DocumentRegistry: zero hash");
        require(documentHash != previousHash,             "DocumentRegistry: hash equals previous");
        require(_records[documentHash].documentHash == 0, "DocumentRegistry: hash already exists");

        string memory creatorDID = didRegistry.lookupDID(msg.sender);
        require(bytes(creatorDID).length > 0, "DocumentRegistry: caller not registered");

        // RF5 + lazy authority check: caller must be fully active
        require(
            didRegistry.isFullyActive(creatorDID),
            "DocumentRegistry: caller or its authority is not active"
        );

        // RF5: permission check
        if (accessControl != address(0)) {
            if (previousHash == bytes32(0)) {
                require(
                    DocumentAccessControl(accessControl).hasCreatePermission(creatorDID),
                    "DocumentRegistry: caller has no canCreate permission"
                );
            } else {
                require(
                    DocumentAccessControl(accessControl).hasPermission(
                        creatorDID,
                        previousHash,
                        DocumentAccessControl.ActionType.CanUpdate
                    ),
                    "DocumentRegistry: caller has no canUpdate permission"
                );
            }
        }

        // Resolve ownerDID:
        // - New document: defaults to creatorDID
        // - Update: defaults to ownerDID of the previous version (WP2)
        string memory resolvedOwner;
        if (bytes(ownerDID).length > 0) {
            resolvedOwner = ownerDID;
        } else if (previousHash == bytes32(0)) {
            resolvedOwner = creatorDID;
        } else {
            resolvedOwner = _records[previousHash].ownerDID;
        }

        if (previousHash != 0) {
            DocumentRecord storage prev = _records[previousHash];
            require(prev.documentHash != 0,          "DocumentRegistry: previous version not found");
            require(prev.status != DocumentStatus.Revoked, "DocumentRegistry: previous version revoked");
            require(prev.followingVersion == 0,      "DocumentRegistry: not the latest version");
        }

        _records[documentHash] = DocumentRecord({
            documentHash:     documentHash,
            cid:              "",
            status:           DocumentStatus.Pending,
            creatorDID:       creatorDID,
            ownerDID:         resolvedOwner,
            certifiedBy:      address(0),
            sigAuthority:     "",
            version:          previousHash == 0 ? 1 : _records[previousHash].version + 1,
            previousVersion:  previousHash,
            followingVersion: 0,
            certifiedAt:      0,
            revocationReason: ""
        });

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.CertificationRequested,
            documentHash,
            abi.encode(documentHash, previousHash, creatorDID, resolvedOwner)
        );

        emit CertificationRequested(documentHash, creatorDID, block.timestamp);
    }

    // ── Phase 3: On-chain certification ──────────────────────────────────────

    /**
     * @notice Authority certifies a PENDING document after off-chain
     *         integrity verification (WP2 §Certification Phase 3).
     *         Atomically: Certified + version chain link + permission assignment.
     */
    function certify(
        bytes32        documentHash,
        bytes calldata sigAuthority
    ) external onlyAuthority recordExists(documentHash) {
        DocumentRecord storage record = _records[documentHash];
        require(record.status == DocumentStatus.Pending, "DocumentRegistry: not pending");

        // Verify this authority is the domain authority of the creator
        DIDRegistry.DIDDocument memory creatorDoc = didRegistry.resolve(record.creatorDID);
        require(
            creatorDoc.domainAuthority == msg.sender,
            "DocumentRegistry: caller is not creator's domain authority"
        );

        // Lazy check: creator must still be fully active at certification time
        require(
            didRegistry.isFullyActive(record.creatorDID),
            "DocumentRegistry: creator or its authority is not active"
        );

        record.status       = DocumentStatus.Certified;
        record.certifiedBy  = msg.sender;
        record.sigAuthority = sigAuthority;
        record.certifiedAt  = block.timestamp;

        // Link version chain (O(1) write)
        if (record.previousVersion != 0) {
            _records[record.previousVersion].followingVersion = documentHash;
        }

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.DocumentCertified,
            documentHash,
            abi.encode(documentHash, msg.sender, record.creatorDID, record.ownerDID, record.version)
        );

        emit DocumentCertified(documentHash, msg.sender, block.timestamp);

        // Phase 3.1: automatic permission assignment (WP2)
        if (accessControl != address(0)) {
            DocumentAccessControl(accessControl).assignCertificationPermissions(
                documentHash,
                record.creatorDID,
                record.ownerDID,
                msg.sender
            );
        }
    }

    // ── CID storage ──────────────────────────────────────────────────────────

    /**
     * @notice Authority stores the IPFS CID after archival (Phase 4).
     *         Only the certifying authority may call this.
     */
    function storeCID(
        bytes32         documentHash,
        string calldata cid
    ) external recordExists(documentHash) {
        DocumentRecord storage record = _records[documentHash];
        require(record.status == DocumentStatus.Certified, "DocumentRegistry: not certified");
        require(record.certifiedBy == msg.sender,          "DocumentRegistry: not certifying authority");
        require(bytes(record.cid).length == 0,             "DocumentRegistry: CID already set");
        require(bytes(cid).length > 0,                     "DocumentRegistry: empty CID");

        record.cid = cid;

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.CIDStored,
            documentHash,
            abi.encode(documentHash, cid)
        );

        emit CIDStored(documentHash, cid, block.timestamp);
    }

    // ── Revocation ───────────────────────────────────────────────────────────

    /**
     * @notice Revoke a document.
     *         - Certifying authority (RF4).
     *         - GovernanceContract bypassing the certifying authority (RF3).
     */
    function revoke(
        bytes32         documentHash,
        string calldata reason
    ) external onlyGovernanceOrAuthority(documentHash) recordExists(documentHash) {
        DocumentRecord storage record = _records[documentHash];
        require(record.status != DocumentStatus.Revoked, "DocumentRegistry: already revoked");

        record.status           = DocumentStatus.Revoked;
        record.revocationReason = reason;

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.DocumentRevoked,
            documentHash,
            abi.encode(documentHash, reason)
        );

        emit DocumentRevoked(documentHash, reason, block.timestamp);
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    /**
     * @notice Returns the effective status of a document.
     *         A document certified by a deactivated authority is considered
     *         inaccessible (lazy check — WP2 §Authority Removal).
     */
    function getStatus(bytes32 documentHash)
        external view recordExists(documentHash)
        returns (DocumentStatus)
    {
        DocumentRecord storage record = _records[documentHash];

        if (record.status == DocumentStatus.Certified) {
            string memory authorityDID = didRegistry.lookupDID(record.certifiedBy);
            if (!didRegistry.isActive(authorityDID)) {
                return DocumentStatus.Revoked;
            }
        }

        return record.status;
    }

    function getRecord(bytes32 documentHash)
        external view recordExists(documentHash)
        returns (DocumentRecord memory)
    {
        return _records[documentHash];
    }

    function getCID(bytes32 documentHash)
        external view recordExists(documentHash)
        returns (string memory)
    {
        return _records[documentHash].cid;
    }

    function exists(bytes32 documentHash) external view returns (bool) {
        return _records[documentHash].documentHash != 0;
    }

}
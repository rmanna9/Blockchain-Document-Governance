// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./DIDRegistry.sol";
import "./DocumentRegistry.sol";
import "./AuditLog.sol";

/**
 * @title DocumentAccessControl
 * @notice Manages permissions and delegation chains for documents.
 *         Implements RF5 (Access Control), RF7 (Delegation and Revocation).
 */
contract DocumentAccessControl {

    // ── Enums ────────────────────────────────────────────────────────────────

    enum ActionType { CanCreate, CanRead, CanUpdate }

    // ── Structs ──────────────────────────────────────────────────────────────

    struct Permission {
        bytes32    permissionId;
        string     holderDID;
        bytes32    documentHash;
        ActionType actionType;
        address    issuerAddress;
        bool       canDelegate;
        bool       delegableRead;
        bool       delegableUpdate;
        uint256    issuedAt;
        uint256    expiresAt;
        bool       isActive;
    }

    struct Delegation {
        bytes32    delegationId;
        bytes32    parentId;
        string     delegatorDID;
        string     delegateeDID;
        bytes32    documentHash;
        ActionType actionType;
        bool       canDelegate;
        bool       delegableRead;
        bool       delegableUpdate;
        uint256    issuedAt;
        uint256    expiresAt;
        bool       isActive;
    }

    // ── State ────────────────────────────────────────────────────────────────

    DIDRegistry      public didRegistry;
    DocumentRegistry public documentRegistry;
    AuditLog         public auditLog;
    address          public governanceContract;

    mapping(bytes32 => Permission)   private _permissions;
    mapping(bytes32 => Delegation)   private _delegations;
    mapping(string  => bytes32[])    private _userPermissions;
    mapping(bytes32 => bytes32[])    private _delegationChildren;
    mapping(string  => bytes32[])    private _receivedDelegations;

    // ── Events ───────────────────────────────────────────────────────────────

    event PermissionGranted(bytes32 indexed permissionId, string holderDID, ActionType actionType);
    event PermissionRevoked(bytes32 indexed permissionId, string holderDID);
    event DelegationIssued(bytes32 indexed delegationId, string delegatorDID, string delegateeDID);
    event DelegationRevoked(bytes32 indexed delegationId, string holderDID);
    event ReadApproved(address indexed userAddress, bytes32 indexed documentHash, uint256 timestamp);

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyAuthority() {
        string memory did = didRegistry.lookupDID(msg.sender);
        require(bytes(did).length > 0, "DAC: caller not registered");
        DIDRegistry.DIDDocument memory doc = didRegistry.resolve(did);
        require(doc.entityType == DIDRegistry.EntityType.Authority, "DAC: not an authority");
        require(doc.isActive, "DAC: authority not active");
        _;
    }

    modifier onlyGovernanceOrAuthority() {
        if (msg.sender != governanceContract) {
            string memory did = didRegistry.lookupDID(msg.sender);
            require(bytes(did).length > 0, "DAC: caller not registered");
            DIDRegistry.DIDDocument memory doc = didRegistry.resolve(did);
            require(doc.entityType == DIDRegistry.EntityType.Authority, "DAC: not an authority");
            require(doc.isActive, "DAC: authority not active");
        }
        _;
    }

    modifier validDID(string calldata did) {
        require(bytes(did).length > 0, "DAC: empty DID");
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor(
        address didRegistry_,
        address documentRegistry_,
        address auditLog_
    ) {
        didRegistry      = DIDRegistry(didRegistry_);
        documentRegistry = DocumentRegistry(documentRegistry_);
        auditLog         = AuditLog(auditLog_);
    }

    function setGovernanceContract(address governance_) external {
        require(governanceContract == address(0), "DAC: already set");
        require(governance_ != address(0),        "DAC: zero address");
        governanceContract = governance_;
    }

    // ── CanCreate ────────────────────────────────────────────────────────────

    /**
     * @notice Grant canCreate to a user. Only the user's domain authority.
     *         RF5: issuerAddress = msg.sender (domain authority).
     */
    function grantCreate(
        string calldata holderDID,
        uint256         expiresAt
    ) external onlyAuthority validDID(holderDID) {
        DIDRegistry.DIDDocument memory holderDoc = didRegistry.resolve(holderDID);

        // Lazy authority check: holder must be fully active
        require(didRegistry.isFullyActive(holderDID), "DAC: holder or its authority not active");
        require(holderDoc.domainAuthority == msg.sender, "DAC: not domain authority");

        bytes32 permId = keccak256(abi.encodePacked(
            holderDID, ActionType.CanCreate, block.timestamp
        ));

        _permissions[permId] = Permission({
            permissionId:    permId,
            holderDID:       holderDID,
            documentHash:    0,
            actionType:      ActionType.CanCreate,
            issuerAddress:   msg.sender,
            canDelegate:     false,
            delegableRead:   false,
            delegableUpdate: false,
            issuedAt:        block.timestamp,
            expiresAt:       expiresAt,
            isActive:        true
        });

        _userPermissions[holderDID].push(permId);

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.PermissionGranted,
            permId,
            abi.encode(permId, holderDID, ActionType.CanCreate)
        );

        emit PermissionGranted(permId, holderDID, ActionType.CanCreate);
    }

    /**
     * @notice Check if a DID holds an active canCreate permission.
     *         Includes lazy authority check.
     */
    function hasCreatePermission(string calldata holderDID) external view returns (bool) {
        if (!didRegistry.isFullyActive(holderDID)) return false;

        bytes32[] storage perms = _userPermissions[holderDID];
        for (uint256 i = 0; i < perms.length; i++) {
            Permission storage p = _permissions[perms[i]];
            if (
                p.actionType == ActionType.CanCreate &&
                p.isActive &&
                (p.expiresAt == 0 || p.expiresAt > block.timestamp)
            ) {
                return true;
            }
        }
        return false;
    }

    // ── CanRead / CanUpdate (assigned at certification) ──────────────────────

    /**
     * @notice Assign canRead and canUpdate to creator and owner at certification.
     *         Called atomically by DocumentRegistry.certify() — Phase 3.1 (WP2).
     */
    function assignCertificationPermissions(
        bytes32         documentHash,
        string calldata creatorDID,
        string calldata ownerDID,
        address         certifyingAuthority
    ) external {
        require(msg.sender == address(documentRegistry), "DAC: only DocumentRegistry");

        _grantDocumentPermission(documentHash, creatorDID, ActionType.CanRead,   certifyingAuthority, true, true, true,  0);
        _grantDocumentPermission(documentHash, creatorDID, ActionType.CanUpdate, certifyingAuthority, true, true, false, 0);

        if (keccak256(bytes(ownerDID)) != keccak256(bytes(creatorDID))) {
            _grantDocumentPermission(documentHash, ownerDID, ActionType.CanRead, certifyingAuthority, true, true, false, 0);
        }
    }

    // ── Delegation ───────────────────────────────────────────────────────────

    /**
     * @notice Delegate canRead or canUpdate to another user.
     *         The contract automatically finds the caller's active parent
     *         permission or delegation. (RF7)
     */
    function delegate(
        string   calldata delegateeDID,
        bytes32           documentHash,
        ActionType        actionType,
        bool              canDelegate_,
        bool              delegableRead_,
        bool              delegableUpdate_,
        uint256           expiresAt
    ) external validDID(delegateeDID) returns (bytes32 delegationId) {
        require(actionType != ActionType.CanCreate, "DAC: canCreate is not delegable");

        string memory delegatorDID = didRegistry.lookupDID(msg.sender);
        require(bytes(delegatorDID).length > 0, "DAC: caller not registered");

        // Lazy check: delegator must be fully active
        require(didRegistry.isFullyActive(delegatorDID), "DAC: delegator or its authority not active");

        // Lazy check: delegatee must be fully active
        require(didRegistry.isFullyActive(delegateeDID), "DAC: delegatee or its authority not active");

        require(
            documentRegistry.getStatus(documentHash) != DocumentRegistry.DocumentStatus.Revoked,
            "DAC: document is revoked"
        );

        bytes32 parentId = _findActiveParent(
            delegatorDID, documentHash, actionType,
            canDelegate_, delegableRead_, delegableUpdate_
        );
        require(parentId != bytes32(0), "DAC: no valid parent permission found");

        delegationId = keccak256(abi.encodePacked(
            delegatorDID, delegateeDID, documentHash, actionType, block.timestamp
        ));

        _delegations[delegationId] = Delegation({
            delegationId:    delegationId,
            parentId:        parentId,
            delegatorDID:    delegatorDID,
            delegateeDID:    delegateeDID,
            documentHash:    documentHash,
            actionType:      actionType,
            canDelegate:     canDelegate_,
            delegableRead:   delegableRead_,
            delegableUpdate: delegableUpdate_,
            issuedAt:        block.timestamp,
            expiresAt:       expiresAt,
            isActive:        true
        });

        _delegationChildren[parentId].push(delegationId);
        _receivedDelegations[delegateeDID].push(delegationId);

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.DelegationIssued,
            delegationId,
            abi.encode(delegationId, documentHash, actionType)
        );

        emit DelegationIssued(delegationId, delegatorDID, delegateeDID);
    }

    // ── Permission check ─────────────────────────────────────────────────────

    /**
     * @notice Check if a DID holds an active direct permission on a document.
     *         Includes lazy authority check and document status check.
     */
    function hasPermission(
        string  calldata holderDID,
        bytes32          documentHash,
        ActionType       actionType
    ) external view returns (bool) {
        // Lazy check: document must be accessible
        if (documentRegistry.getStatus(documentHash) == DocumentRegistry.DocumentStatus.Revoked) {
            return false;
        }
        // Lazy check: holder must be fully active
        if (!didRegistry.isFullyActive(holderDID)) return false;

        bytes32[] storage perms = _userPermissions[holderDID];
        for (uint256 i = 0; i < perms.length; i++) {
            Permission storage p = _permissions[perms[i]];
            if (
                p.documentHash == documentHash &&
                p.actionType   == actionType   &&
                p.isActive     &&
                (p.expiresAt == 0 || p.expiresAt > block.timestamp)
            ) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Verify read permission and emit ReadApproved event.
     *         Called by the user before requesting key shares (WP2 §Retrieval Phase 1).
     */
    function checkAndApproveRead(bytes32 documentHash) external {
        string memory holderDID = didRegistry.lookupDID(msg.sender);
        require(bytes(holderDID).length > 0, "DAC: caller not registered");

        // Lazy check: caller must be fully active
        require(didRegistry.isFullyActive(holderDID), "DAC: caller or its authority not active");

        require(
            this.hasPermission(holderDID, documentHash, ActionType.CanRead) ||
            _hasDelegatedPermission(holderDID, documentHash, ActionType.CanRead),
            "DAC: no read permission"
        );

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.ReadApproved,
            documentHash,
            abi.encode(msg.sender, documentHash)
        );

        emit ReadApproved(msg.sender, documentHash, block.timestamp);
    }

    function canPresentExternally(
        string calldata holderDID,
        bytes32         documentHash
    ) external view returns (bool) {
        if (documentRegistry.getStatus(documentHash) == DocumentRegistry.DocumentStatus.Revoked) {
            return false;
        }
        if (!didRegistry.isFullyActive(holderDID)) return false;

        // Check direct permissions
        bytes32[] storage perms = _userPermissions[holderDID];
        for (uint256 i = 0; i < perms.length; i++) {
            Permission storage p = _permissions[perms[i]];
            if (
                p.documentHash == documentHash &&
                p.actionType   == ActionType.CanRead &&
                p.isActive     &&
                p.canDelegate  &&
                p.delegableRead &&
                (p.expiresAt == 0 || p.expiresAt > block.timestamp)
            ) return true;
        }

        // Check received delegations
        bytes32[] storage dels = _receivedDelegations[holderDID];
        for (uint256 i = 0; i < dels.length; i++) {
            Delegation storage d = _delegations[dels[i]];
            if (
                d.documentHash == documentHash &&
                d.actionType   == ActionType.CanRead &&
                d.isActive     &&
                d.canDelegate  &&
                d.delegableRead &&
                (d.expiresAt == 0 || d.expiresAt > block.timestamp)
            ) return true;
        }

        return false;
    }

    // ── Revocation ───────────────────────────────────────────────────────────

    /**
     * @notice Revoke a permission. Only the issuing authority or governance.
     *         Cascades to all child delegations. (RF7)
     */
    function revokePermission(bytes32 permissionId) external onlyGovernanceOrAuthority {
        Permission storage p = _permissions[permissionId];
        require(p.permissionId != 0, "DAC: permission not found");
        require(p.isActive,          "DAC: already inactive");

        if (msg.sender != governanceContract) {
            require(p.issuerAddress == msg.sender, "DAC: not the issuer");
        }

        p.isActive = false;
        _cascadeRevokeDelegations(permissionId);

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.PermissionRevoked,
            permissionId,
            abi.encode(permissionId, p.holderDID)
        );

        emit PermissionRevoked(permissionId, p.holderDID);
    }

    /**
     * @notice Revoke a delegation. Only the delegator or governance.
     *         Cascades to all sub-delegations. (RF7)
     */
    function revokeDelegation(bytes32 delegationId) external {
        Delegation storage d = _delegations[delegationId];
        require(d.delegationId != 0, "DAC: delegation not found");
        require(d.isActive,          "DAC: already inactive");

        string memory callerDID = didRegistry.lookupDID(msg.sender);
        require(bytes(callerDID).length > 0, "DAC: caller not registered");

        if (msg.sender != governanceContract) {
            require(
                keccak256(bytes(callerDID)) == keccak256(bytes(d.delegatorDID)),
                "DAC: not the delegator"
            );
        }

        d.isActive = false;
        _cascadeRevokeDelegations(delegationId);

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.DelegationRevoked,
            delegationId,
            abi.encode(delegationId, d.delegatorDID, d.delegateeDID)
        );

        emit DelegationRevoked(delegationId, d.delegateeDID);
    }

    /**
     * @notice Invalidate all permissions and delegations of a deactivated user.
     *         Called by DIDRegistry upon user deactivation (WP2 §Entity Deregistration).
     */
    function invalidateUserPermissions(string calldata holderDID) external {
        require(msg.sender == address(didRegistry), "DAC: only DIDRegistry");

        // Invalidate direct permissions and cascade
        bytes32[] storage perms = _userPermissions[holderDID];
        for (uint256 i = 0; i < perms.length; i++) {
            Permission storage p = _permissions[perms[i]];
            if (p.isActive) {
                p.isActive = false;
                _cascadeRevokeDelegations(perms[i]);

                auditLog.log(
                    msg.sender,
                    AuditLog.ActionType.PermissionRevoked,
                    perms[i],
                    abi.encode(perms[i], holderDID)
                );

                emit PermissionRevoked(perms[i], holderDID);
            }
        }

        // Also invalidate received delegations and cascade
        // This handles the case where the deactivated user is an intermediate node
        bytes32[] storage dels = _receivedDelegations[holderDID];
        for (uint256 i = 0; i < dels.length; i++) {
            Delegation storage d = _delegations[dels[i]];
            if (d.isActive) {
                d.isActive = false;
                _cascadeRevokeDelegations(dels[i]);

                auditLog.log(
                    msg.sender,
                    AuditLog.ActionType.DelegationRevoked,
                    dels[i],
                    abi.encode(dels[i], holderDID)
                );

                emit DelegationRevoked(dels[i], holderDID);
            }
        }
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    function getPermission(bytes32 permissionId) external view returns (Permission memory) {
        return _permissions[permissionId];
    }

    function getDelegation(bytes32 delegationId) external view returns (Delegation memory) {
        return _delegations[delegationId];
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    function _grantDocumentPermission(
        bytes32       documentHash,
        string memory holderDID,
        ActionType    actionType,
        address       issuer,
        bool          canDelegate_,
        bool          delegableRead_,
        bool          delegableUpdate_,
        uint256       expiresAt
    ) internal {
        bytes32 permId = keccak256(abi.encodePacked(
            holderDID, documentHash, actionType, block.timestamp
        ));

        _permissions[permId] = Permission({
            permissionId:    permId,
            holderDID:       holderDID,
            documentHash:    documentHash,
            actionType:      actionType,
            issuerAddress:   issuer,
            canDelegate:     canDelegate_,
            delegableRead:   delegableRead_,
            delegableUpdate: delegableUpdate_,
            issuedAt:        block.timestamp,
            expiresAt:       expiresAt,
            isActive:        true
        });

        _userPermissions[holderDID].push(permId);
        emit PermissionGranted(permId, holderDID, actionType);
    }

    function _findActiveParent(
        string memory delegatorDID,
        bytes32       documentHash,
        ActionType    actionType,
        bool          canDelegate_,
        bool          delegableRead_,
        bool          delegableUpdate_
    ) internal view returns (bytes32) {
        bytes32[] storage perms = _userPermissions[delegatorDID];
        for (uint256 i = 0; i < perms.length; i++) {
            Permission storage p = _permissions[perms[i]];
            if (
                p.documentHash == documentHash &&
                p.actionType   == actionType   &&
                p.isActive     &&
                p.canDelegate  &&
                (p.expiresAt == 0 || p.expiresAt > block.timestamp)
            ) {
                if (canDelegate_) {
                    if (delegableRead_   && !p.delegableRead)   continue;
                    if (delegableUpdate_ && !p.delegableUpdate) continue;
                }
                return p.permissionId;
            }
        }

        bytes32[] storage dels = _receivedDelegations[delegatorDID];
        for (uint256 i = 0; i < dels.length; i++) {
            Delegation storage d = _delegations[dels[i]];
            if (
                d.documentHash == documentHash &&
                d.actionType   == actionType   &&
                d.isActive     &&
                d.canDelegate  &&
                (d.expiresAt == 0 || d.expiresAt > block.timestamp)
            ) {
                if (canDelegate_) {
                    if (delegableRead_   && !d.delegableRead)   continue;
                    if (delegableUpdate_ && !d.delegableUpdate) continue;
                }
                return d.delegationId;
            }
        }

        return bytes32(0);
    }

    function _hasDelegatedPermission(
        string memory holderDID,
        bytes32       documentHash,
        ActionType    actionType
    ) internal view returns (bool) {
        // Lazy check: document must be accessible
        if (documentRegistry.getStatus(documentHash) == DocumentRegistry.DocumentStatus.Revoked) {
            return false;
        }
        // Lazy check: holder must be fully active
        if (!didRegistry.isFullyActive(holderDID)) return false;

        bytes32[] storage dels = _receivedDelegations[holderDID];
        for (uint256 i = 0; i < dels.length; i++) {
            Delegation storage d = _delegations[dels[i]];
            if (
                d.documentHash == documentHash &&
                d.actionType   == actionType   &&
                d.isActive     &&
                (d.expiresAt == 0 || d.expiresAt > block.timestamp)
            ) {
                return true;
            }
        }
        return false;
    }

    function _cascadeRevokeDelegations(bytes32 recordId) internal {
        bytes32[] storage children = _delegationChildren[recordId];
        for (uint256 i = 0; i < children.length; i++) {
            bytes32 childId = children[i];
            Delegation storage child = _delegations[childId];
            if (child.isActive) {
                child.isActive = false;
                emit DelegationRevoked(childId, child.delegateeDID);
                _cascadeRevokeDelegations(childId);
            }
        }
    }
}
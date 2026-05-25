// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./AuditLog.sol";

/**
 * @title DIDRegistry
 * @notice Stores and manages DID Documents for all consortium entities.
 *         Acts as the authoritative on-chain identity resolver.
 *         Implements RF1 (Identity Management) and RF3 (Collective Enforcement).
 */
contract DIDRegistry {

    // ── Enums ────────────────────────────────────────────────────────────────

    enum EntityType { Authority, User, Auditor }

    // ── Structs ──────────────────────────────────────────────────────────────

    struct DIDDocument {
        string     did;
        string     activePublicKey;
        string     recoveryPublicKey;
        address    domainAuthority;    // address(0) for Authority and Auditor
        address    entityAddress;
        EntityType entityType;
        bool       isActive;
        uint256    createdAt;
        uint256    expiresAt;          // 0 = no expiry
    }

    // ── State ────────────────────────────────────────────────────────────────

    AuditLog public auditLog;
    address  public governanceContract;
    address  public accessControl;     // DocumentAccessControl — set after deploy

    mapping(string => DIDDocument) private _documents;
    mapping(address => string)     private _addressToDID;

    // ── Events ───────────────────────────────────────────────────────────────

    event DIDRegistered(
        string indexed did,
        address indexed entityAddress,
        EntityType entityType,
        uint256 timestamp
    );

    event DIDDeactivated(string indexed did, uint256 timestamp);

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyGovernance() {
        require(msg.sender == governanceContract, "DIDRegistry: caller is not governance");
        _;
    }

    modifier onlyRegisteredAuthority() {
        string memory did = _addressToDID[msg.sender];
        require(bytes(did).length > 0, "DIDRegistry: caller not registered");
        DIDDocument storage doc = _documents[did];
        require(doc.entityType == EntityType.Authority, "DIDRegistry: caller is not an authority");
        require(doc.isActive, "DIDRegistry: authority is not active");
        _;
    }

    modifier didExists(string calldata did) {
        require(bytes(_documents[did].did).length > 0, "DIDRegistry: DID not found");
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor(
        address[] memory foundingAuthorities,
        string[]  memory dids,
        string[]  memory activeKeys,
        string[]  memory recoveryKeys,
        address          auditLog_
    ) {
        require(
            foundingAuthorities.length == dids.length &&
            dids.length == activeKeys.length &&
            activeKeys.length == recoveryKeys.length,
            "DIDRegistry: array length mismatch"
        );
        require(auditLog_ != address(0), "DIDRegistry: zero auditLog");
        auditLog = AuditLog(auditLog_);

        for (uint256 i = 0; i < foundingAuthorities.length; i++) {
            _registerDID(
                dids[i],
                activeKeys[i],
                recoveryKeys[i],
                address(0),
                foundingAuthorities[i],
                EntityType.Authority,
                0
            );
        }
    }

    // ── Setup ────────────────────────────────────────────────────────────────

    function setGovernanceContract(address governance) external {
        require(governanceContract == address(0), "DIDRegistry: already set");
        require(governance != address(0), "DIDRegistry: zero address");
        governanceContract = governance;
    }

    function setAccessControl(address accessControl_) external {
        require(accessControl == address(0), "DIDRegistry: already set");
        require(accessControl_ != address(0), "DIDRegistry: zero address");
        accessControl = accessControl_;
    }

    // ── Registration ─────────────────────────────────────────────────────────

    function registerUser(
        string  calldata did,
        string  calldata activePublicKey,
        string  calldata recoveryPublicKey,
        address          userAddress,
        uint256          expiresAt
    ) external onlyRegisteredAuthority {
        _registerDID(
            did, activePublicKey, recoveryPublicKey,
            msg.sender, userAddress, EntityType.User, expiresAt
        );

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.DIDRegistered,
            keccak256(bytes(did)),
            abi.encode(did, EntityType.User, userAddress, msg.sender)
        );
    }

    function registerAuditor(
        string  calldata did,
        string  calldata activePublicKey,
        string  calldata recoveryPublicKey,
        address          auditorAddress
    ) external onlyGovernance {
        _registerDID(
            did, activePublicKey, recoveryPublicKey,
            address(0), auditorAddress, EntityType.Auditor, 0
        );

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.DIDRegistered,
            keccak256(bytes(did)),
            abi.encode(did, EntityType.Auditor, auditorAddress, address(0))
        );
    }

    function registerAuthority(
        string  calldata did,
        string  calldata activePublicKey,
        string  calldata recoveryPublicKey,
        address          authorityAddress
    ) external onlyGovernance {
        _registerDID(
            did, activePublicKey, recoveryPublicKey,
            address(0), authorityAddress, EntityType.Authority, 0
        );

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.DIDRegistered,
            keccak256(bytes(did)),
            abi.encode(did, EntityType.Authority, authorityAddress, address(0))
        );
    }

    // ── Deactivation ─────────────────────────────────────────────────────────

    function deactivate(string calldata did) external didExists(did) {
        DIDDocument storage doc = _documents[did];
        require(doc.isActive, "DIDRegistry: already inactive");

        if (msg.sender != governanceContract) {
            require(
                doc.entityType == EntityType.User,
                "DIDRegistry: only governance can deactivate non-users"
            );
            require(
                msg.sender == doc.domainAuthority,
                "DIDRegistry: caller is not domain authority"
            );
        }

        doc.isActive = false;

        // WP2 §Entity Deregistration: invalidate all permissions and delegations.
        // Only Users hold document-level permissions in DocumentAccessControl.
        if (doc.entityType == EntityType.User && accessControl != address(0)) {
            (bool success, ) = accessControl.call(
                abi.encodeWithSignature("invalidateUserPermissions(string)", did)
            );
            require(success, "DIDRegistry: failed to invalidate permissions");
        }

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.DIDDeactivated,
            keccak256(bytes(did)),
            abi.encode(did, doc.entityType, doc.entityAddress)
        );

        emit DIDDeactivated(did, block.timestamp);
    }

    // ── Resolvers ────────────────────────────────────────────────────────────

    function resolve(string calldata did)
        external view didExists(did)
        returns (DIDDocument memory)
    {
        return _documents[did];
    }

    function lookupDID(address entityAddress)
        external view
        returns (string memory)
    {
        return _addressToDID[entityAddress];
    }

    /**
     * @notice Returns true if the DID is active at the individual level.
     *         Does not check the domain authority chain.
     */
    function isActive(string calldata did)
        external view
        returns (bool)
    {
        return _documents[did].isActive;
    }

    /**
     * @notice Returns true only if the entity is active AND
     *         its domain authority (if any) is still active.
     *         Used for lazy validation of users after authority removal.
     *         Authorities and Auditors have no domainAuthority — always
     *         returns their own isActive.
     */
    function isFullyActive(string calldata did)
        external view
        returns (bool)
    {
        DIDDocument storage doc = _documents[did];
        if (!doc.isActive) return false;
        // Authority and Auditor have no domain authority
        if (doc.domainAuthority == address(0)) return true;
        // User: check that domain authority is still active
        string storage authorityDID = _addressToDID[doc.domainAuthority];
        if (bytes(authorityDID).length == 0) return false;
        return _documents[authorityDID].isActive;
    }

    function getActivePublicKey(string calldata did)
        external view didExists(did)
        returns (string memory)
    {
        return _documents[did].activePublicKey;
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    function _registerDID(
        string memory did,
        string memory activePublicKey,
        string memory recoveryPublicKey,
        address       domainAuthority,
        address       entityAddress,
        EntityType    entityType,
        uint256       expiresAt
    ) internal {
        require(bytes(did).length > 0,                           "DIDRegistry: empty DID");
        require(bytes(_documents[did].did).length == 0,          "DIDRegistry: DID already registered");
        require(entityAddress != address(0),                      "DIDRegistry: zero entity address");
        require(bytes(_addressToDID[entityAddress]).length == 0,  "DIDRegistry: address already registered");

        _documents[did] = DIDDocument({
            did:               did,
            activePublicKey:   activePublicKey,
            recoveryPublicKey: recoveryPublicKey,
            domainAuthority:   domainAuthority,
            entityAddress:     entityAddress,
            entityType:        entityType,
            isActive:          true,
            createdAt:         block.timestamp,
            expiresAt:         expiresAt
        });

        _addressToDID[entityAddress] = did;

        emit DIDRegistered(did, entityAddress, entityType, block.timestamp);
    }
}
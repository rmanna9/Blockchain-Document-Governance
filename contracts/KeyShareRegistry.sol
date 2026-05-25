// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./DIDRegistry.sol";
import "./AuditLog.sol";

/**
 * @title KeyShareRegistry
 * @notice Stores encrypted Shamir Secret Sharing shares for each archived document.
 *         Maps documentHash => { (authorityIndex, encryptedShare) }
 *         No single authority can reconstruct k_doc alone.
 *         Share access is gated by ReadApproved events in DocumentAccessControl.
 */
contract KeyShareRegistry {

    // ── Structs ──────────────────────────────────────────────────────────────

    struct EncryptedShare {
        uint256 shareIndex;       // i-th authority (1-based)
        address authorityAddress;
        bytes   encryptedShare;   // Enc(pk_i, share_i)
    }

    struct ShareSet {
        bool    exists;
        uint256 threshold;        // t = ceil(2N/3)
        uint256 totalShares;      // N at the time of archival
        mapping(address => EncryptedShare) shares;  // authorityAddress => share
        address[] authorityList;
    }

    // ── State ────────────────────────────────────────────────────────────────

    DIDRegistry public didRegistry;
    AuditLog    public auditLog;

    mapping(bytes32 => ShareSet) private _shareSets;

    // ── Events ───────────────────────────────────────────────────────────────

    event SharesStored(bytes32 indexed documentHash, uint256 totalShares, uint256 threshold);

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyAuthority() {
        string memory did = didRegistry.lookupDID(msg.sender);
        require(bytes(did).length > 0, "KSR: caller not registered");
        DIDRegistry.DIDDocument memory doc = didRegistry.resolve(did);
        require(doc.entityType == DIDRegistry.EntityType.Authority, "KSR: not an authority");
        require(doc.isActive, "KSR: authority not active");
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor(address didRegistry_, address auditLog_) {
        didRegistry = DIDRegistry(didRegistry_);
        auditLog    = AuditLog(auditLog_);
    }

    // ── Store shares ─────────────────────────────────────────────────────────

    /**
     * @notice Store all encrypted shares for a document after IPFS archival.
     *         Called by the certifying authority (Phase 4 of archival workflow).
     * @param documentHash       H(document)
     * @param authorityAddresses Ordered list of all authority addresses.
     * @param shareIndices       Corresponding share indices (1-based).
     * @param encryptedShares    Enc(pk_i, share_i) for each authority.
     * @param threshold          Reconstruction threshold t = ceil(2N/3).
     */
    function storeShares(
        bytes32            documentHash,
        address[] calldata authorityAddresses,
        uint256[] calldata shareIndices,
        bytes[]   calldata encryptedShares,
        uint256            threshold
    ) external onlyAuthority {
        require(!_shareSets[documentHash].exists,                        "KSR: shares already stored");
        require(authorityAddresses.length > 0,                           "KSR: empty authority list");
        require(authorityAddresses.length == shareIndices.length,        "KSR: array mismatch");
        require(authorityAddresses.length == encryptedShares.length,     "KSR: array mismatch");
        require(threshold > 0 && threshold <= authorityAddresses.length, "KSR: invalid threshold");

        ShareSet storage ss = _shareSets[documentHash];
        ss.exists      = true;
        ss.threshold   = threshold;
        ss.totalShares = authorityAddresses.length;

        for (uint256 i = 0; i < authorityAddresses.length; i++) {
            require(authorityAddresses[i] != address(0), "KSR: zero authority address");
            require(encryptedShares[i].length > 0,       "KSR: empty share");

            ss.shares[authorityAddresses[i]] = EncryptedShare({
                shareIndex:       shareIndices[i],
                authorityAddress: authorityAddresses[i],
                encryptedShare:   encryptedShares[i]
            });
            ss.authorityList.push(authorityAddresses[i]);
        }

        auditLog.log(
            msg.sender,
            AuditLog.ActionType.SharesStored,
            documentHash,
            abi.encode(documentHash, authorityAddresses.length, threshold)
        );

        emit SharesStored(documentHash, authorityAddresses.length, threshold);
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    /**
     * @notice Get the encrypted share assigned to a specific authority.
     *         Each authority calls this to retrieve its own share, then
     *         decrypts it off-chain and releases the plaintext share to
     *         the requesting user after verifying ReadApproved on-chain.
     */
    function getShare(
        bytes32 documentHash,
        address authorityAddress
    ) external view returns (EncryptedShare memory) {
        ShareSet storage ss = _shareSets[documentHash];
        require(ss.exists, "KSR: shares not found");
        EncryptedShare storage share = ss.shares[authorityAddress];
        require(share.authorityAddress != address(0), "KSR: share not found");
        return share;
    }

    function getThreshold(bytes32 documentHash) external view returns (uint256) {
        require(_shareSets[documentHash].exists, "KSR: shares not found");
        return _shareSets[documentHash].threshold;
    }

    function getTotalShares(bytes32 documentHash) external view returns (uint256) {
        require(_shareSets[documentHash].exists, "KSR: shares not found");
        return _shareSets[documentHash].totalShares;
    }

    function sharesExist(bytes32 documentHash) external view returns (bool) {
        return _shareSets[documentHash].exists;
    }
}
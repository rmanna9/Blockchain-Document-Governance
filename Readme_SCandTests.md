# Blockchain-Document-Governance

**Multi-Authority Decentralized System for Document Lifecycle Management**  
University of Salerno — DIEM — Master's Degree in Computer Engineering  
Blockchain Course A.A. 2025/2026 — Prof. Carlo Mazzocca

---

## Overview

This repository contains the WP4 prototype implementation of the system designed in WP2. It implements a permissioned consortium blockchain for decentralized document lifecycle governance with multi-authority access control.

The prototype covers the full on-chain layer (6 Solidity smart contracts) and a comprehensive test suite verifying all WP2 processes. The off-chain layer (authority nodes, IPFS archival, oracle, client scenarios) is implemented in `authority-node/` and `client/`.

---

## Smart Contracts

### Contract Overview

| Contract | Responsibilities | WP2 Reference |
|---|---|---|
| `AuditLog` | Append-only tamper-evident event log. All contracts write here. No entry is ever deleted or modified. | §Auditing and Monitoring |
| `DIDRegistry` | Stores DID Documents on-chain. Authoritative identity resolver. Bidirectional mappings DID ↔ address. | §Identity Management, §Entity Registration |
| `GovernanceContract` | Five-stage proposal-and-vote mechanism. Membership-based voting (one authority = one vote). | §Governance and Policy Management |
| `DocumentRegistry` | Document metadata, lifecycle state, and version chain management. | §Document Certification, §Document Revocation, §Versioning |
| `DocumentAccessControl` | Per-user and per-document permissions. Delegation tree with cascading revocation. | §Permission and Delegation Model |
| `KeyShareRegistry` | Encrypted Shamir Secret Sharing shares for each archived document. | §Document Archival on IPFS |

---

### AuditLog

| Element | Description |
|---|---|
| **State** | `_entries: uint256 → LogEntry` — immutable sequential log |
| | `authorisedWriters: address → bool` — contracts allowed to write |
| | `admin: address` — deployer, used only during setup, then renounced |
| **ActionTypes** | `DIDRegistered`, `DIDDeactivated`, `CertificationRequested`, `DocumentCertified`, `DocumentRevoked`, `CIDStored`, `SharesStored`, `PermissionGranted`, `PermissionRevoked`, `DelegationIssued`, `DelegationRevoked`, `ProposalSubmitted`, `VoteCast`, `ProposalExecuted`, `AnomalyReported`, `ReadApproved` |
| **`log(actor, actionType, targetId, payload)`** | Appends immutable entry. Only authorised writers. |
| **`getEntry(id)`** | Read by any Auditor or Authority. |
| **`renounceAdmin()`** | Freezes writer set permanently after setup. |

**WP2 Design Choices:**
- Writer set is frozen after deployment — no writer can be added after `renounceAdmin()`.
- Genesis authorities are not logged (DIDRegistry is not yet an authorised writer during deployment). This is documented as a known limitation — genesis configuration is traceable via the deployment transaction itself.

---

### DIDRegistry

| Element | Description |
|---|---|
| **State** | `_documents: string → DIDDocument` |
| | `_addressToDID: address → string` |
| | `governanceContract: address` |
| | `accessControl: address` — DocumentAccessControl, set post-deploy |
| **DIDDocument fields** | `did`, `activePublicKey`, `recoveryPublicKey`, `domainAuthority`, `entityAddress`, `entityType`, `isActive`, `createdAt`, `expiresAt` |
| **`registerUser(did, pk, rk, address, expiresAt)`** | Only registered active Authority. Sets `domainAuthority = msg.sender`. |
| **`registerAuditor(did, pk, rk, address)`** | Only GovernanceContract. |
| **`registerAuthority(did, pk, rk, address)`** | Only GovernanceContract. |
| **`deactivate(did)`** | Domain authority for its users; GovernanceContract for any entity (RF3). Permanent — irreversible. |
| **`isActive(did)`** | Returns individual `isActive` flag. |
| **`isFullyActive(did)`** | Returns `true` only if entity is active **and** its domain authority is still active. Used for lazy validation after authority removal. |
| **`resolve(did)`** | Returns full DIDDocument. |
| **`lookupDID(address)`** | Returns DID for a given address. |
| **`getActivePublicKey(did)`** | Used by lightweight authentication protocol. |

**WP2 Design Choices:**
- **Key rotation** is out of scope for this prototype (marked as "to do" in WP2).
- **`isFullyActive()`** implements the lazy authority check described in WP2 §Policy Model (behavioral policy): when an authority is removed, its users' validity is checked lazily at access time without explicit per-user invalidation.
- **`deactivate()` on User** calls `DocumentAccessControl.invalidateUserPermissions()` via low-level `call()` to avoid circular imports. This performs explicit cascading invalidation of all permissions and delegations as required by WP2 §Entity Deregistration.
- Genesis authorities are registered in the constructor without logging (AuditLog not yet authorised at that point).

---

### GovernanceContract

| Element | Description |
|---|---|
| **State** | `_authorities: address[]`, `isAuthority: address → bool`, `authorityDID: address → string` |
| | `_proposals: uint256 → Proposal`, `_hasVoted: proposalId → address → bool` |
| **Constants** | `VOTING_DELAY = 1 hour`, `VOTING_PERIOD = 3 days`, `TIMELOCK = 1 day` |
| **Proposal fields** | `proposalId`, `proposer`, `targetContract`, `calldata_`, `status`, `thresholdType`, `eligibleVoters` (snapshot), `forVotes`, `againstVotes`, `abstainVotes` |
| **`propose(description, target, calldata, threshold)`** | Stage 2. Only Authority. Snapshots `eligibleVoters` at proposal time. |
| **`castVote(proposalId, support)`** | Stage 3. For/Against/Abstain. One vote per authority. |
| **`queue(proposalId)`** | Stage 4. Anyone. Checks quorum, starts timelock. |
| **`execute(proposalId)`** | Stage 5. Only Authority. After timelock elapses. |
| **`admitAuthority(address, did, pk, rk)`** | Via proposal only. Atomically registers DID + adds to consortium. |
| **`removeAuthority(address)`** | Via proposal only. Atomically removes from consortium + deactivates DID. |

**Quorum Thresholds (WP2 §Quorum Thresholds):**

| Action | Threshold |
|---|---|
| Standard policy, Auditor admission/removal | Majority `> 1/2` |
| Authority admission | Supermajority `> 2/3` |
| Authority exclusion | Supermajority `> 2/3` |
| Cross-authority enforcement (RF3) | Supermajority `> 2/3` |
| Forced document read (RF3) | Supermajority `> 2/3` |

**WP2 Design Choices:**
- `eligibleVoters` is snapshotted at proposal submission — new authorities admitted after a proposal is submitted cannot influence its outcome.
- `admitAuthority()` is atomic: both DID registration and governance membership happen in a single transaction, preventing partial state.
- `removeAuthority()` calls `didRegistry.deactivate()` atomically as required by WP2 §Authority Exclusion.
- Quorum uses integer arithmetic without division: `forVotes * 2 > total` avoids rounding errors.

---

### DocumentRegistry

| Element | Description |
|---|---|
| **State** | `_records: bytes32 → DocumentRecord` |
| **DocumentRecord fields** | `documentHash`, `cid`, `status`, `creatorDID`, `ownerDID`, `certifiedBy`, `sigAuthority`, `version`, `previousVersion`, `followingVersion`, `certifiedAt`, `revocationReason` |
| **`requestCertification(hash, prevHash, ownerDID)`** | Phase 1. Anchors hash on-chain before document transfer. Checks `canCreate` (new) or `canUpdate` scoped to `prevHash` (update). |
| **`certify(hash, sig)`** | Phase 3. Only domain authority of creator. Transitions PENDING→CERTIFIED. Links version chain. Calls `assignCertificationPermissions()`. |
| **`storeCID(hash, cid)`** | Phase 4. Only certifying authority. Anchors IPFS CID on-chain. |
| **`revoke(hash, reason)`** | Certifying authority or GovernanceContract (RF3). CERTIFIED→REVOKED. |
| **`getStatus(hash)`** | Returns effective status. Returns `Revoked` if certifying authority has been deactivated (lazy check). |

**WP2 Design Choices:**
- Hash commitment before document transfer is the key security design (WP2 §Certification Design Rationale): prevents malicious authority from altering document content after receiving it.
- `ownerDID` defaults: for new documents → `creatorDID`; for updates → `ownerDID` of previous version (preserving ownership continuity across versions).
- Version chain uses a doubly-linked list (`previousVersion` / `followingVersion`) with O(1) write cost per versioning event.
- Only the latest version in a chain can be updated — prevents diverging version history.
- **Lazy authority check in `getStatus()`**: a document certified by a deactivated authority is treated as effectively revoked without modifying on-chain state.

---

### DocumentAccessControl

| Element | Description |
|---|---|
| **State** | `_permissions: bytes32 → Permission`, `_delegations: bytes32 → Delegation` |
| | `_userPermissions: holderDID → permissionId[]` |
| | `_receivedDelegations: delegateeDID → delegationId[]` |
| | `_delegationChildren: recordId → childId[]` |
| **Permission fields** | `permissionId`, `holderDID`, `documentHash`, `actionType`, `issuerAddress`, `canDelegate`, `delegableRead`, `delegableUpdate`, `issuedAt`, `expiresAt`, `isActive` |
| **Delegation fields** | `delegationId`, `parentId`, `delegatorDID`, `delegateeDID`, `documentHash`, `actionType`, `canDelegate`, `delegableRead`, `delegableUpdate`, `issuedAt`, `expiresAt`, `isActive` |
| **`grantCreate(holderDID, expiresAt)`** | Only domain authority. Issues `CanCreate` permission. |
| **`assignCertificationPermissions(hash, creator, owner, authority)`** | Only DocumentRegistry. Assigns `CanRead` + `CanUpdate` to creator, `CanRead` to owner if distinct. |
| **`delegate(delegateeDID, hash, type, canDelegate, scopes, expiresAt)`** | Automatically finds active parent permission. Enforces scope constraints. |
| **`checkAndApproveRead(hash)`** | Verifies read permission and emits `ReadApproved` event — the oracle trigger for key share release. |
| **`revokePermission(permId)`** | Issuing authority or Governance. Cascades to all child delegations. |
| **`revokeDelegation(delId)`** | Delegator or Governance. Cascades to all sub-delegations. |
| **`invalidateUserPermissions(holderDID)`** | Only DIDRegistry. Invalidates all permissions and received delegations of a deactivated user, with full cascade. |
| **`hasPermission(did, hash, type)`** | Includes lazy checks: document not revoked, holder fully active. |
| **`hasCreatePermission(did)`** | Includes lazy check: holder fully active. |

**Permission Types (WP2 §Permission Types):**

| Type | Scope | Delegable |
|---|---|---|
| `CanCreate` | User-level | No |
| `CanRead` | Document-level (hash) | Yes |
| `CanUpdate` | Document-level (hash) | Yes |

**WP2 Design Choices:**
- Parent permission is found automatically by `_findActiveParent()` — the caller does not need to supply a `parentId`. This simplifies the client interface while maintaining the explicit delegation tree on-chain.
- Scope enforcement: delegated scope cannot exceed parent scope (`delegableRead`, `delegableUpdate` flags).
- `invalidateUserPermissions()` invalidates both direct permissions and received delegations — covers intermediate nodes in delegation chains.
- All permission and delegation checks include `isFullyActive()` for lazy authority validation.
- `checkAndApproveRead()` is the on-chain gate for document retrieval. Without a `ReadApproved` event, authority nodes will not release key shares.

---

### KeyShareRegistry

| Element | Description |
|---|---|
| **State** | `_shareSets: bytes32 → ShareSet` |
| **ShareSet fields** | `exists`, `threshold`, `totalShares`, `shares: address → EncryptedShare`, `authorityList` |
| **EncryptedShare fields** | `shareIndex`, `authorityAddress`, `encryptedShare` — `Enc(pk_i, share_i)` |
| **`storeShares(hash, addresses[], indices[], encShares[], threshold)`** | Only Authority. Stores N encrypted shares after IPFS archival (Archival Phase 4). |
| **`getShare(hash, authorityAddress)`** | Returns `Enc(pk_i, share_i)` for authority i. Decrypted off-chain. |
| **`getThreshold(hash)`** | Returns `t = ceil(2N/3)`. |
| **`sharesExist(hash)`** | Checks if a document has been archived. |

**WP2 Design Choices:**
- SSS split and per-authority encryption happen **off-chain** in the authority node. This contract only stores the resulting encrypted blobs.
- Share access is gated by `ReadApproved` events in `DocumentAccessControl`, not by this contract. After document revocation, `checkAndApproveRead()` fails so no `ReadApproved` is emitted — authority nodes never release shares, making the document effectively unretrievable even though shares remain on-chain.
- Threshold `t = ceil(2N/3)` is consistent with the honest majority assumption of WP1.

---

## Test Suite

All tests use Hardhat v3 with Node.js native test runner (`node:test`) and `viem`.

### Summary

| Test File | Tests | Coverage |
|---|---|---|
| `DIDRegistry.test.ts` | 18 | RF1, RF3, lazy authority check |
| `GovernanceContract.test.ts` | 15 | RF2, RF3, five-stage workflow, quorum |
| `DocumentRegistry.test.ts` | 22 | RF4, RF5, certification workflow, versioning, revocation, lazy checks |
| `DocumentAccessControl.test.ts` | 25 | RF5, RF7, permissions, delegation, cascading revocation, deactivation |
| `KeyShareRegistry.test.ts` | 12 | SSS archival, retrieval gating, revocation |
| **Total** | **92** | |

---

### DIDRegistry Tests

| Test | WP2 Process |
|---|---|
| Genesis authorities registered in constructor | RF1 §Authority Registration |
| Resolve DID from address | RF1 §DID Document |
| Return active public key | RF1 §Lightweight Auth Protocol |
| Authority registers user — domainAuthority set correctly | RF1 §User Registration |
| Reject user registration from non-authority | RF1 |
| Reject duplicate DID and address | RF1 |
| Domain authority deactivates its user | RF1 §User Deregistration |
| Reject deactivation by non-domain authority | RF1 |
| Reject deactivation of authority by non-governance | RF3 |
| Reject double deactivation | RF1 |
| Governance deactivates user bypassing domain authority | RF3 §Collective Enforcement |
| `isFullyActive` true for active user with active authority | Lazy check |
| `isFullyActive` false for deactivated user | Lazy check |
| `isFullyActive` false for user whose authority was deactivated | Lazy check §Authority Removal |
| `isFullyActive` true for authority (no domain chain) | Lazy check |

---

### GovernanceContract Tests

| Test | WP2 Process |
|---|---|
| Founding authorities registered | RF2 §Authority Registration |
| Reject proposal from non-authority | RF2 |
| Proposal transitions to Active after voting delay | RF2 Stage 2→3 |
| Reject voting before voting delay | RF2 Stage 3 |
| Reject double voting | RF2 Stage 3 |
| Reject voting after period ends | RF2 Stage 3 |
| Majority succeeded — 2/3 for votes | RF2 §Quorum Thresholds |
| Majority defeated — 1/3 for votes | RF2 §Quorum Thresholds |
| Supermajority succeeded — 3/3 for votes | RF2 §Quorum Thresholds |
| Supermajority defeated — 2/3 not enough | RF2 §Quorum Thresholds |
| Reject execution before timelock | RF2 Stage 5 |
| `eligibleVoters` snapshot at proposal time | RF2 |
| `admitAuthority` — DID registered + governance updated atomically | RF3 §Authority Admission |
| `removeAuthority` — DID deactivated + governance updated atomically | RF3 §Authority Exclusion |
| Users of removed authority become `isFullyActive=false` | RF3 + Lazy check |

---

### DocumentRegistry Tests

| Test | WP2 Process |
|---|---|
| User with `canCreate` requests certification | RF5 §canCreate |
| Reject certification request without `canCreate` | RF5 |
| Reject from unregistered caller | RF1 |
| `ownerDID` defaults to `creatorDID` for new document | RF4 §Certification Phase 1 |
| Allow specifying different `ownerDID` | RF4 §Certification Phase 1 |
| Reject duplicate hash | RF4 |
| Domain authority certifies pending document | RF4 §Certification Phase 3 |
| Reject certification by non-domain authority | RF4 |
| Reject certifying non-pending document | RF4 |
| Assign `canRead` and `canUpdate` at certification | RF5 §Phase 3.1 |
| Certifying authority stores CID | RF4 §Archival Phase 4 |
| Reject CID storage by non-certifying authority | RF4 |
| Version chain linked correctly | RF4 §Versioning |
| `ownerDID` defaults to previous version's owner on update | RF4 §Certification Phase 1 |
| Reject update to non-latest version | RF4 §Versioning |
| Reject update without `canUpdate` | RF5 |
| Certifying authority revokes document | RF4 §Revocation |
| Reject revocation by non-certifying authority | RF4 |
| Reject double revocation | RF4 |
| `getStatus` returns Revoked if certifying authority deactivated | Lazy check §Authority Removal |
| Reject request from user whose authority is deactivated | Lazy check |
| Reject update from user with `canUpdate` but deactivated authority | Lazy check |

---

### DocumentAccessControl Tests

| Test | WP2 Process |
|---|---|
| Domain authority grants `canCreate` | RF5 §canCreate Issuance |
| Reject `canCreate` from non-domain authority | RF5 |
| `hasCreatePermission` false if authority deactivated | Lazy check |
| Assign `canRead` + `canUpdate` to creator at certification | RF5 §Phase 3.1 |
| No permissions assigned to unrelated user | RF5 |
| `hasPermission` false if document revoked | RF5 |
| `hasPermission` false if holder authority deactivated | Lazy check |
| Creator approves read | RF5 §Retrieval Phase 1 |
| Reject read for user without permission | RF5 |
| Reject read if user authority deactivated | Lazy check |
| Reject read on revoked document | RF5 |
| Delegate `canRead` to another user | RF7 §Delegation Workflow |
| Reject delegation of `canCreate` | RF7 |
| Reject delegation when caller has no permission | RF7 |
| Reject delegation if delegator authority deactivated | Lazy check |
| Reject read for delegatee with deactivated authority | Lazy check |
| Cascade revoke delegations when permission revoked | RF7 §Revocation |
| Delegatee revokes sub-delegation | RF7 §User-initiated Revocation |
| All permissions invalidated when user deactivated | WP2 §Entity Deregistration |
| Delegations cascade-invalidated when user deactivated | WP2 §Entity Deregistration |
| Reject read for deactivated delegatee | WP2 §Entity Deregistration |
| Cascade-revoke when intermediate delegator deactivated | WP2 §Entity Deregistration |
| Reject delegation to deactivated user | RF7 |
| Reject delegation from deactivated user | RF7 |
| Entire delegation chain invalidated when root user deactivated | WP2 §Entity Deregistration |

---

### KeyShareRegistry Tests

| Test | WP2 Process |
|---|---|
| Store shares for certified document | §Archival Phase 4 |
| Correct encrypted share per authority | §Archival Phase 4 |
| Reject `storeShares` from non-authority | §Archival Phase 4 |
| Reject duplicate `storeShares` for same document | §Archival Phase 4 |
| Reject invalid threshold — zero | SSS constraint |
| Reject threshold greater than total shares | SSS constraint |
| Reject mismatched array lengths | §Archival Phase 4 |
| Reject empty encrypted share | §Archival Phase 4 |
| Return error for unknown document | §Retrieval Phase 2 |
| Return error for unknown authority | §Retrieval Phase 2 |
| Shares remain on-chain after revocation — retrieval blocked via `checkAndApproveRead` | §Revocation |
| Threshold matches `ceil(2N/3)` for N=3 | SSS §Honest Majority |

---

## Running Tests

```bash
# Compile contracts
npx hardhat compile

# Run all tests
npx hardhat test

# Run individual test file
npx hardhat test test/DIDRegistry.test.ts
npx hardhat test test/GovernanceContract.test.ts
npx hardhat test test/DocumentRegistry.test.ts
npx hardhat test test/DocumentAccessControl.test.ts
npx hardhat test test/KeyShareRegistry.test.ts

# Deploy to local Hardhat network
npx hardhat run scripts/deploy.ts
```

---

## Implementation Notes and Known Limitations

| Topic | Note |
|---|---|
| **Key rotation** | Not implemented. Marked as "to do" in WP2. The DIDDocument struct retains `recoveryPublicKey` for future implementation. |
| **Genesis authority logging** | Genesis authorities are not logged in AuditLog — DIDRegistry is not an authorised writer during constructor execution. The genesis configuration is traceable via the deployment transaction. |
| **Lazy vs explicit invalidation on authority removal** | When an authority is removed, its users' permissions are not explicitly invalidated. Instead, `isFullyActive()` checks the authority chain at every access. This is the behavioral policy described in WP2 §Policy Model. |
| **SSS share redistribution on membership change** | When an authority is admitted or removed, existing document key shares are not redistributed. WP2 acknowledges this as acceptable given that authority membership changes are expected to be rare events. |
| **Loop-based permission lookup** | `hasPermission()` and related functions use linear scans over per-user permission arrays. For the prototype with limited users and documents this is acceptable. A production system would use indexed mappings for O(1) lookup. |
| **Delegation depth** | `_cascadeRevokeDelegations()` is recursive. Stack overflow is theoretically possible for extremely deep delegation chains, but unrealistic in practice. |
| **`assignCertificationPermissions()` caller restriction** | Only `DocumentRegistry` can call this function. Any direct call is rejected, preventing unauthorized permission assignment. |
| **Circular import resolution** | `DIDRegistry` calls `DocumentAccessControl.invalidateUserPermissions()` via `address.call()` with `abi.encodeWithSignature` to avoid a circular Solidity import. |
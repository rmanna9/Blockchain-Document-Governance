## [18:30:06] Register User
- did: did:consortium:user-3
- account: user-3
- authority: authority-a
- result: ✓ SUCCESS
- tx: 0x10dd5fdc54f6e082ae35b369a3e803df684f88a04e51538874e2289a93d1f916

## [18:30:20] Grant canCreate
- holderDID: did:consortium:user-3
- authority: authority-a
- result: ✓ SUCCESS
- tx: 0xcff4e4b381deec2ca94cb38ff4934878358b6045edd371ab7f27f340b6d33ee2

## [18:30:41] Request Certification
- did: did:consortium:user-3
- docHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- result: ✓ SUCCESS
- tx: 0xae409ba5972cde45f71093c5ddd62bf9d5d83bad022e2f0e178c7294d800b06c

## [ORACLE] Archival Workflow — DocumentCertified
- documentHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- block: 33
- CID: bafkreiddf7fk5xmsi62gmlbyx4kup2cfvgkekuzwsbbup3iirmirvwibda
- pinned: true
- shares: 3  threshold: 2
- txSharesStored: 0x0b965a741bdff07071b948a3e4c77be80c841fec7b2a839ccd67c3bc1d083c7f
- txCIDStored: 0x9bd71c7e3f57c554afb05f0c0a4b46f849aa84cc10d580ee779340b34a118357

## [18:31:01] Certify Document
- docHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- authority: authority-a
- result: ✓ SUCCESS
- tx: 0x1b6ef6378a86a6b785cc21ea6a8d04dce1fd8575be2803f7bf86442c003f07c0

## [ORACLE INBOUND] External Verification
- did_A: did:consortium:authority-a
- did_U: did:consortium:user-3
- documentHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- canPresentExternally: true
- H(metadata): aa1228a1afbcade718a6297920c92f2731b3ec6e60b30c24f34a7048c6db1dd7

## [18:31:27] External Verify
- docHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- didA: did:consortium:authority-a
- didU: did:consortium:user-3
- result: ✓ VALID
- sigValid: true
- phase7: match=true

## [GOVERNANCE] Forced Read
- documentHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- sharesUsed: 2  threshold: 2
- k_doc reconstructed: true
- CID: bafkreiddf7fk5xmsi62gmlbyx4kup2cfvgkekuzwsbbup3iirmirvwibda
- content: This is a test document for certification.

## [18:34:36] Forced Read (Governance)
- docHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- result: ✓ SUCCESS
- cid: bafkreiddf7fk5xmsi62gmlbyx4kup2cfvgkekuzwsbbup3iirmirvwibda
- sharesUsed: 2

## [ORACLE] Revocation Workflow — DocumentRevoked
- documentHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- reason: policy violation
- block: 36
- CID unpinned: bafkreiddf7fk5xmsi62gmlbyx4kup2cfvgkekuzwsbbup3iirmirvwibda

## [18:40:08] Revoke Document
- docHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- reason: policy violation
- authority: authority-a
- result: ✓ SUCCESS
- tx: 0xbd968ea7e4c1e76a65d56ee8781d16844c23db9a647da5804cab287c13a7b371

## [18:42:33] Retrieve Document
- docHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- account: user-3
- result: ✗ BLOCKED: VM Exception while processing transaction: revert DAC: no read permission

## [18:42:56] Get Document Status
- docHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- result: ✓ Revoked

## [18:43:42] Check Permission
- holderDID: did:consortium:user-3
- docHash: 0x13b8445523831d02847d5a0000287e2a42f1d1904b7063ed4bd42393195fe2ea
- actionType: 1
- result: ✓ false

## [18:48:04] Query Audit Log
- from: 1
- max: 20
- result: ✓ SUCCESS

## [18:49:05] Query Audit Log
- from: 1
- max: 10
- result: ✓ SUCCESS

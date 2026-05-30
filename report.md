## [12:29:47] Resolve DID
- did: did:consortium:user-1
- result: ✓ SUCCESS

## [12:30:08] Check canCreate Permission
- holderDID: did:consortium:user-1
- actionType: 0
- result: ✓ true

## [12:30:44] Request Certification
- did: did:consortium:user-1
- docHash: 0x8fb6f46cda60b29b34a8549d1ae716b1313e4993b0ec2fb7b41e2cf7ef224ba9
- result: ✓ SUCCESS
- tx: 0x1ed7a386a344653a75161c85fad50fbcaea9cc6975aa69c935e04fb7642d535b

## [12:33:10] Get Document Status
- docHash: 0x8fb6f46cda60b29b34a8549d1ae716b1313e4993b0ec2fb7b41e2cf7ef224ba9
- result: ✓ Pending

## [12:33:46] Certify Document
- docHash: 0x8fb6f46cda60b29b34a8549d1ae716b1313e4993b0ec2fb7b41e2cf7ef224ba9
- result: ✗ FAILED: VM Exception while processing transaction: revert DocumentRegistry: caller is not creator's domain authority

## [ORACLE] Archival Workflow — DocumentCertified
- documentHash: 0x8fb6f46cda60b29b34a8549d1ae716b1313e4993b0ec2fb7b41e2cf7ef224ba9
- block: 24
- CID: bafkreihyuovgku7k6x4lrqhch2z6fsvcgqgxdn4htgrfvjqemvnvtjykma
- pinned: true
- shares: 3  threshold: 2
- txSharesStored: 0x890258dffde46b15d79e04f08969ac6376ecd12cd281947336545deebefb3bbc
- txCIDStored: 0x0b6bfaee91fb1c0f4ce3ec7d0ac444d3039edcfd4aed4c40e47aaf262fe0b45e

## [12:34:07] Certify Document
- docHash: 0x8fb6f46cda60b29b34a8549d1ae716b1313e4993b0ec2fb7b41e2cf7ef224ba9
- authority: authority-a
- result: ✓ SUCCESS
- tx: 0x5c85a0b8a8691885a9c8591ab9569f04e95ace2b67cdcdfa0796aada192e077d

## [12:34:51] Get Document Status
- docHash: 0x8fb6f46cda60b29b34a8549d1ae716b1313e4993b0ec2fb7b41e2cf7ef224ba9
- result: ✓ Certified

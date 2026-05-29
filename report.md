## [12:30:25] Register User
- did: did:consortium:user-1
- account: user-1
- authority: authority-a
- result: ✓ SUCCESS
- tx: 0x1a768b7fcb662f9052f05a91588cd48561e5b53b205b343c77af5c2483fb5d7a

## [12:30:49] Grant canCreate
- holderDID: did:consortium:user-1
- authority: authority-a
- result: ✓ SUCCESS
- tx: 0x94889caa449ce27d8b6326ade4a86452739c4ac69124bcd921dd5e1241cb691a

## [12:31:17] Request Certification
- did: did:consortium:user-1
- docHash: 0x44d13e3f5168655e1d0b42ef3286fe1f692a48c9e5473594dad1164a06e5065e
- result: ✓ SUCCESS
- tx: 0x7ca216b748688b6df122544e09822a531105e1fe3cdf7aa812f683b8c818622b

## [ORACLE] Archival Workflow — DocumentCertified
- documentHash: 0x44d13e3f5168655e1d0b42ef3286fe1f692a48c9e5473594dad1164a06e5065e
- block: 21
- CID: bafkreif3yo5iwszpmrtgjs4otev2bswiavnn56z345wojmcywvl63mea5q
- pinned: true
- shares: 3  threshold: 2
- txSharesStored: 0xb8b647ba8bf9bb49cf36af4eefa4ad6f16ec666c9c6f8891aad6ac319b65ece9
- txCIDStored: 0x86642c9ca9b508e2c209eb37f2aa50312f65b2ca242c647cb3b8610ecf5720dd

## [12:31:53] Certify Document
- docHash: 0x44d13e3f5168655e1d0b42ef3286fe1f692a48c9e5473594dad1164a06e5065e
- authority: authority-a
- result: ✓ SUCCESS
- tx: 0x196455040e7ae19f29b66ecf4b8e2b623e4beac75019c80ed8483f3145c94686

## [12:32:59] Retrieve Document
- docHash: 0x44d13e3f5168655e1d0b42ef3286fe1f692a48c9e5473594dad1164a06e5065e
- account: user-1
- callerDID: did:consortium:user-1
- result: ✓ SUCCESS
- tx: 0x3882553d0238c7f8eb14bd69f9c503a43f28424a24c2791b4235fb47d9412b4b
- content: CiaoQuestaEunaProva!!!

## [GOVERNANCE] Forced Read
- documentHash: 0x44d13e3f5168655e1d0b42ef3286fe1f692a48c9e5473594dad1164a06e5065e
- sharesUsed: 2  threshold: 2
- k_doc reconstructed: true
- CID: bafkreif3yo5iwszpmrtgjs4otev2bswiavnn56z345wojmcywvl63mea5q
- content: CiaoQuestaEunaProva!!!

## [12:34:39] Forced Read (Governance)
- docHash: 0x44d13e3f5168655e1d0b42ef3286fe1f692a48c9e5473594dad1164a06e5065e
- result: ✓ SUCCESS
- cid: bafkreif3yo5iwszpmrtgjs4otev2bswiavnn56z345wojmcywvl63mea5q
- sharesUsed: 2

## [ORACLE INBOUND] External Verification
- did_A: did:consortium:authority-a
- did_U: did:consortium:user-1
- documentHash: 0x44d13e3f5168655e1d0b42ef3286fe1f692a48c9e5473594dad1164a06e5065e
- canPresentExternally: true
- H(metadata): 51c4a67219649472a8ba074f91275ffe514e1613cc0b19ec30a47e0431980560

## [12:35:51] External Verify
- docHash: 0x44d13e3f5168655e1d0b42ef3286fe1f692a48c9e5473594dad1164a06e5065e
- didA: did:consortium:authority-a
- didU: did:consortium:user-1
- result: ✓ VALID
- sigValid: true
- phase7: match=true

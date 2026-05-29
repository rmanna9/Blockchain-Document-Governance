# CLI Test Plan — Multi-Authority Decentralized Document Lifecycle System

Questo piano di test esegue **tutti** i processi del WP2 attraverso la CLI,
includendo sia i percorsi nominali (happy path) sia gli scenari di errore
(permessi negati, identità disattivate, documenti revocati, soglie non
raggiunte). Ogni blocco indica l'opzione di menu, gli input, e il
**risultato atteso**.

Prerequisiti:
- Ganache Desktop attivo (mnemonic `test test test test test test test test test test test junk`, chainId 31337)
- Genesis deployato: `npx hardhat run scripts/deploy.ts --network ganache`
- CLI avviata: `npx ts-node scripts/cli.ts`

Legenda: ✓ = deve avere successo · ✗ = deve fallire (errore atteso)

---

## FASE 0 — Stato iniziale (genesis)

| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 0.1 | 21 Show system state | — | ✓ 3 authority attive (a,b,c), nessun utente, nessun documento |
| 0.2 | 5 List active DIDs | — | ✓ did:consortium:authority-a/b/c, isActive=true |
| 0.3 | 4 Resolve DID | `did:consortium:authority-a` | ✓ DIDDocument, entityType=Authority, domainAuthority=null |

---

## FASE 1 — Identity Management

### 1A. Registrazione utenti (happy path)
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 1.1 | 1 Register User | DID `did:consortium:user-1`, domain `authority-a` | ✓ keypair RSA generato, registrato on-chain, domainAuthority=authority-a |
| 1.2 | 1 Register User | DID `did:consortium:user-2`, domain `authority-a` | ✓ |
| 1.3 | 1 Register User | DID `did:consortium:user-3`, domain `authority-b` | ✓ (dominio diverso) |
| 1.4 | 4 Resolve DID | `did:consortium:user-1` | ✓ domainAuthority = indirizzo di authority-a |

### 1B. Scenari di errore identità
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 1.5 | 1 Register User | DID `did:consortium:user-1` (duplicato) | ✗ "DID already registered" |
| 1.6 | 4 Resolve DID | `did:consortium:nonexistent` | ✗ "DID not found" |

---

## FASE 2 — Permessi canCreate

### 2A. Concessione (happy path)
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 2.1 | 11 Grant canCreate | holder `user-1`, authority `authority-a` | ✓ permesso emesso, issuerAddress=authority-a |
| 2.2 | 14 Check Permission | `user-1`, canCreate | ✓ permesso attivo |

### 2B. Scenari di errore permessi
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 2.3 | 11 Grant canCreate | holder `user-3` (dominio authority-b), authority `authority-a` | ✗ "not domain authority" (authority-a non è il dominio di user-3) |
| 2.4 | 14 Check Permission | `user-2`, canCreate | ✗/falso (user-2 non ha mai ricevuto canCreate) |

---

## FASE 3 — Certificazione + Archival (Oracle + IPFS)

### 3A. Certificazione documento nuovo (happy path)
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 3.1 | 6 Request Certification | user `user-1`, contenuto `Contratto v1`, ownerDID vuoto (=creator) | ✓ status PENDING, evento on-chain |
| 3.2 | 10 Get Document Status | hash dal 3.1 | ✓ PENDING |
| 3.3 | 7 Certify Document | authority `authority-a`, hash dal 3.1 | ✓ **ascolta DocumentCertified** → Archival: CID `bafk...`, pin, SSS split (3 shares, t=2), E_A, storeShares, storeCID |
| 3.4 | 10 Get Document Status | hash | ✓ CERTIFIED, CID valorizzato |

### 3B. Scenari di errore certificazione
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 3.5 | 6 Request Certification | user `user-2` (senza canCreate), contenuto `X` | ✗ "caller has no canCreate permission" |
| 3.6 | 7 Certify Document | authority `authority-b`, hash di un PENDING creato da user-1 (dominio authority-a) | ✗ "not domainAuthority of creator" |
| 3.7 | 6 Request Certification | user `user-1`, stesso contenuto `Contratto v1` (hash già certificato) | ✗ documento già esistente / hash duplicato |

---

## FASE 4 — Retrieval ordinario (IPFS, E_A + sk_A, NO SSS)

### 4A. Recupero (happy path)
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 4.1 | 8 Retrieve Document | user `user-1`, hash dal 3.1 | ✓ Phase1 checkAndApproveRead→ReadApproved, Phase3 getFile(Helia), Phase4 decryptDocumentKey(E_A,sk_A), Phase5 plaintext = `Contratto v1` |

### 4B. Scenari di errore retrieval
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 4.2 | 8 Retrieve Document | user `user-2` (no canRead su quel doc), hash dal 3.1 | ✗ checkAndApproveRead fallisce, no ReadApproved, retrieval bloccato |

---

## FASE 5 — Delega permessi

### 5A. Delega (happy path)
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 5.1 | 12 Delegate Permission | delegator `user-1`, delegatee `user-2`, hash dal 3.1, actionType canRead, canDelegate=false | ✓ delegation record, parentId = permesso di user-1 |
| 5.2 | 8 Retrieve Document | user `user-2`, hash dal 3.1 | ✓ ora user-2 può leggere (ha canRead delegato) |
| 5.3 | 14 Check Permission | `user-2`, canRead su hash | ✓ attivo via delega |

### 5B. Scenari di errore delega
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 5.4 | 12 Delegate Permission | delegator `user-2` (delega ricevuta con canDelegate=false), delegatee `user-3`, canRead | ✗ "canDelegate=false" non può sub-delegare |
| 5.5 | 12 Delegate Permission | delegator `user-3` (nessun permesso sul doc), delegatee `user-1`, canRead | ✗ "no active permission to delegate" |

### 5C. Revoca delega (cascading)
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 5.6 | 13 Revoke Permission | record = delegationId del 5.1, account `user-1` | ✓ delega revocata (cascading sul sotto-albero) |
| 5.7 | 8 Retrieve Document | user `user-2`, hash dal 3.1 | ✗ delega revocata, retrieval bloccato di nuovo |

---

## FASE 6 — Versioning (update documento)

| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 6.1 | 6 Request Certification | user `user-1`, contenuto `Contratto v2`, h_ref = hash del 3.1 | ✓ PENDING, riferimento alla versione precedente |
| 6.2 | 7 Certify Document | authority `authority-a`, hash v2 | ✓ CERTIFIED, version=2, previousVersion=hash v1; archival con NUOVO k_doc/CID |
| 6.3 | 10 Get Document Status | hash v1 | ✓ followingVersion = hash v2 |
| 6.4 | 6 Request Certification | user `user-1`, contenuto `Contratto v3`, h_ref = hash v1 (versione superata) | ✗ "h_ref is not the latest version" |

---

## FASE 7 — Governance (admission nuova authority)

### 7A. Proposta + voto + esecuzione (happy path)
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 7.1 | 2 Register Authority | candidato `authority-d` (account 4), via governance | ✓ proposta creata (actionType admitAuthority) |
| 7.2 | 16 Vote on Proposal | proposalId, authority-a, FOR | ✓ voto registrato |
| 7.3 | 16 Vote on Proposal | proposalId, authority-b, FOR | ✓ voto registrato (2/3 raggiunto, soglia >2/3) |
| 7.4 | 16 Vote on Proposal | proposalId, authority-c, FOR | ✓ supermajority |
| 7.5 | 18 Get Proposal Status | proposalId | ✓ stato Succeeded/Queued |
| 7.6 | 17 Execute Proposal | proposalId | ✓ authority-d aggiunta, DID registrato, evento AuthorityAdmitted |
| 7.7 | 5 List active DIDs | — | ✓ ora 4 authority (a,b,c,d) |

### 7B. Scenari di errore governance
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 7.8 | 16 Vote on Proposal | proposalId già eseguito | ✗ "proposal not active" |
| 7.9 | 2 Register Authority + voti insufficienti | solo 1 voto FOR su soglia >2/3 | ✗ Execute fallisce "quorum not reached" |

---

## FASE 8 — Forced Read via Governance (SSS combine)

| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 8.1 | 20 Forced Read | hash dal 3.1, governance >2/3 | ✓ proposta+voti, raccolta share E_i da authority a/b (≥t=2), decryptShare(sk_i), **SSS combine** → k_doc, getFile, decrypt = `Contratto v1` |
| 8.2 | 20 Forced Read | hash, solo 1 authority partecipa (sotto soglia t) | ✗ "insufficient shares for reconstruction" |

> Nota: dopo la FASE 7 ci sono 4 authority → t = ceil(2·4/3) = 3. Gli shares
> del documento certificato in FASE 3 erano stati splittati per N=3 (t=2).
> Questo è lo scenario "threshold mismatch" documentato nel WP2: verificare
> se il forced read sul vecchio documento usa il vecchio threshold (2) o
> fallisce. **Annotare il comportamento osservato per la relazione.**

---

## FASE 9 — External Verification (Oracle inbound)

### 9A. Verifica valida (happy path)
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 9.1 | 19 External Verify | hash dal 3.1, did_A `authority-a`, did_U `user-1` (owner) | ✓ Oracle: canPresentExternally→true, c_meta=Enc(pk_U,meta); Phase6 verifyAuthoritySignature(σ_A)→valid; Phase7 user-1 decifra c_meta con sk_U → match |

### 9B. Scenari di errore verifica
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 9.2 | 19 External Verify | hash, did_A `authority-a`, did_U `user-2` (non owner, no canPresent) | ✗ canPresentExternally→false, verifica fallisce |
| 9.3 | 19 External Verify | hash, did_U `user-1` ma decifratura con chiave sbagliata (simula presenter fraudolento) | ✗ Phase7 decrypt fallisce → impossibile provare possesso sk_U |

---

## FASE 10 — Revocation (Oracle + IPFS unpin)

### 10A. Revoca (happy path)
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 10.1 | 9 Revoke Document | authority `authority-a`, hash dal 3.1, reason `superseded` | ✓ status REVOKED, **ascolta DocumentRevoked** → unpin CID da Helia |
| 10.2 | 10 Get Document Status | hash | ✓ REVOKED |
| 10.3 | 8 Retrieve Document | user `user-1`, hash revocato | ✗ checkAndApproveRead fallisce (REVOKED), retrieval bloccato |

### 10B. Scenari di errore revoca
| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 10.4 | 9 Revoke Document | authority `authority-b` (non certificante), hash dal 3.1 | ✗ "msg.sender not certifiedBy" |

---

## FASE 11 — Deregistrazione (cascading)

| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 11.1 | 3 Deactivate DID | `user-2`, via authority-a (domain) | ✓ isActive=false, permessi/deleghe invalidati a cascata |
| 11.2 | 4 Resolve DID | `user-2` | ✓ isActive=false |
| 11.3 | 8 Retrieve Document | user `user-2` (disattivato), qualsiasi hash | ✗ lightweight auth fallisce (isActive=false) |
| 11.4 | 3 Deactivate DID | `user-2` di nuovo | ✗ "cannot reactivate / already inactive" |

---

## FASE 12 — Audit

| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 12.1 | 20→Audit / opzione Audit Log | from 1, max 50 | ✓ elenco completo eventi: DIDRegistered, PermissionGranted, CertificationRequested, DocumentCertified, SharesStored, CIDStored, ReadApproved, DelegationIssued, DocumentRevoked, AuthorityAdmitted, ... |
| 12.2 | Audit filtrato per actor | actor = authority-a | ✓ solo eventi attribuiti ad authority-a |

---

## FASE 13 — Export

| # | Opzione | Input | Atteso |
|---|---------|-------|--------|
| 13.1 | 22 Export report.md | — | ✓ file report.md con transcript completo di tutte le operazioni, timestamp, tx hash, CID, eventi |

---

## Copertura processi WP2

| Processo WP2 | Fasi del test |
|---|---|
| Identity Management (registrazione) | 1, 7 |
| Key Rotation | (non simulato in CLI — proof of concept nel WP2) |
| Lightweight Auth | implicito in 4, 8, 11 |
| canCreate Issuance | 2 |
| Certification | 3 |
| Archival (Oracle outbound + IPFS) | 3 |
| Retrieval ordinario (E_A + sk_A) | 4 |
| Delegation + cascading revoke | 5 |
| Versioning | 6 |
| Governance (5-stage) | 7 |
| Forced Read (SSS combine) | 8 |
| External Verification (Oracle inbound) | 9 |
| Revocation (Oracle + IPFS unpin) | 10 |
| Entity Deregistration (cascading) | 11 |
| Auditing | 12 |
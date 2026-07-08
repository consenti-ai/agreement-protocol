# Consenti Agreement Privacy Architecture v0.1

**Status:** Draft
**Companion specs:** [Agreement Schema v0.1](./agreement-schema-v0.1.json) | [Discovery Spec v0.1](./well-known-agreements-spec.md)

---

## 1. Design Principle

**The commitment is public. The content is private.**

A verifier can confirm that a valid agreement exists, that specific parties are bound, and when it was anchored — without ever seeing the terms. Content disclosure is always at the discretion of the parties, never the protocol.

This is the cryptographic equivalent of a sealed envelope filed with a notary. The notary can confirm the envelope exists, who deposited it, and when. Opening the envelope requires the depositors' consent.

---

## 2. Three-Layer Privacy Model

### Layer 1 — Public Commitment (on-chain / anchor)

What goes on the anchor (Pangea, EVM, TSA, etc.):

```
{
  "agreement_hash": "sha256:3f2a...",    // hash of canonicalized acceptance record
  "merkle_root": "sha256:b7e1...",        // root of clause Merkle tree (if selective disclosure enabled)
  "acceptor_hash": "sha256:9c4d...",      // hash of acceptor identifier (not the identifier itself)
  "accepted_at": "2026-04-06T12:00:00Z",
  "anchor_timestamp": "2026-04-06T12:00:05Z"
}
```

**What this proves:** An acceptance record with this hash exists. An acceptor committed to specific terms at a specific time. It was anchored at a specific time.

**What this reveals:** Nothing about the acceptor's identity, the terms content, or the subject matter.

### Layer 2 — Private Acceptance Record (held by publisher and acceptor)

The full acceptance record JSON is stored by the publisher (in their dashboard) and the acceptor. The protocol does not require — and Consenti infrastructure does not retain — the record content in zero-custody mode.

The publisher holds:
- The full acceptance record JSON (displayed in their dashboard log)
- The terms document the acceptor agreed to
- Merkle proof set (for selective disclosure, if enabled)

The acceptor holds:
- Their copy of the acceptance record
- Their signing key (agents)

Storage is each party's responsibility. Consenti MAY offer an encrypted vault service (see §5), but the protocol works without it.

### Layer 3 — Selective Disclosure (publisher-controlled)

The publisher can reveal specific elements of an acceptance record to third parties (auditors, regulators, courts) without exposing the full record. This is implemented via a Merkle tree.

---

## 3. Clause-Level Merkle Tree

### 3.1 Construction

Each clause and each top-level field is hashed independently. These leaf hashes are assembled into a Merkle tree whose root is committed on-chain.

```
                    Merkle Root (anchored)
                   /                      \
              H(left)                    H(right)
             /      \                  /         \
      H(parties)  H(clause_1)   H(clause_2)  H(clause_3)
```

Leaf construction:

```
leaf_hash = SHA-256(
  canonical(field_path) || ":" || canonical(field_value)
)
```

Where `canonical()` applies RFC 8785 JCS to the value.

### 3.2 Selective Disclosure

To prove a specific clause to a third party (auditor, regulator, court), a party provides:

1. **The clause content** (plaintext)
2. **The Merkle proof** (sibling hashes from leaf to root)
3. **The Merkle root** (which the third party can independently verify against the public anchor)

The third party can verify:
- This clause is genuinely part of the anchored agreement (Merkle proof valid)
- The agreement was committed at a specific time (anchor timestamp)
- Without learning anything about other clauses

### 3.3 Schema Addition

```json
{
  "privacy": {
    "model": "selective_disclosure",
    "merkle_tree": {
      "algorithm": "SHA-256",
      "leaf_construction": "jcs_path_value",
      "root": "sha256:b7e1..."
    },
    "content_encryption": {
      "method": "X25519-XSalsa20-Poly1305",
      "party_public_keys": [
        {
          "party_id": "party_a",
          "encryption_key_ref": "did:web:example.com#enc-key-1"
        }
      ]
    }
  }
}
```

---

## 4. Verification Without Disclosure

The protocol supports three levels of verification, each requiring progressively more disclosure:

### Level 0 — Existence Proof (zero disclosure)

**Question:** "Does an acceptance record exist for this acceptor?"

**Required inputs:**
- Acceptor identifier
- Agreement hash or anchor reference

**Process:**
1. Look up anchor by agreement hash
2. Verify acceptor_hash matches `SHA-256(acceptor_identifier)`
3. Confirm anchor timestamp

**Disclosed:** Nothing about terms, acceptor identity, or obligations.

### Level 1 — Acceptance Proof (identity + terms confirmation)

**Question:** "Did this specific acceptor agree to this specific version of terms?"

**Required inputs:**
- Acceptor identifier
- Detached signature (for agent acceptors) or acceptance record
- Agreement hash + terms_hash

**Process:**
1. Verify signature over agreement hash using acceptor's public key (agents), or verify acceptance record hash matches anchor (humans)
2. Confirm terms_hash in the acceptance record matches the known terms version
3. Confirm agreement hash matches anchor

**Disclosed:** Who accepted what terms, when. Nothing about other acceptors or the terms content itself.

### Level 2 — Full Verification (for dispute resolution)

**Question:** "Show me the complete acceptance record with full audit trail."

**Required inputs:**
- Full acceptance record JSON
- Signature(s)
- Anchor reference

**Process:**
1. Canonicalize and hash acceptance record
2. Verify hash matches anchor
3. Verify signature(s)
4. Verify terms_hash matches known terms version

**Disclosed:** Everything. Used for dispute resolution ("I never agreed to those terms"), regulatory examination, or audit. This is what the publisher produces from their dashboard when a dispute arises.

---

## 5. Encrypted Vault (Optional Consenti Service)

Publishers MAY choose to store encrypted acceptance records with Consenti for convenience (backup, cross-device access, dashboard hosting). This is a premium service, not a protocol requirement.

### 5.1 Encryption Model

```
Acceptance Record JSON
      |
      v
Encrypt with symmetric key K
      |
      v
K encrypted for publisher's public key
      |
      v
Ciphertext + encrypted key stored in vault
```

- **Consenti never holds K in plaintext.** Cannot read acceptance records.
- Publisher decrypts K with their own private key.
- Publisher can grant time-limited access by re-encrypting K for a third party's public key (e.g., for an auditor or legal counsel).

### 5.2 Third-Party Access Grants

```json
{
  "access_grant": {
    "agreement_id": "agr_abc123",
    "granted_by": "publisher",
    "granted_to": {
      "identifier": { "type": "did", "value": "did:web:auditor.example.com" },
      "display_name": "External Auditor LLC"
    },
    "scope": "full",
    "valid_from": "2026-04-06T00:00:00Z",
    "valid_until": "2026-05-06T00:00:00Z",
    "encrypted_key": "base64url...",
    "granted_at": "2026-04-06T12:00:00Z",
    "signature": "base64url..."
  }
}
```

- Access grants are themselves signed and anchored.
- Revocation: publisher publishes a revocation to the anchor chain. Vault enforces.
- Time-limited by default. Expired grants cannot be used to decrypt.

---

## 6. Privacy Properties Summary

| Property | Guarantee |
|---|---|
| **Content confidentiality** | Acceptance record details visible only to publisher and acceptor (and explicit grantees). |
| **Acceptor pseudonymity** | On-chain commitment uses acceptor_hash, not identifiers. Real identity linkable only by publisher. |
| **Selective disclosure** | Individual fields provable without revealing others via Merkle proofs. |
| **Existence without content** | Third parties can verify an acceptance exists and is anchored without seeing any details. |
| **Zero-custody** | Consenti infrastructure never holds plaintext acceptance records or signing keys. |
| **Forward secrecy of access grants** | Time-limited, revocable. Expiry enforced by vault + anchor. |
| **Protocol independence** | All privacy guarantees hold without Consenti infrastructure. Vault is convenience, not dependency. |

---

## 7. Relationship to Discovery Spec

The `.well-known/agreements.json` directory is intentionally **public-facing**. It describes *what terms a service requires acceptance of* — not the acceptance records themselves.

- **Directory (public):** "We require agents and users to accept our TOS before transacting."
- **Terms document (public or authenticated):** The terms an acceptor would need to review and accept.
- **Acceptance record (private):** The anchored, verifiable proof that a specific acceptor agreed to specific terms at a specific time. Held in the publisher's dashboard and the acceptor's records.

Post-acceptance, the record lives in the publisher's dashboard. Only the commitment hash persists on the anchor chain.

---

## 8. Threat Model

| Threat | Mitigation |
|---|---|
| Chain observer learns acceptance details | Only hashes anchored. Content never on-chain. |
| Chain observer identifies acceptor | Acceptor commitment uses `SHA-256(acceptor_identifier)`, not plaintext. |
| Consenti is compromised | Vault stores only ciphertext. Consenti never holds decryption keys. Protocol works without Consenti. |
| Third-party access grant leaked | Time-limited, revocable. Vault enforces expiry. |
| Acceptor disputes acceptance | Publisher produces anchored acceptance record (Level 2 verification). Independent anchor proves acceptance — not just the publisher's database. |
| Court orders full disclosure | Level 2 verification supports this. Publisher (not Consenti) produces the record. Standard legal process applies. |
| Terms substitution attack | Acceptance records bind to `terms_hash`. Changing the terms after acceptance produces a hash mismatch. |

---

## 9. Open Questions (v0.1 → v0.2)

- **Key recovery.** If a publisher loses their private key, encrypted vault content is irrecoverable by design. Social recovery (Shamir's Secret Sharing) is a possible future extension.
- **Quantum resistance.** Current hash and signature algorithms are not post-quantum. Migration path to CRYSTALS-Dilithium (signatures) and CRYSTALS-Kyber (key encapsulation) should be planned for v0.2+.
- **Batch anchoring.** For high-volume publishers (thousands of acceptances per day), batching acceptance hashes into a single Merkle tree anchored once per interval reduces chain costs.

---

**Maintainer:** Consenti (FHBK Technologies, Inc.)
**License:** MIT
**Contact:** eric@blocksee.co

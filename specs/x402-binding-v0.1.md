# Consenti x402 Binding v0.1

**Status:** Superseded by [Consenti x402 Binding v0.2](./x402-binding-v0.2.md). Retained for reference. Draft proposal. **Not implemented.** Every MUST in this document is a proposed rule, not a description of running code.
**Binding ID:** `consenti/x402-binding/v0.1`
**Requires:** [Consenti Authority to Accept Terms v0.3](./authority-to-accept-terms-v0.3.md)
**Carries:** x402 v2 (Linux Foundation). Field and header names follow x402 v2.
**Origin:** Split from §17 of the Consenti Delegation & Principal Authorization Extension v0.2.
**Maintainer:** Consenti (FHBK Technologies, Inc.)
**License:** MIT

---

## 1. Purpose

x402 settles a payment in one HTTP round trip: the seller answers `402` with `PAYMENT-REQUIRED`, and the buyer retries with `PAYMENT-SIGNATURE`. It establishes that a payment was made and settled. It does not establish what the paying agent agreed to, for whom it acted, or whether it was allowed to agree.

This binding carries a Consenti agreement and its authority evidence inside that exchange, and ties the payment to the agreement so a verifier can later show that *this payment was made under these terms, by an agent authorized to accept them*.

It defines four things:

1. Where the terms, acceptance and authority references travel in x402 messages (§3).
2. How the paying account is tied to the authority grant (§4).
3. How the payment nonce commits to the agreement, which also yields a trusted commitment time (§5).
4. A seller rule: **do not settle until terms and authority have verified** (§2).

Outside x402, over plain HTTP or MCP, the core flow (409, 403, then payment) applies unchanged.

---

## 2. Ordering

The core document resolves agreement, authority and payment as three HTTP responses. Inside x402 that costs two extra round trips and two status codes x402 does not use. This binding replaces them with checks inside the single 402 exchange:

1. Seller's `402` states the required terms and authority.
2. Buyer accepts the terms, obtains an Approval Event if required, builds the acceptance record and derives the payment nonce.
3. Buyer's retry carries the acceptance, authority references and payment.
4. Seller verifies terms, then authority (core Level 1A), then payment, and **MUST NOT settle until the first two pass**.

A seller that receives a payment payload without the `consenti` extension, when its `PAYMENT-REQUIRED` demanded one, MUST NOT settle. It answers `402` again with the same requirements, not `409` or `403`.

---

## 3. Transport in x402 Extensions

The objects below are the content of a `consenti` extension, wrapped in whatever envelope x402 v2's extension convention requires.

### 3.1 Seller, in `PaymentRequired`

```json
{
  "extensions": {
    "consenti": {
      "binding": "consenti/x402-binding/v0.1",
      "core": "consenti/authority/v0.3",
      "terms_ref": {
        "terms_url": "https://seller.example/.well-known/agreements/api-v3.json",
        "terms_hash": "sha256:8fa574…"
      },
      "requires_authority": {
        "minimum_status": "granted_only",
        "above_value": { "amount": "100.00", "currency": "USD" },
        "accepted_sources": ["w3c_vc", "consenti_native"]
      }
    }
  }
}
```

The seller publishes `terms_hash`, not `agreement_hash`. The agreement hash covers the acceptance record, which exists only once the buyer accepts.

### 3.2 Buyer, in `PaymentPayload`

```json
{
  "extensions": {
    "consenti": {
      "binding": "consenti/x402-binding/v0.1",
      "acceptance": { "…": "signed acceptance record, authority object included (core §7)" },
      "agreement_hash": "sha256:…",
      "payment_seq": 0,
      "grant": {
        "source_type": "w3c_vc",
        "ref": "https://buyer.example/.well-known/grants/procurement-3.json",
        "grant_hash": "sha256:…"
      },
      "approval": { "source_type": "consenti_approval", "ref": "…", "event_hash": "sha256:…" },
      "nonce_salt": "base64url…"
    }
  }
}
```

### 3.3 Rules

- The acceptance record's `terms_hash` MUST equal the `terms_hash` in the seller's `402`.
- `grant.grant_hash` MUST equal `authority.grant.grant_hash` in the acceptance record.
- The acceptance record travels inline because the seller must verify the agent's signature before settling. The grant and approval MAY travel by reference with their hashes; the seller fetches and checks the hash.
- The grant reference MUST resolve to a location the principal controls (core §15, grant injection).
- `grant.source_type` MUST be one the seller listed in `accepted_sources`.

---

## 4. Binding the Paying Account to the Grant

On EVM networks the x402 payment is usually signed by an ordinary wallet with a secp256k1 key, and the payload names the payer as `authorization.from`. The agent's agreement-signing key named in the grant is typically a different key. Without a further rule a verifier holds a valid grant and a valid payment with no cryptographic link between them.

### 4.1 Requirement on the authority source

The grant MUST carry, under the principal's signature, the list of accounts the agent pays from: `accept_terms.payment_accounts` (core §4.2), as CAIP-10 identifiers.

A verifier MUST confirm that the payer (`authorization.from`, or the scheme's equivalent) is in that list, and that the entry's CAIP-2 chain matches the payment's `network`. EVM addresses compare case-insensitively. A grant without the field cannot bind an x402 payment, and the verifier reports the payment as **unbound**.

### 4.2 Which sources meet it

| Source (core §5.2) | Carries `payment_accounts`? |
|---|---|
| `w3c_vc` | Yes, inside `credentialSubject.accept_terms` |
| `consenti_native` | Yes, inside `scope` |
| `erc7710` | Where the payment executes through the delegation itself, the delegation is the binding and this check is replaced by verifying the redemption. Otherwise use a composite VC. |
| `aap_grant` | Not in draft-02. Use a composite VC that names the AAP grant by hash (core §5.3). |
| `aauth` | Not in AAuth. Use the composite VC of core §5.2 (AAuth, Route 2), which names the agent by identifier and key thumbprint and supplies R1 where the person server's key is not the principal's. |
| `ap2_intent_mandate` | Not applicable as specified; AP2 payments use their own Payment Mandate. A composite VC is required for x402. |
| `ucan` | As a caveat on the `accept_terms` capability. Not yet mapped in detail. |

### 4.3 Notes

- Smart-contract accounts (ERC-4337, EIP-1271) are listed by address. Whether they can pay through ERC-3009 depends on the token accepting contract signatures and the facilitator supporting them.
- A shared treasury account listed for several agents binds the payment to the principal but not to one agent. Principals who need per-agent attribution list a separate account per agent.
- Alternative considered: let the paying wallet sign the agreement directly with ES256K or EIP-712. It removes one hop but ties agreement signing to wallet custody and adds an algorithm to the verifier. Open (§9).

The chain of evidence: the principal signs the grant, which names the agent's signing key and its paying accounts; the signing key signs the agreement; the paying account signs a payment whose nonce commits to that agreement.

---

## 5. Binding the Payment to the Agreement

In the x402 `exact` scheme on EVM, the payment is an ERC-3009 `transferWithAuthorization`. Its 32-byte `nonce` is chosen and signed by the payer, and the token contract records it on-chain in `AuthorizationUsed(authorizer, nonce)`. This binding fixes how the nonce is chosen:

```
nonce = SHA-256( "consenti/x402-binding/v0.1" || agreement_hash || nonce_salt || uint64_be(payment_seq) )
```

- `agreement_hash` is the raw 32-byte hash. `payment_seq` starts at 0 and increments for each payment under the same agreement, keeping nonces unique per authorizer as ERC-3009 requires.
- `nonce_salt` MUST be at least 16 random bytes chosen by the buyer, carried base64url-encoded in the payload extension and in the parties' private records, and hashed as raw bytes. Verifiers MUST reject a missing or short salt. The agreement hash is public on the anchor, so without a salt anyone reading the chain could link the anchor to the payer's wallet.
- A verifier recomputes the nonce, finds the settlement transaction, and confirms it succeeded.

**The nonce binds which agreement, not the amount or payee.** A verifier MUST also confirm:

- the recipient is a `payTo` the seller declared somewhere it signed (its agreements directory or the terms), not only in the `402`;
- the asset and network are ones the seller offered;
- the amount is within the agreement's price and the grant's scope.

For scope and threshold checks (`max_value`, `requires_approval_above`, `aggregate_cap`), the commitment's value is the larger of the agreement's stated value and the sum of payments bound to it. Otherwise an agent could accept a small agreement and pay a large sum under its nonce.

### 5.1 Trusted time source: `x402_settlement`

This binding registers a trusted-time source under core §9.2:

| Source | Definition |
|---|---|
| `x402_settlement` | The block time of a successful settlement transaction whose ERC-3009 nonce equals the value recomputed under §5 for the agreement in hand |

The time is set by the chain, not the agent, and is bound to `agreement_hash` by the nonce. It closes the commitment window seconds after acceptance, which resolves almost every revocation-ordering dispute in an x402 flow without a separate anchoring step. Verifiers MUST derive it from the transaction themselves.

### 5.2 Limits

This works for assets implementing ERC-3009 (USDC does). x402 also supports Permit2 and non-EVM networks, whose nonce rules differ. Bindings for those are open (§9). Where no binding exists the payment is reported as unbound and the commitment falls back to other trusted-time sources or to the untrusted window.

---

## 6. Human Approval Above Threshold

When the commitment value exceeds `requires_approval_above`, the buyer's agent MUST obtain an Approval Event (core §6) after the `402` arrives and before signing the payment. It is not an x402 message and should not become one: the point of the approval is that it reaches the principal through a channel the agent does not control.

- Human approval takes minutes. A seller's `maxTimeoutSeconds` may be shorter. The agent SHOULD request the approval, wait for the decision, and then request fresh payment requirements rather than reuse expired ones.
- The approval's own short expiry sits inside the commitment window like any other boundary. An approval that expired before settlement gives `unknown` under core §9.4. Settlement time usually falls well inside the default fifteen-minute window when the agent proceeds promptly.

`presented.summary_hash` records what x402 has no place for: what the approving human was shown.

---

## 7. The Facilitator

A facilitator runs verify and settle, and is a natural place to check bindings. This binding allows that and does not require it.

- A facilitator MAY confirm, before settling, that the payer is in `payment_accounts` and that the nonce matches §5. Doing so requires the grant, the agreement hash and the salt.
- A facilitator that does this holds private-layer material, which weakens the zero-custody property. It MUST NOT retain that material after settlement, and a deployment using one MUST say so in its trust-assumption disclosure.
- The seller remains the relying party. A facilitator's check does not replace the seller's Level 1A verification.

---

## 8. Verification Summary

A verifier holding an x402-bound record runs core Level 1A, with these additions:

1. Confirm the acceptance record's `terms_hash` matches the seller's published terms.
2. Confirm the payer is in the grant's `payment_accounts` on the payment's network (§4), or verify the ERC-7710 redemption where that is the binding.
3. Recompute the nonce and locate the successful settlement (§5).
4. Confirm payee, asset, network and amount (§5).
5. Use the settlement block time as an `x402_settlement` trusted time (§5.1).

Results are reported per core §10: `valid`, `invalid`, or `unknown`, plus **bound** or **unbound** for the payment.

---

## 9. Open Questions

- The extension key and envelope under x402 v2's extension convention.
- Nonce bindings for Permit2 and non-EVM networks.
- ES256K or EIP-712 agreement signatures by the paying wallet.
- Size limits for an inline acceptance record in a header, and when to send it by reference.
- Whether facilitator checks belong in the binding at all.
- Whether `payment_accounts` belongs in the core `accept_terms` object or should be defined only here.
- Interaction with x402 identity work, including the x402 Identity Working Group's delegated-authority discussions. This draft is offered there for review.

---

## 10. Implementation Status

Nothing in this document is implemented. Dependencies, in order: core v0.3 VC mapping and Level 1A for that source; a settlement-lookup evidence source returning block time; nonce derivation and recomputation in the verifier; the `payment_accounts` check; seller middleware enforcing §2.

---

**Protocol:** Consenti Agreement Protocol
**Repository:** `github.com/consenti-ai/agreement-protocol`
**License:** MIT
**Contact:** eric@blocksee.co

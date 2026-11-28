# Consenti x402 Binding v0.2

**Status:** Draft proposal. **Not implemented.** Every MUST in this document is a proposed rule, not a description of running code.
**Binding ID:** `consenti/x402-binding/v0.2`
**Requires:** [Consenti Authority to Accept Terms v0.3](./authority-to-accept-terms-v0.3.md), with the core amendment in §11
**Carries:** x402 v2 (Linux Foundation). Object and field names follow x402 v2.
**Supersedes:** Consenti x402 Binding v0.1
**Maintainer:** Consenti (FHBK Technologies, Inc.)
**License:** MIT

---

## 0. What changed from v0.1

| v0.1 | v0.2 |
|---|---|
| Written in terms of HTTP status codes and headers | Written in terms of the x402 `PaymentRequired` and `PaymentPayload` objects, whatever transport carries them (§1, §2) |
| One assurance mode: full authority evidence | Three acceptance levels, including a terms-only level for low-value calls (§3) |
| "Do not settle until authority has verified", with no rule for `unknown` | A defined seller check, separate from later verification, and a seller-declared policy for `unknown` results (§4) |
| Fiat caps compared with token amounts without a conversion rule | Valuation rule: comparison only where the principal's grant declares how an asset is valued (§7) |
| Implied the seller checks `aggregate_cap` | States that the seller cannot, and who can (§7.3) |
| Open question on where `payment_accounts` belongs | Closed: it is defined in core v0.3 §4.2 |
| Nonce domain `consenti/x402-binding/v0.1` | `consenti/x402-binding/v0.2` (§6). Nothing was implemented under v0.1, so no records are affected. |

---

## 1. Purpose

x402 settles a payment in one request-and-retry exchange: the seller returns a `PaymentRequired` object, and the buyer retries with a `PaymentPayload`. It establishes that a payment was made and settled. It does not establish which terms governed the sale, whether the buyer accepted them, or whether the buyer was allowed to.

This binding carries a Consenti acceptance record and its authority evidence inside that exchange, and ties the payment to the agreement, so a verifier can later show that *this payment was made under these terms, by a buyer that accepted them, with the authority the record states*.

It defines:

1. Where terms, acceptance and authority references travel in x402 objects (§2).
2. Acceptance levels a seller can require, from terms-only to approved authority (§3).
3. What the seller checks before settling, and what it does when a check is inconclusive (§4).
4. How the paying account is tied to the authority grant (§5).
5. How the payment nonce commits to the agreement, which also yields a trusted commitment time (§6).
6. How payment amounts are compared with the grant's limits (§7).

**Transport.** Everything here is carried in the `extensions` member of the `PaymentRequired` and `PaymentPayload` objects. Nothing depends on HTTP status codes or header names. Where this document says the seller "returns `PaymentRequired`", that is a 402 response over HTTP and the equivalent message over any other transport x402 supports. Outside x402 entirely, the core flow (agreement, then authority, then payment) applies unchanged.

---

## 2. Transport in x402 Extensions

The objects below are the content of a `consenti` extension, wrapped in whatever envelope x402 v2's extension convention requires (open, §10).

### 2.1 Seller, in `PaymentRequired`

```json
{
  "extensions": {
    "consenti": {
      "binding": "consenti/x402-binding/v0.2",
      "core": "consenti/authority/v0.3",
      "terms_ref": {
        "terms_url": "https://seller.example/.well-known/agreements/api-v3.json",
        "terms_hash": "sha256:8fa574…"
      },
      "acceptance_policy": {
        "levels": [
          { "up_to": { "amount": "1.00", "currency": "USD" }, "minimum_status": "unauthorized" },
          { "up_to": { "amount": "10000.00", "currency": "USD" }, "minimum_status": "granted_only" },
          { "minimum_status": "authorized" }
        ],
        "accepted_sources": ["w3c_vc", "consenti_native"],
        "accept_unknown": []
      }
    }
  }
}
```

The seller publishes `terms_hash`, not `agreement_hash`. The agreement hash covers the acceptance record, which exists only once the buyer accepts.

`acceptance_policy` is defined in §3 and §4.

### 2.2 Buyer, in `PaymentPayload`

```json
{
  "extensions": {
    "consenti": {
      "binding": "consenti/x402-binding/v0.2",
      "acceptance": { "…": "acceptance record, authority object included (core §7)" },
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

`grant` is absent at the `unauthorized` level. `approval` is present only where the buyer's grant or the seller's policy requires one.

### 2.3 Rules

- The acceptance record's `terms_hash` MUST equal the `terms_hash` in the seller's `PaymentRequired`.
- Where `grant` is present, `grant.grant_hash` MUST equal `authority.grant.grant_hash` in the acceptance record, and `grant.source_type` MUST be one the seller listed in `accepted_sources`.
- The acceptance record travels inline because the seller must check it before settling. The grant and approval MAY travel by reference with their hashes; the seller fetches them and checks the hash.
- A grant reference MUST resolve to a location the principal controls (core §15, grant injection).
- A seller that receives a `PaymentPayload` without the `consenti` extension, when its `PaymentRequired` required one, MUST NOT settle. It returns `PaymentRequired` again with the same requirements.
- If the buyer retries against a fresh `PaymentRequired` whose `terms_hash` differs from the one it accepted, the earlier acceptance and any approval bound to it do not carry over. The buyer builds a new acceptance record.

---

## 3. Acceptance Levels

A seller decides how much evidence it needs. Low-value pay-per-use calls may need only a record of which terms applied; a large B2B purchase may need a grant and a human approval. `acceptance_policy.levels` states this by value band.

### 3.1 Levels

Levels use the core `authority.status` values, ordered from least to most evidence:

| Level | Buyer provides | Evidence produced |
|---|---|---|
| `unauthorized` (terms-only) | Acceptance record with `authority.status: "unauthorized"`; payment bound under §6 | Which terms governed the sale, and that the paying account paid under them. Nothing about authority. |
| `granted_only` | Acceptance record signed by the agent key; a grant whose `accept_terms` scope covers the commitment | The above, plus that a principal authorized the agent to accept terms of this kind |
| `authorized` | The above, plus an Approval Event (core §6) | The above, plus that the principal approved this specific agreement |

A buyer MAY provide more evidence than the seller requires. A buyer whose own grant requires approval above a threshold MUST obtain it regardless of the seller's policy (core §6).

### 3.2 Bands

- `levels` is an ordered list. Each entry except the last carries `up_to`, an inclusive ceiling on the commitment value (§7.1). The last entry carries no `up_to` and covers everything above.
- The commitment falls in the first band whose `up_to` it does not exceed. The buyer MUST meet that band's `minimum_status` or higher.
- `up_to` values MUST be in ascending order and in one currency.
- A seller that requires the same level at every value lists one entry with no `up_to`.

### 3.3 The terms-only level

At `unauthorized` the acceptance record need not be signed by a separate agent key. The acceptor is identified by the paying account (CAIP-10), and the payer's ERC-3009 signature over a nonce that commits to `agreement_hash` (§6) is the evidence that the payer accepted those terms. This keeps the overhead of a sub-dollar call to one extension object and one nonce derivation.

This level records acceptance; it does not record authority. Core §7 already treats an unauthorized acceptance as a valid commitment, and verifiers report it as such. Whether the principal is bound by it is a question for agency law, not for this binding (core §14).

---

## 4. The Seller Check Before Settlement

The seller's check and later verification are different procedures. The seller decides at the moment of payment whether to settle, using its own clock as the enforcement point. A verifier reviewing the record later asks whether the acceptance was within authority at the time it happened, using trusted time (core §9). §4 defines the first; §9 defines the second.

### 4.1 Procedure

Before settling, the seller runs:

1. **Terms.** The acceptance record's `terms_hash` equals the one the seller published (§2.3).
2. **Level.** Determine the commitment value (§7.1), find the band (§3.2), and confirm the acceptance record's `authority.status` meets it.
3. **Authority**, at `granted_only` and above: core Level 1A steps 1, 3, 4, 5, 6 and 7, with the commitment window ending at the seller's check time. Step 2's trusted time does not yet exist (settlement will supply it) and step 8's anchor does not yet exist; both are skipped here and run at later verification.
4. **Payment account**, at `granted_only` and above: the payer is in the grant's `payment_accounts` on the payment's network (§5).
5. **Nonce.** The payload's ERC-3009 nonce equals the value derived under §6.
6. **Payment terms.** Payee, asset, network and amount (§6.1, §7).

### 4.2 Results and the `unknown` policy

Each step returns `pass`, `fail` or `unknown`, as in core §10.1.

- Any `fail`: the seller MUST NOT settle.
- All `pass`: the seller MAY settle.
- Any `unknown`: the seller MUST NOT settle unless every `unknown` step is named in its `acceptance_policy.accept_unknown`.

`accept_unknown` lists step names from: `scope`, `revocation`, `approval`. The default is empty, which refuses any inconclusive result. Steps 1, 2, 4, 5 and 6 of §4.1 cannot be accepted as `unknown`; they depend only on data the seller already holds.

The common cases this policy exists for:

- **`scope`**: the grant names a clause vocabulary the seller's verifier does not recognize (core §4.3). Until vocabularies are published this is the usual result for any grant that carries `terms_classes`.
- **`revocation`**: the principal's status source cannot be fetched, or is not fresh enough (core §11).

A seller that settles on an accepted `unknown` takes on that risk knowingly, and the record shows it (§4.3).

### 4.3 Seller check record

The seller SHOULD return, in the `consenti` extension of its settlement response, a record of the check:

```json
{
  "seller_check": {
    "agreement_hash": "sha256:…",
    "result": "pass",
    "steps": { "terms": "pass", "level": "pass", "authority": "pass", "scope": "unknown",
               "revocation": "pass", "payment_account": "pass", "nonce": "pass", "payment_terms": "pass" },
    "accepted_unknown": ["scope"],
    "checked_at": "2026-11-25T14:02:11Z",
    "signature": { "algorithm": "ES256", "public_key_ref": "did:web:seller.example#key-1", "value": "base64url…" }
  }
}
```

`checked_at` is the seller's assertion and is not a trusted time. The record's value is that the seller signed what it relied on: in a later dispute it shows which checks the seller ran and which inconclusive results it chose to accept. Both parties SHOULD keep it with the agreement record.

---

## 5. Binding the Paying Account to the Grant

On EVM networks the x402 payment is usually signed by an ordinary wallet with a secp256k1 key, and the payload names the payer as `authorization.from`. The agent's agreement-signing key named in the grant is typically a different key. Without a further rule a verifier holds a valid grant and a valid payment with no link between them.

### 5.1 Requirement

At `granted_only` and above, the grant MUST carry `accept_terms.payment_accounts` (core v0.3 §4.2) under the principal's signature.

A verifier MUST confirm that the payer (`authorization.from`, or the scheme's equivalent) is in that list and that the entry's CAIP-2 chain matches the payment's `network`. EVM addresses compare case-insensitively. A grant without the field cannot bind an x402 payment; the seller check step returns `fail`, and later verification reports the payment as **unbound**.

At `unauthorized` there is no grant, and the payer is the acceptor (§3.3).

### 5.2 Which sources meet it

| Source (core §5.2) | Carries `payment_accounts`? |
|---|---|
| `w3c_vc` | Yes, inside `credentialSubject.accept_terms` |
| `consenti_native` | Yes, inside `scope` |
| `erc7710` | Where the payment executes through the delegation itself, the delegation is the binding and this check is replaced by verifying the redemption. Otherwise use a composite VC. |
| `aap_grant` | Not in draft-02. Use a composite VC that names the AAP grant by hash (core §5.3). |
| `aauth` | Not in AAuth. Use the composite VC of core §5.2 (AAuth, Route 2). |
| `ap2_intent_mandate` | Not applicable; AP2 payments use their own Payment Mandate. A composite VC is required for x402. |
| `ucan` | As a caveat on the `accept_terms` capability. Not yet mapped in detail. |

In practice, x402 binding at `granted_only` and above runs on a VC or the native credential, alone or as the second half of a composite.

### 5.3 Notes

- Smart-contract accounts (ERC-4337, EIP-1271) are listed by address. Whether they can pay through ERC-3009 depends on the token accepting contract signatures and the facilitator supporting them.
- A shared treasury account listed for several agents binds the payment to the principal but not to one agent. Principals who need per-agent attribution list a separate account per agent.
- Alternative considered: let the paying wallet sign the agreement directly with ES256K or EIP-712. Open (§10).

The chain of evidence: the principal signs the grant, which names the agent's signing key and its paying accounts; the signing key signs the agreement; the paying account signs a payment whose nonce commits to that agreement.

---

## 6. Binding the Payment to the Agreement

In the x402 `exact` scheme on EVM, the payment is an ERC-3009 `transferWithAuthorization`. Its 32-byte `nonce` is chosen and signed by the payer, and the token contract records it on-chain in `AuthorizationUsed(authorizer, nonce)`. This binding fixes how the nonce is chosen:

```
nonce = SHA-256( "consenti/x402-binding/v0.2" || agreement_hash || nonce_salt || uint64_be(payment_seq) )
```

- `agreement_hash` is the raw 32-byte hash. `payment_seq` starts at 0 and increments for each payment under the same agreement, keeping nonces unique per authorizer as ERC-3009 requires.
- `nonce_salt` MUST be at least 16 random bytes chosen by the buyer, carried base64url-encoded in the payload extension and in the parties' private records, and hashed as raw bytes. Verifiers MUST reject a missing or short salt. The agreement hash is public on the anchor, so without a salt anyone reading the chain could link the anchor to the payer's wallet.
- A verifier recomputes the nonce, finds the settlement transaction, and confirms it succeeded.

### 6.1 What the nonce does not bind

The nonce binds which agreement, not the amount or payee. A verifier MUST also confirm:

- the recipient is a `payTo` the seller declared somewhere it signed (its agreements directory or the terms), not only in `PaymentRequired`;
- the asset and network are ones the seller offered;
- the amount is within the agreement's price and, at `granted_only` and above, within the grant's scope (§7).

### 6.2 Trusted time source: `x402_settlement`

This binding registers a trusted-time source under core §9.2:

| Source | Definition |
|---|---|
| `x402_settlement` | The block time of a successful settlement transaction whose ERC-3009 nonce equals the value recomputed under §6 for the agreement in hand |

The time is set by the chain, not the agent, and is bound to `agreement_hash` by the nonce. It closes the commitment window seconds after acceptance, which resolves almost every revocation-ordering dispute in an x402 flow without a separate anchoring step. Verifiers MUST derive it from the transaction themselves.

### 6.3 Limits

This works for assets implementing ERC-3009 (USDC does). x402 also supports Permit2 and non-EVM networks, whose nonce rules differ. Bindings for those are open (§10). Where no binding exists the payment is reported as unbound and the commitment falls back to other trusted-time sources or to the untrusted window.

---

## 7. Valuing Payments Against Limits

### 7.1 Commitment value

For band selection (§3.2) and scope checks (`max_value`, `requires_approval_above`), the commitment value is the larger of the agreement's stated value and the sum of payments bound to it under §6. Otherwise an agent could accept a small agreement and pay a large sum under its nonce.

### 7.2 Comparing token amounts with limits

Grant limits and seller bands are often stated in a fiat currency (`"currency": "USD"`); x402 payments are in a token, in base units. A verifier compares the two only on a stated basis:

1. **Same unit.** A limit MAY be stated in the payment asset itself, using its CAIP-19 identifier as `currency`, with `amount` in whole token units. The verifier converts the payment's base units using the token's decimals and compares directly.
2. **Declared valuation.** Otherwise, the verifier uses `accept_terms.asset_valuation` (§11), which the principal signs as part of the grant:

   ```json
   "asset_valuation": [
     { "asset": "eip155:8453/erc20:0x8335…", "currency": "USD", "rate": "1" }
   ]
   ```

   `rate` is the value of one whole token in `currency`. The verifier uses the declared rate, not a market price, so the result is reproducible later.
3. **Neither.** The scope step returns `unknown`.

For seller bands, the seller is the one comparing, and it applies the same rules with its own declared valuation in `acceptance_policy` (an `asset_valuation` member with the same form). The seller's valuation governs band selection; the principal's governs scope. They may differ, and each party is bound only by its own.

### 7.3 `aggregate_cap`

The seller cannot check `aggregate_cap`. The cap counts commitments across every agreement in a period, and a seller sees only its own. The seller check (§4) does not include it.

The cap is enforced by the buyer's agent before it commits, and checked later by a verifier holding the principal's full set of records for the period. Sellers SHOULD NOT state or imply that their check covers it.

---

## 8. Human Approval Above Threshold

When the commitment value exceeds the grant's `requires_approval_above`, or the seller's band requires `authorized`, the buyer's agent MUST obtain an Approval Event (core §6) after receiving `PaymentRequired` and before signing the payment. It is not an x402 message and should not become one: the approval must reach the principal through a channel the agent does not control.

- Human approval takes minutes. A seller's `maxTimeoutSeconds` may be shorter. The agent SHOULD request the approval, wait for the decision, and then request fresh payment requirements rather than reuse expired ones. If the fresh requirements carry a different `terms_hash`, the approval does not carry over (§2.3).
- The approval's own short expiry sits inside the commitment window like any other boundary. An approval that expired before settlement gives `unknown` under core §9.4. Settlement usually falls well inside the default fifteen-minute window when the agent proceeds promptly.

`presented.summary_hash` records what x402 has no place for: what the approving human was shown.

---

## 9. Verification After Settlement

A verifier holding an x402-bound record later runs:

1. Confirm the acceptance record's `terms_hash` matches the seller's published terms.
2. Recompute the nonce and locate the successful settlement (§6).
3. Confirm payee, asset, network and amount (§6.1, §7).
4. Use the settlement block time as an `x402_settlement` trusted time (§6.2).
5. At `granted_only` and above: run core Level 1A in full, all eight steps, with that trusted time, and confirm the payer is in `payment_accounts` (§5), or verify the ERC-7710 redemption where that is the binding.
6. Where a seller check record (§4.3) is present, verify its signature and report which `unknown` results the seller accepted.

Results are reported per core §10: `valid`, `invalid` or `unknown` for authority (or "not asserted" at the `unauthorized` level), plus **bound** or **unbound** for the payment. A verifier MUST NOT treat a seller check record as a substitute for its own Level 1A run; the seller checked against its own clock, the verifier checks against trusted time, and the two can differ.

---

## 10. Facilitator and Open Questions

### Facilitator

A facilitator runs verify and settle, and is a natural place to check bindings. This binding allows that and does not require it.

- A facilitator MAY run §4.1 steps 4 and 5 before settling. Doing so requires the grant, the agreement hash and the salt.
- A facilitator that does this holds private-layer material, which weakens the zero-custody property. It MUST NOT retain that material after settlement, and a deployment using one MUST say so in its trust-assumption disclosure.
- The seller remains the relying party. A facilitator's check does not replace the seller check (§4).

### Open questions

- The extension key and envelope under x402 v2's extension convention.
- Nonce bindings for Permit2 and non-EVM networks.
- ES256K or EIP-712 agreement signatures by the paying wallet.
- Size limits for an inline acceptance record, and when to send it by reference.
- Whether facilitator checks belong in the binding at all.
- Whether sellers need finer-grained `accept_unknown` conditions (per source type, per value band).
- Interaction with the x402 Identity Working Group's requirements for terms acceptance (Evidence Chain RFP §4.2, terms placeholder). This draft is offered there as one way to meet them.

---

## 11. Core Amendment Required

This binding depends on one addition to core v0.3 §4.2, the `accept_terms` object:

| Field | Required | Description |
|---|---|---|
| `asset_valuation` | no | List of `{asset, currency, rate}` entries: the value of one whole unit of a CAIP-19 asset in the currency of the grant's limits, as declared by the principal. Used to compare payments in that asset with `max_value`, `aggregate_cap` and `requires_approval_above`. Without an entry for the payment asset, a limit in another currency cannot be checked and the scope step returns `unknown`. |

Attenuation (core §4.4): a derived object's `asset_valuation` MUST be a subset of its parent's, with identical rates. A child may not revalue an asset.

`payment_accounts`, which v0.1 listed as possibly belonging only to the binding, stays where core v0.3 §4.2 already defines it.

---

## 12. Implementation Status

Nothing in this document is implemented. Dependencies, in order:

1. Core v0.3 VC mapping and Level 1A for that source. (Core today implements Level 1A for `consenti_native` only.)
2. The `asset_valuation` core amendment (§11).
3. A settlement-lookup evidence source returning block time.
4. Nonce derivation and recomputation in the verifier.
5. Seller middleware implementing the §4 check, the `unknown` policy and the seller check record.
6. At least one published clause vocabulary. Until one exists, any grant carrying `terms_classes` produces `scope: unknown`, and sellers must either list `scope` in `accept_unknown` or refuse.

The terms-only level (§3.3) depends only on items 3, 4 and the `terms_hash` check, and is the shortest path to a working implementation.

---

**Protocol:** Consenti Agreement Protocol
**Repository:** `github.com/consenti-ai/agreement-protocol`
**License:** MIT
**Contact:** eric@blocksee.co

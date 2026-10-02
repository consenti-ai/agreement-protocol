# Consenti Delegation & Principal Authorization Extension v0.2

**Status:** Draft
**Protocol ID:** `consenti/authorization/v0.2`
**Extends:** [Discovery Spec v0.1](./well-known-agreements-spec.md) · [Privacy Architecture v0.1](./agreement-privacy-architecture.md) · Agreement Schema v0.1
**Maintainer:** Consenti (FHBK Technologies, Inc.)
**License:** MIT

---

## 1. Purpose

Discovery Spec v0.1 §5 names two steps in its sequence diagram and defines neither:

```
  |-- evaluate terms against principal authorization   |
  |-- sign agreement with delegated key                |
```

Neither appears in the v0.1 field tables, the 409 handshake, the verification
inputs, or the security considerations. The Privacy Architecture models party
identity as a flat `party_hash` with no principal/agent distinction, so its
Level 1 "Binding Proof" can answer *did this party sign* but cannot answer
*was the signer authorized to*.

This extension defines the missing layer. It specifies what a delegation is,
how an authorization is recorded, how a third party verifies one without
trusting any of the parties, and how both stay private under the existing
disclosure model.

**Scope.** This document covers the authority to commit. It does not cover
negotiation, payment, escrow, or adjudication.

---

## 2. Design Principles

**Authority is evidence, not configuration.** A delegation is an artifact a
third party can verify after the fact, not a setting in a dashboard. If it
cannot be checked by someone who trusts neither party nor Consenti, it does
not belong in this layer.

**Standing authority and per-commitment authorization are different acts.**
A delegation says *this agent may commit to terms of this kind, up to these
limits, until this date*. An authorization event says *this principal
approved this specific agreement at this moment*. Conflating them is the
central modeling error: the first is a policy, the second is a fact about one
transaction. High-value commitments need both.

**Absence is a valid state and must be representable.** An agent signing on
its own account produces a valid commitment — an unauthorized one. The record
must be able to say so plainly rather than omitting the field. A missing
`authorization` block and an explicit unauthorized commitment are different
claims and must not be encoded identically.

**The principal's identity is as private as the party's.** v0.1 hashes party
identifiers precisely so a chain observer cannot identify who transacted.
Authorization must not reintroduce plaintext identity at the same layer.

---

## 3. Two Artifacts

| | Delegation Credential | Authorization Event |
|---|---|---|
| **Answers** | May this agent commit to this class of terms? | Did the principal approve this agreement? |
| **Lifetime** | Standing, until expiry or revocation | One agreement |
| **Issued** | Ahead of time, out of band | At commitment time |
| **Bound to** | An agent key and a scope | A specific `agreement_hash` |
| **Required** | Always, to claim authorized status | Above the principal's threshold |
| **Analogy** | A signing authority matrix | The bank's confirmation text |

A commitment below threshold carries a delegation reference alone. A
commitment above threshold carries both.

---

## 4. The Delegation Credential

### 4.1 Format

```json
{
  "type": "consenti/delegation/v0.2",
  "delegation_id": "dlg_7f3a9c21",
  "principal": {
    "identifier": { "type": "did", "value": "did:web:acme.example" },
    "commitment": "sha256:4b1e…"
  },
  "agent": {
    "identifier": { "type": "erc8004", "value": "eip155:1:0xAgent…" },
    "public_key_ref": "did:web:acme.example#agent-key-3"
  },
  "scope": {
    "actions": ["purchase", "data_access"],
    "counterparties": ["did:web:supplier.example", "*"],
    "max_value": { "amount": "5000.00", "currency": "USD" },
    "aggregate_cap": { "amount": "50000.00", "currency": "USD", "period": "P30D" },
    "prohibited_clauses": ["arbitration_waiver", "perpetual_license", "auto_renew"],
    "requires_authorization_above": { "amount": "1000.00", "currency": "USD" }
  },
  "chain_binding": {
    "standard": "erc7710",
    "delegation_hash": "0x…",
    "chain": "eip155:1"
  },
  "issued_at": "2026-07-01T00:00:00Z",
  "expires_at": "2026-12-31T23:59:59Z",
  "revocation": {
    "check_url": "https://acme.example/.well-known/delegations/revoked.json",
    "anchor_ref": "pangea:…"
  },
  "signature": {
    "algorithm": "ES256",
    "public_key_ref": "did:web:acme.example#key-1",
    "value": "base64url…"
  }
}
```

### 4.2 Fields

| Field | Required | Description |
|---|---|---|
| `delegation_id` | yes | Stable identifier. Opaque; carries no semantics. |
| `principal.identifier` | yes | DID, URL, or other resolvable identifier of the granting party. |
| `principal.commitment` | yes | `SHA-256(canonical(principal.identifier))`. The value published in any public context. See §7. |
| `agent.identifier` | yes | The agent's identifier. ERC-8004 where one exists. |
| `agent.public_key_ref` | yes | The key the agent signs commitments with. Verifiers resolve this and check the commitment signature against it. |
| `scope` | yes | Bounds on the grant. MUST be present; an unbounded delegation is expressed as explicit wildcards, never by omission. |
| `scope.requires_authorization_above` | no | Threshold above which a per-commitment Authorization Event (§5) is also required. Absent means no threshold — delegation alone suffices at any value within `max_value`. |
| `scope.prohibited_clauses` | no | Clause types the agent may not accept regardless of value. Evaluated against the agreement's clause paths. |
| `chain_binding` | no | Where the grant is also expressed on-chain. ERC-7710 is the reference standard. Present makes the delegation independently checkable against chain state. |
| `expires_at` | yes | No perpetual delegations. A verifier MUST reject a credential past expiry. |
| `revocation.check_url` | yes | Where a verifier checks live revocation status. |
| `signature` | yes | Principal's signature over the canonicalized credential with `signature` removed. RFC 8785 (JCS). |

### 4.3 Chain-backed and self-contained modes

Two conformant modes, and implementations MUST support both:

**Chain-backed.** `chain_binding` is present. The authority is expressed as an
on-chain permission (ERC-7710) and the credential references its hash. A
verifier can check the grant against chain state without contacting the
principal. Strongest, and appropriate where the agent transacts on-chain
anyway.

**Self-contained.** `chain_binding` is absent. The credential stands on the
principal's signature alone, verified against the principal's published DID
document. A verifier resolves the DID, checks the signature, checks expiry,
and checks the revocation list. No chain dependency. Appropriate for
enterprise principals who will not put a signing authority matrix on a public
chain — which, in the target market, is most of them.

Self-contained is the default for the legal/compliance ICP. Do not require a
chain to express corporate signing authority.

---

## 5. The Authorization Event

Issued when a commitment crosses `scope.requires_authorization_above`, or
whenever the principal's policy demands a human in the loop.

```json
{
  "type": "consenti/authorization/v0.2",
  "authorization_id": "auth_c81f…",
  "delegation_id": "dlg_7f3a9c21",
  "agreement_hash": "sha256:8fa574…",
  "merkle_root": "sha256:b7e1…",
  "decision": "approved",
  "authorized_by": {
    "commitment": "sha256:9c4d…",
    "method": "out_of_band_confirmation",
    "channel": "sms"
  },
  "comprehension": {
    "attested": true,
    "attestation_ref": "pou_4d21…",
    "method": "consenti/pou/v1"
  },
  "presented": {
    "summary_hash": "sha256:1a7f…",
    "disclosed_clause_paths": ["clauses.term", "clauses.value", "clauses.liability_cap"]
  },
  "authorized_at": "2026-07-15T09:12:44Z",
  "expires_at": "2026-07-15T09:27:44Z",
  "signature": {
    "algorithm": "ES256",
    "public_key_ref": "did:web:acme.example#key-1",
    "value": "base64url…"
  }
}
```

### 5.1 Binding rules

- An Authorization Event MUST bind to exactly one `agreement_hash`. It is not
  reusable and not transferable.
- It MUST reference the `delegation_id` under which the agent is acting.
  Authorization without an underlying delegation is malformed — the principal
  is approving a specific act by a specific agent, and the agent's identity
  comes from the delegation.
- It SHOULD carry a short `expires_at`. An approval that sat unused for a week
  is weak evidence that the principal approved *this* transaction. Fifteen
  minutes is the reference default.
- `decision` MUST be one of `approved`, `denied`, `expired`. Denials are
  recorded and anchored like approvals. A record that only ever shows
  approvals proves nothing about the ones that were refused.

### 5.2 `presented` — what the principal actually saw

`summary_hash` commits to the exact text shown to the authorizing human, and
`disclosed_clause_paths` records which clauses were surfaced. This matters
because an approval is only as good as what was in front of the approver. A
principal who approved against a three-line summary, when the agreement
contained a clause they never saw, has a materially different record from one
who approved against full terms.

This field is what makes the authorization defensible rather than merely
present. Implementations MUST populate it.

### 5.3 Comprehension

The optional `comprehension` block links a Proof of Understanding attestation
to the authorization. Authorization and comprehension are separate claims:
a principal may authorize without being tested, and this block is absent in
that case. Never infer comprehension from authorization.

Where present, `attestation_ref` resolves to the PoU record and `method`
names the mechanism. The PoU attestation itself is specified elsewhere and is
out of scope for this document.

---

## 6. Schema Integration

The agreement schema gains an optional top-level `authority` object:

```json
{
  "authority": {
    "status": "authorized",
    "delegation": { "delegation_id": "dlg_7f3a9c21", "credential_hash": "sha256:…" },
    "authorization": { "authorization_id": "auth_c81f…", "event_hash": "sha256:…" }
  }
}
```

`status` is one of:

| Value | Meaning |
|---|---|
| `authorized` | Valid delegation, and an Authorization Event where the threshold required one. |
| `delegated_only` | Valid delegation, commitment below threshold. No per-commitment event. |
| `unauthorized` | The agent signed on its own account. No delegation asserted. A valid commitment; an unauthorized one. |
| `exceeded_scope` | A delegation exists and the commitment falls outside it. The agent MUST NOT commit in this state; the value exists so a verifier can label a non-conformant record it encounters. |

**This supersedes the inline `authorization` block** in the Consenti
Agreements skill (§2, "Principal authorization"), which embeds
`principal.display_name` as plaintext — for example
`"Acme Corp — J. Rivera, VP Procurement"`. That conflicts with the Privacy
Architecture's party pseudonymity guarantee, which exists so that a chain
observer cannot identify who transacted. A named individual and their job
title inside the agreement record defeats it at the same layer.

Under this extension the agreement carries hashes and identifiers only. The
credential and the event are separate documents held by the parties and
disclosed under §8.

---

## 7. Privacy Model

Authorization artifacts follow the existing three-layer model.

**Layer 1 — anchor.** The anchor gains two optional fields:

```json
{
  "authority_commitment": "sha256:…",
  "authority_status": "authorized"
}
```

`authority_commitment` is the hash of the canonicalized authority object from
§6. `authority_status` is public because a counterparty's decision to
transact depends on it and it leaks nothing — it reveals that *an* authorized
commitment occurred, not by whom.

**Layer 2 — private.** The delegation credential and authorization event are
held by the parties, alongside the agreement content. Consenti retains
neither.

**Layer 3 — selective disclosure.** The authority object is included in the
clause Merkle tree as its own subtree, so a party can prove authorization to
an auditor without disclosing the terms, and can prove the terms without
disclosing who internally approved them. These are separate disclosures and
the tree structure must keep them separable.

**Principal pseudonymity.** Everything published outside the parties uses
`principal.commitment` = `SHA-256(canonical(identifier))`, consistent with
`party_hash`. The plaintext identifier appears only in the credential itself,
which is Layer 2.

**Residual risk, stated plainly.** Hashed identifiers are vulnerable to
dictionary attack where the identifier space is small and guessable —
`did:web:acme.example` is trivially enumerable. This is inherited from the
v0.1 `party_hash` model and is not solved here. A salted commitment
(`SHA-256(salt || identifier)`, salt held by the parties and revealed on
disclosure) closes it at the cost of making Level 0 existence proofs
interactive. Flagged in §14 for v0.3; implementers handling sensitive
counterparty relationships should not rely on hash pseudonymity today.

---

## 8. Verification

The Privacy Architecture's four levels gain one:

### Level 1A — Authority Proof

**Question:** "Was the signer authorized by a named principal to commit to
this agreement?"

**Required inputs:** delegation credential · authorization event, where
`authority_status` is `authorized` · agreement hash · anchor reference

**Procedure:**

1. Verify the delegation credential's signature against the principal's
   published key. Where `chain_binding` is present, check the ERC-7710
   delegation hash against chain state.
2. Check `issued_at` ≤ commitment time ≤ `expires_at`.
3. Fetch `revocation.check_url`; confirm `delegation_id` is absent from the
   revocation list as of the commitment time, not as of now (§9).
4. Confirm the commitment signature on the agreement verifies against
   `agent.public_key_ref` from the credential. **This is the step that binds
   the signature to the authority.** Without it a verifier has two unrelated
   documents.
5. Evaluate the agreement against `scope`: action type, counterparty,
   `max_value`, `prohibited_clauses`.
6. Where an Authorization Event is present: verify its signature, confirm
   `agreement_hash` matches, confirm `delegation_id` matches, confirm it had
   not expired at commitment time.
7. Recompute the authority object hash and confirm it matches
   `authority_commitment` on the anchor.

**Disclosed:** That a named principal authorized this commitment, under what
scope. Nothing about the terms.

Level 1A sits between Level 1 (this party signed) and Level 2 (this clause is
in the agreement). It is the level most compliance reviews actually need, and
v0.1 has no way to express it.

---

## 9. Revocation

Principals publish a revocation list:

```
https://{principal-domain}/.well-known/delegations/revoked.json
```

```json
{
  "protocol_version": "consenti/authorization/v0.2",
  "updated_at": "2026-09-01T00:00:00Z",
  "revoked": [
    {
      "delegation_id": "dlg_7f3a9c21",
      "revoked_at": "2026-08-15T14:22:00Z",
      "effective": "prospective"
    }
  ],
  "anchor_ref": "pangea:…",
  "signature": { "algorithm": "ES256", "public_key_ref": "…", "value": "…" }
}
```

**Revocation is prospective by default.** Commitments made before
`revoked_at` remain authorized. This is deliberate and it is the correct
default: a principal who could retroactively un-authorize a commitment could
repudiate any deal at will, which destroys the counterparty's reason to rely
on the record at all.

`effective: "retroactive"` exists for key-compromise cases and is a distinct,
louder claim — the principal is asserting the agent's key was not under its
control from `revoked_at`. Verifiers MUST surface retroactive revocation
prominently rather than silently invalidating.

**The revocation race.** A commitment and a revocation can be concurrent. The
anchor timestamp on each is the tiebreaker; where both anchor within the
same block or timestamp granularity, the record is ambiguous and a verifier
MUST report it as ambiguous rather than resolving it. This is an honest
limitation of any distributed revocation scheme and should not be papered
over.

---

## 10. Discovery Flow Integration

Replacing the two undefined lines in Discovery §5:

```
Agent A                                           Service B
  |                                                    |
  |-- GET /.well-known/agreements.json --------------->|
  |<-- 200 OK (directory) -----------------------------|
  |                                                    |
  |-- evaluate applies_to against intended action      |
  |-- GET {agreement_ref} ---------------------------->|
  |<-- 200 OK (canonical agreement v0.1) --------------|
  |-- verify agreement_hash matches                    |
  |                                                    |
  |== AUTHORITY EVALUATION (this extension) ==         |
  |-- load delegation credential                       |
  |-- check expiry + revocation list                   |
  |-- evaluate agreement against scope:                |
  |     action type / counterparty / max_value         |
  |     / prohibited_clauses                           |
  |                                                    |
  |-- IF out of scope: HALT. Return to principal.      |
  |-- IF above requires_authorization_above:           |
  |     request Authorization Event from principal     |
  |     (out of band; agent does not self-authorize)   |
  |     await decision or expiry                       |
  |                                                    |
  |-- sign agreement with agent.public_key_ref key     |
  |-- attach authority object (§6)                     |
  |                                                    |
  |-- POST signed commitment ------------------------->|
  |                                    verify Level 1A |
  |<-- 201 Created (agreement_id, anchor_ref) ---------|
  |                                                    |
  |-- proceed with transaction ----------------------->|
```

**The agent never self-authorizes.** Requesting an Authorization Event is an
out-of-band call to the principal through a channel the agent does not
control. An agent that can mint its own authorization has not solved the
problem this extension exists to solve.

### 10.1 Counterparty requirements

Directory entries gain an optional field:

```json
{
  "requires_authority": {
    "minimum_status": "delegated_only",
    "above_value": { "amount": "10000.00", "currency": "USD" }
  }
}
```

A service can then decline to transact with unauthorized agents — which is
the demand-side driver for adoption. A supplier who requires verified
authority above $10,000 is protecting itself from a buyer who later claims
its agent went rogue.

### 10.2 403 Authorization Required

Distinct from 409 Agreement Required. 409 means *you have not agreed to
terms*; 403 means *you have agreed, but you have not shown authority to*.

```http
HTTP/1.1 403 Authorization Required
Content-Type: application/agreement+json
Link: <https://example.com/.well-known/agreements.json>; rel="agreement-directory"

{
  "error": "authority_required",
  "minimum_status": "authorized",
  "reason": "commitment value exceeds unauthenticated threshold",
  "authority_endpoint": "https://example.com/api/authority/present"
}
```

Resolution order in a combined flow: **409 → 403 → 402.** Agree to terms,
prove you were allowed to, then pay. An agent that pays first has committed
funds under terms it had no authority to accept, which is the compound
failure this stack exists to prevent.

---

## 11. Relationship to Existing Standards

| Standard | What it does | Relationship |
|---|---|---|
| **ERC-7710** (delegation) | On-chain bounded permissions between smart accounts | Reference `chain_binding`. Bounds *spend*; this extension bounds *assent to terms*. Complementary, and `delegation_hash` is the join. |
| **ERC-8004** (trustless agents) | Agent identity and reputation on-chain | Preferred value for `agent.identifier`. |
| **AP2 mandates** (Google + 60 partners) | Intent / Cart / Payment mandates as verifiable credentials | Closest analogue. AP2 authorizes a *purchase*; this authorizes *acceptance of terms*. An Intent Mandate and a Delegation Credential could reference each other; worth pursuing as an interop profile. |
| **Visa TAP** | Agent identity and payment trust | Payment-scoped. Same complement as ERC-7710. |
| **W3C Verifiable Credentials 2.0** | Credential data model, issuance, revocation | The Delegation Credential SHOULD be expressible as a VC. A VC profile is v0.3 work (§14). |
| **UCAN / ZCAP-LD** | Object-capability delegation, attenuation, chaining | Prior art for delegation chains. Sub-delegation (§14) should follow UCAN attenuation semantics rather than invent new ones. |
| **OAuth 2.0 / GNAP** | Human-to-application authorization | Different problem. OAuth authorizes *access*; this authorizes *contractual commitment*. Do not model this as OAuth scopes — an access token is not evidence of assent and does not survive as a record. |
| **RFC 8785 (JCS)** | JSON canonicalization | Required for every hash and signature here, as in v0.1. |

The honest positioning: the identity and payment layers are well served and
consolidating fast. Nothing in this table binds a named principal's authority
to a specific set of *terms* and preserves it as verifiable evidence. That is
the gap this extension fills, and it is narrow enough to be defensible and
wide enough to matter.

---

## 12. Legal Design Rationale

*Design rationale, not legal advice. The protocol records facts; it does not
determine enforceability, authority, jurisdiction, or liability. Those are
questions for the parties' counsel and any adjudicator.*

Under UETA § 14 and ESIGN 15 U.S.C. § 7001(h), a contract formed by an
electronic agent binds the principal without human review. Agency doctrine
then supplies the limits: a principal is bound within the agent's **actual**
authority, and may also be bound by **apparent** authority — what a third
party reasonably believed based on the principal's own manifestations
(Restatement (Third) of Agency §§ 2.01, 2.03, 3.03).

A verifiable, scoped delegation changes the evidentiary position for both
sides, which is why both sides have reason to adopt it:

**For the principal.** Scope limits are documentary evidence of the bounds of
actual authority, fixed before the transaction rather than asserted after it.

**For the counterparty.** A verified credential is the stronger benefit and
the one that drives adoption. A counterparty who checked authority before
transacting is not relying on an appearance — it is relying on a
representation the principal signed. That substantially undercuts a later
claim that the agent went rogue.

**The trade the principal is making.** Publishing discoverable scope also
*limits* apparent authority, because a counterparty who can read the scope
cannot easily claim a reasonable belief that authority ran beyond it. A
principal gains protection against over-committing agents and gives up the
ambiguity that a counterparty might otherwise have exploited. That is a
sound trade for anyone deploying agents at volume, and it should be stated
to buyers plainly rather than sold as costless.

None of this is self-executing. The record is evidence an adjudicator can
verify; it is not a determination.

---

## 13. Security Considerations

**Confused deputy.** An agent holding a broad delegation can be induced by a
malicious counterparty into committing within scope but against the
principal's interest. Scope alone cannot prevent this. `prohibited_clauses`
and `requires_authorization_above` are the mitigations; narrow scopes and low
thresholds are the operational answer. Implementations SHOULD warn when a
delegation's scope is unusually broad relative to peers.

**Over-broad delegation as the default failure.** The realistic failure mode
is not forgery, it is a principal issuing one wildcard delegation with a
distant expiry because it is easier. Implementations SHOULD make narrow,
short-lived delegations the path of least resistance, and SHOULD NOT offer a
one-click unlimited grant.

**Agent key compromise.** Compromise of `agent.public_key_ref` allows
commitment within scope until revocation. Scope caps the blast radius;
`aggregate_cap` caps it over time. This is the argument for per-agent keys
over a shared principal key.

**Authorization replay.** Binding to a single `agreement_hash` plus a short
`expires_at` prevents reuse. Verifiers MUST reject an event whose
`agreement_hash` does not match the agreement in hand.

**Revocation list availability.** If `check_url` is unreachable, a verifier
cannot establish current status. Verifiers MUST report unknown status rather
than defaulting to valid. Anchoring the revocation list (`anchor_ref`)
provides a fallback attestation of its state at a point in time.

**Threshold bypass.** An agent could split one commitment into several below
threshold. `aggregate_cap` over a rolling period is the defense; verifiers
SHOULD flag clustered sub-threshold commitments between the same parties.

**Principal identity enumeration.** See §7. Hash pseudonymity does not resist
dictionary attack over a small identifier space. Do not represent it as
anonymity.

**Directory scope injection.** Inherited from v0.1 §11 and extended: a
delegation credential MUST NOT be accepted from the counterparty. It comes
from the principal or its resolvable DID document, never from the party on
the other side of the transaction.

---

## 14. Open Questions (v0.2 → v0.3)

- **Sub-delegation.** May an agent delegate to a sub-agent? Multi-agent
  systems will require it. Attenuation semantics should follow UCAN rather
  than be invented here. Chain depth limits and liability attribution across
  a chain are unresolved.
- **Salted principal commitments.** Closing the enumeration gap in §7 without
  making Level 0 proofs interactive.
- **W3C VC profile.** Expressing the Delegation Credential as a Verifiable
  Credential for interoperability with existing issuance and status
  infrastructure (StatusList2021 for revocation).
- **AP2 interop profile.** Mapping between an Intent Mandate and a Delegation
  Credential, so an agent authorized to purchase is also authorized to accept
  the terms of that purchase.
- **Machine comprehension.** `comprehension.attested` currently presumes a
  human. Whether an agent can meaningfully attest to understanding, and what
  that would prove, is unresolved and should not be shipped until it is.
- **Standing organizational authority.** Mapping a corporate signing-authority
  matrix — approval tiers, dual signatures, board thresholds — onto
  delegations. Dual-control ("two principals must both authorize") is not
  expressible in v0.2 and enterprise buyers will ask for it.
- **Cross-jurisdiction scope.** Whether scope should carry governing-law or
  jurisdiction constraints, or whether that belongs in the agreement.

---

## 15. Implementation Notes

Ordered by dependency, not by priority.

1. **Agreement schema v0.2** — add the `authority` object (§6). Additive and
   optional; v0.1 agreements remain valid and read as `unauthorized`.
2. **Delegation credential issuance + verification** — self-contained mode
   first. It has no chain dependency and covers the legal/compliance ICP.
3. **Revocation endpoint** — `.well-known/delegations/revoked.json`, plus
   publishing it for Blocksee's own principal identity.
4. **Level 1A verification in `@consenti/verifier`** — the reference
   implementation is what makes the claim checkable by a third party. Until
   this exists, authorization is documented but not verifiable, which is the
   state this document was written to end.
5. **Authorization Event + out-of-band confirmation channel** — the threshold
   mechanism. Depends on a delivery channel the agent does not control.
6. **Directory `requires_authority`** (§10.1) and **403** (§10.2) — the
   demand side. Only useful once counterparties can verify.
7. **ERC-7710 chain binding** — after self-contained mode is proven.

Two corrections to live artifacts, independent of the above:

- `blocksee.co/.well-known/agreements.json` omits the `signature` block that
  Discovery §4.3 says publishers SHOULD include. The reference implementation
  should not be non-conformant with its own spec.
- The same file declares `"anchor_chains": ["pangea"]` while document
  anchoring reportedly runs against Ethereum. Confirm whether these are
  distinct layers (Merkle-root anchoring vs document anchoring) and reconcile
  the published directory either way.

---

**Protocol:** Consenti Agreement Protocol
**Repository:** `github.com/consenti-ai/agreement-protocol`
**Governance:** BDFL + RFC process
**License:** MIT — spec and reference implementations
**Contact:** eric@blocksee.co

---

## 16. Amendments from the Reference Implementation

Decisions the first implementation (`src/authority.ts`) had to make where the
draft above was silent or ambiguous. Each is normative for v0.2 unless revised.

**A1. `authority` is excluded from `agreement_hash`.** An Authorization Event
binds to `agreement_hash` (§5.1), and the authority object carries that event's
hash (§6). Including `authority` in the agreement hash would make the two
circular. Records carrying `authority` MUST list it in
`canonicalization.excluded_fields`; verifiers MUST reject records that do not.
Authority integrity is carried instead by `authority_commitment` on the anchor
(§7) and, from Level 1A step 4, by the agent's signature over the agreement.

**A2. The signing key must belong to the principal.** A valid signature proves
nothing if the signer chose the key. For `did` principals,
`signature.public_key_ref` MUST be a fragment of the principal DID. For any
other identifier type, a verifier MUST establish ownership out of band and MUST
fail closed if it cannot. The same rule applies to the revocation list.

**A3. Revocation lists are signed and must be fresh.** A revocation list MUST be
signed by the principal under A2. An unsigned list, a list whose signature fails,
or a list whose `updated_at` precedes the commitment yields status `unknown`. A
list published before the commitment cannot speak to a revocation in between.

**A4. Revocation timing.** Where several entries name one delegation, the
earliest `revoked_at` governs. The ambiguity window (§9) is a verifier parameter,
default one second. The verifier takes commitment time as an input; callers
SHOULD pass the anchor timestamp where one exists, since §9 names it the
tiebreaker, and fall back to `acceptor.accepted_at` otherwise.

**A5. Scope profiles.** Credentials MAY carry an optional `profile` naming a
namespaced action vocabulary (for example `consenti/media-licensing/v0.1`). The
core spec defines no action names; profiles do.

**A6. ES256 encoding.** Signatures MAY be raw r||s (preferred) or DER.
Verifiers MUST normalize before verification. The v0.2 reference verifier
supports ES256 only and fails closed on any other algorithm.

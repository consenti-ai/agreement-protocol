# Consenti Authority to Accept Terms v0.3

### Vocabulary, Verification, and Mappings to Existing Authorization Standards

**Status:** Draft. Supersedes *Consenti Delegation & Principal Authorization Extension v0.2*. Section 17 states what is implemented and what is not.
**Revised:** 19 November 2026, adding the AAuth mapping (§5.2).
**Protocol ID:** `consenti/authority/v0.3`
**Extends:** [Discovery Spec v0.1](./well-known-agreements-spec.md) · [Privacy Architecture v0.1](./agreement-privacy-architecture.md) · Agreement Schema v0.1
**Companion document:** [Consenti x402 Binding v0.1](./x402-binding-v0.1.md) (draft, not implemented)
**Maintainer:** Consenti (FHBK Technologies, Inc.)
**License:** MIT

---

## 0. What changed from v0.2

v0.2 defined its own delegation credential. Review against existing work showed that the grant itself is already well served: the IETF Agent Authorization Protocol draft, AAuth, AP2 mandates, W3C Verifiable Credentials, ERC-7710, UCAN and zCap all carry scoped, expiring, revocable grants from a principal to an agent (for AAuth, issued by a server acting for the principal). Accepting terms is one more action an agent takes, and any of those can carry the permission to take it.

What they do not yet define is a vocabulary for authority over *terms*, a place in the agreement record for that authority, and a procedure for verifying it after the fact. v0.3 keeps those and stops defining a credential.

| v0.2 | v0.3 |
|---|---|
| Normative Consenti Delegation Credential (§4) | Grants come from any **authority source** meeting §5.1. The v0.2 format survives as a fallback in Appendix A. |
| `scope` block inside the Consenti credential | An `accept_terms` scope object (§4) that other formats carry |
| Authorization Event | Renamed **Approval Event** (§6). Content unchanged; AP2 Cart Mandate countersignature and AAuth per-call approval mapped as equivalents under stated conditions. |
| Amendments A1 to A7 (§16) | Folded into the normative text. Traceability in Appendix B. |
| A4 commitment-time rules, an amendment | Promoted to their own section, **§9 Commitment Time**, ahead of the verification procedure |
| A5 "scope profiles" | Renamed **clause vocabularies** (§4.3) |
| §17 x402 binding | Moved to its own document |
| Related standards table (§11) | Expanded and corrected (§13) |

v0.2 records remain verifiable. A v0.2 `authority` object is read as `source.type = "consenti_native"`.

---

## 1. Purpose

Under UETA § 14 and ESIGN, 15 U.S.C. § 7001(h), a contract formed by an electronic agent binds its principal. Agents already accept terms of service, licences, purchase terms and data-use terms on someone's behalf. When a dispute arrives, three questions matter: what terms were accepted, by which agent, and whether that agent was allowed to accept them for that principal.

Existing standards answer the second question well and parts of the third. A verifier holding an agreement record and an access grant still cannot tell whether the grant covered *these terms*, or whether it was valid at the moment of commitment rather than at the moment of checking.

This document defines:

1. An `accept_terms` scope object stating what terms an agent may accept (§4).
2. Requirements any authority source must meet to back an agreement, and mappings for the main existing sources (§5).
3. A per-agreement Approval Event for commitments above a principal's threshold (§6).
4. The `authority` object inside the agreement record (§7).
5. A verification procedure that a third party can run later, without trusting any party or Consenti (§10), built on a defined treatment of commitment time (§9).

**Scope.** Authority to commit to terms. Not negotiation, payment, escrow, or adjudication. Payment-rail bindings are separate documents.

---

## 2. Design Principles

**Do not invent a credential.** Use an existing grant format wherever one can carry the scope. Define only what none of them define.

**Authority is evidence, not configuration.** If a third party who trusts neither party nor Consenti cannot check it after the fact, it does not belong in this layer.

**Standing authority and per-commitment approval are different acts.** A grant says *this agent may accept terms of this kind, up to these limits, until this date*. An Approval Event says *this principal approved this specific agreement at this moment*. High-value commitments need both.

**Verification happens later than enforcement.** Access-control systems ask whether an action is permitted now. An adjudicator asks whether it was permitted then. Sections 9 and 10 are built for the second question.

**Absence is a state and must be representable.** An agent accepting terms on its own account produces a valid, unauthorized commitment. The record says so explicitly.

**The principal's identity is as private as the party's.** Authority must not reintroduce plaintext identity at the anchor layer.

---

## 3. Model

| | Grant | Approval Event |
|---|---|---|
| **Answers** | May this agent accept this class of terms? | Did the principal approve this agreement? |
| **Lifetime** | Standing, until expiry or revocation | One agreement |
| **Issued** | Ahead of time, out of band | At commitment time |
| **Bound to** | An agent key and an `accept_terms` scope | A specific `agreement_hash` |
| **Format** | Any authority source meeting §5.1 | §6, or a mapped equivalent |
| **Required** | Always, to claim authorized status | Above the principal's threshold |

---

## 4. The `accept_terms` Scope Object

### 4.1 Format

```json
{
  "type": "accept_terms",
  "vocabulary": "consenti/clauses/commerce/v0.1",
  "counterparties": ["did:web:supplier.example"],
  "terms_classes": ["purchase", "data_access"],
  "max_value": { "amount": "5000.00", "currency": "USD" },
  "aggregate_cap": { "amount": "50000.00", "currency": "USD", "period": "P30D" },
  "prohibited_clauses": ["arbitration_waiver", "perpetual_license", "auto_renew"],
  "requires_approval_above": { "amount": "1000.00", "currency": "USD" },
  "payment_accounts": ["eip155:8453:0x4b1e…"]
}
```

### 4.2 Fields

| Field | Required | Description |
|---|---|---|
| `type` | yes | The literal `accept_terms`. Lets the object sit beside other action types in a container such as an `authorization_details` array. |
| `vocabulary` | yes if `terms_classes` or `prohibited_clauses` is present | Namespaced clause vocabulary (§4.3) that gives those values meaning. |
| `counterparties` | yes | Identifiers the agent may contract with. Unbounded is expressed as `["*"]`, never by omission. |
| `terms_classes` | yes | Kinds of agreement the agent may enter, from the vocabulary. `["*"]` for any. |
| `max_value` | yes | Ceiling on the value of a single commitment. |
| `aggregate_cap` | no | Ceiling over a rolling period. The defense against splitting one commitment into many. |
| `prohibited_clauses` | no | Clause types the agent may not accept at any value. |
| `requires_approval_above` | no | Value above which an Approval Event (§6) is also required. Absent means the grant alone suffices up to `max_value`. |
| `payment_accounts` | no | CAIP-10 accounts the agent pays from. Payment-rail bindings may require it. Because it sits inside the grant, the principal's signature covers it. |

The object MUST be covered by the principal's signature in whatever authority source carries it. An `accept_terms` object the agent or counterparty could edit is not a scope.

### 4.3 Clause vocabularies

The core defines no clause or terms-class names. A vocabulary is a published, versioned list of names with definitions and the agreement-schema clause paths each name matches, for example `consenti/clauses/commerce/v0.1` or `consenti/clauses/media-licensing/v0.1`. A verifier that does not recognize a grant's vocabulary MUST report the scope check as `unknown`, not passed.

Vocabulary design is open work (§16). Clause classification is a judgment, and the vocabulary should say who makes it and how a disputed classification is recorded.

### 4.4 Attenuation

Where one `accept_terms` object is derived from another (a sub-delegation, or the second artifact of a composite grant under §5.3), the derived object MUST be narrower than or equal to its parent, member by member:

| Member | Derived object must be |
|---|---|
| `vocabulary` | Identical. A derived object under a different vocabulary is invalid. |
| `counterparties` | A subset. `["*"]` in the parent admits any set; `["*"]` in the child requires `["*"]` in the parent. |
| `terms_classes` | A subset, under the same rule for `["*"]`. |
| `max_value` | Less than or equal, in the same currency. A currency the parent does not carry is invalid. |
| `aggregate_cap` | Amount less than or equal, same currency, and a period no longer than the parent's. Present in the child if present in the parent. |
| `prohibited_clauses` | A superset. A child may prohibit more, never less. |
| `requires_approval_above` | Less than or equal. Present in the child if present in the parent. A child may require approval sooner, never later. |
| `payment_accounts` | A subset. |

A verifier evaluating a derived object MUST check it against every ancestor it can resolve and MUST report the scope step as `fail` on any violation and `unknown` if an ancestor cannot be resolved.

These rules follow the "narrower than or equal to" relation used by the IETF Agent Authorization Protocol draft for its own entry types, so that `accept_terms` attenuates the same way when carried there.

---

## 5. Authority Sources

### 5.1 Requirements

An authority source can back a Consenti agreement if it provides all of the following. Each mapping in §5.2 states how.

| # | Requirement | Why |
|---|---|---|
| R1 | A principal identifier and a signature by that principal, verifiable against a key the principal controls | Otherwise anyone can claim to be the principal |
| R2 | A binding to the agent's signing key | §10 step 5: ties the agreement signature to the grant |
| R3 | The `accept_terms` object, or a defined equivalent, under the principal's signature | The scope check needs it |
| R4 | Issuance and expiry times | Window checks (§9) |
| R5 | Revocation status determinable **for a past time window**, not only now | An adjudicator asks about the commitment window, not the day of review (§9) |
| R6 | A stable reference and hash, so the agreement record can commit to the exact grant | §7 |

A source that meets R1, R2, R4 and R6 but not R3 can still back a commitment if paired with a second artifact that carries R3 under the same principal's signature and names the first by hash (composite grant, §5.3). A source that does not meet R5 yields `unknown` at the revocation step unless a trusted time (§9.2) falls inside a period the source can vouch for.

### 5.2 Mappings

Status key: **Specified** means this document defines the mapping completely. **Needs upstream change** means the source standard must change before the mapping works. **Untested** applies to every mapping except the native fallback; no interoperability testing has been done.

#### W3C Verifiable Credentials 2.0 (recommended default)

| Req | Mapping |
|---|---|
| R1 | `issuer` is the principal; proof by Data Integrity or by securing with JOSE/COSE (including SD-JWT VC), per VC 2.0 |
| R2 | `credentialSubject.id` is the agent; `credentialSubject.agentKey` names the agent's signing key |
| R3 | `credentialSubject.accept_terms` carries the §4 object |
| R4 | `validFrom`, `validUntil` |
| R5 | `credentialStatus` using W3C Bitstring Status List. **Gap:** a status list reports current state. To meet R5 the issuer MUST keep and sign dated snapshots, or anchor each list publication, so a verifier can establish status during a past window. Without that, VC status is current-only. |
| R6 | Credential URL plus JCS hash of the credential |

Status: Specified. Untested. Credential type name and JSON-LD context to be published.

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2", "<consenti authority context, to be published>"],
  "type": ["VerifiableCredential", "ConsentiTermsAuthority"],
  "issuer": "did:web:acme.example",
  "validFrom": "2026-11-01T00:00:00Z",
  "validUntil": "2027-04-30T23:59:59Z",
  "credentialSubject": {
    "id": "did:web:acme.example:agents:procurement-3",
    "agentKey": "did:web:acme.example#agent-key-3",
    "accept_terms": { "type": "accept_terms", "…": "§4 object" }
  },
  "credentialStatus": {
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "4211",
    "statusListCredential": "https://acme.example/status/3"
  }
}
```

#### AP2 Intent Mandate and Cart Mandate

Based on AP2 v0.1. Verify against the current AP2 release before relying on this mapping.

| Req | Mapping |
|---|---|
| R1 | User signature on the mandate, from a device-bound key |
| R2 | **Gap.** The mandate authorizes a purchase by a shopping agent; it does not name an agent signing key for agreements. |
| R3 | **Partial.** Allowed merchants map to `counterparties`; `requires_refundability` is a single clause constraint; the natural-language description is not machine-checkable. No field for `prohibited_clauses` or terms classes, and v0.1 has no mandate-level extension point. |
| R4 | `intent_expiry`, `cart_expiry` |
| R5 | Not defined in the mandate. |
| R6 | Mandate hash |

**Per-agreement approval.** A Cart Mandate signed by the merchant and countersigned by the user is a strong Approval Event (§6) *if* the cart contents include the terms hash the agent accepted. AP2 v0.1 does not carry terms. Adding `terms_url` and `terms_hash` to the Cart Mandate contents would let AP2 bind approval to terms with one field. That change is proposed upstream, not assumed here.

Status: Needs upstream change for standalone use. Usable today as a composite (§5.3): the Intent Mandate for the purchase grant, plus a VC carrying `accept_terms` that names the mandate by hash.

#### IETF Agent Authorization Protocol (draft-fane-opena2a-aap)

Based on draft-02 (30 September 2026), an individual submission. Not to be confused with AAuth, below: different drafts, different authors.

| Req | Mapping |
|---|---|
| R1 | Capability Grant Token signed per the draft (JWS) |
| R2 | Agent identity assertion and proof-of-possession binding |
| R3 | **Needs upstream change, for part of the object.** draft-02 fixes seven `authorization_details` entry types (`mcp_tool`, `skill`, `peer_agent`, `model`, `network`, `data`, `budget`), new types arrive by revision of the draft, and verifiers MUST reject unknown types. Value limits already have a home: `budget` carries spend caps with an attenuation rule matching §4.4. What no AAP type carries is terms-specific scope. See "Split across AAP entry types" below. |
| R4 | Token `iat`, `exp`. Lifetimes are short by design (15 minutes to 4 hours by tier), so the agent MUST retain the token and the agreement record MUST commit to its hash. |
| R5 | **Gap.** Grant revocation is checked by the broker at resolution time. The draft does not define how to establish revocation status at a past time. Verifiers report `unknown` unless the token's own short validity period contains the commitment window, in which case expiry alone bounds the exposure and the record says so. |
| R6 | Token hash |

**Split across AAP entry types.** Inside an AAP Capability Grant Token, the §4 object is not carried whole. It is split so that AAP's existing types do what they already do:

| §4 member | Carried in AAP by |
|---|---|
| `max_value`, `aggregate_cap` | The grant's `budget` entry (spend limit and period). Not repeated in `accept_terms`. |
| `counterparties` | Proposed `accept_terms` entry. (`peer_agent` names agents for delegation, not contracting counterparties, so it is not reused.) |
| `vocabulary`, `terms_classes`, `prohibited_clauses`, `requires_approval_above` | Proposed `accept_terms` entry |
| Approval above threshold | The entry's `requiresApproval` member and the broker's escalation hook, mapped under §6.4 |
| `payment_accounts` | No AAP equivalent in draft-02. Composite VC where a binding requires it. |

The proposed entry, in AAP's form, would look like:

```json
{
  "type": "https://specs.opena2a.org/aap/types/accept_terms",
  "vocabulary": "consenti/clauses/commerce/v0.1",
  "counterparties": ["did:web:supplier.example"],
  "terms_classes": ["purchase"],
  "prohibited_clauses": ["arbitration_waiver", "auto_renew"],
  "requires_approval_above": { "amount": "1000.00", "currency": "USD" }
}
```

The type URI sits in AAP's namespace and is a proposal to its author, not a registration. Attenuation follows §4.4 for the members it carries; the `budget` entry attenuates under AAP's own rule. A Level 1A verifier reconstructs the §4 object from the `accept_terms` and `budget` entries of the same token before step 6, and reports the scope step `unknown` if the token carries `accept_terms` without a `budget` entry in a matching currency.

Status: Needs upstream change. Until then, usable as a composite: AAP for agent identity, the grant and its `budget`, plus a VC carrying the terms-specific members that names the AAP grant by hash.

#### AAuth (draft-hardt-oauth-aauth-protocol) with R3

Based on draft-11 (25 September 2026) and its companion, AAuth Rich Resource Requests, draft-hardt-aauth-r3-00 (28 September 2026). Both are individual submissions; R3 is marked exploratory. Verify against current revisions before relying on this mapping.

In AAuth, authority comes from a server, not from the person. In three-party deployments the **Person Server (PS)** acts for the person: it runs consent, approves missions, and signs auth tokens (`typ: aa-auth+jwt`). In four-party deployments the auth token is signed by the **resource's own Access Server (AS)**, named in the token's `aud`, which in a purchase is the counterparty's server. The person signs nothing; approval is recorded at the PS through an authenticated channel. A separate agent provider issues the agent token (`typ: aa-agent+jwt`) that binds the agent's key to its identifier. That division shapes R1 and the approval mapping below.

| Req | Mapping |
|---|---|
| R1 | **Conditional.** The auth token is signed by the PS or AS, not by the person. R1 is met only where the signing key is a key the principal controls under the key-ownership rule (§15): in practice, an organization running its own PS under its own domain or DID, in a three-party deployment. A four-party token is signed by the counterparty's AS and can never meet R1 this way. Where R1 is not met by key ownership, it is met only by Route 2 below, in which a principal-signed VC supplies R1 and R3 and the AAuth tokens serve only to bind the agent's key (R2). AAuth itself states that a person token proves continuity ("the same entity again"), not verified legal identity. |
| R2 | The auth token's `cnf.jwk` (required) binds it to the agent's key; the agent token binds that key to the agent identifier (`sub`, of the form `aauth:local@domain`). **Algorithm note:** AAuth parties MUST support Ed25519 and SHOULD support ES256. The reference verifier supports ES256 only (Appendix A.1), so agreements signed with an Ed25519 agent key cannot be verified until Ed25519 is added. |
| R3 | **Partial.** AAuth expresses authorization as `scope` strings or, with R3, as operations in a published vocabulary that the issuer (PS or AS) lists in the auth token's `r3_granted`. The principal's standing policy (the equivalent of the §4 object) stays inside the PS and is not carried in any token. Two routes, below: a per-agreement grant through a Consenti R3 vocabulary, or a composite VC for standing scope. |
| R4 | Auth token `iat`, `exp`. Auth tokens MUST NOT exceed one hour; agent tokens SHOULD NOT exceed 24 hours; a mission may carry `expires_at`. The agent MUST retain the auth token, and the agreement record MUST commit to its hash. |
| R5 | **Gap.** A PS or AS SHOULD offer a revocation endpoint. A server without one honors a revoked token until `exp`, and revocation records MAY be discarded once a token is past `exp` plus clock skew. Nothing establishes revocation status at a past time; AAuth describes its own signatures as request-time authentication, not long-term non-repudiation. Verifiers report the revocation step `unknown`, even when a trusted time falls within the token's life: AAuth cannot vouch for non-revocation at a past time, so the §5.1 exception does not apply. The PS's mission log could support reconstruction but is not defined as evidence a third party can verify. |
| R6 | Hash of the auth token JWS. Where present, `mission_s256` and `r3_s256` are recorded alongside it. |

**Route 1: a per-agreement grant through R3.** R3 lets third parties define vocabularies under their own URI namespaces. This document proposes one, `https://consenti.ai/r3/accept-terms/v0.1` (not yet published), with a single operation, `accept_terms`, which the seller marks `per-call` so that each acceptance is approved with its parameters (terms hash, terms class, value).

In R3 the resource writes the R3 document, mapping the operations an agent requests; agents cannot fetch R3 documents, only the PS and AS can. A seller supporting this route advertises the vocabulary in `r3_vocabularies` in its `/.well-known/aauth-resource.json`, and challenges an acceptance with a per-call proposal like this:

```json
{
  "vocabulary": "https://consenti.ai/r3/accept-terms/v0.1",
  "operations": [ { "operation": "accept_terms" } ],
  "parameters": {
    "terms_hash": "sha256:8fa574…",
    "terms_class": "purchase",
    "value": { "amount": "750.00", "currency": "USD" }
  },
  "display": {
    "summary": "Accept supplier.example purchase terms, $750",
    "irreversible": "Acceptance binds the principal to these terms."
  }
}
```

After approval, the issuer (the PS in three-party, the AS in four-party) issues a single-use per-call auth token that repeats the proposal's `r3_uri` and `r3_s256` and lists `accept_terms` in `r3_granted`. The token itself carries no terms; they are bound through `r3_s256`. Because agents cannot fetch R3 documents, the seller, which keeps the proposal under its `r3_s256`, MUST add the proposal bytes to the agreement record. The verifier checks them against `r3_s256` before Level 1A step 6, then matches the proposal's `terms_hash` and value against the agreement in hand, and reports the scope step `fail` on a mismatch and `unknown` if the proposal is absent. It does not evaluate the principal's standing policy, which no token carries; the record says so.

Under Route 1 the per-call auth token is both the grant (`source_type: aauth`) and the approval (`aauth_per_call`); both entries in the `authority` object (§7) reference the same hash. This route needs no change to AAuth or R3. It does need the seller to support R3 per-call and to disclose the proposal. Registering the vocabulary in the R3 Vocabulary Registry is optional.

**Route 2: standing scope by composite.** A principal-signed VC carries the §4 object and names the AAuth agent. AAuth tokens live an hour or less, too short to name by hash ahead of time, and the auth token carries no agent identifier, so the VC names the agent by its identifier and its key's JWK Thumbprint, computed per RFC 7638 from the auth token's `cnf.jwk` (AAuth carries the same value as `agent_jkt` in resource tokens). This is the stable binding §5.3 permits for short-lived sources. The agreement record commits to the VC hash, the auth token hash, and the agent token hash, which links `sub` to the key. A key rotation breaks the binding until the VC is reissued.

**Approval.** R3's `per-call` access mode has the issuer ask for approval on each call. AAuth says the PS SHOULD record interaction requests and responses in the mission log, and its consent screen MUST distinguish resource-asserted from agent-asserted content. Recorded as approval type `aauth_per_call`. It meets §6.4 only where R1 holds by key ownership. Otherwise it is a server's attestation of approval, not the principal's (in four-party, the counterparty's server), and the approval step returns `unknown` unless the relying party's declared policy accepts server-attested approvals (§16). The per-call proposal, including its `display`, is hashed as `r3_s256` and repeated in the per-call token; `presented.summary_hash` MAY carry that value, recorded as a hash of resource-asserted content, not of what the PS rendered. No hash of the PS's rendering is defined.

**Delegation.** AAuth deliberately has no delegation-chain claim: the PS authorizes every hop and holds the mission log, and sub-agents are one level deep via `parent_agent`. A third party cannot check that chain without the PS, so §4.4 attenuation applies only to the composite VC.

Status: Partially specified. Untested. Route 1 needs the Consenti R3 vocabulary published and seller support for R3 per-call; both routes need Ed25519 in the reference verifier where agents use it; R5 remains a gap.

#### ERC-7710 delegations

| Req | Mapping |
|---|---|
| R1 | Delegator smart account signature |
| R2 | Delegate account. Where the agent signs agreements with a different key, the composite VC names both. |
| R3 | A caveat enforcer for `accept_terms` would need to be written. Value caps are expressible with existing enforcers; clause constraints are not on-chain concepts. |
| R4 | Timestamp caveats |
| R5 | **Strongest of the sources.** Revocation is chain state with history, so status at a past block is determinable. |
| R6 | Delegation hash |

Status: Partially specified. Recommended where the agent transacts on-chain anyway.

#### UCAN and zCap

Both support attenuated delegation chains, which v0.3 does not yet define (§16). A UCAN capability with `accept_terms` as its ability and the §4 object as caveats meets R1 to R4 and R6. R5 depends on the revocation mechanism deployed. Status: not yet mapped in detail. These are the reference for sub-delegation semantics.

#### Consenti native credential (fallback)

The v0.2 credential, retained in Appendix A for principals with no other source and for backward compatibility. Meets R1 to R6; R5 through the signed revocation list in Appendix A.2. Status: Implemented in the reference verifier. New deployments SHOULD prefer a VC.

### 5.3 Composite grants

Where one source carries identity and grant but cannot carry the `accept_terms` scope, a second artifact may. Rules:

1. Both MUST be signed by the same principal under R1, except where a mapping states that the second artifact alone supplies R1 (AAuth, Route 2); the first then serves only to bind the agent's key.
2. The second MUST name the first by hash. Where the first artifact lives too briefly to name in advance, a mapping MAY define a stable binding instead (the AAuth mapping names the agent by identifier and key thumbprint), and the agreement record then commits to the hashes of both artifacts.
3. The second MAY only narrow what the first grants, under the attenuation rules in §4.4. It cannot widen it.
4. Expiry of the composite is the earlier of the two. Revocation of either revokes the composite.
5. Both are evaluated over the commitment window (§9).

---

## 6. The Approval Event

Required when a commitment exceeds `requires_approval_above`, or whenever the principal's policy demands a human in the loop.

```json
{
  "type": "consenti/approval/v0.3",
  "approval_id": "apv_c81f…",
  "grant_ref": { "source_type": "w3c_vc", "grant_hash": "sha256:…" },
  "agreement_hash": "sha256:8fa574…",
  "decision": "approved",
  "approved_by": {
    "commitment": "sha256:9c4d…",
    "method": "webauthn",
    "channel": "principal_device"
  },
  "presented": {
    "summary_hash": "sha256:1a7f…",
    "disclosed_clause_paths": ["clauses.term", "clauses.value", "clauses.liability_cap"]
  },
  "comprehension": {
    "attested": true,
    "attestation_ref": "pou_4d21…",
    "method": "consenti/pou/v1"
  },
  "approved_at": "2026-11-15T09:12:44Z",
  "expires_at": "2026-11-15T09:27:44Z",
  "signature": { "algorithm": "ES256", "public_key_ref": "did:web:acme.example#key-1", "value": "base64url…" }
}
```

### 6.1 Rules

- MUST bind to exactly one `agreement_hash`. Not reusable, not transferable.
- MUST reference the grant the agent acts under. An approval with no grant is malformed.
- MUST reach the principal through a channel the agent does not control. An agent that can mint its own approval has not solved the problem.
- `method` SHOULD be a phishing-resistant authenticator such as a passkey. SMS and email confirmations are permitted but are weaker evidence, and the record says which was used.
- SHOULD carry a short `expires_at`. Fifteen minutes is the reference default. An approval that expires before a trusted time is bound to the agreement yields `unknown` under §9.4, so approved commitments need prompt anchoring (§9.5).
- `decision` is one of `approved`, `denied`, `expired`. Denials are recorded and anchored like approvals.

### 6.2 `presented`: what the principal saw

`summary_hash` commits to the exact text shown to the approver; `disclosed_clause_paths` records which clauses were surfaced. An approval is only as good as what was in front of the approver. Implementations MUST populate it.

Under UETA § 10, an individual may avoid the effect of an error in an automated transaction where the electronic agent provided no opportunity to prevent or correct it. `presented` records whether that opportunity existed and what it showed. This is design rationale, not a legal conclusion (§14).

### 6.3 Comprehension

`comprehension` links an optional Proof of Understanding attestation. Approval and comprehension are separate claims. Never infer comprehension from approval; where no attestation exists the block is absent.

### 6.4 Mapped equivalents

A source-native approval MAY stand in for an Approval Event if it is signed by the principal, binds the `agreement_hash` or the accepted `terms_hash`, carries a time, and reached the principal through a channel the agent does not control. Equivalents mapped in this document: AP2 Cart Mandate countersignature (once it carries `terms_hash`, §5.2); AAP `requiresApproval` escalation (subject to the broker profile recording what was presented); AAuth `per-call` approval (only where the issuer's key is the principal's under §15; otherwise server-attested, §5.2). A mapped equivalent without `presented` content is recorded with `presented: null`, which verifiers surface.

---

## 7. The `authority` Object in the Agreement Record

```json
{
  "authority": {
    "status": "authorized",
    "grant": {
      "source_type": "w3c_vc",
      "ref": "https://acme.example/.well-known/grants/procurement-3.json",
      "grant_hash": "sha256:…",
      "composite_with": null
    },
    "approval": {
      "source_type": "consenti_approval",
      "ref": "…",
      "event_hash": "sha256:…"
    }
  }
}
```

`source_type` values defined here: `w3c_vc`, `ap2_intent_mandate`, `aap_grant`, `aauth`, `erc7710`, `ucan`, `consenti_native`. Approval types: `consenti_approval`, `ap2_cart_mandate`, `aap_escalation`, `aauth_per_call`. Other documents may define more.

`status` is one of:

| Value | Meaning |
|---|---|
| `authorized` | Valid grant, and an approval where the threshold required one |
| `granted_only` | Valid grant, commitment below threshold, no approval required |
| `unauthorized` | The agent accepted on its own account. No grant asserted. A valid commitment; an unauthorized one. |
| `exceeded_scope` | A grant exists and the commitment falls outside it. Agents MUST NOT commit in this state; the value lets a verifier label a non-conformant record. |

(`delegated_only` from v0.2 is read as `granted_only`.)

Rules carried from v0.2:

- `authority` is excluded from `agreement_hash`, because the approval binds to that hash. Records carrying `authority` MUST list it in `canonicalization.excluded_fields`; verifiers MUST reject records that do not.
- The agreement record carries hashes and references only. Plaintext principal names and job titles do not appear in it.

---

## 8. Privacy Model

Unchanged from v0.2 except for naming.

**Layer 1, anchor.** Adds `authority_commitment` (hash of the canonicalized `authority` object) and `authority_status`. Status is public because a counterparty's decision depends on it, and it reveals that an authorized commitment occurred, not by whom.

**Layer 2, private.** Grants and approvals are held by the parties. Consenti retains neither.

**Layer 3, selective disclosure.** The `authority` object is its own subtree of the clause Merkle tree, so a party can prove authority without disclosing terms, and terms without disclosing who approved them.

**Pseudonymity and its limit.** Published references to the principal use `SHA-256(canonical(identifier))`. Hashes of small, guessable identifier spaces such as `did:web:acme.example` fall to dictionary attack. Salted commitments are open work (§16). Do not describe hash pseudonymity as anonymity.

Choice of authority source affects privacy. A grant on a public chain (ERC-7710) is visible to anyone; a VC or native credential is disclosed only by the parties. A source that routes consent through a server (AAuth's PS, AAP's broker) gives that server a record of the principal's approvals. Principals should choose accordingly.

---

## 9. Commitment Time

This section is the core of the verification model. It applies to every authority source in §5, and requirement R5 exists because of it. The approach follows long-term validation of electronic signatures (ETSI EN 319 102-1), which solved the same ordering problem for certificates; this section applies it to agent grants.

### 9.1 The problem

Every authority check compares a boundary (when the grant was issued, when it expires, when it was revoked, when an approval expires) with the moment the agent committed. That moment is the hardest fact in the record to establish, because the only party that knows it is the agent whose authority is in question.

**Example.** An agent's grant is revoked at 14:22. At 14:30 the agent accepts terms and writes `accepted_at: 14:15` into the record. A verifier that trusts the asserted time reports the commitment as authorized. The same backdating defeats expiry checks, and an agent can backdate an acceptance into the life of an approval that has already lapsed.

Access-control systems do not face this, because they decide at the moment of use and the enforcement point's own clock is the time. A verifier reviewing a record weeks or years later has no enforcement point, only the record. This section defines how that verifier establishes commitment time without trusting the agent, and what it reports when it cannot.

### 9.2 Asserted time and trusted time

- The time a record asserts (`acceptor.accepted_at`) is **untrusted**. It is written by the party whose authority is in question.
- A **trusted time** is a time bound to `agreement_hash` by a third party. Sources defined here:
  - `anchor`: the block time of the anchor transaction carrying the hash.
  - `rfc3161`: the `genTime` of an RFC 3161 timestamp token over the hash.
- Binding documents may register more sources. The x402 binding registers `x402_settlement`.
- Verifiers MUST derive trusted time from the evidence themselves. They MUST NOT accept it as a caller input, and MUST NOT use the record's self-reported `anchoring.anchored_at`.

### 9.3 The commitment window

The **commitment window** runs from the asserted time to the earliest trusted time, or to the verification time where there is none. The commitment happened somewhere inside it; the verifier does not need to know where.

A record asserting a time after its own trusted time is malformed and fails.

### 9.4 Evaluating boundaries against the window

| Boundary position | Step result |
|---|---|
| Grant issued before the window starts, expiry after it ends, no revocation before or inside it, approval (if any) issued before it starts and unexpired at its end | `pass` |
| Grant expired, or revoked prospectively, before the window starts | `fail` |
| Grant issued after the window ends | `fail` |
| Any boundary inside the window | `unknown` |
| Any boundary within the ambiguity margin of either end of the window (verifier parameter, default one second) | `unknown` |

Where several revocations name one grant, the earliest governs.

**Why backdating cannot help.** When every boundary falls outside the window, the result is the same wherever in the window the commitment actually happened. An agent that backdates within the window changes nothing. An agent that backdates to before the window's true start widens the window, which can only pull more boundaries inside it and turn a `pass` into `unknown`.

**Why `unknown` is not `fail`.** A boundary inside the window means the order of events cannot be established from the evidence. That is not evidence the commitment was unauthorized, and reporting it as such would let a principal manufacture a failure by revoking promptly. The verifier says what the evidence supports and no more.

### 9.5 Consequences, stated plainly

- **Without a trusted time, a record can verify but cannot win a dispute over whether it came before a revocation.**
- **Unanchored records degrade.** With no trusted time the window runs to whenever the record is checked. Once the grant expires, or is revoked for any reason, the boundary falls inside the window and the record becomes `unknown` permanently.
- **Approved records degrade fastest.** An `authorized` record without a trusted time becomes `unknown` when its approval expires, fifteen minutes by default (§6.1).
- **Short-lived grants degrade too.** AAP tokens expire within hours; AAuth auth tokens within an hour. A record backed by one needs a trusted time inside the token's life.
- **Prompt anchoring fixes the window's end and stops the degradation.** Records meant to be relied on later need it. Payment-rail bindings can supply a trusted time as a side effect of settlement.

### 9.6 Residual: post-dating

An agent can also post-date a record. That only makes expiry and revocation checks stricter, but it can hide a commitment signed before the grant was issued. Disputes about issuance time need a trusted lower bound on commitment time, which this version does not define (§16).

### 9.7 What this asks of authority sources

The window can only be evaluated if the source can say whether the grant was revoked at any point in it. That is requirement R5 (§5.1), and it is where most existing grant formats fall short: status mechanisms built for access control report current state, not state during a past interval. The mappings in §5.2 state for each source whether R5 is met and what the verifier reports when it is not.

---

## 10. Verification: Level 1A, Authority Proof

**Question:** Was the signer authorized by the principal to accept these terms, at the time it accepted them?

**Inputs:** the agreement record · the grant (and composite artifact, if any) · the approval, where status is `authorized` · the anchor reference · any trusted-time evidence.

### 10.1 Procedure

1. **Verify the grant** under the mapping for its `source_type` (§5.2): principal signature (R1), hash matches `grant.grant_hash` (R6), and composite rules (§5.3) where `composite_with` is set.
2. **Form the commitment window** (§9.3) from the asserted time and any trusted time (§9.2).
3. **Check validity over the window** (§9.4). Grant issuance is before the window starts; expiry is after it ends.
4. **Check revocation over the window** (§9.4) by the source's R5 mechanism.
5. **Bind signature to authority.** The agreement signature verifies against the agent key named in the grant (R2). Without this step a verifier holds two unrelated documents.
6. **Evaluate scope.** The agreement against `accept_terms`: counterparty, terms class, `max_value`, `prohibited_clauses`, under the named vocabulary, and against ancestors under §4.4. For a per-agreement grant (AAuth Route 1), check the disclosed proposal against its hash and match its terms and value against the agreement.
7. **Verify the approval** where present: signature, `agreement_hash` or accepted `terms_hash` match (§6.4), grant reference match, and its issuance and expiry evaluated against the window (§9.4).
8. **Check the anchor.** Recompute the `authority` object hash and compare with `authority_commitment`.

Each step returns `pass`, `fail`, or `unknown`. Level 1A returns `valid` only if every step passes, `invalid` if any step fails, and `unknown` otherwise. A verifier MUST NOT report `valid` by default when a step could not be completed, and SHOULD report which step was `unknown` and why.

### 10.2 Disclosure

Level 1A discloses that the principal authorized this commitment and under what scope. It discloses nothing about the terms beyond what scope evaluation requires, and the scope evaluation result can be disclosed without the terms.

---

## 11. Revocation

Revocation mechanics belong to the authority source (§5.2, R5). This document sets the semantics every source must be read under.

**Prospective by default.** Commitments made before revocation remain authorized. A principal who could retroactively un-authorize any commitment could repudiate any deal, which removes the counterparty's reason to rely on the record.

**Retroactive revocation** exists only for key compromise. It is a distinct, louder claim, and verifiers MUST surface it prominently rather than silently invalidating.

**Ambiguity.** Where a revocation falls inside the commitment window, including the same block or timestamp granularity, the verifier reports `unknown`. This is a limitation of any distributed revocation scheme.

**Unavailability.** If status cannot be fetched or is not current through the end of the window, the step returns `unknown`.

**Push signals.** Event-based revocation, such as the OpenID Shared Signals Framework, MAY supplement a source's status mechanism. It shortens the time to enforcement. It does not by itself establish status at a past time unless the events are retained and timestamped by a third party.

---

## 12. Discovery Flow

Replacing the two undefined steps in Discovery v0.1 §5:

```
Agent A                                           Service B
  |-- GET /.well-known/agreements.json --------------->|
  |<-- 200 OK (directory) -----------------------------|
  |-- GET {agreement_ref} ---------------------------->|
  |<-- 200 OK (canonical agreement) -------------------|
  |-- verify agreement_hash                            |
  |                                                    |
  |== AUTHORITY EVALUATION ==                          |
  |-- load grant (any §5 source)                       |
  |-- check validity and revocation                    |
  |-- evaluate agreement against accept_terms          |
  |-- IF out of scope: HALT. Return to principal.      |
  |-- IF above requires_approval_above:                |
  |     request approval out of band; await decision   |
  |-- sign agreement with the grant's agent key        |
  |-- attach authority object (§7)                     |
  |                                                    |
  |-- POST signed commitment ------------------------->|
  |                                    verify Level 1A |
  |<-- 201 Created (agreement_id, anchor_ref) ---------|
```

### 12.1 Counterparty requirements

Directory entries MAY declare:

```json
{
  "requires_authority": {
    "minimum_status": "granted_only",
    "above_value": { "amount": "10000.00", "currency": "USD" },
    "accepted_sources": ["w3c_vc", "erc7710", "consenti_native"]
  }
}
```

`accepted_sources` lets a service state which grant formats it can verify.

### 12.2 403 Authorization Required

409 means *you have not agreed to terms*. 403 means *you have agreed but have not shown authority to*. Over plain HTTP the resolution order is 409, then 403, then payment. Payment-rail bindings may fold these into the rail's own exchange; see the x402 binding.

```http
HTTP/1.1 403 Authorization Required
Content-Type: application/agreement+json
Link: <https://example.com/.well-known/agreements.json>; rel="agreement-directory"

{
  "error": "authority_required",
  "minimum_status": "authorized",
  "accepted_sources": ["w3c_vc", "consenti_native"],
  "authority_endpoint": "https://example.com/api/authority/present"
}
```

---

## 13. Relationship to Other Work

This document depends on the work below, and several of these efforts address parts of the same problem. Characterizations are ours and may be incomplete; corrections from the authors are welcome.

| Work | What it does | Relationship |
|---|---|---|
| **Agent Authorization Protocol** (IETF individual draft, A. Fane, OpenA2A) | Agent identity assertions, scoped short-lived capability grants, attenuating delegation, revocation propagation, behavioral attestation; built on OAuth token exchange and RAR | Mapped authority source (§5.2). `accept_terms` proposed as an additional entry type. Complementary: AAP governs whether an agent may act now; this document verifies later whether an acceptance of terms was within authority. |
| **AAuth** (IETF individual draft, D. Hardt), with **R3** (Rich Resource Requests) | Agent identity via agent providers and HTTP Message Signatures; person servers that run consent, approve missions and issue key-bound auth tokens; R3 vocabularies for structured operations, including per-call approval | Mapped authority source (§5.2). A Consenti R3 vocabulary is proposed for per-agreement grants. Complementary: AAuth authorizes requests at the time they are made; this document verifies acceptance of terms after the fact. AAuth's resource metadata can point to terms (`tos_uri`) but does not record assent to them. An earlier version (draft-hardt-aauth-protocol-01) is listed among the delegation standards in the AAIF Identity & Trust reference architecture. |
| **AP2** (Google and partners) | Intent, Cart and Payment mandates for agent purchases | Closest analogue. Intent Mandate maps to a grant, Cart Mandate countersignature to an approval (§5.2, §6.4). Gap: v0.1 mandates do not carry terms. |
| **Verifiable Intent** (Mastercard, with Google) | Cryptographic record linking cardholder, instructions and the agent-merchant interaction | Payment-side counterpart. Mapping not yet done. |
| **W3C Verifiable Credentials 2.0; Bitstring Status List** | Credential data model; status lists | Recommended default authority source (§5.2). |
| **SD-JWT VC** | Selective-disclosure credentials in JOSE | Permitted securing mechanism for the VC mapping |
| **ERC-7710** (MetaMask Delegation Framework) | On-chain bounded delegation with caveat enforcers | Mapped authority source with the strongest historical revocation. |
| **ERC-8004** | On-chain agent identity and reputation | Usable agent identifier in any mapping. |
| **UCAN; zCap (W3C CCG)** | Object-capability delegation, attenuation, chaining | Prior art and reference for sub-delegation (§16). |
| **OAuth 2.0 Rich Authorization Requests (RFC 9396); Cedar profile for RAR** | Structured authorization details; a policy language carried in them | `accept_terms` is designed to sit in an `authorization_details` array. Expressing scope as Cedar policy is an open option (§16). OAuth records a grant of access; it does not by itself record assent to terms, which is why the agreement record carries authority separately. |
| **GNAP** | Grant negotiation | Possible authority source; not mapped. |
| **OpenID Shared Signals Framework** | Push security events, including proposed mandate lifecycle events | Supplements revocation (§11). |
| **AAIF Identity & Trust Working Group, Agent Identity Primitives** | Reference architecture defining identifier, accountability, discovery, attestation, delegation and revocability primitives | Review venue. Its delegation primitive's five elements map onto §5.1; its approval attestation corresponds to the Approval Event (§6). |
| **DIF Trusted AI Agents WG, Delegated Authority work items** | Reports on delegated authority against existing authorization protocols, threat model, governance | Review venue. This document should be checked against their findings. |
| **GLEIF vLEI; KERI/ACDC** | Verifiable organizational identity and role credentials | Answers to standing organizational authority (§16). |
| **JLINC** | Protocol for signed agreements between parties using verifiable credentials | Prior art for signed, credential-backed agreements. |
| **Legal Context Protocol** (Integra Ledger, AAA-ICDR) | Legal context for agent interactions | Overlaps the agreement layer; defers consumer-side authority. |
| **Proof-of-Control** (Advanced AI Society) | Evidence standard for agent control across six domains | This document is intended as evidence for the Authorization domain in commerce. |
| **x402** (Linux Foundation) | HTTP-native payment | Payment rail. See the separate binding. |
| **ETSI EN 319 102-1; RFC 3161 long-term validation** | Validation of electronic signatures at a past time: best-signature-time from proof of existence, revocation checked against it, INDETERMINATE results where order cannot be established | The model §9 applies to agent grants. `unknown` corresponds to INDETERMINATE; trusted time corresponds to proof of existence. |
| **RFC 8785 (JCS)** | JSON canonicalization | Required for every hash and signature here. |

---

## 14. Legal Design Rationale

*Design rationale, not legal advice. The protocol records facts; it does not determine enforceability, authority, or liability.*

Under UETA § 14 and ESIGN § 7001(h), a contract formed by an electronic agent binds the principal without human review. Agency doctrine supplies the limits: a principal is bound within the agent's actual authority and may be bound by apparent authority, meaning what a third party reasonably believed from the principal's own manifestations (Restatement (Third) of Agency §§ 2.01, 2.03, 3.03). UETA § 10 adds rules for errors in automated transactions, including an individual's ability to avoid an error the electronic agent gave no opportunity to prevent or correct.

A verifiable, scoped grant changes the evidentiary position on both sides:

- **For the principal,** scope limits are evidence of the bounds of actual authority, fixed before the transaction.
- **For the counterparty,** a verified grant is a representation the principal signed, which undercuts a later claim that the agent went rogue. A grant signed only by a server acting for the principal (§5.2, AAuth), or by the counterparty's own server, is weaker evidence of the principal's own manifestation, and the record should say which kind it holds.
- **The trade:** published, discoverable scope also limits apparent authority. A principal gains protection against over-committing agents and gives up ambiguity a counterparty might otherwise rely on. This should be stated to buyers plainly.
- **The approval record** (§6.2) shows whether the human had an opportunity to see and correct the terms, which bears on § 10.

None of this is self-executing. The record is evidence an adjudicator can verify, not a determination.

---

## 15. Security Considerations

**Confused deputy.** An agent with a broad grant can be induced to commit within scope but against the principal's interest. `prohibited_clauses` and approval thresholds mitigate; narrow scopes and low thresholds are the operational answer.

**Over-broad grants as the default failure.** The realistic failure is a wildcard grant with a distant expiry. Implementations SHOULD make narrow, short-lived grants the easy path and SHOULD NOT offer a one-click unlimited grant.

**Agent key compromise.** Allows commitment within scope until revocation. Scope caps the blast radius; `aggregate_cap` caps it over time. Use per-agent keys.

**Approval replay.** Prevented by single-`agreement_hash` binding and short expiry.

**Threshold bypass.** `aggregate_cap` is the defense; verifiers SHOULD flag clustered sub-threshold commitments between the same parties.

**Grant injection.** A grant MUST come from the principal or a location the principal controls (its DID document, its domain, chain state). A grant supplied only by the counterparty, or only by the agent with no principal-controlled source, is not accepted.

**Key ownership.** A signature proves nothing if the signer chose the key. For DID principals the signing key MUST be a verification method of the principal's DID. For other identifiers, verifiers MUST establish ownership out of band and fail closed if they cannot. A server that signs for the principal (an AAuth PS) meets this rule only if its key is published under the principal's own DID or domain. An AAuth AS in a four-party deployment is the counterparty's server and never meets it.

**Server compromise.** Where a server signs grants or approvals for the principal, compromise of that server's key forges authority for every principal it serves. Scope and expiry cap the damage; per-principal keys reduce it.

**Composite substitution.** A composite artifact naming the wrong grant hash or agent binding, or widening the grant, MUST fail (§5.3).

**Vocabulary drift.** A grant naming one vocabulary version and an agreement classified under another MUST yield `unknown` for the scope step unless the vocabulary defines the mapping.

**Mixed-format verifiers.** Supporting several sources increases attack surface. A verifier MUST fail closed on any source type, algorithm, or vocabulary it does not implement.

**Principal enumeration.** See §8.

---

## 16. Open Questions (v0.3 to v0.4)

- **Sub-delegation.** Attenuation of the scope object is defined (§4.4). Chain mechanics should follow UCAN, zCap or AAP `peer_agent` depth rules rather than be invented here. Depth limits and liability attribution across a chain are unresolved. AAuth keeps the chain at the person server, out of a third party's view.
- **Server-attested authority.** Whether, and how, a relying party declares that it accepts grants and approvals signed by a server acting for the principal (an AAuth PS) rather than by the principal, and whether a counterparty's own server (AAuth four-party) can ever qualify. A candidate is an `accepted_attesters` list beside `accepted_sources` (§12.1).
- **Clause vocabularies.** Who classifies clauses, how a disputed classification is recorded, and how vocabularies are governed.
- **Policy-language scope.** Whether `accept_terms` should allow a Cedar or similar policy instead of fixed fields.
- **Historical status for VCs.** A standard way to sign or anchor status-list snapshots so R5 is met.
- **AP2 terms field.** Proposal to add `terms_url` and `terms_hash` to Cart Mandate contents.
- **AAP entry type.** Proposal of `accept_terms` to the AAP author, relying on `budget` for value limits (§5.2).
- **AAuth R3 vocabulary.** Publishing `https://consenti.ai/r3/accept-terms/v0.1`, and whether to register it in the R3 Vocabulary Registry.
- **Ed25519 signatures.** Required by AAuth; not supported by the reference verifier.
- **Verifiable Intent mapping.**
- **Salted principal commitments** without making existence proofs interactive.
- **Machine comprehension.** Whether an agent can meaningfully attest to understanding. Not to be shipped until resolved.
- **Standing organizational authority.** Mapping signing-authority matrices, dual control and board thresholds, possibly via vLEI role credentials.
- **Trusted lower bound on commitment time.**
- **Cross-jurisdiction scope.**

---

## 17. Implementation Status

Stated so that nothing here is read as shipped when it is not.

| Component | Status |
|---|---|
| Agreement record `authority` object | Implemented in v0.2 form (`src/authority.ts`); v0.3 `source_type` fields not yet implemented |
| Level 1A verification, commitment window, `unknown` results | Implemented for `consenti_native` with `anchor` trusted time |
| Native credential and signed revocation list (Appendix A) | Implemented |
| Approval Event | Specified; out-of-band delivery channel not implemented |
| VC mapping | Specified; not implemented |
| AP2, AAP, ERC-7710, UCAN mappings | Not implemented; AP2 and AAP need upstream changes |
| AAuth mapping | Partially specified; not implemented. R3 vocabulary not published; Ed25519 not supported |
| `rfc3161` trusted time | Specified; not implemented |
| Clause vocabularies | None published |
| Directory `requires_authority` and 403 | Specified; not implemented |

Corrections to live artifacts carried from v0.2: `blocksee.co/.well-known/agreements.json` omits the `signature` block Discovery §4.3 says publishers SHOULD include, and declares `"anchor_chains": ["pangea"]` while document anchoring reportedly runs against Ethereum. Both should be reconciled.

**Suggested order of work:** VC mapping and historical status (R5) first, since it is the recommended default; then approval delivery over passkeys; then the AP2 and AAP upstream proposals and the AAuth R3 vocabulary; then a first clause vocabulary.

---

## Appendix A. Consenti Native Credential (fallback)

### A.1 Format

The v0.2 Delegation Credential, unchanged except that `scope` is now an `accept_terms` object (§4).

```json
{
  "type": "consenti/delegation/v0.2",
  "delegation_id": "dlg_7f3a9c21",
  "principal": {
    "identifier": { "type": "did", "value": "did:web:acme.example" },
    "commitment": "sha256:4b1e…"
  },
  "agent": {
    "identifier": { "type": "erc8004", "value": "eip155:1:0xIdentityRegistry…#42" },
    "public_key_ref": "did:web:acme.example#agent-key-3"
  },
  "scope": { "type": "accept_terms", "…": "§4 object" },
  "issued_at": "2026-07-01T00:00:00Z",
  "expires_at": "2026-12-31T23:59:59Z",
  "revocation": {
    "check_url": "https://acme.example/.well-known/delegations/revoked.json",
    "anchor_ref": "pangea:…"
  },
  "signature": { "algorithm": "ES256", "public_key_ref": "did:web:acme.example#key-1", "value": "base64url…" }
}
```

Field rules are those of v0.2 §4.2. ES256 signatures may be raw r||s (preferred) or DER; verifiers normalize. The reference verifier supports ES256 only and fails closed on any other algorithm.

### A.2 Revocation list

```
https://{principal-domain}/.well-known/delegations/revoked.json
```

- Signed by the principal under the key-ownership rule (§15). Unsigned or failing lists yield `unknown`.
- `updated_at` means "accurate as of", not "last changed". Publishers MUST set it to generation time and SHOULD serve a list generated within the last five minutes.
- Verifiers treat a list as current through the window's end when `updated_at` is within a freshness tolerance of it (default 300 seconds), and report `unknown` otherwise.
- Entries carry `delegation_id`, `revoked_at`, and `effective` (`prospective` or `retroactive`).
- `anchor_ref` anchors list publications so status at a past time can be shown (R5).

---

## Appendix B. Traceability of v0.2 Amendments

| v0.2 | v0.3 location |
|---|---|
| A1 `authority` excluded from `agreement_hash` | §7 |
| A2 signing key must belong to the principal | §15, Key ownership |
| A3 revocation lists signed and fresh | Appendix A.2 |
| A4 commitment window | §9, Commitment Time |
| A5 scope profiles | §4.3, renamed clause vocabularies |
| A6 ES256 encoding | Appendix A.1 |
| A7 `updated_at` semantics | Appendix A.2 |
| §17 x402 binding | Separate document: Consenti x402 Binding v0.1 |

---

**Protocol:** Consenti Agreement Protocol
**Repository:** `github.com/consenti-ai/agreement-protocol`
**Governance:** BDFL + RFC process
**License:** MIT, spec and reference implementations
**Contact:** eric@blocksee.co

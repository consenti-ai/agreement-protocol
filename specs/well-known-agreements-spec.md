# Consenti Agreement Discovery Protocol v0.1

**Status:** Draft
**Protocol ID:** `consenti/discovery/v0.1`
**Companion specs:** [Agreement Schema v0.1](./agreement-schema-v0.1.json) | [Privacy Architecture v0.1](./agreement-privacy-architecture.md)

---

## 1. Purpose

This spec defines how any domain, service, or agent publishes its operative terms at a well-known URI, enabling agents and humans to discover and accept those terms **before** initiating a transaction.

Agents accept or reject terms. There is no negotiation. Acceptance records — whether from a human clicking a checkbox on a website or an agent committing via the protocol — flow into the same dashboard log with the same third-party proof.

This is the infrastructure layer for *terms before transactions*.

## 2. The Problem

Under UETA § 14 and ESIGN 15 U.S.C. § 7001(h), AI agent contracts are already legally binding. When a dispute arises — a customer says "I never agreed to those terms" or an agent transacts without accepting terms — the company's only evidence is a checkbox flag in their own database. As Matt Kotnik put it: "It's their word against my word. Their database means nothing because it's their word."

Consenti solves this by adding a third-party, independently verifiable record — anchored on a tamper-proof ledger — that proves acceptance happened, when it happened, what version of the terms was accepted, and by whom.

## 3. Location

Implementers MUST publish agreement terms at:

```
https://{domain}/.well-known/agreements.json
```

Following RFC 8615. The path is fixed. No redirects to non-`.well-known` paths.

## 4. Content-Type

```
Content-Type: application/agreement-directory+json; charset=utf-8
```

## 5. Directory Document Format

The document is a JSON object listing the terms a service requires acceptance of:

```json
{
  "protocol_version": "consenti/discovery/v0.1",
  "publisher": {
    "identifier": { "type": "domain", "value": "anytech365.com" },
    "display_name": "AnyTech365",
    "contact": "legal@anytech365.com"
  },
  "updated_at": "2026-04-16T00:00:00Z",
  "terms": [
    {
      "terms_ref": "https://anytech365.com/.well-known/agreements/tos-v4.json",
      "terms_hash": "sha256:3f2a...",
      "terms_title": "Terms of Service",
      "terms_version": "v4",
      "applies_to": {
        "paths": ["/api/*", "/agent/*", "/*"],
        "actions": ["purchase", "data_access", "service_use"],
        "acceptor_types": ["human", "agent"]
      },
      "required": true,
      "effective_from": "2026-04-01T00:00:00Z",
      "effective_until": null,
      "summary": "Standard terms for all users and agents transacting via this service.",
      "human_readable_url": "https://anytech365.com/legal/terms"
    },
    {
      "terms_ref": "https://anytech365.com/.well-known/agreements/dpa-v2.json",
      "terms_hash": "sha256:9e1b...",
      "terms_title": "Data Processing Agreement",
      "applies_to": {
        "actions": ["data_processing"],
        "acceptor_types": ["agent"]
      },
      "required": true,
      "effective_from": "2026-01-01T00:00:00Z"
    }
  ],
  "acceptance_endpoint": "https://anytech365.com/api/agreements/accept",
  "verification": {
    "verifier_urls": [
      "https://verify.consenti.ai",
      "https://anytech365.com/verify"
    ],
    "anchor_chains": ["pangea"]
  },
  "signature": {
    "algorithm": "ES256",
    "public_key_ref": "did:web:anytech365.com#key-1",
    "signature": "base64url..."
  }
}
```

### 5.1 Required Fields

| Field | Type | Description |
|---|---|---|
| `protocol_version` | string | MUST be `"consenti/discovery/v0.1"`. |
| `publisher` | object | Identity of the entity publishing the directory. |
| `updated_at` | RFC 3339 datetime | Last modification timestamp. |
| `terms` | array | One or more terms entries. |
| `acceptance_endpoint` | URI | Where acceptors POST their signed acceptance records. |

### 5.2 Terms Entry Fields

| Field | Type | Description |
|---|---|---|
| `terms_ref` | URI | Location of the full terms document. |
| `terms_hash` | string | SHA-256 of the canonicalized terms document. Clients MUST verify match after fetch. |
| `terms_title` | string | Human-readable title for dashboard display. |
| `applies_to` | object | Scope predicates — which paths, actions, and acceptor types require this terms acceptance. |
| `required` | boolean | If true, transaction MUST NOT proceed without acceptance. |
| `effective_from` | datetime | When the terms become operative. |
| `effective_until` | datetime \| null | When the terms expire. Null = indefinite. |

### 5.3 Signature

The directory document SHOULD be signed by the publisher. Signature covers the canonicalized document with the `signature` field removed.

## 6. Acceptance Flow

There is no negotiation. Agents accept or reject. Humans click or don't. Both flows produce the same acceptance record.

### 6.1 Agent Flow

```
Agent                                              Service
  |                                                    |
  |-- GET /.well-known/agreements.json --------------->|
  |<-- 200 OK (directory) -----------------------------|
  |                                                    |
  |-- evaluate applies_to against intended action      |
  |-- GET {terms_ref} -------------------------------->|
  |<-- 200 OK (terms document) ------------------------|
  |                                                    |
  |-- verify terms_hash matches                        |
  |-- ACCEPT or REJECT (no negotiation)                |
  |                                                    |
  |   If ACCEPT:                                       |
  |-- sign acceptance record                           |
  |-- POST signed record to acceptance_endpoint ------>|
  |<-- 201 Created (agreement_id, anchor_ref) ---------|
  |                                                    |
  |-- proceed with transaction ----------------------->|
  |                                                    |
  |   If REJECT:                                       |
  |-- do not transact                                  |
```

### 6.2 Human Flow (Website T&C)

```
User                        Website + Consenti Widget
  |                                    |
  |-- visit page ---------------------->|
  |<-- page with T&C checkbox ----------|
  |                                    |
  |   (optional: click AI assistant,   |
  |    ask questions about terms)      |
  |                                    |
  |-- check box / click accept -------->|
  |                                    |
  |   Widget creates acceptance record |
  |   with acceptor_type: "human"      |
  |   Anchors to chain                 |
  |                                    |
  |-- proceed with service ------------>|
```

### 6.3 Unified Dashboard Log

Both flows produce acceptance records conforming to the [Agreement Schema v0.1](./agreement-schema-v0.1.json). The dashboard displays them in a single chronological log:

```
TIMESTAMP           TYPE    ACCEPTOR                    TERMS              STATUS
2026-04-16 09:14    human   john@example.com            TOS v4             ✓ Anchored
2026-04-16 09:17    agent   agent://stripe/pay-v2.1     TOS v4             ✓ Anchored
2026-04-16 09:22    human   jane@example.com            TOS v4 + DPA v2    ✓ Anchored
2026-04-16 09:31    agent   agent://openai/gpt-shop     TOS v4             ✓ Anchored
2026-04-16 09:45    agent   agent://unknown/crawler      TOS v4             ✗ Rejected
```

The dashboard can be filtered by `acceptor_type` (human / agent), by terms version, by date range, and by acceptance status. Flagged entries (rejections, expired acceptances, version mismatches) surface in a daily or weekly summary — not real-time alerts.

## 7. HTTP 409 Enforcement

When an agent attempts an action that requires a prior terms acceptance and none exists, the service MUST respond:

```
HTTP/1.1 409 Agreement Required
Content-Type: application/agreement+json
Link: <https://example.com/.well-known/agreements.json>; rel="agreement-directory"

{
  "error": "agreement_required",
  "terms_ref": "https://example.com/.well-known/agreements/tos-v4.json",
  "terms_hash": "sha256:3f2a...",
  "acceptance_endpoint": "https://example.com/api/agreements/accept"
}
```

The agent fetches the terms, signs an acceptance record, and POSTs it to `acceptance_endpoint`. On success, the service returns `201 Created` with the anchored `agreement_id`. The agent includes this in subsequent requests (e.g., via `X-Agreement-Id` header).

This is a gate, not a negotiation. The agent either accepts and proceeds, or does not accept and does not transact.

## 8. Caching

- Clients SHOULD cache the directory document per standard HTTP cache headers.
- Clients MUST re-fetch before acting if the cached `updated_at` is older than 24 hours.
- Terms documents referenced by `terms_ref` are immutable (addressed by hash). Clients MAY cache indefinitely.

## 9. Versioning

- Directory protocol version is declared in `protocol_version`.
- Breaking changes produce a new version string (`consenti/discovery/v0.2`, etc.).
- Publishers MAY serve multiple protocol versions via content negotiation.

## 10. Transport Independence

This spec defines an HTTPS discovery mechanism. Equivalent bindings MAY be defined for:

- **MCP**: a `list_terms` / `accept_terms` tool pair returning the same structures.
- **A2A**: a capability exposing the directory.
- **DNS**: TXT records pointing to the well-known URI.
- **IPFS/content-addressed**: `ipfs://{cid}/agreements.json` for decentralized publishers.

Any binding MUST preserve the directory document format defined in §5 and the acceptance record format defined in the Agreement Schema.

## 11. Verification

The protocol supports three verification levels:

- **Level 0 — Existence Proof:** Verify an acceptance record exists using only the agreement_hash and anchor reference. Zero content disclosure.
- **Level 1 — Acceptance Proof:** Verify that a specific acceptor committed to a specific terms_hash at a specific time. Confirms who agreed to what, when.
- **Level 2 — Full Verification:** Full acceptance record + signature(s) + anchor reference. Complete audit trail suitable for dispute resolution.

All levels require NO call to Consenti infrastructure. The anchor chain is the independent third party.

Reference verifier: [github.com/consenti-ai/verifier](#) (MIT licensed).

## 12. Privacy and Confidentiality

See companion spec: [Agreement Privacy Architecture v0.1](./agreement-privacy-architecture.md).

Key principles:

- **Directory is public; acceptance records are private.** The `.well-known/agreements.json` directory describes what terms a service requires. Executed acceptance records are held by the publisher and the acceptor — not published.
- **Only hashes are anchored.** The public anchor chain receives `agreement_hash` and `acceptor_hash` (a hash of the identifier, not the identifier itself). Acceptance details never touch the chain.
- **Selective disclosure via Merkle proofs** is available for sensitive agreements (see Privacy Architecture spec).

## 13. Security Considerations

- **TLS required.** Directory documents MUST be served over HTTPS.
- **Key rotation.** Publishers SHOULD use DID methods supporting key rotation.
- **Replay protection.** Signed acceptances include `accepted_at` and bind to a specific `terms_hash`; anchoring provides non-repudiation.
- **Scope enforcement.** Agents MUST validate that `applies_to` constraints match their intended action before accepting.
- **No negotiation surface.** By design, the protocol has no modification flow. This eliminates an entire class of man-in-the-middle and terms-substitution attacks.

## 14. Open Questions (v0.1 → v0.2)

- Standardized terms document formats (structured JSON clauses vs. prose with hash).
- Batch acceptance for agents accepting multiple terms sets simultaneously.
- Revocation semantics beyond `effective_until` (publisher revokes terms mid-cycle).
- Acceptance delegation (agent accepts on behalf of an organization, with org-level authorization — potential future extension, not in v0.1).
- Post-quantum migration path (CRYSTALS-Dilithium, CRYSTALS-Kyber).

---

**Maintainer:** Consenti (FHBK Technologies, Inc.)
**License:** MIT (spec + reference implementations)
**Governance:** BDFL + RFC process. Protocol-level changes tracked at `github.com/consenti-ai/agreement-protocol`.

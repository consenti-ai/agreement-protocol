# Consenti Agreement Protocol

**Terms before transactions.** An open protocol for cryptographically verifiable terms acceptance — by humans or AI agents — with independent third-party proof.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol Version](https://img.shields.io/badge/protocol-v0.1-green.svg)](schemas/agreement-schema-v0.1.json)

---

## The Problem

Under [UETA § 14](https://www.uniformlaws.org/committees/community-home?CommunityKey=2c04b76c-2b7d-4399-977e-d5876f7f0e88) and [ESIGN 15 U.S.C. § 7001(h)](https://www.law.cornell.edu/uscode/text/15/7001), AI agent contracts are already legally binding. When a dispute arises — a customer says "I never agreed to those terms" or an agent transacts without accepting terms — the company's only evidence is a checkbox flag in their own database.

**It's their word against yours. Their database means nothing because it's their word.**

Consenti solves this by adding an independent, tamper-proof record that proves acceptance happened, when it happened, what version of the terms was accepted, and by whom. Humans and agents produce identical acceptance records in the same dashboard log.

## How It Works

```
Publisher                                        Acceptor (human or agent)
    |                                                    |
    |-- publishes terms at                               |
    |   /.well-known/agreements.json                     |
    |                                                    |
    |                           GET /.well-known/agreements.json
    |                                                    |
    |   Human: clicks checkbox on website                |
    |   Agent: fetches terms, signs acceptance record    |
    |                                                    |
    |              acceptance record created              |
    |              anchored to tamper-proof ledger        |
    |              appears in publisher's dashboard       |
    |                                                    |
```

Both flows produce the same acceptance record. Same schema. Same verification. Same dashboard log.

```
TIMESTAMP           TYPE    ACCEPTOR                    TERMS         STATUS
2026-04-16 09:14    human   john@example.com            TOS v4        ✓ Anchored
2026-04-16 09:17    agent   agent://stripe/pay-v2.1     TOS v4        ✓ Anchored
2026-04-16 09:22    human   jane@example.com            TOS v4        ✓ Anchored
2026-04-16 09:31    agent   agent://openai/gpt-shop     TOS v4        ✓ Anchored
```

## Key Properties

- **Terms before transactions.** Agents must accept terms before they can transact. Enforced via HTTP 409 or equivalent.
- **Accept or reject. No negotiation.** The protocol is a gate, not a conversation.
- **Third-party proof.** Acceptance records are anchored to an independent, tamper-proof ledger. Not just your database.
- **Zero-custody.** Consenti infrastructure never holds signing keys or (in zero-custody mode) acceptance record content.
- **Transport-agnostic.** Works over HTTP, MCP, A2A, or any transport that can carry JSON.
- **Chain-agnostic.** Anchor to Pangea, Ethereum, Bitcoin, Solana, or an RFC 3161 timestamp authority.
- **Unified human + agent log.** Same schema, same dashboard, same verification — just an `acceptor_type` filter.

## Specifications

| Document | Description |
|---|---|
| [Agreement Schema v0.1](schemas/agreement-schema-v0.1.json) | Canonical JSON Schema for acceptance records |
| [Discovery Spec v0.1](specs/well-known-agreements-spec.md) | `.well-known/agreements.json` discovery + HTTP 409 enforcement |
| [Privacy Architecture v0.1](specs/agreement-privacy-architecture.md) | Commitment/content separation, selective disclosure, encrypted vault |

## Reference Verifier

A TypeScript library that independently verifies acceptance records against their anchored commitments. No Consenti API call required.

### Install

```bash
npm install @consenti-ai/verifier
```

### Usage

```typescript
import { verify, VerificationLevel } from '@consenti-ai/verifier';

// Load an acceptance record (from your dashboard, a file, an API response, etc.)
const record = await fetch('https://example.com/api/agreements/agr_abc123').then(r => r.json());

// Verify it
const result = await verify(record, {
  level: VerificationLevel.ACCEPTANCE_PROOF,
  anchorProvider: pangeaProvider,
});

if (result.valid) {
  console.log(`✓ ${result.acceptor} accepted "${result.termsTitle}" at ${result.acceptedAt}`);
  console.log(`  Anchored at ${result.anchoredAt} via ${pangeaProvider.name}`);
} else {
  console.log(`✗ Verification failed:`);
  result.errors.forEach(e => console.log(`  - ${e}`));
}
```

### Verification Levels

| Level | Name | What it proves | Disclosure required |
|---|---|---|---|
| 0 | Existence | An acceptance record with this hash exists on the anchor chain | None |
| 1 | Acceptance Proof | A specific acceptor agreed to specific terms at a specific time | Acceptor ID + terms hash |
| 2 | Full | Complete audit trail with signatures, suitable for dispute resolution | Full acceptance record |

### Standalone Functions

```typescript
import { computeAgreementHash, computeAcceptorHash, canonicalize } from '@consenti-ai/verifier';

// Compute the canonical hash of an acceptance record
const hash = computeAgreementHash(record);

// Compute the pseudonymous acceptor hash (what goes on-chain)
const acceptorHash = computeAcceptorHash({ type: 'email', value: 'john@example.com' });

// Canonicalize any JSON value per RFC 8785
const canonical = canonicalize({ b: 2, a: 1 }); // → '{"a":1,"b":2}'
```

## Examples

| File | Description |
|---|---|
| [human-acceptance.json](examples/human-acceptance.json) | Human clicking a T&C checkbox on a website |
| [agent-acceptance.json](examples/agent-acceptance.json) | AI agent accepting terms via the protocol before transacting |
| [well-known-directory.json](examples/well-known-directory.json) | `.well-known/agreements.json` for a publisher |

## Implementing the Protocol

### For publishers (companies with T&C)

1. **Publish your terms** at `/.well-known/agreements.json` (see [Discovery Spec](specs/well-known-agreements-spec.md))
2. **Add the Consenti widget** to your website (or use the API) to capture human acceptances
3. **Return HTTP 409** when agents attempt actions without prior terms acceptance
4. **View all acceptances** — human and agent — in a single dashboard log

### For agent developers

1. **Check `/.well-known/agreements.json`** before transacting with any service
2. **Accept or reject.** If terms are acceptable, sign an acceptance record and POST to the `acceptance_endpoint`
3. **Include `X-Agreement-Id`** in subsequent requests

### For verifiers (auditors, courts, regulators)

1. **Obtain the acceptance record** from the publisher or acceptor
2. **Run the reference verifier** at the appropriate level
3. **Check the anchor independently** — no Consenti infrastructure needed

## FAQ

**Why not just use clickwrap?**
Clickwrap proves you *displayed* terms. A checkbox in your database is your word. Consenti proves acceptance with an independent, tamper-proof record that survives "I never agreed to that" in court.

**Why no negotiation?**
Because C-level officers don't want to get pinged every time an agent disagrees with a clause. Agents accept or reject. If terms don't work, the agent doesn't transact. Negotiation may be a future extension, but it's not in v0.1.

**How is this different from DocuSign / Icertis?**
DocuSign and Icertis are centralized — they hold your agreements. Consenti is zero-custody: we never hold your signing keys or (in zero-custody mode) your acceptance records. The protocol works even if Consenti disappears.

**What chains are supported for anchoring?**
Pangea (default), Ethereum, Bitcoin (OP_RETURN), Solana (memo), and RFC 3161 timestamp authorities. Chain-agnostic by design.

**What about privacy?**
The commitment is public (hashes only). The content is private. See the [Privacy Architecture](specs/agreement-privacy-architecture.md) for selective disclosure, encrypted vault, and access grant details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Governance

See [GOVERNANCE.md](GOVERNANCE.md).

## License

MIT. See [LICENSE](LICENSE).

---


**Maintained by [Consenti](https://consenti.ai) (FHBK Technologies, Inc.)**

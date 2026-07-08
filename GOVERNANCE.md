# Governance

## Model: BDFL + RFC Process

The Consenti Agreement Protocol is governed by a Benevolent Dictator For Life (BDFL) model with a structured RFC process for protocol-level changes.

**BDFL:** Eric Forst (eric@blocksee.co), Founder & CEO, FHBK Technologies, Inc.

## Decision Levels

### 1. Implementation decisions (PR-level)

Bug fixes, new anchor providers, SDK ports, documentation, and tooling. These are reviewed and merged by maintainers without an RFC.

### 2. Protocol changes (RFC required)

Any change to:
- The acceptance record schema (`schemas/agreement-schema-v0.1.json`)
- The discovery spec (`specs/well-known-agreements-spec.md`)
- The privacy architecture (`specs/agreement-privacy-architecture.md`)
- Canonicalization rules
- Verification semantics

These require an RFC (see below).

### 3. Version bumps

Breaking changes produce a new protocol version string (e.g., `consenti/v0.2`). The BDFL decides when accumulated RFCs warrant a version bump.

## RFC Process

1. **Propose.** Open an Issue titled `RFC: [Proposal Title]`. Describe the problem, the proposed change, alternatives considered, and backward compatibility impact.

2. **Discuss.** The Issue remains open for a minimum of 14 days. Anyone can comment. Maintainers will tag relevant reviewers.

3. **Decide.** The BDFL reviews discussion and makes a decision: Accept, Accept with Modifications, Defer (not now, revisit later), or Reject. The decision and rationale are posted to the Issue.

4. **Implement.** Accepted RFCs are implemented via PR, referencing the RFC Issue.

## Maintainers

| Name | Role | Focus |
|---|---|---|
| Eric Forst | BDFL | Protocol design, governance |
| Matt Kotnik | CTO | Reference implementation, anchor integrations |

## Principles

- **Backward compatibility matters.** Don't break existing implementations without a version bump.
- **Simplicity over completeness.** The protocol should stay small enough that one person can read and understand the entire spec in an afternoon.
- **No vendor lock-in.** The protocol must work without Consenti infrastructure. Any change that creates a dependency on Consenti services will be rejected.
- **Zero external runtime dependencies** for the reference verifier. It must work standalone.

## Contact

- Protocol questions: Open a GitHub Issue
- Security: security@consenti.ai
- Commercial (Consenti hosted product): eric@blocksee.co

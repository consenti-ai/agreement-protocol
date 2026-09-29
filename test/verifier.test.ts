import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  canonicalize,
  sha256,
  computeAgreementHash,
  computeAcceptorHash,
  verify,
  VerificationLevel,
  AcceptorType,
} from '../src/verifier.js';
import type { AcceptanceRecord, AnchorProvider } from '../src/verifier.js';

function baseRecord(overrides: Partial<AcceptanceRecord> = {}): AcceptanceRecord {
  return {
    protocol_version: 'consenti/v0.1',
    agreement_id: '01JBQX8P2N4RWXEQ6U7AZSIB53',
    created_at: '2026-04-16T09:17:00Z',
    publisher: { identifier: { type: 'domain', value: 'example.com' } },
    acceptor: {
      acceptor_type: AcceptorType.HUMAN,
      identifier: { type: 'email', value: 'a@example.com' },
      accepted_at: '2026-04-16T09:17:00Z',
    },
    terms_ref: { terms_hash: 'sha256:deadbeef', terms_url: 'https://example.com/tos' },
    canonicalization: {
      method: 'RFC8785',
      hash_algorithm: 'SHA-256',
      excluded_fields: ['anchoring', 'signatures', 'privacy.anchor_commitment', 'privacy.merkle_tree.root'],
    },
    ...overrides,
  };
}

// ─── canonicalize() ──────────────────────────────────────────────────────────

test('canonicalize sorts object keys', () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
});

test('canonicalize omits undefined values, keeps null', () => {
  assert.equal(canonicalize({ a: 1, b: undefined, c: null }), '{"a":1,"c":null}');
});

test('canonicalize serializes booleans and nested structures', () => {
  assert.equal(canonicalize(true), 'true');
  assert.equal(canonicalize(false), 'false');
  assert.equal(canonicalize({ z: [3, 2, 1], a: { y: 1, x: 2 } }), '{"a":{"x":2,"y":1},"z":[3,2,1]}');
});

test('canonicalize rejects non-finite numbers', () => {
  assert.throws(() => canonicalize(NaN));
  assert.throws(() => canonicalize(Infinity));
});

// ─── hashing ─────────────────────────────────────────────────────────────────

test('sha256 matches known vector for empty string', () => {
  assert.equal(sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('computeAgreementHash is deterministic and ignores anchoring/signatures', () => {
  const record = baseRecord();
  const h1 = computeAgreementHash(record);
  const withAnchoring = {
    ...record,
    anchoring: { method: 'pangea', agreement_hash: `sha256:${h1}` },
  };
  assert.equal(computeAgreementHash(withAnchoring), h1);
  assert.equal(h1.length, 64);
});

test('computeAcceptorHash hashes the canonicalized identifier', () => {
  const id = { type: 'email', value: 'a@example.com' };
  assert.equal(computeAcceptorHash(id), sha256(canonicalize(id)));
});

// ─── verify() ────────────────────────────────────────────────────────────────

test('verify: EXISTENCE level requires an anchorProvider', async () => {
  const result = await verify(baseRecord(), { level: VerificationLevel.EXISTENCE });
  assert.equal(result.valid, false);
  assert.match(result.errors[0], /requires an anchorProvider/);
});

test('verify: detects agreement_hash tampering', async () => {
  const record = baseRecord({
    anchoring: {
      method: 'pangea',
      agreement_hash: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    },
  });
  const result = await verify(record, { level: VerificationLevel.ACCEPTANCE_PROOF });
  assert.equal(result.valid, false);
  assert.match(result.errors[0], /Hash mismatch/);
});

test('verify: ACCEPTANCE_PROOF succeeds against a matching anchor', async () => {
  const record = baseRecord();
  const agreementHash = computeAgreementHash(record);
  const anchorProvider: AnchorProvider = {
    name: 'test',
    async resolve() {
      return { agreement_hash: agreementHash, anchored_at: '2026-04-16T09:17:05Z', transaction_ref: 'tx1' };
    },
  };
  const result = await verify(record, { level: VerificationLevel.ACCEPTANCE_PROOF, anchorProvider });
  assert.equal(result.valid, true);
  assert.equal(result.acceptor, 'a@example.com');
});

test('verify: flags a malformed accepted_at instead of silently passing', async () => {
  const record = baseRecord({
    acceptor: {
      acceptor_type: AcceptorType.HUMAN,
      identifier: { type: 'email', value: 'a@example.com' },
      accepted_at: 'not-a-real-timestamp',
    },
  });
  const agreementHash = computeAgreementHash(record);
  const anchorProvider: AnchorProvider = {
    name: 'test',
    async resolve() {
      return { agreement_hash: agreementHash, anchored_at: '2026-04-16T09:17:05Z', transaction_ref: 'tx1' };
    },
  };
  const result = await verify(record, { level: VerificationLevel.ACCEPTANCE_PROOF, anchorProvider });
  assert.equal(result.valid, false);
  assert.match(result.errors.join(' '), /Invalid acceptor\.accepted_at/);
});

test('verify: FULL level fails closed on an unsupported signature algorithm (regression)', async () => {
  const record = baseRecord({
    acceptor: {
      acceptor_type: AcceptorType.AGENT,
      identifier: { type: 'agent_id', value: 'agent://forger' },
      accepted_at: '2026-04-16T09:17:00Z',
    },
    signatures: [
      {
        signer: 'acceptor',
        algorithm: 'EdDSA',
        public_key_ref: 'did:web:evil.com#k1',
        signature: 'not-a-real-signature',
        signed_at: '2026-04-16T09:17:00Z',
      },
    ],
  });
  const result = await verify(record, {
    level: VerificationLevel.FULL,
    keyResolver: async () => ({}) as CryptoKey,
  });
  assert.equal(result.valid, false, 'an unsupported signature algorithm must never verify as valid');
  assert.equal(result.signaturesVerified, false);
});

test('verify: FULL level accepts a genuine ES256 signature', async () => {
  const keyPair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const record = baseRecord({
    acceptor: {
      acceptor_type: AcceptorType.AGENT,
      identifier: { type: 'agent_id', value: 'agent://good' },
      accepted_at: '2026-04-16T09:17:00Z',
    },
  });
  const agreementHash = computeAgreementHash(record);
  const sigBytes = await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    new TextEncoder().encode(agreementHash)
  );
  const signedRecord = {
    ...record,
    signatures: [
      {
        signer: 'acceptor' as const,
        algorithm: 'ES256',
        public_key_ref: 'test-key',
        signature: Buffer.from(sigBytes).toString('base64url'),
        signed_at: '2026-04-16T09:17:00Z',
      },
    ],
  };
  const result = await verify(signedRecord, {
    level: VerificationLevel.FULL,
    keyResolver: async () => keyPair.publicKey,
  });
  assert.equal(result.valid, true);
  assert.equal(result.signaturesVerified, true);
});

test('verify: FULL level rejects a forged ES256 signature (wrong key)', async () => {
  const signingKeyPair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const wrongKeyPair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const record = baseRecord({
    acceptor: {
      acceptor_type: AcceptorType.AGENT,
      identifier: { type: 'agent_id', value: 'agent://good' },
      accepted_at: '2026-04-16T09:17:00Z',
    },
  });
  const agreementHash = computeAgreementHash(record);
  const sigBytes = await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingKeyPair.privateKey,
    new TextEncoder().encode(agreementHash)
  );
  const signedRecord = {
    ...record,
    signatures: [
      {
        signer: 'acceptor' as const,
        algorithm: 'ES256',
        public_key_ref: 'test-key',
        signature: Buffer.from(sigBytes).toString('base64url'),
        signed_at: '2026-04-16T09:17:00Z',
      },
    ],
  };
  const result = await verify(signedRecord, {
    level: VerificationLevel.FULL,
    keyResolver: async () => wrongKeyPair.publicKey,
  });
  assert.equal(result.valid, false);
  assert.equal(result.signaturesVerified, false);
});

test('verify: missing public_key_ref is treated as unverified, not skipped', async () => {
  const record = baseRecord({
    acceptor: {
      acceptor_type: AcceptorType.AGENT,
      identifier: { type: 'agent_id', value: 'agent://good' },
      accepted_at: '2026-04-16T09:17:00Z',
    },
    signatures: [
      {
        signer: 'acceptor' as const,
        algorithm: 'ES256',
        signature: 'irrelevant',
        signed_at: '2026-04-16T09:17:00Z',
      },
    ],
  });
  const result = await verify(record, {
    level: VerificationLevel.FULL,
    keyResolver: async () => {
      throw new Error('keyResolver must not be called without a public_key_ref');
    },
  });
  assert.equal(result.valid, false);
  assert.equal(result.signaturesVerified, false);
});

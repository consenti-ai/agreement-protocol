import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { computeAgreementHash, verify, VerificationLevel, AcceptorType } from '../src/verifier.js';
import type { AcceptanceRecord } from '../src/verifier.js';
import {
  AuthorityStatus,
  computeCredentialHash,
  computePrincipalCommitment,
  signingInput,
  validateAuthorityObject,
  readAuthorityStatus,
  normalizeEs256Signature,
  verifyDelegationCredential,
  verifyAgentBinding,
} from '../src/authority.js';
import type { DelegationCredential, RevocationList, CredentialVerifyOptions } from '../src/authority.js';

// ─── Fixtures ────────────────────────────────────────────────────────────────

const PRINCIPAL_DID = 'did:web:productions.example';
const PRINCIPAL_KEY = `${PRINCIPAL_DID}#key-1`;
const AGENT_KEY = `${PRINCIPAL_DID}#agent-key-3`;
const ATTACKER_KEY = 'did:web:attacker.example#key-1';
const REVOCATION_URL = 'https://productions.example/.well-known/delegations/revoked.json';
const COMMIT = '2026-10-15T12:00:00Z';

type KeyPair = { publicKey: CryptoKey; privateKey: CryptoKey };
const gen = (): Promise<KeyPair> =>
  webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as Promise<KeyPair>;

const b64url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function signRaw(key: CryptoKey, input: string): Promise<Uint8Array> {
  return new Uint8Array(
    await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(input))
  );
}

function toDer(raw: Uint8Array): Uint8Array {
  const int = (v: Uint8Array): number[] => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    const b = Array.from(v.slice(i));
    if (b[0] & 0x80) b.unshift(0);
    return [0x02, b.length, ...b];
  };
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}

let principal: KeyPair, agent: KeyPair, attacker: KeyPair;
const keys = new Map<string, CryptoKey>();
const keyResolver = async (ref: string) => keys.get(ref) ?? null;

async function setup() {
  if (principal) return;
  principal = await gen();
  agent = await gen();
  attacker = await gen();
  keys.set(PRINCIPAL_KEY, principal.publicKey);
  keys.set(AGENT_KEY, agent.publicKey);
  keys.set(ATTACKER_KEY, attacker.publicKey);
}

function unsignedCredential(overrides: Partial<DelegationCredential> = {}): DelegationCredential {
  const identifier = { type: 'did', value: PRINCIPAL_DID };
  return {
    type: 'consenti/delegation/v0.2',
    profile: 'consenti/media-licensing/v0.1',
    delegation_id: 'dlg_media_001',
    principal: { identifier, commitment: computePrincipalCommitment(identifier) },
    agent: { identifier: { type: 'agent_id', value: 'agent://productions/research-1' }, public_key_ref: AGENT_KEY },
    scope: {
      actions: ['license.editorial', 'license.research'],
      counterparties: ['did:web:starchive.io'],
      max_value: { amount: '750.00', currency: 'USD' },
      prohibited_clauses: ['exclusivity', 'perpetual_term'],
      requires_authorization_above: { amount: '250.00', currency: 'USD' },
    },
    issued_at: '2026-10-01T00:00:00Z',
    expires_at: '2026-12-31T23:59:59Z',
    revocation: { check_url: REVOCATION_URL },
    signature: { algorithm: 'ES256', public_key_ref: PRINCIPAL_KEY, value: '' },
    ...overrides,
  };
}

async function sign<T extends { signature: { value: string; public_key_ref: string } }>(
  doc: T,
  key: CryptoKey,
  der = false
): Promise<T> {
  const raw = await signRaw(key, signingInput(doc));
  doc.signature.value = b64url(der ? toDer(raw) : raw);
  return doc;
}

async function revocationList(
  revoked: RevocationList['revoked'] = [],
  updated_at = '2026-10-20T00:00:00Z',
  signer: CryptoKey = principal.privateKey,
  keyRef = PRINCIPAL_KEY
): Promise<RevocationList> {
  return sign(
    {
      protocol_version: 'consenti/authorization/v0.2',
      updated_at,
      revoked,
      signature: { algorithm: 'ES256', public_key_ref: keyRef, value: '' },
    },
    signer
  );
}

async function opts(list: RevocationList | null, extra: Partial<CredentialVerifyOptions> = {}): Promise<CredentialVerifyOptions> {
  return { commitmentTime: COMMIT, keyResolver, fetchRevocationList: async () => list, ...extra };
}

async function signedRecord(cred: DelegationCredential, mutate?: (r: AcceptanceRecord) => void, signer?: CryptoKey) {
  const record: AcceptanceRecord = {
    protocol_version: 'consenti/v0.2',
    agreement_id: '01JC0STARCHIVEPILOT0001',
    created_at: COMMIT,
    publisher: { identifier: { type: 'domain', value: 'starchive.io' } },
    acceptor: {
      acceptor_type: AcceptorType.AGENT,
      identifier: cred.agent.identifier,
      accepted_at: COMMIT,
    },
    terms_ref: { terms_hash: 'sha256:' + 'ab'.repeat(32), terms_url: 'https://starchive.io/.well-known/agreements/editorial-v1.json' },
    canonicalization: {
      method: 'RFC8785',
      hash_algorithm: 'SHA-256',
      excluded_fields: ['anchoring', 'signatures', 'authority', 'privacy.anchor_commitment', 'privacy.merkle_tree.root'],
    },
    authority: {
      status: AuthorityStatus.DELEGATED_ONLY,
      delegation: { delegation_id: cred.delegation_id, credential_hash: computeCredentialHash(cred) },
    },
  };
  mutate?.(record);
  const hash = computeAgreementHash(record);
  const sig = await signRaw(signer ?? agent.privateKey, hash);
  record.signatures = [
    { signer: 'acceptor', algorithm: 'ES256', public_key_ref: AGENT_KEY, signature: b64url(sig), signed_at: COMMIT },
  ];
  return record;
}

// ─── Authority object ────────────────────────────────────────────────────────

test('authority object: each status enforces its references', () => {
  const ref = { delegation_id: 'd', credential_hash: 'sha256:' + '0'.repeat(64) };
  const ev = { authorization_id: 'a', event_hash: 'sha256:' + '1'.repeat(64) };
  assert.deepEqual(validateAuthorityObject({ status: 'authorized', delegation: ref, authorization: ev }), []);
  assert.ok(validateAuthorityObject({ status: 'authorized', delegation: ref }).length > 0);
  assert.deepEqual(validateAuthorityObject({ status: 'delegated_only', delegation: ref }), []);
  assert.ok(validateAuthorityObject({ status: 'delegated_only', delegation: ref, authorization: ev }).length > 0);
  assert.deepEqual(validateAuthorityObject({ status: 'unauthorized' }), []);
  assert.ok(validateAuthorityObject({ status: 'unauthorized', delegation: ref }).length > 0);
  assert.ok(validateAuthorityObject({ status: 'exceeded_scope' }).length > 0);
  assert.ok(validateAuthorityObject({ status: 'sort_of' }).length > 0);
  assert.ok(validateAuthorityObject({ status: 'delegated_only', delegation: { delegation_id: 'd', credential_hash: 'abc' } }).length > 0);
});

test('missing authority reads unauthorized but unasserted; explicit unauthorized is asserted', () => {
  const base = { authority: undefined } as unknown as AcceptanceRecord;
  assert.deepEqual(readAuthorityStatus(base), { status: AuthorityStatus.UNAUTHORIZED, asserted: false });
  const explicit = { authority: { status: 'unauthorized' } } as unknown as AcceptanceRecord;
  assert.deepEqual(readAuthorityStatus(explicit), { status: AuthorityStatus.UNAUTHORIZED, asserted: true });
});

// ─── Credential verification ─────────────────────────────────────────────────

test('valid credential verifies at commitment time', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const r = await verifyDelegationCredential(cred, await opts(await revocationList()));
  assert.equal(r.valid, true, r.errors.join('; '));
  assert.equal(r.revocation.status, 'not_revoked');
});

test('DER-encoded principal signature is accepted', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey, true);
  const r = await verifyDelegationCredential(cred, await opts(await revocationList()));
  assert.equal(r.valid, true, r.errors.join('; '));
});

test('scope edited after signing fails the signature', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  cred.scope.actions.push('license.commercial');
  const r = await verifyDelegationCredential(cred, await opts(await revocationList()));
  assert.equal(r.valid, false);
  assert.equal(r.signatureVerified, false);
});

test('credential signed by a key outside the principal DID is rejected', async () => {
  await setup();
  const cred = unsignedCredential();
  cred.signature.public_key_ref = ATTACKER_KEY;
  await sign(cred, attacker.privateKey);
  const r = await verifyDelegationCredential(cred, await opts(await revocationList()));
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('not a fragment of principal DID')));
});

test('non-DID principal without an ownership check fails closed', async () => {
  await setup();
  const identifier = { type: 'domain', value: 'productions.example' };
  const cred = await sign(
    unsignedCredential({ principal: { identifier, commitment: computePrincipalCommitment(identifier) } }),
    principal.privateKey
  );
  const r = await verifyDelegationCredential(cred, await opts(await revocationList()));
  assert.equal(r.valid, false);
  const ok = await verifyDelegationCredential(
    cred,
    await opts(await revocationList(), { keyOwnership: async (_p, ref) => ref === PRINCIPAL_KEY })
  );
  // Revocation list is also validated through keyOwnership, so this passes end to end.
  assert.equal(ok.valid, true, ok.errors.join('; '));
});

test('principal commitment that does not match identifier is rejected', async () => {
  await setup();
  const cred = unsignedCredential();
  cred.principal.commitment = 'sha256:' + 'f'.repeat(64);
  await sign(cred, principal.privateKey);
  const r = await verifyDelegationCredential(cred, await opts(await revocationList()));
  assert.equal(r.valid, false);
  assert.equal(r.principalCommitmentMatches, false);
});

test('unsupported algorithm fails closed', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  cred.signature.algorithm = 'EdDSA';
  const r = await verifyDelegationCredential(cred, await opts(await revocationList()));
  assert.equal(r.valid, false);
});

test('commitment after expiry or before issuance is outside validity', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const late = await verifyDelegationCredential(cred, await opts(await revocationList([], '2027-02-01T00:00:00Z'), { commitmentTime: '2027-01-15T00:00:00Z' }));
  assert.equal(late.withinValidity, false);
  assert.equal(late.valid, false);
  const early = await verifyDelegationCredential(cred, await opts(await revocationList(), { commitmentTime: '2026-09-01T00:00:00Z' }));
  assert.equal(early.withinValidity, false);
});

test('missing scope fields or expiry are structural failures', async () => {
  await setup();
  const noExpiry = unsignedCredential();
  delete (noExpiry as Partial<DelegationCredential>).expires_at;
  await sign(noExpiry, principal.privateKey);
  assert.equal((await verifyDelegationCredential(noExpiry, await opts(await revocationList()))).valid, false);
  const emptyActions = await sign(unsignedCredential({ scope: { actions: [], counterparties: ['*'] } }), principal.privateKey);
  assert.equal((await verifyDelegationCredential(emptyActions, await opts(await revocationList()))).valid, false);
});

// ─── Revocation ──────────────────────────────────────────────────────────────

test('revoked before commitment is invalid', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const list = await revocationList([{ delegation_id: 'dlg_media_001', revoked_at: '2026-10-10T00:00:00Z', effective: 'prospective' }]);
  const r = await verifyDelegationCredential(cred, await opts(list));
  assert.equal(r.revocation.status, 'revoked');
  assert.equal(r.valid, false);
});

test('revoked after commitment stays valid (prospective by default)', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const list = await revocationList([{ delegation_id: 'dlg_media_001', revoked_at: '2026-10-18T00:00:00Z', effective: 'prospective' }]);
  const r = await verifyDelegationCredential(cred, await opts(list));
  assert.equal(r.revocation.status, 'not_revoked');
  assert.equal(r.valid, true, r.errors.join('; '));
});

test('revocation inside the race window is ambiguous, not resolved', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const list = await revocationList([{ delegation_id: 'dlg_media_001', revoked_at: '2026-10-15T12:00:00.500Z', effective: 'prospective' }]);
  const r = await verifyDelegationCredential(cred, await opts(list));
  assert.equal(r.revocation.status, 'ambiguous');
  assert.equal(r.valid, false);
});

test('retroactive revocation is surfaced loudly', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const list = await revocationList([{ delegation_id: 'dlg_media_001', revoked_at: '2026-10-12T00:00:00Z', effective: 'retroactive' }]);
  const r = await verifyDelegationCredential(cred, await opts(list));
  assert.equal(r.revocation.retroactive, true);
  assert.ok(r.warnings.some((w) => w.startsWith('RETROACTIVE REVOCATION')));
  assert.equal(r.valid, false);
});

test('unreachable, unsigned, foreign-signed, or stale lists give unknown status', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);

  const unreachable = await verifyDelegationCredential(cred, await opts(null));
  assert.equal(unreachable.revocation.status, 'unknown');
  assert.equal(unreachable.valid, false);

  const tampered = await revocationList();
  tampered.revoked = [];
  tampered.updated_at = '2026-10-21T00:00:00Z';
  assert.equal((await verifyDelegationCredential(cred, await opts(tampered))).revocation.status, 'unknown');

  const foreign = await revocationList([], '2026-10-20T00:00:00Z', attacker.privateKey, ATTACKER_KEY);
  assert.equal((await verifyDelegationCredential(cred, await opts(foreign))).revocation.status, 'unknown');

  const stale = await revocationList([], '2026-10-14T00:00:00Z');
  const s = await verifyDelegationCredential(cred, await opts(stale));
  assert.equal(s.revocation.status, 'unknown');
  assert.equal(s.valid, false);
});

test('chain_binding is reported as unchecked, not silently trusted', async () => {
  await setup();
  const cred = await sign(
    unsignedCredential({ chain_binding: { standard: 'erc7710', delegation_hash: '0xabc', chain: 'eip155:1' } }),
    principal.privateKey
  );
  const r = await verifyDelegationCredential(cred, await opts(await revocationList()));
  assert.equal(r.chainBindingVerified, null);
  assert.ok(r.warnings.some((w) => w.includes('chain_binding present but not checked')));
});

// ─── Binding ─────────────────────────────────────────────────────────────────

test('binding: delegated agent key signed this agreement', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred);
  const r = await verifyAgentBinding(record, cred, keyResolver);
  assert.equal(r.valid, true, r.errors.join('; '));
});

test('binding: signature by any other key does not bind', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred, undefined, attacker.privateKey);
  const r = await verifyAgentBinding(record, cred, keyResolver);
  assert.equal(r.valid, false);
});

test('binding: agreement altered after the agent signed fails', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred);
  record.terms_ref.terms_url = 'https://starchive.io/.well-known/agreements/commercial-v1.json';
  const r = await verifyAgentBinding(record, cred, keyResolver);
  assert.equal(r.valid, false);
});

test('binding: acceptor identifier must be the delegated agent', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred, (r) => {
    r.acceptor.identifier = { type: 'agent_id', value: 'agent://someone-else' };
  });
  assert.equal((await verifyAgentBinding(record, cred, keyResolver)).valid, false);
});

test('binding: human acceptors cannot claim delegation', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred, (r) => {
    r.acceptor.acceptor_type = AcceptorType.HUMAN;
  });
  assert.equal((await verifyAgentBinding(record, cred, keyResolver)).valid, false);
});

test('binding: authority must be excluded from agreement_hash', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred, (r) => {
    r.canonicalization.excluded_fields = ['anchoring', 'signatures'];
  });
  const r = await verifyAgentBinding(record, cred, keyResolver);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('excluded_fields')));
});

test('binding: authority reference must match the credential presented', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const other = await sign(unsignedCredential({ delegation_id: 'dlg_other' }), principal.privateKey);
  const record = await signedRecord(cred);
  assert.equal((await verifyAgentBinding(record, other, keyResolver)).valid, false);
});

test('authority object can change without breaking the agent signature', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred);
  const before = computeAgreementHash(record);
  record.authority = { ...record.authority, status: AuthorityStatus.AUTHORIZED,
    authorization: { authorization_id: 'auth_1', event_hash: 'sha256:' + '2'.repeat(64) } };
  assert.equal(computeAgreementHash(record), before);
});

// ─── Backward compatibility ──────────────────────────────────────────────────

test('v0.2 record still passes the v0.1 verifier without a version warning', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred);
  const r = await verify(record, { level: VerificationLevel.FULL, keyResolver });
  assert.ok(!r.warnings.some((w) => w.includes('Unknown protocol version')));
});

test('normalizeEs256Signature rejects garbage', () => {
  assert.equal(normalizeEs256Signature(new Uint8Array([1, 2, 3])), null);
  assert.equal(normalizeEs256Signature(new Uint8Array(70)), null);
});

test('binding: a different credential reusing the same delegation_id is caught by credential_hash', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred);
  // Same id, broader scope, validly re-signed by the principal later.
  const swapped = await sign(
    unsignedCredential({ scope: { ...unsignedCredential().scope, actions: ['license.commercial', 'license.ai_training'] } }),
    principal.privateKey
  );
  const r = await verifyAgentBinding(record, swapped, keyResolver);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('credential_hash does not match')));
});

test('binding: a valid signature under a non-delegated key reference does not bind', async () => {
  await setup();
  const cred = await sign(unsignedCredential(), principal.privateKey);
  const record = await signedRecord(cred);
  const hash = computeAgreementHash(record);
  record.signatures = [
    { signer: 'acceptor', algorithm: 'ES256', public_key_ref: ATTACKER_KEY,
      signature: b64url(await signRaw(attacker.privateKey, hash)), signed_at: COMMIT },
  ];
  const r = await verifyAgentBinding(record, cred, keyResolver);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('No acceptor signature under the delegated agent key')));
});

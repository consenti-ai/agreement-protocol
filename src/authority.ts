/**
 * Consenti Delegation & Principal Authorization — Reference Verifier (v0.2)
 *
 * Implements, from specs/delegation-authorization-spec-v0.2.md:
 *   §6   authority object structure and status semantics
 *   §4   delegation credential verification, self-contained mode
 *   §9   revocation, evaluated over the commitment window
 *   §8.4 the binding check: the agreement's agent signature verifies against
 *        the key the principal named in the credential
 *   §16 A4 commitment time as a bounded window: the agent's asserted time is
 *        never trusted alone; the delegation must hold through a trusted time
 *        bound to agreement_hash, or through verification time without one
 *
 * Not yet implemented here (Level 1A steps 5-7, tracked separately):
 *   scope evaluation, Authorization Event verification, and recomputation of
 *   the anchor's authority_commitment. Nothing in this module, used alone,
 *   establishes that a commitment was AUTHORIZED. It establishes that a
 *   delegation was valid at commitment time and that the delegated agent
 *   signed the agreement.
 *
 * Design rule throughout: fail closed. Anything this verifier cannot check is
 * reported as unverified or unknown, never as valid.
 *
 * @license MIT
 */

import { webcrypto } from 'crypto';
import { canonicalize, sha256, computeAgreementHash } from './verifier.js';
import type { AcceptanceRecord, Identifier, AnchorProvider, AnchorRecord } from './verifier.js';

// ─── Constants ───────────────────────────────────────────────────────────────

export const AUTHORIZATION_PROTOCOL = 'consenti/authorization/v0.2';
export const DELEGATION_CREDENTIAL_TYPE = 'consenti/delegation/v0.2';

// ─── Types ───────────────────────────────────────────────────────────────────

export enum AuthorityStatus {
  AUTHORIZED = 'authorized',
  DELEGATED_ONLY = 'delegated_only',
  UNAUTHORIZED = 'unauthorized',
  EXCEEDED_SCOPE = 'exceeded_scope',
}

export interface Money {
  amount: string;
  currency: string;
}

export interface DelegationScope {
  actions: string[];
  counterparties: string[];
  max_value?: Money;
  aggregate_cap?: Money & { period: string };
  prohibited_clauses?: string[];
  requires_authorization_above?: Money;
}

export interface DetachedSignature {
  algorithm: string;
  public_key_ref: string;
  value: string;
}

export interface DelegationCredential {
  type: string;
  profile?: string;
  delegation_id: string;
  principal: { identifier: Identifier; commitment: string };
  agent: { identifier: Identifier; public_key_ref: string };
  scope: DelegationScope;
  chain_binding?: { standard: string; delegation_hash: string; chain: string };
  issued_at: string;
  expires_at: string;
  revocation: { check_url: string; anchor_ref?: string };
  signature: DetachedSignature;
}

export interface AuthorityObject {
  status: AuthorityStatus | string;
  delegation?: { delegation_id: string; credential_hash: string };
  authorization?: { authorization_id: string; event_hash: string };
}

export interface RevocationEntry {
  delegation_id: string;
  revoked_at: string;
  effective: 'prospective' | 'retroactive';
}

export interface RevocationList {
  protocol_version: string;
  updated_at: string;
  revoked: RevocationEntry[];
  anchor_ref?: string;
  signature: DetachedSignature;
}

/** Resolves a public key reference (e.g. did:web:acme.example#key-1) to a key. */
export type KeyResolver = (publicKeyRef: string) => Promise<CryptoKey | null>;

/** Fetches a principal's revocation list. Return null when unreachable. */
export type RevocationFetcher = (checkUrl: string) => Promise<RevocationList | null>;

/**
 * Confirms that a key reference is controlled by the principal. Required for
 * any principal identifier that is not a DID; for DIDs the reference verifier
 * enforces that the key is a fragment of the principal's own DID.
 */
export type KeyOwnershipCheck = (principal: Identifier, publicKeyRef: string) => Promise<boolean>;

export type RevocationStatus = 'not_revoked' | 'revoked' | 'ambiguous' | 'unknown';

export interface RevocationResult {
  status: RevocationStatus;
  /** True when the matching entry claims retroactive effect. Surface loudly. */
  retroactive: boolean;
  revokedAt: string | null;
  listUpdatedAt: string | null;
}

/**
 * Where a trusted commitment time came from. Each source is bound to the
 * agreement hash by something other than the agent's own say-so (§16 A4).
 *   anchor          — block time of the anchor carrying agreement_hash
 *   rfc3161         — genTime of an RFC 3161 token over agreement_hash
 *   x402_settlement — block time of an x402 settlement whose payment nonce
 *                     commits to agreement_hash (§17.5)
 */
export type TrustedTimeSource = 'anchor' | 'rfc3161' | 'x402_settlement';

/**
 * Evidence of when a commitment happened (§16 A4).
 *
 * The asserted time is written by the agent whose authority is in question,
 * so it is never trusted on its own. The verifier evaluates the delegation over
 * the window [asserted, end], where end is the trusted time if there is one and
 * the verification time otherwise. The delegation must hold for the whole
 * window; if a boundary (revocation or expiry) falls inside it, the order of
 * events cannot be established and the result is indeterminate.
 */
export interface CommitmentEvidence {
  /** Time the record asserts, normally acceptor.accepted_at. Untrusted. */
  asserted: string;
  /** A time bound to agreement_hash by a third party. Upper bound of the window. */
  trusted?: { time: string; source: TrustedTimeSource } | null;
  /** When verification runs. Upper bound when there is no trusted time. Default: now. */
  verifiedAt?: string;
}

export interface CredentialVerifyOptions {
  /** When the commitment happened. See CommitmentEvidence and §16 A4. */
  commitment: CommitmentEvidence;
  keyResolver: KeyResolver;
  fetchRevocationList: RevocationFetcher;
  keyOwnership?: KeyOwnershipCheck;
  /**
   * A revocation within this many seconds of either end of the commitment
   * window is ambiguous and reported as such (§9, the revocation race). Default 1.
   */
  ambiguityWindowSec?: number;
  /**
   * A revocation list whose updated_at is within this many seconds before the
   * end of the window is treated as current through the end (§16 A7). Default 300.
   */
  maxListAgeSec?: number;
}

/** The window a delegation was evaluated over, in ISO form. */
export interface CommitmentWindow {
  start: string;
  end: string;
  /** Which bound closed the window: a trusted source, or the verification time. */
  endSource: TrustedTimeSource | 'verification_time';
}

export interface CredentialVerifyResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  credentialHash: string;
  principalCommitmentMatches: boolean;
  signatureVerified: boolean;
  withinValidity: boolean | null;
  revocation: RevocationResult;
  /** The window the delegation was evaluated over; null if it could not be formed. */
  window: CommitmentWindow | null;
  /**
   * True when the only reason the result is not valid is that a boundary
   * (revocation or expiry) falls inside the commitment window, so the order of
   * events cannot be established. Reported as "unknown", not as proof of
   * invalidity. A trusted time usually narrows the window enough to resolve it.
   */
  indeterminate: boolean;
  /** Always null in the self-contained verifier; chain state is not checked here. */
  chainBindingVerified: null;
}

export interface BindingVerifyResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  agreementHash: string;
}

// ─── Hashing helpers ─────────────────────────────────────────────────────────

const stripPrefix = (h: string): string => h.replace(/^sha256:/, '');

/** `sha256:` + SHA-256 of the canonical identifier (§4.2, consistent with party_hash). */
export function computePrincipalCommitment(identifier: Identifier): string {
  return 'sha256:' + sha256(canonicalize(identifier));
}

/** Hash of the complete credential, signature included. Referenced as credential_hash. */
export function computeCredentialHash(credential: DelegationCredential): string {
  return 'sha256:' + sha256(canonicalize(credential));
}

/** Hash of the canonical authority object. Anchored as authority_commitment (§7). */
export function computeAuthorityCommitment(authority: AuthorityObject): string {
  return 'sha256:' + sha256(canonicalize(authority));
}

/** The bytes a principal signs: the canonical document with `signature` removed. */
export function signingInput(doc: { signature?: unknown }): string {
  const rest: Record<string, unknown> = { ...(doc as Record<string, unknown>) };
  delete rest.signature;
  return canonicalize(rest);
}

// ─── Authority object (§6) ───────────────────────────────────────────────────

/**
 * Structural validation of an authority object. Returns error strings; empty
 * means well-formed. Does not verify any referenced document.
 */
export function validateAuthorityObject(authority: AuthorityObject): string[] {
  const errors: string[] = [];
  const statuses = Object.values(AuthorityStatus) as string[];
  if (!statuses.includes(authority.status)) {
    errors.push(`authority.status "${authority.status}" is not one of ${statuses.join(', ')}.`);
    return errors;
  }
  const hasDelegation = !!authority.delegation;
  const hasAuthorization = !!authority.authorization;

  if (hasDelegation && !/^sha256:[0-9a-f]{64}$/.test(authority.delegation!.credential_hash ?? '')) {
    errors.push('authority.delegation.credential_hash must be sha256:<64 hex>.');
  }
  if (hasAuthorization && !/^sha256:[0-9a-f]{64}$/.test(authority.authorization!.event_hash ?? '')) {
    errors.push('authority.authorization.event_hash must be sha256:<64 hex>.');
  }

  switch (authority.status) {
    case AuthorityStatus.AUTHORIZED:
      if (!hasDelegation || !hasAuthorization) {
        errors.push('status "authorized" requires both delegation and authorization references.');
      }
      break;
    case AuthorityStatus.DELEGATED_ONLY:
      if (!hasDelegation) errors.push('status "delegated_only" requires a delegation reference.');
      if (hasAuthorization) {
        errors.push('status "delegated_only" must not carry an authorization reference; use "authorized".');
      }
      break;
    case AuthorityStatus.UNAUTHORIZED:
      if (hasDelegation || hasAuthorization) {
        errors.push('status "unauthorized" asserts no delegation; it must not carry references.');
      }
      break;
    case AuthorityStatus.EXCEEDED_SCOPE:
      if (!hasDelegation) errors.push('status "exceeded_scope" requires the delegation it exceeded.');
      break;
  }
  return errors;
}

/**
 * Reads the authority status of a record. A record with no authority object
 * (including every v0.1 record) reads as unauthorized with asserted:false,
 * which is a different claim from an explicit "unauthorized" (§2).
 */
export function readAuthorityStatus(record: AcceptanceRecord): {
  status: AuthorityStatus;
  asserted: boolean;
} {
  const a = record.authority as AuthorityObject | null | undefined;
  if (!a) return { status: AuthorityStatus.UNAUTHORIZED, asserted: false };
  return { status: a.status as AuthorityStatus, asserted: true };
}

// ─── Signatures ──────────────────────────────────────────────────────────────

function base64urlDecode(input: string): Uint8Array<ArrayBuffer> {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * WebCrypto ECDSA expects raw r||s (IEEE P1363). Many signers emit DER.
 * Accept either; return null for anything malformed.
 */
export function normalizeEs256Signature(sig: Uint8Array): Uint8Array<ArrayBuffer> | null {
  if (sig.length === 64) return new Uint8Array(sig);
  // DER: 30 len 02 rlen r 02 slen s
  if (sig.length < 8 || sig[0] !== 0x30) return null;
  let i = 2;
  if (sig[1] & 0x80) return null; // long-form length never needed for P-256
  if (sig[1] !== sig.length - 2) return null;
  const readInt = (): Uint8Array | null => {
    if (sig[i] !== 0x02) return null;
    const len = sig[i + 1];
    const start = i + 2;
    const end = start + len;
    if (len === 0 || end > sig.length) return null;
    let v = sig.slice(start, end);
    while (v.length > 1 && v[0] === 0x00) v = v.slice(1);
    if (v.length > 32) return null;
    i = end;
    return v;
  };
  const r = readInt();
  const s = readInt();
  if (!r || !s || i !== sig.length) return null;
  const out = new Uint8Array(64);
  out.set(r, 32 - r.length);
  out.set(s, 64 - s.length);
  return out;
}

/**
 * Verifies a detached ES256 signature over a UTF-8 string. Fails closed on
 * unsupported algorithms, unresolvable keys, and malformed signatures.
 */
export async function verifyDetachedSignature(
  input: string,
  signature: DetachedSignature,
  keyResolver: KeyResolver,
  label: string,
  errors: string[]
): Promise<boolean> {
  if (signature.algorithm !== 'ES256') {
    errors.push(
      `${label}: algorithm ${signature.algorithm} is not supported by this reference ` +
        'verifier. Treating as UNVERIFIED.'
    );
    return false;
  }
  let key: CryptoKey | null;
  try {
    key = await keyResolver(signature.public_key_ref);
  } catch (err) {
    errors.push(`${label}: key resolution failed for ${signature.public_key_ref}: ${(err as Error).message}`);
    return false;
  }
  if (!key) {
    errors.push(`${label}: cannot resolve public key ${signature.public_key_ref}.`);
    return false;
  }
  let raw: Uint8Array<ArrayBuffer> | null;
  try {
    raw = normalizeEs256Signature(base64urlDecode(signature.value));
  } catch {
    raw = null;
  }
  if (!raw) {
    errors.push(`${label}: signature is not a well-formed ES256 signature.`);
    return false;
  }
  try {
    const ok = await webcrypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      raw,
      new TextEncoder().encode(input)
    );
    if (!ok) errors.push(`${label}: signature is INVALID.`);
    return ok;
  } catch (err) {
    errors.push(`${label}: verification error: ${(err as Error).message}`);
    return false;
  }
}

/**
 * Whether a key reference is controlled by the principal. For a DID principal
 * the key MUST be a fragment of that DID. Otherwise a caller-supplied ownership
 * check is required; without one, ownership cannot be established and this
 * returns false. This is what stops a third party signing a credential "on
 * behalf of" a principal with its own key.
 */
export async function keyBelongsToPrincipal(
  principal: Identifier,
  publicKeyRef: string,
  keyOwnership?: KeyOwnershipCheck
): Promise<{ owned: boolean; reason?: string }> {
  if (principal.type === 'did') {
    if (publicKeyRef.startsWith(principal.value + '#')) return { owned: true };
    return {
      owned: false,
      reason: `key ${publicKeyRef} is not a fragment of principal DID ${principal.value}`,
    };
  }
  if (!keyOwnership) {
    return {
      owned: false,
      reason:
        `principal identifier type "${principal.type}" has no built-in key ownership ` +
        'rule; supply options.keyOwnership',
    };
  }
  try {
    return (await keyOwnership(principal, publicKeyRef))
      ? { owned: true }
      : { owned: false, reason: `keyOwnership check rejected ${publicKeyRef}` };
  } catch (err) {
    return { owned: false, reason: `keyOwnership check failed: ${(err as Error).message}` };
  }
}

// ─── Time ────────────────────────────────────────────────────────────────────

function parseTime(value: string | undefined, label: string, errors: string[]): number | null {
  if (!value) {
    errors.push(`${label} is missing.`);
    return null;
  }
  const t = Date.parse(value);
  if (Number.isNaN(t)) {
    errors.push(`${label} is not a valid timestamp: ${value}`);
    return null;
  }
  return t;
}

interface ResolvedWindow {
  startMs: number;
  endMs: number;
  window: CommitmentWindow;
}

/**
 * Forms the commitment window [asserted, end] (§16 A4). Returns null, with an
 * error, when the evidence is malformed or self-contradictory: an asserted time
 * after the trusted time, or either time in the verifier's future.
 */
export function resolveCommitmentWindow(
  evidence: CommitmentEvidence | undefined,
  errors: string[],
  skewSec = 1
): ResolvedWindow | null {
  if (!evidence) {
    errors.push('commitment evidence is missing.');
    return null;
  }
  const skewMs = skewSec * 1000;
  const startMs = parseTime(evidence.asserted, 'commitment.asserted', errors);
  const verifiedMs =
    evidence.verifiedAt !== undefined
      ? parseTime(evidence.verifiedAt, 'commitment.verifiedAt', errors)
      : Date.now();
  const trustedMs = evidence.trusted
    ? parseTime(evidence.trusted.time, `commitment.trusted.time (${evidence.trusted.source})`, errors)
    : null;
  if (startMs === null || verifiedMs === null || (evidence.trusted && trustedMs === null)) return null;

  if (trustedMs !== null && trustedMs > verifiedMs + skewMs) {
    errors.push(`Trusted time ${evidence.trusted!.time} is after the verification time.`);
    return null;
  }
  const endMs = trustedMs ?? verifiedMs;
  if (startMs > endMs + skewMs) {
    errors.push(
      trustedMs !== null
        ? `Record asserts ${evidence.asserted}, after its trusted ${evidence.trusted!.source} time ` +
            `${evidence.trusted!.time}. A genuine record cannot postdate its own anchor.`
        : `Record asserts ${evidence.asserted}, which is after the verification time.`
    );
    return null;
  }
  return {
    startMs,
    endMs: Math.max(startMs, endMs),
    window: {
      start: new Date(startMs).toISOString(),
      end: new Date(Math.max(startMs, endMs)).toISOString(),
      endSource: evidence.trusted ? evidence.trusted.source : 'verification_time',
    },
  };
}

/**
 * Builds commitment evidence for a record, taking the trusted time from the
 * anchor provider rather than from the record or the caller. The record's own
 * anchoring.anchored_at is self-reported and is never used as trusted time.
 * With no provider, or no anchor found, the evidence carries no trusted time
 * and the window runs to the verification time.
 */
export async function commitmentFromAnchor(
  record: AcceptanceRecord,
  anchorProvider: AnchorProvider | undefined,
  verifiedAt?: string
): Promise<{ evidence: CommitmentEvidence; warnings: string[] }> {
  const warnings: string[] = [];
  const evidence: CommitmentEvidence = { asserted: record.acceptor?.accepted_at, trusted: null, verifiedAt };
  if (!anchorProvider) {
    warnings.push('No anchor provider: no trusted commitment time; window runs to verification time.');
    return { evidence, warnings };
  }
  const hash = computeAgreementHash(record);
  let anchor: AnchorRecord | null = null;
  try {
    anchor = await anchorProvider.resolve(hash);
  } catch (err) {
    warnings.push(`Anchor lookup failed (${(err as Error).message}); no trusted commitment time.`);
    return { evidence, warnings };
  }
  if (!anchor || stripPrefix(anchor.agreement_hash) !== hash) {
    warnings.push(`No anchor for agreement_hash via ${anchorProvider.name}; no trusted commitment time.`);
    return { evidence, warnings };
  }
  evidence.trusted = { time: anchor.anchored_at, source: 'anchor' };
  return { evidence, warnings };
}

// ─── Revocation (§9) ─────────────────────────────────────────────────────────

/**
 * Determines revocation status of a delegation over the commitment window.
 *
 * - The list must be signed by the principal; otherwise status is unknown.
 * - The list must be current through the end of the window (A3, A7); otherwise unknown.
 * - Revoked before the window: revoked. After it: not revoked (prospective default).
 * - Revoked inside the window, or within the ambiguity margin of either end:
 *   ambiguous. The order of revocation and commitment cannot be established.
 */
export async function checkRevocation(
  credential: DelegationCredential,
  win: { startMs: number; endMs: number },
  options: CredentialVerifyOptions,
  errors: string[],
  warnings: string[]
): Promise<RevocationResult> {
  const unknown = (listUpdatedAt: string | null = null): RevocationResult => ({
    status: 'unknown',
    retroactive: false,
    revokedAt: null,
    listUpdatedAt,
  });

  let list: RevocationList | null;
  try {
    list = await options.fetchRevocationList(credential.revocation.check_url);
  } catch (err) {
    errors.push(`Revocation list fetch failed: ${(err as Error).message}. Status unknown.`);
    return unknown();
  }
  if (!list) {
    errors.push(`Revocation list unreachable at ${credential.revocation.check_url}. Status unknown.`);
    return unknown();
  }
  if (list.protocol_version !== AUTHORIZATION_PROTOCOL) {
    errors.push(`Revocation list protocol_version ${list.protocol_version} not recognized. Status unknown.`);
    return unknown(list.updated_at ?? null);
  }
  if (!list.signature) {
    errors.push('Revocation list is unsigned. Status unknown.');
    return unknown(list.updated_at ?? null);
  }
  const owner = await keyBelongsToPrincipal(
    credential.principal.identifier,
    list.signature.public_key_ref,
    options.keyOwnership
  );
  if (!owner.owned) {
    errors.push(`Revocation list not signed by the principal: ${owner.reason}. Status unknown.`);
    return unknown(list.updated_at ?? null);
  }
  const listSigErrors: string[] = [];
  const listSigOk = await verifyDetachedSignature(
    signingInput(list),
    list.signature,
    options.keyResolver,
    'Revocation list signature',
    listSigErrors
  );
  if (!listSigOk) {
    errors.push(...listSigErrors.map((e) => `${e} Status unknown.`));
    return unknown(list.updated_at ?? null);
  }

  const updatedMs = parseTime(list.updated_at, 'Revocation list updated_at', errors);
  if (updatedMs === null) return unknown(list.updated_at ?? null);
  const maxAgeMs = (options.maxListAgeSec ?? 300) * 1000;
  if (updatedMs + maxAgeMs < win.endMs) {
    errors.push(
      `Revocation list is accurate as of ${list.updated_at}, before the end of the commitment ` +
        `window (${new Date(win.endMs).toISOString()}); it cannot rule out a revocation inside ` +
        'the window. Status unknown.'
    );
    return unknown(list.updated_at);
  }

  const entries = (list.revoked ?? []).filter((e) => e.delegation_id === credential.delegation_id);
  if (entries.length === 0) {
    return { status: 'not_revoked', retroactive: false, revokedAt: null, listUpdatedAt: list.updated_at };
  }

  // Earliest effective revocation governs.
  let earliest: RevocationEntry | null = null;
  let earliestMs = Infinity;
  for (const e of entries) {
    const ms = parseTime(e.revoked_at, `Revocation entry revoked_at for ${e.delegation_id}`, errors);
    if (ms === null) return unknown(list.updated_at);
    if (ms < earliestMs) {
      earliestMs = ms;
      earliest = e;
    }
  }
  const retroactive = earliest!.effective === 'retroactive';
  if (retroactive) {
    warnings.push(
      `RETROACTIVE REVOCATION: principal asserts the agent key was not under its control ` +
        `from ${earliest!.revoked_at}. This is a key-compromise claim, not an ordinary revocation.`
    );
  }
  const marginMs = (options.ambiguityWindowSec ?? 1) * 1000;
  if (earliestMs >= win.startMs - marginMs && earliestMs <= win.endMs + marginMs) {
    errors.push(
      win.endMs - win.startMs <= marginMs
        ? `Revocation at ${earliest!.revoked_at} and commitment are within ${marginMs / 1000}s. ` +
            'Order cannot be established; reported as ambiguous.'
        : `Revocation at ${earliest!.revoked_at} falls inside the commitment window ` +
            `${new Date(win.startMs).toISOString()} to ${new Date(win.endMs).toISOString()}. ` +
            'Without a trusted time closer to the commitment, the order cannot be established; ' +
            'reported as ambiguous.'
    );
    return { status: 'ambiguous', retroactive, revokedAt: earliest!.revoked_at, listUpdatedAt: list.updated_at };
  }
  if (earliestMs < win.startMs) {
    errors.push(`Delegation ${credential.delegation_id} was revoked at ${earliest!.revoked_at}, before the commitment.`);
    return { status: 'revoked', retroactive, revokedAt: earliest!.revoked_at, listUpdatedAt: list.updated_at };
  }
  warnings.push(
    `Delegation was revoked at ${earliest!.revoked_at}, after this commitment. ` +
      'Revocation is prospective; this commitment remains within the delegation.'
  );
  return { status: 'not_revoked', retroactive, revokedAt: earliest!.revoked_at, listUpdatedAt: list.updated_at };
}

// ─── Delegation credential (§4, self-contained mode) ─────────────────────────

/**
 * Verifies a delegation credential over the commitment window:
 * structure, principal commitment, key ownership, principal signature,
 * validity, and revocation. Valid only if every check passes for the whole
 * window. See CredentialVerifyResult.indeterminate for the "unknown" outcome.
 */
export async function verifyDelegationCredential(
  credential: DelegationCredential,
  options: CredentialVerifyOptions
): Promise<CredentialVerifyResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const credentialHash = (() => {
    try {
      return computeCredentialHash(credential);
    } catch {
      return '';
    }
  })();
  const fail = (extra: Partial<CredentialVerifyResult> = {}): CredentialVerifyResult => ({
    valid: false,
    errors,
    warnings,
    credentialHash,
    principalCommitmentMatches: false,
    signatureVerified: false,
    withinValidity: null,
    revocation: { status: 'unknown', retroactive: false, revokedAt: null, listUpdatedAt: null },
    window: null,
    indeterminate: false,
    chainBindingVerified: null,
    ...extra,
  });

  // Structure
  if (credential?.type !== DELEGATION_CREDENTIAL_TYPE) {
    errors.push(`Credential type must be ${DELEGATION_CREDENTIAL_TYPE}.`);
  }
  const required: Array<[unknown, string]> = [
    [credential?.delegation_id, 'delegation_id'],
    [credential?.principal?.identifier, 'principal.identifier'],
    [credential?.principal?.commitment, 'principal.commitment'],
    [credential?.agent?.identifier, 'agent.identifier'],
    [credential?.agent?.public_key_ref, 'agent.public_key_ref'],
    [credential?.scope, 'scope'],
    [credential?.expires_at, 'expires_at'],
    [credential?.revocation?.check_url, 'revocation.check_url'],
    [credential?.signature, 'signature'],
  ];
  for (const [v, name] of required) if (!v) errors.push(`Credential is missing required field ${name}.`);
  if (credential?.scope) {
    if (!Array.isArray(credential.scope.actions) || credential.scope.actions.length === 0) {
      errors.push('scope.actions must be a non-empty list; unbounded grants use an explicit "*".');
    }
    if (!Array.isArray(credential.scope.counterparties) || credential.scope.counterparties.length === 0) {
      errors.push('scope.counterparties must be a non-empty list; unbounded grants use an explicit "*".');
    }
  }
  if (errors.length > 0) return fail();

  if (credential.chain_binding) {
    warnings.push(
      'chain_binding present but not checked: this self-contained verifier does not ' +
        'read chain state. The credential is verified on the principal signature alone.'
    );
  }

  // Principal commitment
  const principalCommitmentMatches =
    stripPrefix(credential.principal.commitment) ===
    stripPrefix(computePrincipalCommitment(credential.principal.identifier));
  if (!principalCommitmentMatches) {
    errors.push('principal.commitment does not match the hash of principal.identifier.');
  }

  // Key ownership, then signature
  let signatureVerified = false;
  const owner = await keyBelongsToPrincipal(
    credential.principal.identifier,
    credential.signature.public_key_ref,
    options.keyOwnership
  );
  if (!owner.owned) {
    errors.push(`Credential not signed by a principal-controlled key: ${owner.reason}.`);
  } else {
    signatureVerified = await verifyDetachedSignature(
      signingInput(credential),
      credential.signature,
      options.keyResolver,
      'Credential signature',
      errors
    );
  }

  // Validity, over the whole commitment window (§16 A4). The asserted time is
  // the agent's own claim, so the credential must be valid from it through the
  // trusted time (or verification time). An expiry inside the window means the
  // order cannot be established: withinValidity is null, not false.
  let withinValidity: boolean | null = null;
  let expiryInWindow = false;
  const resolved = resolveCommitmentWindow(options.commitment, errors, options.ambiguityWindowSec ?? 1);
  const issuedMs = parseTime(credential.issued_at, 'issued_at', errors);
  const expiresMs = parseTime(credential.expires_at, 'expires_at', errors);
  if (resolved && issuedMs !== null && expiresMs !== null) {
    const { startMs, endMs, window: w } = resolved;
    if (issuedMs >= expiresMs) {
      errors.push('issued_at must precede expires_at.');
      withinValidity = false;
    } else if (startMs < issuedMs) {
      errors.push(`Commitment asserted at ${w.start} precedes credential issuance at ${credential.issued_at}.`);
      withinValidity = false;
    } else if (startMs > expiresMs) {
      errors.push(`Commitment asserted at ${w.start} is after credential expiry at ${credential.expires_at}.`);
      withinValidity = false;
    } else if (endMs > expiresMs) {
      expiryInWindow = true;
      errors.push(
        `Credential expired at ${credential.expires_at}, inside the commitment window ${w.start} to ` +
          `${w.end}. Whether the commitment preceded expiry cannot be established.`
      );
    } else {
      withinValidity = true;
    }
  }

  // Revocation. Checked even when earlier steps fail, so the result is complete.
  const revocation = resolved
    ? await checkRevocation(credential, resolved, options, errors, warnings)
    : ({ status: 'unknown', retroactive: false, revokedAt: null, listUpdatedAt: null } as RevocationResult);

  const valid =
    principalCommitmentMatches &&
    signatureVerified &&
    withinValidity === true &&
    revocation.status === 'not_revoked' &&
    errors.length === 0;

  // Indeterminate: every other check passed and the only failures are a
  // boundary inside the window. Not proof of invalidity; proof is not possible.
  const indeterminate =
    !valid &&
    principalCommitmentMatches &&
    signatureVerified &&
    (expiryInWindow || revocation.status === 'ambiguous') &&
    (withinValidity === true || expiryInWindow) &&
    (revocation.status === 'not_revoked' || revocation.status === 'ambiguous');

  return {
    valid,
    errors,
    warnings,
    credentialHash,
    principalCommitmentMatches,
    signatureVerified,
    withinValidity,
    revocation,
    window: resolved?.window ?? null,
    indeterminate,
    chainBindingVerified: null,
  };
}

// ─── Binding (§8 step 4) ─────────────────────────────────────────────────────

/**
 * Confirms the agreement was signed by the agent the credential names, with
 * the key the principal named. Without this, a verifier holds two unrelated
 * documents: a valid delegation, and a signature by someone.
 *
 * Checks:
 *   1. The record's acceptor is an agent, with the credential's agent identifier.
 *   2. If an authority object is present, it is excluded from agreement_hash and
 *      its delegation reference matches this credential.
 *   3. An acceptor signature exists under credential.agent.public_key_ref and
 *      verifies over the agreement hash (the v0.1 signing convention).
 */
export async function verifyAgentBinding(
  record: AcceptanceRecord,
  credential: DelegationCredential,
  keyResolver: KeyResolver
): Promise<BindingVerifyResult> {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (record.acceptor?.acceptor_type !== 'agent') {
    errors.push(`Acceptor type is "${record.acceptor?.acceptor_type}"; delegation binds only agent acceptors.`);
  }
  if (canonicalize(record.acceptor?.identifier ?? null) !== canonicalize(credential.agent.identifier)) {
    errors.push(
      'Acceptor identifier does not match the agent named in the delegation credential.'
    );
  }

  const authority = record.authority as AuthorityObject | null | undefined;
  if (authority) {
    if (record.protocol_version !== 'consenti/v0.2') {
      errors.push('An authority object requires protocol_version consenti/v0.2.');
    }
    const excluded = record.canonicalization?.excluded_fields;
    if (excluded && !excluded.includes('authority')) {
      errors.push(
        'authority is present but not listed in canonicalization.excluded_fields. ' +
          'It must be excluded from agreement_hash (the Authorization Event binds to that hash).'
      );
    }
    errors.push(...validateAuthorityObject(authority));
    if (authority.delegation) {
      if (authority.delegation.delegation_id !== credential.delegation_id) {
        errors.push('authority.delegation.delegation_id does not match the credential.');
      }
      if (stripPrefix(authority.delegation.credential_hash) !== stripPrefix(computeCredentialHash(credential))) {
        errors.push('authority.delegation.credential_hash does not match the credential presented.');
      }
    }
  } else {
    warnings.push('Record carries no authority object; it reads as unauthorized with no assertion.');
  }

  let agreementHash = '';
  try {
    agreementHash = computeAgreementHash(record);
  } catch (err) {
    errors.push(`Hash computation failed: ${(err as Error).message}`);
    return { valid: false, errors, warnings, agreementHash };
  }
  if (record.anchoring?.agreement_hash && stripPrefix(record.anchoring.agreement_hash) !== agreementHash) {
    errors.push('Computed agreement hash does not match anchoring.agreement_hash.');
  }

  const agentKey = credential.agent.public_key_ref;
  const acceptorSigs = (record.signatures ?? []).filter((s) => s.signer === 'acceptor');
  const bound = acceptorSigs.filter((s) => s.public_key_ref === agentKey);
  if (bound.length === 0) {
    errors.push(`No acceptor signature under the delegated agent key ${agentKey}.`);
  } else {
    if (acceptorSigs.length > bound.length) {
      warnings.push('Record carries acceptor signatures under other keys; only the delegated key was evaluated.');
    }
    let anyValid = false;
    for (const sig of bound) {
      const ok = await verifyDetachedSignature(
        agreementHash,
        { algorithm: sig.algorithm, public_key_ref: agentKey, value: sig.signature },
        keyResolver,
        'Agent signature',
        errors
      );
      anyValid = anyValid || ok;
    }
    if (!anyValid) errors.push('The delegated agent key did not produce a valid signature over this agreement.');
  }

  return { valid: errors.length === 0, errors, warnings, agreementHash };
}

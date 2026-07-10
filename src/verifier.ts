/**
 * Consenti Agreement Protocol — Reference Verifier v0.1
 *
 * Independently verifies acceptance records against their anchored commitments.
 * No Consenti infrastructure required. MIT licensed.
 *
 * Usage:
 *   import { verify, VerificationLevel } from '@consenti-ai/verifier';
 *
 *   const result = await verify(acceptanceRecord, {
 *     level: VerificationLevel.ACCEPTANCE_PROOF,
 *     anchorProvider: pangeaProvider,  // or evmProvider, tsaProvider, etc.
 *   });
 *
 *   if (result.valid) {
 *     console.log(`Verified: ${result.acceptor} accepted ${result.termsTitle} at ${result.acceptedAt}`);
 *   }
 *
 * @module @consenti-ai/verifier
 * @version 0.1.0
 * @license MIT
 */

import { createHash } from 'crypto';

// ─── Types ───────────────────────────────────────────────────────────────────

export enum VerificationLevel {
  /** Confirm an acceptance record exists on the anchor. Zero content disclosure. */
  EXISTENCE = 0,
  /** Confirm a specific acceptor agreed to specific terms at a specific time. */
  ACCEPTANCE_PROOF = 1,
  /** Full verification with signatures, suitable for dispute resolution. */
  FULL = 2,
}

export enum AcceptorType {
  HUMAN = 'human',
  AGENT = 'agent',
}

export interface Identifier {
  type: string;
  value: string;
}

export interface Publisher {
  identifier: Identifier;
  display_name?: string | null;
}

export interface Acceptor {
  acceptor_type: AcceptorType;
  identifier: Identifier;
  display_name?: string | null;
  accepted_at: string;
  ip_address?: string | null;
  user_agent?: string | null;
}

export interface TermsRef {
  terms_hash: string;
  terms_url: string;
  terms_version?: string | null;
  terms_title?: string | null;
}

export interface Anchoring {
  method: string;
  chain_id?: string | null;
  transaction_ref?: string | null;
  anchored_at?: string | null;
  agreement_hash: string;
}

export interface Signature {
  signer: 'publisher' | 'acceptor';
  algorithm: string;
  public_key_ref: string;
  signature: string;
  signed_at: string;
}

export interface Canonicalization {
  method: 'RFC8785';
  hash_algorithm: 'SHA-256';
  excluded_fields: string[];
}

export interface AcceptanceRecord {
  protocol_version: string;
  agreement_id: string;
  created_at: string;
  expires_at?: string | null;
  publisher: Publisher;
  acceptor: Acceptor;
  terms_ref: TermsRef;
  acceptance_method?: string;
  proof_of_understanding?: Record<string, unknown> | null;
  jurisdiction?: Record<string, unknown> | null;
  anchoring?: Anchoring | null;
  signatures?: Signature[] | null;
  privacy?: Record<string, unknown> | null;
  canonicalization: Canonicalization;
  extensions?: Record<string, unknown> | null;
}

export interface AnchorRecord {
  agreement_hash: string;
  acceptor_hash?: string;
  anchored_at: string;
  transaction_ref: string;
}

/**
 * An anchor provider resolves an agreement_hash to its on-chain anchor record.
 * Implementers provide one per chain (Pangea, EVM, RFC 3161 TSA, etc.).
 */
export interface AnchorProvider {
  name: string;
  resolve(agreementHash: string): Promise<AnchorRecord | null>;
}

export interface VerifyOptions {
  level: VerificationLevel;
  /**
   * Resolves an agreement_hash to its on-chain anchor record.
   * Optional: if omitted, anchor existence is NOT verified — the verifier
   * performs structural, hash-consistency, and (at Level 2) signature checks
   * only, and emits a warning. EXISTENCE-level verification requires a provider.
   */
  anchorProvider?: AnchorProvider;
  /** Optional: verify cryptographic signatures (requires key resolver). */
  keyResolver?: (publicKeyRef: string) => Promise<CryptoKey | null>;
  /** Optional: tolerance in seconds for timestamp comparison. Default: 60. */
  timestampToleranceSec?: number;
}

export interface VerificationResult {
  valid: boolean;
  level: VerificationLevel;
  agreementHash: string;
  errors: string[];
  warnings: string[];

  // Populated at Level 0+
  anchorFound: boolean;
  anchoredAt: string | null;

  // Populated at Level 1+
  acceptor: string | null;
  acceptorType: AcceptorType | null;
  termsHash: string | null;
  termsTitle: string | null;
  acceptedAt: string | null;

  // Populated at Level 2
  signaturesVerified: boolean | null;
  expired: boolean | null;
}

// ─── Canonicalization (RFC 8785 — JSON Canonicalization Scheme) ──────────────

/**
 * Canonicalizes a JSON value per RFC 8785 (JCS).
 * Produces deterministic serialization: sorted keys, no whitespace, specific number formatting.
 */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (typeof value === 'number') {
    if (!isFinite(value)) {
      throw new Error('RFC 8785: non-finite numbers are not allowed');
    }
    // RFC 8785 uses ES2015 Number serialization
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalize(item));
    return '[' + items.join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const entries = sortedKeys
      .filter((key) => obj[key] !== undefined)
      .map((key) => JSON.stringify(key) + ':' + canonicalize(obj[key]));
    return '{' + entries.join(',') + '}';
  }
  throw new Error(`RFC 8785: unsupported type ${typeof value}`);
}

// ─── Hashing ─────────────────────────────────────────────────────────────────

/**
 * SHA-256 hash of a UTF-8 string, returned as hex.
 */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Computes the canonical agreement_hash for an acceptance record.
 *
 * 1. Deep-clone the record
 * 2. Remove excluded fields (anchoring, signatures, privacy derived fields)
 * 3. Canonicalize via RFC 8785
 * 4. SHA-256 the canonical form
 */
export function computeAgreementHash(record: AcceptanceRecord): string {
  const excluded = record.canonicalization?.excluded_fields ?? [
    'anchoring',
    'signatures',
    'privacy.anchor_commitment',
    'privacy.merkle_tree.root',
  ];

  // Deep clone
  const clone = JSON.parse(JSON.stringify(record)) as Record<string, unknown>;

  // Remove top-level excluded fields
  for (const field of excluded) {
    if (!field.includes('.')) {
      delete clone[field];
    } else {
      // Handle dotted paths like 'privacy.anchor_commitment'
      const parts = field.split('.');
      let target: Record<string, unknown> = clone;
      for (let i = 0; i < parts.length - 1; i++) {
        if (target[parts[i]] && typeof target[parts[i]] === 'object') {
          target = target[parts[i]] as Record<string, unknown>;
        } else {
          break;
        }
      }
      delete target[parts[parts.length - 1]];
    }
  }

  const canonical = canonicalize(clone);
  return sha256(canonical);
}

/**
 * Computes the acceptor_hash (pseudonymous anchor commitment).
 */
export function computeAcceptorHash(identifier: Identifier): string {
  const canonical = canonicalize(identifier);
  return sha256(canonical);
}

// ─── Verification ────────────────────────────────────────────────────────────

/**
 * Verify an acceptance record at the specified verification level.
 *
 * Level 0 — Existence: Confirms the agreement_hash exists on the anchor chain.
 * Level 1 — Acceptance Proof: Confirms acceptor, terms, and timestamp match.
 * Level 2 — Full: Verifies signatures and expiration in addition to Level 1.
 */
export async function verify(
  record: AcceptanceRecord,
  options: VerifyOptions
): Promise<VerificationResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const toleranceSec = options.timestampToleranceSec ?? 60;

  // ── Step 1: Compute agreement hash ────────────────────────────────────

  let agreementHash: string;
  try {
    agreementHash = computeAgreementHash(record);
  } catch (err) {
    return failResult(
      options.level,
      '',
      [`Hash computation failed: ${(err as Error).message}`]
    );
  }

  // Verify self-consistency if anchoring.agreement_hash is present
  if (record.anchoring?.agreement_hash) {
    const declaredHash = record.anchoring.agreement_hash.replace(/^sha256:/, '');
    if (declaredHash !== agreementHash) {
      errors.push(
        `Hash mismatch: computed ${agreementHash}, declared ${declaredHash}. ` +
        'Record may have been tampered with.'
      );
      return failResult(options.level, agreementHash, errors);
    }
  }

  // ── Step 2: Protocol version check ────────────────────────────────────

  if (record.protocol_version !== 'consenti/v0.1') {
    warnings.push(
      `Unknown protocol version: ${record.protocol_version}. ` +
      'This verifier targets consenti/v0.1.'
    );
  }

  // ── Step 3: Anchor lookup (Level 0+) ──────────────────────────────────

  let anchorRecord: AnchorRecord | null = null;

  if (!options.anchorProvider) {
    if (options.level === VerificationLevel.EXISTENCE) {
      errors.push(
        'EXISTENCE verification requires an anchorProvider: ' +
        'existence is defined as presence on the anchor, which cannot be ' +
        'checked without one.'
      );
      return {
        valid: false,
        level: options.level,
        agreementHash,
        errors,
        warnings,
        anchorFound: false,
        anchoredAt: null,
        acceptor: null,
        acceptorType: null,
        termsHash: null,
        termsTitle: null,
        acceptedAt: null,
        signaturesVerified: null,
        expired: null,
      };
    }
    warnings.push(
      'No anchorProvider supplied: anchor existence NOT verified. ' +
      'Result reflects structural and hash-consistency checks only.'
    );
  } else {
    try {
      anchorRecord = await options.anchorProvider.resolve(agreementHash);
    } catch (err) {
      errors.push(`Anchor lookup failed: ${(err as Error).message}`);
    }
  }

  if (options.anchorProvider && !anchorRecord) {
    errors.push(
      `No anchor found for agreement_hash ${agreementHash} ` +
      `via ${options.anchorProvider.name}. ` +
      'Record may not yet be anchored, or anchor provider may be unreachable.'
    );
    return {
      valid: false,
      level: options.level,
      agreementHash,
      errors,
      warnings,
      anchorFound: false,
      anchoredAt: null,
      acceptor: null,
      acceptorType: null,
      termsHash: null,
      termsTitle: null,
      acceptedAt: null,
      signaturesVerified: null,
      expired: null,
    };
  }

  // Level 0 satisfied: anchor exists
  if (options.level === VerificationLevel.EXISTENCE) {
    return {
      valid: errors.length === 0,
      level: VerificationLevel.EXISTENCE,
      agreementHash,
      errors,
      warnings,
      anchorFound: anchorRecord !== null,
      anchoredAt: anchorRecord?.anchored_at ?? null,
      acceptor: null,
      acceptorType: null,
      termsHash: null,
      termsTitle: null,
      acceptedAt: null,
      signaturesVerified: null,
      expired: null,
    };
  }

  // ── Step 4: Acceptance proof (Level 1+) ───────────────────────────────

  // Verify acceptor_hash if anchor provides one
  if (anchorRecord?.acceptor_hash) {
    const computedAcceptorHash = computeAcceptorHash(record.acceptor.identifier);
    const declaredAcceptorHash = anchorRecord.acceptor_hash.replace(/^sha256:/, '');
    if (computedAcceptorHash !== declaredAcceptorHash) {
      errors.push(
        `Acceptor hash mismatch: computed ${computedAcceptorHash}, ` +
        `anchor has ${declaredAcceptorHash}. Acceptor identity may have been altered.`
      );
    }
  }

  // Verify timestamp consistency
  const acceptedAt = new Date(record.acceptor.accepted_at);
  const anchoredAt = anchorRecord ? new Date(anchorRecord.anchored_at) : null;
  if (anchoredAt && acceptedAt > anchoredAt) {
    const diffSec = (acceptedAt.getTime() - anchoredAt.getTime()) / 1000;
    if (diffSec > toleranceSec) {
      errors.push(
        `Timestamp inconsistency: accepted_at (${record.acceptor.accepted_at}) ` +
        `is after anchored_at (${anchoredAt.toISOString()}) by ${diffSec}s. ` +
        'Acceptance cannot occur after anchoring.'
      );
    }
  }

  // Required fields check
  if (!record.terms_ref?.terms_hash) {
    errors.push('Missing terms_ref.terms_hash — cannot verify which terms were accepted.');
  }
  if (!record.acceptor?.identifier?.value) {
    errors.push('Missing acceptor.identifier.value — cannot verify who accepted.');
  }

  if (options.level === VerificationLevel.ACCEPTANCE_PROOF) {
    return {
      valid: errors.length === 0,
      level: VerificationLevel.ACCEPTANCE_PROOF,
      agreementHash,
      errors,
      warnings,
      anchorFound: anchorRecord !== null,
      anchoredAt: anchorRecord?.anchored_at ?? null,
      acceptor: record.acceptor?.identifier?.value ?? null,
      acceptorType: (record.acceptor?.acceptor_type as AcceptorType) ?? null,
      termsHash: record.terms_ref?.terms_hash ?? null,
      termsTitle: record.terms_ref?.terms_title ?? null,
      acceptedAt: record.acceptor?.accepted_at ?? null,
      signaturesVerified: null,
      expired: null,
    };
  }

  // ── Step 5: Full verification (Level 2) ───────────────────────────────

  // Check expiration
  let expired = false;
  if (record.expires_at) {
    expired = new Date(record.expires_at) < new Date();
    if (expired) {
      warnings.push(
        `Acceptance expired at ${record.expires_at}. ` +
        'Record is valid but no longer in force.'
      );
    }
  }

  // Verify signatures if present and key resolver is provided
  let signaturesVerified: boolean | null = null;
  if (record.signatures && record.signatures.length > 0) {
    if (options.keyResolver) {
      signaturesVerified = true;
      for (const sig of record.signatures) {
        try {
          const key = await options.keyResolver(sig.public_key_ref);
          if (!key) {
            errors.push(
              `Cannot resolve public key for ${sig.signer}: ${sig.public_key_ref}`
            );
            signaturesVerified = false;
            continue;
          }

          // Signature verification is algorithm-specific.
          // This reference implementation defers to the WebCrypto API.
          const signatureBytes = base64urlDecode(sig.signature);
          const dataBytes = new TextEncoder().encode(agreementHash);

          const algorithmMap: Record<string, RsaHashedImportParams | EcdsaParams> = {
            ES256: { name: 'ECDSA', hash: 'SHA-256' },
            RS256: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          };

          const algo = algorithmMap[sig.algorithm];
          if (!algo) {
            warnings.push(
              `Signature algorithm ${sig.algorithm} not supported by reference verifier. ` +
              'Use a specialized verifier for this algorithm.'
            );
            continue;
          }

          const valid = await crypto.subtle.verify(
            algo,
            key,
            signatureBytes,
            dataBytes
          );

          if (!valid) {
            errors.push(`Signature by ${sig.signer} is INVALID.`);
            signaturesVerified = false;
          }
        } catch (err) {
          errors.push(
            `Signature verification failed for ${sig.signer}: ${(err as Error).message}`
          );
          signaturesVerified = false;
        }
      }
    } else {
      warnings.push(
        'Signatures present but no keyResolver provided. ' +
        'Signatures were not verified.'
      );
    }
  } else if (record.acceptor.acceptor_type === AcceptorType.AGENT) {
    warnings.push(
      'Agent acceptor has no signatures. ' +
      'Agent acceptance records SHOULD include a cryptographic signature.'
    );
  }

  return {
    valid: errors.length === 0,
    level: VerificationLevel.FULL,
    agreementHash,
    errors,
    warnings,
    anchorFound: anchorRecord !== null,
    anchoredAt: anchorRecord?.anchored_at ?? null,
    acceptor: record.acceptor?.identifier?.value ?? null,
    acceptorType: (record.acceptor?.acceptor_type as AcceptorType) ?? null,
    termsHash: record.terms_ref?.terms_hash ?? null,
    termsTitle: record.terms_ref?.terms_title ?? null,
    acceptedAt: record.acceptor?.accepted_at ?? null,
    signaturesVerified,
    expired,
  };
}

// ─── Utilities ───────────────────────────────────────────────────────────────

function failResult(
  level: VerificationLevel,
  agreementHash: string,
  errors: string[]
): VerificationResult {
  return {
    valid: false,
    level,
    agreementHash,
    errors,
    warnings: [],
    anchorFound: false,
    anchoredAt: null,
    acceptor: null,
    acceptorType: null,
    termsHash: null,
    termsTitle: null,
    acceptedAt: null,
    signaturesVerified: null,
    expired: null,
  };
}

function base64urlDecode(input: string): Uint8Array<ArrayBuffer> {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export default {
  verify,
  computeAgreementHash,
  computeAcceptorHash,
  canonicalize,
  sha256,
  VerificationLevel,
  AcceptorType,
};

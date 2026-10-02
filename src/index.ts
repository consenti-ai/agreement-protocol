export {
  verify,
  computeAgreementHash,
  computeAcceptorHash,
  canonicalize,
  sha256,
  VerificationLevel,
  AcceptorType,
} from './verifier.js';

export type {
  AcceptanceRecord,
  AnchorProvider,
  AnchorRecord,
  VerifyOptions,
  VerificationResult,
  Identifier,
  Publisher,
  Acceptor,
  TermsRef,
  Anchoring,
  Signature,
  Canonicalization,
} from './verifier.js';

// ─── v0.2: consenti/authorization/v0.2 ───────────────────────────────────────
export {
  AUTHORIZATION_PROTOCOL,
  DELEGATION_CREDENTIAL_TYPE,
  AuthorityStatus,
  computePrincipalCommitment,
  computeCredentialHash,
  computeAuthorityCommitment,
  signingInput,
  validateAuthorityObject,
  readAuthorityStatus,
  normalizeEs256Signature,
  verifyDetachedSignature,
  keyBelongsToPrincipal,
  checkRevocation,
  verifyDelegationCredential,
  verifyAgentBinding,
} from './authority.js';

export type {
  Money,
  DelegationScope,
  DetachedSignature,
  DelegationCredential,
  AuthorityObject,
  RevocationEntry,
  RevocationList,
  KeyResolver,
  RevocationFetcher,
  KeyOwnershipCheck,
  RevocationStatus,
  RevocationResult,
  CredentialVerifyOptions,
  CredentialVerifyResult,
  BindingVerifyResult,
} from './authority.js';

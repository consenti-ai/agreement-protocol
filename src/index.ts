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

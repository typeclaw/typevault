// typevault/core: the vault format and its cryptography with no file system, daemon or native code, so a browser,
// an app or another sync transport can read and write TypeVault entries. Re-exports only.
export {
  decodeSecretKey,
  encodeSecretKey,
  generateSecretKey,
  generateSigningKey,
  type Identity,
  type KeyRole,
  type PublicKey,
  publicKeyOf,
  recipientOf,
  seal,
  type SecretKey,
  sha256Hex,
  sign,
  unseal,
  verifySignature,
} from './crypto'
export { canonicalJson, fromBase64, fromUtf8, type Json, toBase64, utf8 } from './encoding'
export {
  type Envelope,
  EnvelopeSchema,
  openEntry,
  sealEntry,
  type OnlyMatcher,
  type SignerContext,
  signerOf,
  signCiphertext,
  type TierKeys,
  verifyEnvelope,
  type VerifyOptions,
} from './entries'
export { type ErrorCode, TypeVaultError } from './errors'
export {
  includersOf,
  type Member,
  type Members,
  parseMemberName,
  parseTierName,
  reach,
  reachesTier,
  type Tier,
  type Tiers,
  type VaultState,
} from './model'
export { type EntryName, type Field, type FieldType, parseEntryName } from './naming'
export { decodePayload, encodePayload, type EntryPayload } from './payload'
export { RevisionLedger } from './revision-ledger'
export { openWrap, ownerWrapPath, samePublic, sealWrap, type WrapHolder, wrapPath } from './wraps'

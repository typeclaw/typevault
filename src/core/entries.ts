import { z } from 'zod'

import { seal, type SecretKey, sign, unseal, verifySignature } from './crypto'
import { canonicalJson, fromBase64, type Json, toBase64, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import type { Keyring } from './keyring'
import { matchesOnly } from './naming'
import { decodePayload, encodePayload, type EntryPayload } from './payload'
import { reach, reachesGroup, type VaultState } from './state'

const IssuerSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('owner') }),
  z.object({ kind: z.literal('group'), group: z.string(), gen: z.number().int().positive() }),
  z.object({ kind: z.literal('signer'), id: z.string() }),
])
export const CertSchema = z.object({
  signPublic: z.string(),
  groups: z.array(z.string()),
  /** Name patterns the holder may write; empty means any name in its groups. */
  only: z.array(z.string()),
  exp: z.iso.datetime(),
  issuer: IssuerSchema,
  sig: z.string(),
})
const SignerSchema = z.union([IssuerSchema, z.object({ kind: z.literal('cert'), cert: CertSchema })])
export const EnvelopeSchema = z.object({
  v: z.literal(1),
  id: z.string().regex(/^[0-9a-f]{32}$/),
  group: z.string(),
  gen: z.number().int().positive(),
  rev: z.number().int().positive(),
  at: z.iso.datetime(),
  payload: z.string(),
  signer: SignerSchema,
  sig: z.string(),
})

export type IssuerRef = z.infer<typeof IssuerSchema>
export type Cert = z.infer<typeof CertSchema>
export type SignerRef = z.infer<typeof SignerSchema>
export type Envelope = z.infer<typeof EnvelopeSchema>

/** Who signs a write: a reference other readers can check plus the matching signing secret. */
export type SignerContext = { readonly ref: SignerRef; readonly signSecret: Uint8Array }

export const signerOf = (key: SecretKey): SignerContext => ({
  ref: key.role.kind === 'owner' ? { kind: 'owner' } : { kind: 'group', group: key.role.group, gen: key.role.gen },
  signSecret: key.signSecret,
})

type Authority = { readonly signPublic: string; readonly groups: readonly string[] }

function authorityOf(ref: IssuerRef, state: VaultState): Authority | undefined {
  switch (ref.kind) {
    case 'owner':
      return { signPublic: state.owner.signPublic, groups: ['*'] }
    case 'group': {
      const group = state.groups[ref.group]
      return group === undefined || group.gen !== ref.gen
        ? undefined
        : { signPublic: group.signPublic, groups: [ref.group] }
    }
    case 'signer':
      return state.signers[ref.id]
    default:
      return assertNever(ref)
  }
}

function assertNever(value: never): never {
  throw new TypeVaultError('invalid', `unexpected value ${JSON.stringify(value)}`)
}

const certBytes = (cert: Omit<Cert, 'sig'>): Uint8Array =>
  utf8(
    canonicalJson({
      signPublic: cert.signPublic,
      groups: cert.groups,
      only: cert.only,
      exp: cert.exp,
      issuer: cert.issuer,
    }),
  )

export function issueCert(cert: Omit<Cert, 'sig' | 'issuer'>, issuer: SignerContext): Cert {
  if (issuer.ref.kind === 'cert') throw new TypeVaultError('denied', 'a grant certificate cannot issue another')
  const unsigned = { ...cert, issuer: issuer.ref }
  return { ...unsigned, sig: sign(issuer.signSecret, certBytes(unsigned)) }
}

const envelopeBytes = (envelope: Omit<Envelope, 'sig'>): Uint8Array => {
  const { v, id, group, gen, rev, at, payload, signer } = envelope
  const body: Json = { v, id, group, gen, rev, at, payload, signer }
  return utf8(canonicalJson(body))
}

/** Whether `signer` may sign entries of `group`, judged only from owner-signed state. */
/** `now` is the reader's clock for certificate expiry; `null` skips that one check (explicit owner adoption). */
export function signerAuthority(
  signer: SignerRef,
  group: string,
  state: VaultState,
  at: string,
  now: number | null = Date.now(),
): string | undefined {
  if (signer.kind !== 'cert') {
    const authority = authorityOf(signer, state)
    return authority !== undefined && reachesGroup(state.groups, authority.groups, group)
      ? authority.signPublic
      : undefined
  }
  const { cert } = signer
  const issuer = authorityOf(cert.issuer, state)
  if (issuer === undefined || !verifySignature(issuer.signPublic, certBytes(cert), cert.sig)) return undefined
  if (!cert.groups.every((g) => reachesGroup(state.groups, issuer.groups, g))) return undefined
  // Expiry is judged by the reader's clock: `at` is chosen by the holder, so it can't be trusted to bound it.
  const exp = Date.parse(cert.exp)
  if (
    !cert.groups.some((g) => reach(state.groups, g).has(group)) ||
    Date.parse(at) > exp ||
    (now !== null && now > exp)
  ) {
    return undefined
  }
  return cert.signPublic
}

export type EntryDraft = {
  readonly id: string
  readonly group: string
  readonly rev: number
  readonly at: string
  readonly payload: EntryPayload
}

export async function sealEntry(draft: EntryDraft, state: VaultState, signer: SignerContext): Promise<Envelope> {
  const group = state.groups[draft.group]
  if (group === undefined) throw new TypeVaultError('not_found', `no group "${draft.group}"`)
  const ciphertext = await seal([group.recipient, state.owner.recipient], encodePayload(draft.payload))
  return signCiphertext({ id: draft.id, group: draft.group, rev: draft.rev, at: draft.at }, ciphertext, state, signer)
}

/** Signs an envelope around a payload that was encrypted elsewhere (the secret-prompt page encrypts in the browser). */
export function signCiphertext(
  draft: Omit<EntryDraft, 'payload'>,
  ciphertext: Uint8Array,
  state: VaultState,
  signer: SignerContext,
): Envelope {
  const group = state.groups[draft.group]
  if (group === undefined) throw new TypeVaultError('not_found', `no group "${draft.group}"`)
  if (signerAuthority(signer.ref, draft.group, state, draft.at) === undefined) {
    throw new TypeVaultError('denied', `this key cannot sign entries in group "${draft.group}"`)
  }
  const unsigned = { v: 1 as const, id: draft.id, group: draft.group, gen: group.gen, rev: draft.rev, at: draft.at }
  const envelope = { ...unsigned, payload: toBase64(ciphertext), signer: signer.ref }
  return { ...envelope, sig: sign(signer.signSecret, envelopeBytes(envelope)) }
}

const CLOCK_SKEW_MS = 5 * 60_000

/** Why an envelope can't be trusted, or undefined when it can. */
export type VerifyOptions = { readonly acceptExpiredCerts?: boolean }

export function verifyEnvelope(envelope: Envelope, state: VaultState, options: VerifyOptions = {}): string | undefined {
  const group = state.groups[envelope.group]
  if (group === undefined) return `unknown group "${envelope.group}"`
  if (group.gen !== envelope.gen) return `stale generation ${envelope.gen} (current ${group.gen})`
  if (Date.parse(envelope.at) > Date.now() + CLOCK_SKEW_MS) return 'timestamp is in the future'
  const signPublic = signerAuthority(
    envelope.signer,
    envelope.group,
    state,
    envelope.at,
    options.acceptExpiredCerts === true ? null : Date.now(),
  )
  if (signPublic === undefined) return 'signer is not allowed to write this group'
  return verifySignature(signPublic, envelopeBytes(envelope), envelope.sig) ? undefined : 'bad signature'
}

export async function openEntry(envelope: Envelope, keyring: Keyring): Promise<EntryPayload | undefined> {
  const key = await keyring.unlock(envelope.group)
  if (key === undefined) return undefined
  const payload = decodePayload(await unseal([key.identity], fromBase64(envelope.payload)))
  const { signer } = envelope
  if (signer.kind === 'cert' && signer.cert.only.length > 0 && !matchesOnly(payload.name, signer.cert.only)) {
    throw new TypeVaultError('tampered', `${payload.name} is outside the writing grant's --only`)
  }
  return payload
}

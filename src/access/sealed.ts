import { readFileSync } from 'node:fs'

import { generateX25519Identity, identityToRecipient } from 'age-encryption'
import { z } from 'zod'

import { appendAudit } from '../audit/log'
import { generateSigningKey, randomHex, seal, type SecretKey, unseal } from '../core/crypto'
import { fromBase64, fromBase64Url, fromUtf8, toBase64, toBase64Url, utf8 } from '../core/encoding'
import { CertSchema, issueCert, signerOf } from '../core/entries'
import { TypeVaultError } from '../core/errors'
import { reach } from '../core/state'
import { resolveName, type Vault } from '../core/vault'
import { EntryValueSchema, toEntryValue } from './schemas'
import { allowsEntry, type GrantScope } from './scope'
import { type EntryValue, toValue, writtenFromAbove } from './types'

const PREFIX = 'tvg1:'

const BundleSchema = z.object({
  v: z.literal(1),
  id: z.string(),
  label: z.string(),
  tiers: z.array(z.string()),
  only: z.array(z.string()),
  exp: z.iso.datetime(),
  entries: z.array(EntryValueSchema),
  write: z.object({ signSecret: z.string(), cert: CertSchema }),
})

export type SealedBundle = {
  readonly id: string
  readonly label: string
  readonly scope: GrantScope
  readonly exp: string
  readonly entries: readonly EntryValue[]
  readonly write: z.infer<typeof BundleSchema>['write']
}

export type SealedRequest = GrantScope & { readonly ttlMs: number; readonly label: string }

/** Re-seals every entry the scope allows into a self-contained grant. The issuer's own key never leaves. */
export async function issueSealedGrant(vault: Vault, request: SealedRequest): Promise<string> {
  const issuer = vault.keyring.owner ?? (await memberTierKey(vault, request.tiers))
  if (issuer === undefined) throw new TypeVaultError('denied', 'no key here reaches every requested tier')
  for (const tier of request.tiers) {
    if (vault.state.tiers[tier] === undefined) throw new TypeVaultError('not_found', `no tier "${tier}"`)
  }
  const chain = [{ tiers: request.tiers, only: request.only }]
  const { entries } = await vault.scan()
  const allowed = entries.filter((entry) => allowsEntry(chain, vault.state, entry.envelope.tier, entry.payload.name))
  const granted = [...Map.groupBy(allowed, (entry) => entry.payload.name).values()]
    .flatMap((copies) => resolveName(vault.state.tiers, copies) ?? [])
    .map((entry) => ({
      ...toValue(entry.envelope.tier, entry.envelope.id, entry.envelope.rev, entry.payload),
      trustedWriter: writtenFromAbove(entry.envelope.signer, vault.state, request.tiers),
    }))
  const id = randomHex(8)
  const exp = new Date(Date.now() + request.ttlMs).toISOString()
  const signing = generateSigningKey()
  const cert = issueCert(
    { signPublic: signing.signPublic, tiers: [...request.tiers], only: [...request.only], exp },
    signerOf(issuer),
  )
  const bundle = { v: 1, id, label: request.label, tiers: request.tiers, only: request.only, exp, entries: granted }
  const write = { signSecret: toBase64(signing.signSecret), cert }
  const identity = await generateX25519Identity()
  const sealed = await seal([await identityToRecipient(identity)], utf8(JSON.stringify({ ...bundle, write })))
  await appendAudit(vault.layout, {
    action: 'grant.issue',
    mode: 'sealed',
    grant: id,
    label: request.label,
    tiers: request.tiers,
    entries: granted.map((value) => value.name),
  })
  return `${PREFIX}${toBase64Url(utf8(identity))}.${toBase64Url(sealed)}`
}

/** The key of a tier this member holds that reaches every one of `tiers`, to sign the grant's certificate. */
async function memberTierKey(vault: Vault, tiers: readonly string[]): Promise<SecretKey | undefined> {
  const held = vault.member === undefined ? [] : (vault.state.members[vault.member]?.tiers ?? [])
  for (const tier of held) {
    if (!tiers.every((wanted) => reach(vault.state.tiers, tier).has(wanted))) continue
    const key = await vault.keyring.unlock(tier)
    if (key !== undefined) return key
  }
  return undefined
}

/** Opens `tvg1:...` or `@/path/to/file` holding one. */
export async function readSealedGrant(raw: string): Promise<SealedBundle> {
  const text = (raw.startsWith('@') ? readFileSync(raw.slice(1), 'utf8') : raw).trim()
  const [identity, ciphertext] = text.slice(PREFIX.length).split('.')
  if (!text.startsWith(PREFIX) || identity === undefined || ciphertext === undefined) {
    throw new TypeVaultError('invalid', 'not a sealed typevault grant')
  }
  const plaintext = await unseal([fromUtf8(fromBase64Url(identity))], fromBase64Url(ciphertext))
  const parsed = BundleSchema.safeParse(JSON.parse(fromUtf8(plaintext)))
  if (!parsed.success) throw new TypeVaultError('invalid', 'malformed sealed grant')
  const { tiers, only, entries, ...rest } = parsed.data
  return {
    ...rest,
    scope: { tiers, only },
    entries: entries.map(toEntryValue),
  }
}

export const sealedSigningSecret = (bundle: SealedBundle): Uint8Array => fromBase64(bundle.write.signSecret)

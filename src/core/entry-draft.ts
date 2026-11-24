import { randomHex } from './crypto'
import { certEntryId, sealEntry, type SignerContext, type SignerRef } from './entries'
import { TypeVaultError } from './errors'
import type { Field } from './naming'
import type { EntryPayload } from './payload'
import type { VaultState } from './state'
import type { EntryInput, PutOptions, StoredEntry } from './vault'

/** An id is kept within its tier, and a certificate only keeps an id it was issued with. */
export const entryIdIn = (signer: SignerRef, tier: string, name: string, current: string | undefined): string => {
  const kept = current?.startsWith(`${tier}.`) === true ? current : undefined
  if (signer.kind !== 'cert') return kept ?? `${tier}.${randomHex(16)}`
  return kept !== undefined && signer.cert.ids.includes(kept) ? kept : certEntryId(signer.cert, tier, name)
}

const sameFields = (a: Readonly<Record<string, Field>>, b: Readonly<Record<string, Field>>): boolean =>
  JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort())

/** The envelope that writing over `found` (or a blind writer's base) produces. */
export async function draftEntry(
  state: VaultState,
  input: EntryInput,
  found: StoredEntry | undefined,
  options: PutOptions,
  signer: SignerContext,
): Promise<StoredEntry> {
  const prior = found === undefined ? options.base : { ...found.envelope, ...found.payload }
  const currentRev = prior?.rev ?? 0
  if (options.ifRev !== undefined && currentRev !== options.ifRev) {
    throw new TypeVaultError('conflict', `${input.name} is at revision ${currentRev}, not ${options.ifRev}`)
  }
  const now = new Date().toISOString()
  const changed = found === undefined || !sameFields(found.payload.fields, input.fields)
  const source = input.source ?? prior?.source
  const payload: EntryPayload = {
    v: 1,
    name: input.name,
    fields: input.fields,
    tags: input.tags ?? found?.payload.tags ?? [],
    created: prior?.created ?? now,
    rotated: changed ? now : (prior?.rotated ?? now),
    ...(input.env === undefined ? {} : { env: input.env }),
    ...(input.origin === undefined ? {} : { origin: input.origin }),
    ...(source === undefined ? {} : { source }),
    ...(changed || found?.payload.needsRotation !== true ? {} : { needsRotation: true }),
  }
  // A grant issued for an old name must not follow a renamed entry.
  const renamed = found !== undefined && found.payload.name !== input.name
  const id = entryIdIn(signer.ref, input.tier, input.name, renamed ? undefined : prior?.id)
  const draft = { id, tier: input.tier, rev: currentRev + 1, at: now, payload }
  return { envelope: await sealEntry(draft, state, signer), payload }
}

import type { SignerRef } from '../core/entries'
import { TypeVaultError } from '../core/errors'
import { type EntryName, type Field, isReservedEnvName } from '../core/naming'
import type { EntryPayload } from '../core/payload'
import { reachesTier, type VaultState } from '../core/state'
import type { PutOptions } from '../core/vault'

export type EntrySummary = {
  readonly name: EntryName
  readonly tier: string
  readonly rev: number
  readonly tags: readonly string[]
  readonly rotated: string
  readonly needsRotation: boolean
  /** Names only: listing never hands out values. */
  readonly fieldNames: readonly string[]
}

export type EntryValue = Omit<EntrySummary, 'fieldNames'> & {
  readonly id: string
  readonly created: string
  readonly fields: Readonly<Record<string, Field>>
  readonly env?: string
  readonly origin?: string
  readonly source?: string
  /** Written by the owner or by a key that reaches all of the reader's own tiers: its `--env` override counts. */
  readonly trustedWriter?: boolean
}

export type SetInput = {
  readonly name: EntryName
  readonly fields: Readonly<Record<string, Field>>
  readonly tier?: string | undefined
  readonly env?: string | undefined
  readonly origin?: string | undefined
  /** Kept by a blind writer (a sealed grant) that moves an imported entry. */
  readonly source?: string | undefined
  readonly tags?: readonly string[] | undefined
  readonly ifRev?: number | undefined
  /**
   * Write only if the name still holds this entry (`EntryValue.id`): a same-name replacement can share its revision.
   * A sealed grant refuses it, since it can't read what the name holds now.
   */
  readonly ifId?: string | undefined
  /**
   * False when the new fields don't rotate the entry's credentials, such as a passkey's sign count: its rotation time
   * and any `needsRotation` warning stay as they were. A sealed grant refuses `false`, since it can't read the warning.
   */
  readonly rotates?: boolean | undefined
}

/** The compare-and-swap and rotation options of a write, without the ones a parsed request leaves undefined. */
export function putOptionsOf(input: SetInput): PutOptions {
  return {
    ...(input.ifRev === undefined ? {} : { ifRev: input.ifRev }),
    ...(input.ifId === undefined ? {} : { ifId: input.ifId }),
    ...(input.rotates === undefined ? {} : { rotates: input.rotates }),
  }
}

/** The vault-level input for a write, without the optional keys a parsed request leaves undefined. */
export function entryInputOf(input: SetInput, tier: string) {
  if (input.env !== undefined && isReservedEnvName(input.env)) {
    throw new TypeVaultError('invalid', `${input.env} is reserved: run never sets it from the vault`)
  }
  return {
    name: input.name,
    fields: input.fields,
    tier,
    ...(input.env === undefined ? {} : { env: input.env }),
    ...(input.origin === undefined ? {} : { origin: input.origin }),
    ...(input.source === undefined ? {} : { source: input.source }),
    ...(input.tags === undefined ? {} : { tags: input.tags }),
  }
}

/** What a CLI command can do with secrets, whether the values come from a daemon, a sealed grant or a local key. */
export interface Access {
  list(): Promise<readonly EntrySummary[]>
  /** How many entry files `list` left out because they don't verify or can't be read. */
  unreadableEntries(): Promise<number>
  get(name: EntryName, reason?: string): Promise<EntryValue>
  values(only: readonly string[], reason?: string): Promise<readonly EntryValue[]>
  set(input: SetInput): Promise<EntrySummary>
  /** `tier` picks one copy when a name exists in unrelated tiers. */
  remove(name: EntryName, tier?: string): Promise<void>
  move(from: EntryName, to: EntryName): Promise<void>
  /** The tiers this caller holds directly (not through includes): what `run` loads in bulk. */
  ownTiers(): Promise<readonly string[]>
  /** Every secret value this grant has handed out so far, for redaction. */
  readValues(): Promise<readonly string[]>
}

export function toValue(tier: string, id: string, rev: number, payload: EntryPayload): EntryValue {
  return {
    id,
    name: payload.name,
    tier,
    rev,
    tags: payload.tags,
    created: payload.created,
    rotated: payload.rotated,
    needsRotation: payload.needsRotation === true,
    fields: payload.fields,
    ...(payload.env === undefined ? {} : { env: payload.env }),
    ...(payload.origin === undefined ? {} : { origin: payload.origin }),
    ...(payload.source === undefined ? {} : { source: payload.source }),
  }
}

export const toSummary = (value: EntryValue): EntrySummary => ({
  name: value.name,
  tier: value.tier,
  rev: value.rev,
  tags: value.tags,
  rotated: value.rotated,
  needsRotation: value.needsRotation,
  fieldNames: Object.keys(value.fields),
})

/** Whether `signer` is at least as privileged as a reader holding `ownTiers`. */
export function writtenFromAbove(signer: SignerRef, state: VaultState, ownTiers: readonly string[]): boolean {
  if (signer.kind === 'owner') return true
  const tiers =
    signer.kind === 'tier'
      ? [signer.tier]
      : signer.kind === 'signer'
        ? (state.signers[signer.id]?.tiers ?? [])
        : signer.cert.tiers
  return ownTiers.length > 0 && ownTiers.every((own) => reachesTier(state.tiers, tiers, own))
}

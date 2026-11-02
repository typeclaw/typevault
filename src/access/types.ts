import type { EntryName, EntryType } from '../core/naming'
import type { EntryPayload } from '../core/payload'

export type EntrySummary = {
  readonly name: EntryName
  readonly type: EntryType
  readonly group: string
  readonly rev: number
  readonly tags: readonly string[]
  readonly rotated: string
  readonly needsRotation: boolean
}

export type EntryValue = EntrySummary & {
  readonly id: string
  readonly created: string
  readonly fields: Readonly<Record<string, string>>
  readonly env?: string
  readonly origin?: string
}

export type SetInput = {
  readonly name: EntryName
  readonly type: EntryType
  readonly fields: Readonly<Record<string, string>>
  readonly group?: string
  readonly env?: string
  readonly origin?: string
  readonly tags?: readonly string[]
  readonly ifRev?: number
}

/** What a CLI command can do with secrets, whether the values come from a daemon, a sealed grant or a local key. */
export interface Access {
  list(): Promise<readonly EntrySummary[]>
  get(name: EntryName, reason?: string): Promise<EntryValue>
  values(only: readonly string[], reason?: string): Promise<readonly EntryValue[]>
  set(input: SetInput): Promise<EntrySummary>
  remove(name: EntryName): Promise<void>
  move(from: EntryName, to: EntryName): Promise<void>
  /** Every secret value this grant has handed out so far, for redaction. */
  readValues(): Promise<readonly string[]>
}

export function toValue(group: string, id: string, rev: number, payload: EntryPayload): EntryValue {
  return {
    id,
    name: payload.name,
    type: payload.type,
    group,
    rev,
    tags: payload.tags,
    created: payload.created,
    rotated: payload.rotated,
    needsRotation: payload.needsRotation === true,
    fields: payload.fields,
    ...(payload.env === undefined ? {} : { env: payload.env }),
    ...(payload.origin === undefined ? {} : { origin: payload.origin }),
  }
}

export const toSummary = (value: EntryValue): EntrySummary => ({
  name: value.name,
  type: value.type,
  group: value.group,
  rev: value.rev,
  tags: value.tags,
  rotated: value.rotated,
  needsRotation: value.needsRotation,
})

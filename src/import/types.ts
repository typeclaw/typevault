import type { EntryPayload } from '../core/payload'

export type ImportedEntry = Pick<EntryPayload, 'name' | 'type' | 'fields' | 'origin' | 'tags' | 'env'>

export type ImportResult = {
  readonly entries: readonly ImportedEntry[]
  readonly warnings: readonly string[]
}

export type ImportSource = 'dotenv' | 'typeclaw' | '1password' | 'bitwarden' | 'lastpass' | 'keepass' | 'csv'

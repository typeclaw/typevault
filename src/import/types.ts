import type { EntryPayload } from '../core/payload'

export type ImportedEntry = Pick<EntryPayload, 'name' | 'fields' | 'origin' | 'source' | 'tags' | 'env'>

export type ImportResult = {
  readonly entries: readonly ImportedEntry[]
  readonly warnings: readonly string[]
}

export type ImportSource = 'dotenv' | 'typeclaw' | '1password' | 'bitwarden' | 'lastpass' | 'keepass' | 'csv'

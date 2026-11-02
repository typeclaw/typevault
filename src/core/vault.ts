import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { randomHex, type SecretKey } from './crypto'
import { fromUtf8 } from './encoding'
import { type Envelope, EnvelopeSchema, openEntry, sealEntry, type SignerContext, verifyEnvelope } from './entries'
import { TypeVaultError } from './errors'
import { atomicWrite, fsyncDir } from './fsx'
import { Keyring } from './keyring'
import { type Layout, layoutOf } from './layout'
import { withLock } from './lock'
import type { EntryName, EntryType } from './naming'
import type { EntryPayload } from './payload'
import { loadState, type VaultState } from './state'
import { recoverTxns } from './txn'

export type StoredEntry = { readonly envelope: Envelope; readonly payload: EntryPayload }
export type ScanProblem = { readonly file: string; readonly reason: string }
export type Scan = { readonly entries: readonly StoredEntry[]; readonly problems: readonly ScanProblem[] }

export type EntryInput = {
  readonly name: EntryName
  readonly type: EntryType
  readonly fields: Readonly<Record<string, string>>
  readonly group: string
  readonly env?: string
  readonly origin?: string
  readonly tags?: readonly string[]
}

type Env = Readonly<Record<string, string | undefined>>

function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(fromUtf8(bytes))
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof TypeError) return undefined
    throw error
  }
}

const sameFields = (a: Readonly<Record<string, string>>, b: Readonly<Record<string, string>>): boolean =>
  JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort())

/** An opened vault directory plus the keys this process holds. All reads and writes go through the vault lock. */
export class Vault {
  readonly layout: Layout
  readonly #keys: readonly SecretKey[]
  readonly #env: Env
  #state: VaultState
  #keyring: Keyring

  private constructor(layout: Layout, keys: readonly SecretKey[], env: Env) {
    this.layout = layout
    this.#keys = keys
    this.#env = env
    this.#state = loadState(layout, env)
    this.#keyring = new Keyring(layout, this.#state, keys)
  }

  static async open(root: string, keys: readonly SecretKey[], env: Env = process.env): Promise<Vault> {
    const layout = layoutOf(root)
    if (existsSync(layout.txnDir) && readdirSync(layout.txnDir).length > 0) {
      await withLock(layout.lockFile, 'exclusive', async () => recoverTxns(layout))
    }
    return new Vault(layout, keys, env)
  }

  get state(): VaultState {
    return this.#state
  }

  get keyring(): Keyring {
    return this.#keyring
  }

  get keys(): readonly SecretKey[] {
    return this.#keys
  }

  /** Re-reads operator-signed state; call after another process may have changed it. */
  refresh(): void {
    this.#state = loadState(this.layout, this.#env)
    this.#keyring = new Keyring(this.layout, this.#state, this.#keys)
  }

  /** Every entry this process can open. Untrustworthy files are reported, never returned. */
  scan(): Promise<Scan> {
    return withLock(this.layout.lockFile, 'shared', async () => {
      this.refresh()
      const entries: StoredEntry[] = []
      const problems: ScanProblem[] = []
      const files = existsSync(this.layout.entries) ? readdirSync(this.layout.entries) : []
      for (const file of files.filter((name) => name.endsWith('.json'))) {
        const parsed = EnvelopeSchema.safeParse(parseJson(readFileSync(join(this.layout.entries, file))))
        if (!parsed.success) {
          problems.push({ file, reason: 'malformed entry file' })
          continue
        }
        const reason = verifyEnvelope(parsed.data, this.#state)
        if (reason !== undefined) {
          problems.push({ file, reason })
          continue
        }
        const payload = await openEntry(parsed.data, this.#keyring)
        if (payload !== undefined) entries.push({ envelope: parsed.data, payload })
      }
      return { entries, problems }
    })
  }

  /** The newest readable entry named `name`. */
  async find(name: EntryName): Promise<StoredEntry | undefined> {
    const { entries } = await this.scan()
    return entries
      .filter((entry) => entry.payload.name === name)
      .reduce<StoredEntry | undefined>(
        (best, entry) => (best === undefined || entry.envelope.at > best.envelope.at ? entry : best),
        undefined,
      )
  }

  /** Creates or replaces an entry. `ifRev` makes it a compare-and-swap against the current revision. */
  put(input: EntryInput, signer: SignerContext, ifRev?: number): Promise<StoredEntry> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const existing = await this.find(input.name)
      if (ifRev !== undefined && (existing?.envelope.rev ?? 0) !== ifRev) {
        throw new TypeVaultError(
          'conflict',
          `${input.name} is at revision ${existing?.envelope.rev ?? 0}, not ${ifRev}`,
        )
      }
      const now = new Date().toISOString()
      const changed = existing === undefined || !sameFields(existing.payload.fields, input.fields)
      const payload: EntryPayload = {
        v: 1,
        name: input.name,
        type: input.type,
        fields: input.fields,
        tags: input.tags ?? existing?.payload.tags ?? [],
        created: existing?.payload.created ?? now,
        rotated: changed ? now : (existing?.payload.rotated ?? now),
        ...(input.env === undefined ? {} : { env: input.env }),
        ...(input.origin === undefined ? {} : { origin: input.origin }),
        ...(changed || existing?.payload.needsRotation !== true ? {} : { needsRotation: true }),
      }
      const id = existing?.envelope.id ?? randomHex(16)
      const rev = (existing?.envelope.rev ?? 0) + 1
      const envelope = await sealEntry({ id, group: input.group, rev, at: now, payload }, this.#state, signer)
      atomicWrite(join(this.layout.entries, `${id}.json`), `${JSON.stringify(envelope, null, 2)}\n`)
      return { envelope, payload }
    })
  }

  remove(name: EntryName): Promise<StoredEntry> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const existing = await this.find(name)
      if (existing === undefined) throw new TypeVaultError('not_found', `no entry named ${name}`)
      rmSync(join(this.layout.entries, `${existing.envelope.id}.json`))
      fsyncDir(this.layout.entries)
      return existing
    })
  }

  move(from: EntryName, to: EntryName, signer: SignerContext): Promise<StoredEntry> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const existing = await this.find(from)
      if (existing === undefined) throw new TypeVaultError('not_found', `no entry named ${from}`)
      if ((await this.find(to)) !== undefined) throw new TypeVaultError('conflict', `${to} already exists`)
      const payload = { ...existing.payload, name: to }
      const draft = { id: existing.envelope.id, group: existing.envelope.group, rev: existing.envelope.rev + 1 }
      const envelope = await sealEntry({ ...draft, at: new Date().toISOString(), payload }, this.#state, signer)
      atomicWrite(join(this.layout.entries, `${envelope.id}.json`), `${JSON.stringify(envelope, null, 2)}\n`)
      return { envelope, payload }
    })
  }
}

import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'

import { randomHex, type SecretKey } from './crypto'
import { fromUtf8 } from './encoding'
import {
  type Envelope,
  EnvelopeSchema,
  openEntry,
  sealEntry,
  signCiphertext,
  type SignerContext,
  verifyEnvelope,
} from './entries'
import { TypeVaultError } from './errors'
import { atomicWrite, fsyncDir } from './fsx'
import { Keyring } from './keyring'
import { type Layout, layoutOf } from './layout'
import { withLock } from './lock'
import type { EntryName, EntryType } from './naming'
import type { EntryPayload } from './payload'
import { loadState, type VaultState } from './state'
import { commitTxn, recoverTxns, Txn } from './txn'

export type StoredEntry = { readonly envelope: Envelope; readonly payload: EntryPayload }
export type ScanProblem = { readonly file: string; readonly reason: string }
export type Scan = { readonly entries: readonly StoredEntry[]; readonly problems: readonly ScanProblem[] }

/** What a writer that can't read the current entry (a sealed grant) knows about it. */
export type EntryBase = {
  readonly id: string
  readonly rev: number
  readonly created: string
  readonly rotated: string
}

export type PutOptions = { readonly ifRev?: number; readonly base?: EntryBase }

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
        const reason =
          file === `${parsed.data.id}.json`
            ? verifyEnvelope(parsed.data, this.#state)
            : 'file name does not match its entry id'
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

  /** The envelope that writing `input` over `found` (or a blind writer's `base`) produces. */
  async #draft(
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
    const payload: EntryPayload = {
      v: 1,
      name: input.name,
      type: input.type,
      fields: input.fields,
      tags: input.tags ?? found?.payload.tags ?? [],
      created: prior?.created ?? now,
      rotated: changed ? now : (prior?.rotated ?? now),
      ...(input.env === undefined ? {} : { env: input.env }),
      ...(input.origin === undefined ? {} : { origin: input.origin }),
      ...(changed || found?.payload.needsRotation !== true ? {} : { needsRotation: true }),
    }
    const draft = { id: prior?.id ?? randomHex(16), group: input.group, rev: currentRev + 1, at: now, payload }
    return { envelope: await sealEntry(draft, this.#state, signer), payload }
  }

  /**
   * Creates or replaces an entry. `ifRev` makes it a compare-and-swap against the current revision;
   * `base` stands in for the current entry when this process can't read it.
   */
  put(input: EntryInput, signer: SignerContext, options: PutOptions = {}): Promise<StoredEntry> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const stored = await this.#draft(input, await this.find(input.name), options, signer)
      atomicWrite(
        join(this.layout.entries, `${stored.envelope.id}.json`),
        `${JSON.stringify(stored.envelope, null, 2)}\n`,
      )
      return stored
    })
  }

  /** Writes many entries as one transaction (an import): all of them land, or none do. */
  putMany(
    inputs: readonly EntryInput[],
    signerFor: (group: string) => Promise<SignerContext>,
  ): Promise<readonly StoredEntry[]> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const { entries } = await this.scan()
      const txn = new Txn()
      const stored: StoredEntry[] = []
      for (const input of inputs) {
        const found = entries.filter((entry) => entry.payload.name === input.name).at(-1)
        const entry = await this.#draft(input, found, {}, await signerFor(input.group))
        txn.put(`entries/${entry.envelope.id}.json`, `${JSON.stringify(entry.envelope, null, 2)}\n`)
        stored.push(entry)
      }
      commitTxn(this.layout, txn)
      return stored
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

  /** Stores a payload encrypted elsewhere under `name`, replacing any entry of that name. */
  putCiphertext(name: EntryName, group: string, ciphertext: Uint8Array, signer: SignerContext): Promise<Envelope> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const existing = await this.find(name)
      const draft = { id: existing?.envelope.id ?? randomHex(16), group, rev: (existing?.envelope.rev ?? 0) + 1 }
      const envelope = signCiphertext({ ...draft, at: new Date().toISOString() }, ciphertext, this.#state, signer)
      atomicWrite(join(this.layout.entries, `${envelope.id}.json`), `${JSON.stringify(envelope, null, 2)}\n`)
      return envelope
    })
  }

  /** Deletes an entry file by id, for writers that can't read the entry (sealed grants). */
  removeById(id: string): Promise<void> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      if (!/^[0-9a-f]{32}$/.test(id)) throw new TypeVaultError('invalid', 'invalid entry id')
      const path = join(this.layout.entries, `${id}.json`)
      if (!existsSync(path)) throw new TypeVaultError('not_found', 'entry is already gone')
      rmSync(path)
      fsyncDir(this.layout.entries)
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

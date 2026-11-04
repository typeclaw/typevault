import { existsSync, lstatSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'

import { randomHex, type SecretKey } from './crypto'
import { fromUtf8 } from './encoding'
import {
  type Envelope,
  type VerifyOptions,
  EnvelopeSchema,
  openEntry,
  sealEntry,
  signCiphertext,
  type SignerContext,
  verifyEnvelope,
} from './entries'
import { TypeVaultError } from './errors'
import { assertNoSymlinks, atomicWrite, fsyncDir } from './fsx'
import { heldMembers, Keyring, unwrapOwner } from './keyring'
import type { Layout } from './layout'
import { withLock } from './lock'
import type { EntryName, Field } from './naming'
import type { EntryPayload } from './payload'
import { RevisionMarks } from './revisions'
import { type Tiers, loadState, reach, type VaultState } from './state'
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
  readonly fields: Readonly<Record<string, Field>>
  readonly tier: string
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

const sameFields = (a: Readonly<Record<string, Field>>, b: Readonly<Record<string, Field>>): boolean =>
  JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort())

/**
 * The entry a name means when several files carry it. A copy in a tier that reaches the other's tier wins, so a
 * lower tier can never shadow a higher one (timestamps are writer-chosen and never decide). Within one tier the
 * higher revision wins. Copies in tiers neither reaches are a conflict for `doctor`.
 */
export function resolveName(tiers: Tiers, copies: readonly StoredEntry[]): StoredEntry | undefined {
  return copies.reduce<StoredEntry | undefined>((best, entry) => {
    if (best === undefined) return entry
    const [a, b] = [best.envelope, entry.envelope]
    if (a.tier === b.tier) return b.rev > a.rev || (b.rev === a.rev && b.id > a.id) ? entry : best
    if (reach(tiers, a.tier).has(b.tier)) return best
    if (reach(tiers, b.tier).has(a.tier)) return entry
    throw new TypeVaultError(
      'conflict',
      `${entry.payload.name} exists in unrelated tiers "${a.tier}" and "${b.tier}" (run typevault doctor)`,
    )
  }, undefined)
}

/** An opened vault directory plus the keys this process holds. All reads and writes go through the vault lock. */
export class Vault {
  readonly layout: Layout
  readonly #keys: readonly SecretKey[]
  readonly #env: Env
  readonly #member: string | undefined
  #state: VaultState
  #keyring: Keyring

  private constructor(layout: Layout, keys: readonly SecretKey[], env: Env, state: VaultState, member?: string) {
    this.layout = layout
    this.#keys = keys
    this.#env = env
    this.#member = member
    this.#state = state
    this.#keyring = new Keyring(layout, state, keys)
  }

  /** Opens the vault with `keys`. An owner member's key also brings the owner key it unwraps. */
  static async open(layout: Layout, keys: readonly SecretKey[], env: Env = process.env): Promise<Vault> {
    if (existsSync(layout.txnDir) && readdirSync(layout.txnDir).length > 0) {
      await withLock(layout.lockFile, 'exclusive', async () => recoverTxns(layout))
    }
    const state = loadState(layout, env)
    const owner = await unwrapOwner(layout, state, keys)
    const [member] = await heldMembers(state, keys)
    const all = owner === undefined || keys.includes(owner) ? keys : [...keys, owner]
    return new Vault(layout, all, env, state, member?.name)
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

  /** The member this process acts as, when it holds a member key the vault lists. */
  get member(): string | undefined {
    return this.#member
  }

  /** Re-reads owner-signed state; call after another process may have changed it. */
  refresh(): void {
    this.#state = loadState(this.layout, this.#env)
    this.#keyring = new Keyring(this.layout, this.#state, this.#keys)
  }

  /** Every entry this process can open. Untrustworthy files are reported, never returned. */
  scan(options: VerifyOptions = {}): Promise<Scan> {
    return withLock(this.layout.lockFile, 'shared', async () => {
      this.refresh()
      const entries: StoredEntry[] = []
      const problems: ScanProblem[] = []
      assertNoSymlinks(dirname(this.layout.vault), join(basename(this.layout.vault), 'entries'))
      const files = existsSync(this.layout.entries) ? readdirSync(this.layout.entries) : []
      const marks = new RevisionMarks(this.layout.revisionsFile)
      for (const file of files.filter(
        (name) => name.endsWith('.json') && lstatSync(join(this.layout.entries, name)).isFile(),
      )) {
        const parsed = EnvelopeSchema.safeParse(parseJson(readFileSync(join(this.layout.entries, file))))
        if (!parsed.success) {
          problems.push({ file, reason: 'malformed entry file' })
          continue
        }
        const reason =
          file === `${parsed.data.id}.json`
            ? verifyEnvelope(parsed.data, this.#state, options)
            : 'file name does not match its entry id'
        if (reason !== undefined) {
          problems.push({ file, reason })
          continue
        }
        // Accepting expired certificates must not move the marks: a backdated high revision nobody adopts would
        // otherwise lock out the trusted one.
        const current =
          options.acceptExpiredCerts === true
            ? marks.allows(parsed.data.id, parsed.data.rev)
            : marks.accept(parsed.data.id, parsed.data.rev)
        if (!current) {
          problems.push({ file, reason: `revision ${parsed.data.rev} was replaced or deleted on this machine` })
          continue
        }
        // One unreadable file must never take the whole vault down with it.
        const opened = await openEntry(parsed.data, this.#keyring).then(
          (payload) => ({ payload }),
          (error: unknown) => {
            if (error instanceof TypeVaultError) return { problem: error.message }
            throw error
          },
        )
        if ('problem' in opened) problems.push({ file, reason: opened.problem })
        else if (opened.payload !== undefined) entries.push({ envelope: parsed.data, payload: opened.payload })
      }
      marks.save()
      return { entries, problems }
    })
  }

  #tombstone(id: string): void {
    const marks = new RevisionMarks(this.layout.revisionsFile)
    marks.tombstone(id)
    marks.save()
  }

  /** The entry `name` resolves to among the readable ones (see `resolveName`). */
  async find(name: EntryName): Promise<StoredEntry | undefined> {
    const { entries } = await this.scan()
    return resolveName(
      this.#state.tiers,
      entries.filter((entry) => entry.payload.name === name),
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
      fields: input.fields,
      tags: input.tags ?? found?.payload.tags ?? [],
      created: prior?.created ?? now,
      rotated: changed ? now : (prior?.rotated ?? now),
      ...(input.env === undefined ? {} : { env: input.env }),
      ...(input.origin === undefined ? {} : { origin: input.origin }),
      ...(changed || found?.payload.needsRotation !== true ? {} : { needsRotation: true }),
    }
    const draft = { id: entryIdIn(input.tier, prior?.id), tier: input.tier, rev: currentRev + 1, at: now, payload }
    return { envelope: await sealEntry(draft, this.#state, signer), payload }
  }

  /**
   * Creates or replaces an entry. `ifRev` makes it a compare-and-swap against the current revision;
   * `base` stands in for the current entry when this process can't read it.
   */
  put(input: EntryInput, signer: SignerContext, options: PutOptions = {}): Promise<StoredEntry> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const found = await this.find(input.name)
      const stored = await this.#draft(input, found, options, signer)
      atomicWrite(
        join(this.layout.entries, `${stored.envelope.id}.json`),
        `${JSON.stringify(stored.envelope, null, 2)}\n`,
      )
      if (found !== undefined && found.envelope.id !== stored.envelope.id) this.#unlink(found.envelope.id)
      return stored
    })
  }

  /** Writes many entries as one transaction (an import): all of them land, or none do. */
  putMany(
    inputs: readonly EntryInput[],
    signerFor: (tier: string) => Promise<SignerContext>,
  ): Promise<readonly StoredEntry[]> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const { entries } = await this.scan()
      const txn = new Txn()
      const stored: StoredEntry[] = []
      const retiered: string[] = []
      for (const input of inputs) {
        const found = resolveName(
          this.#state.tiers,
          entries.filter((entry) => entry.payload.name === input.name),
        )
        const entry = await this.#draft(input, found, {}, await signerFor(input.tier))
        txn.put(`entries/${entry.envelope.id}.json`, `${JSON.stringify(entry.envelope, null, 2)}\n`)
        if (found !== undefined && found.envelope.id !== entry.envelope.id) {
          txn.remove(`entries/${found.envelope.id}.json`)
          retiered.push(found.envelope.id)
        }
        stored.push(entry)
      }
      commitTxn(this.layout, txn)
      for (const id of retiered) this.#tombstone(id)
      return stored
    })
  }

  /** Removes the entry `name` resolves to, or the copy in `tier` (how a cross-tier conflict is settled). */
  remove(name: EntryName, tier?: string): Promise<StoredEntry> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const existing =
        tier === undefined
          ? await this.find(name)
          : (await this.scan()).entries.find((entry) => entry.payload.name === name && entry.envelope.tier === tier)
      if (existing === undefined) throw new TypeVaultError('not_found', `no entry named ${name}`)
      rmSync(join(this.layout.entries, `${existing.envelope.id}.json`))
      fsyncDir(this.layout.entries)
      this.#tombstone(existing.envelope.id)
      return existing
    })
  }

  /** Stores a payload encrypted elsewhere under `name`, replacing any entry of that name. */
  putCiphertext(name: EntryName, tier: string, ciphertext: Uint8Array, signer: SignerContext): Promise<Envelope> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const existing = await this.find(name)
      const draft = { id: entryIdIn(tier, existing?.envelope.id), tier, rev: (existing?.envelope.rev ?? 0) + 1 }
      const envelope = signCiphertext({ ...draft, at: new Date().toISOString() }, ciphertext, this.#state, signer)
      atomicWrite(join(this.layout.entries, `${envelope.id}.json`), `${JSON.stringify(envelope, null, 2)}\n`)
      if (existing !== undefined && existing.envelope.id !== envelope.id) this.#unlink(existing.envelope.id)
      return envelope
    })
  }

  /**
   * Deletes an entry file by id, for writers that can't read the entry (sealed grants).
   * `allows` judges the verified envelope under the lock; the file stays unless it returns true.
   */
  removeById(id: string, allows: (envelope: Envelope) => boolean): Promise<void> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      if (!EnvelopeSchema.shape.id.safeParse(id).success) throw new TypeVaultError('invalid', 'invalid entry id')
      this.refresh()
      const path = join(this.layout.entries, `${id}.json`)
      if (!existsSync(path)) throw new TypeVaultError('not_found', 'entry is already gone')
      const parsed = EnvelopeSchema.safeParse(parseJson(readFileSync(path)))
      if (!parsed.success || parsed.data.id !== id || verifyEnvelope(parsed.data, this.#state) !== undefined) {
        throw new TypeVaultError('denied', 'refusing to remove an entry file that does not verify')
      }
      if (!allows(parsed.data)) throw new TypeVaultError('denied', 'this grant cannot remove that entry')
      this.#unlink(id)
    })
  }

  #unlink(id: string): void {
    rmSync(join(this.layout.entries, `${id}.json`))
    fsyncDir(this.layout.entries)
    this.#tombstone(id)
  }

  move(from: EntryName, to: EntryName, signer: SignerContext): Promise<StoredEntry> {
    return withLock(this.layout.lockFile, 'exclusive', async () => {
      const existing = await this.find(from)
      if (existing === undefined) throw new TypeVaultError('not_found', `no entry named ${from}`)
      if ((await this.find(to)) !== undefined) throw new TypeVaultError('conflict', `${to} already exists`)
      const payload = { ...existing.payload, name: to }
      const draft = { id: existing.envelope.id, tier: existing.envelope.tier, rev: existing.envelope.rev + 1 }
      const envelope = await sealEntry({ ...draft, at: new Date().toISOString(), payload }, this.#state, signer)
      atomicWrite(join(this.layout.entries, `${envelope.id}.json`), `${JSON.stringify(envelope, null, 2)}\n`)
      return { envelope, payload }
    })
  }
}

/** An entry keeps its id only within its tier: the id names the tier (see `verifyEnvelope`), so a retier mints a new one. */
const entryIdIn = (tier: string, current: string | undefined): string =>
  current?.startsWith(`${tier}.`) === true ? current : `${tier}.${randomHex(16)}`

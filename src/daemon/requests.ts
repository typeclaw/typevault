import { allowsEntry, type ScopeChain } from '../access/scope'
import { appendAudit } from '../audit/log'
import { randomToken } from '../core/crypto'
import { signerOf } from '../core/entries'
import { TypeVaultError } from '../core/errors'
import type { EntryName, EntryType } from '../core/naming'
import type { Vault } from '../core/vault'
import { type PromptServer, startPromptServer } from '../prompt'
import type { GrantRecord } from './grants'

const TTL_MS = 10 * 60_000
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

export type PromptOptions = { readonly port?: number; readonly publicUrl?: string }
export type RequestInput = {
  readonly name: EntryName
  readonly type: EntryType
  readonly group?: string | undefined
  readonly reason: string
}

const matchCode = (): string =>
  [...crypto.getRandomValues(new Uint8Array(6))].map((byte) => CODE_ALPHABET[byte % CODE_ALPHABET.length]).join('')

type Pending = { readonly owner: string; readonly stored: Promise<EntryName> }

/** Secret prompts: a human fills a one-time page, the browser encrypts, the daemon signs and stores. */
export class PromptRequests {
  readonly #vault: Vault
  readonly #options: PromptOptions
  readonly #pending = new Map<string, Pending>()
  #server: Promise<PromptServer> | undefined

  constructor(vault: Vault, options: PromptOptions) {
    this.#vault = vault
    this.#options = options
  }

  #prompt(): Promise<PromptServer> {
    const server = this.#server ?? startPromptServer(this.#options)
    this.#server = server
    return server
  }

  async open(
    chain: ScopeChain,
    grant: GrantRecord,
    input: RequestInput,
  ): Promise<{ id: string; url: string; code: string }> {
    const state = this.#vault.state
    const group = input.group ?? grant.groups[0]
    const meta = group === undefined ? undefined : state.groups[group]
    if (group === undefined || meta === undefined || !allowsEntry(chain, state, group, input.name)) {
      throw new TypeVaultError('denied', `this grant cannot store ${input.name} in group "${group ?? '?'}"`)
    }
    const existing = await this.#vault.find(input.name)
    if (existing !== undefined && !allowsEntry(chain, state, existing.envelope.group, input.name)) {
      throw new TypeVaultError('denied', `the name ${input.name} is not available to this grant`)
    }
    const code = matchCode()
    const handle = (await this.#prompt()).open({
      name: input.name,
      type: input.type,
      group,
      reason: input.reason,
      requester: grant.label,
      code,
      recipients: [meta.recipient, state.operator.recipient],
      expiresAt: new Date(Date.now() + TTL_MS),
    })
    const stored = handle.done.then(async (ciphertext) => {
      const key = (await this.#vault.keyring.unlock(group)) ?? this.#vault.keyring.operator
      if (key === undefined) throw new TypeVaultError('denied', `no key here can write group "${group}"`)
      await this.#vault.putCiphertext(input.name, group, ciphertext, signerOf(key))
      await appendAudit(this.#vault.layout, {
        action: 'request.stored',
        mode: 'live',
        grant: grant.id,
        label: grant.label,
        entries: [input.name],
      })
      return input.name
    })
    // Keep a rejected prompt (expired, cancelled) from surfacing as an unhandled rejection before anyone waits.
    stored.then(undefined, (error: unknown) => {
      if (!(error instanceof TypeVaultError)) console.error('typevault daemon: storing a prompted secret failed', error)
    })
    this.#pending.set(handle.id, { owner: grant.id, stored })
    await appendAudit(this.#vault.layout, {
      action: 'request.open',
      mode: 'live',
      grant: grant.id,
      label: grant.label,
      entries: [input.name],
      groups: [group],
      reason: input.reason,
    })
    return { id: handle.id, url: handle.url, code }
  }

  async wait(grantId: string, id: string): Promise<EntryName> {
    const pending = this.#pending.get(id)
    if (pending === undefined || pending.owner !== grantId) throw new TypeVaultError('not_found', 'no such request')
    try {
      return await pending.stored
    } finally {
      this.#pending.delete(id)
    }
  }

  async stop(): Promise<void> {
    if (this.#server !== undefined) await (await this.#server).stop()
  }
}

export const requestToken = (): string => randomToken(16)

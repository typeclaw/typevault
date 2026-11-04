import { allowsEntry, type ScopeChain } from '../access/scope'
import type { Access } from '../access/types'
import { appendAudit } from '../audit/log'
import { randomToken } from '../core/crypto'
import { unseal } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import type { EntryName, Preset } from '../core/naming'
import { decodePayload } from '../core/payload'
import type { Vault } from '../core/vault'
import { type PromptServer, startPromptServer } from '../prompt'
import type { GrantRecord } from './grants'

const TTL_MS = 10 * 60_000
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

export type PromptOptions = { readonly port?: number; readonly publicUrl?: string }
/** The requesting grant: its scope, a scoped access that stores and audits, and a liveness check. */
export type RequestSession = {
  readonly chain: ScopeChain
  readonly grant: GrantRecord
  readonly access: Access
  readonly isLive: () => boolean
}

export type RequestInput = {
  readonly name: EntryName
  readonly preset?: Preset | undefined
  readonly tier?: string | undefined
  readonly reason: string
}

export const matchCode = (): string =>
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

  async open(session: RequestSession, input: RequestInput): Promise<{ id: string; url: string; code: string }> {
    const { chain, grant } = session
    const state = this.#vault.state
    const tier = input.tier ?? grant.tiers[0]
    const meta = tier === undefined ? undefined : state.tiers[tier]
    if (tier === undefined || meta === undefined || !allowsEntry(chain, state, tier, input.name)) {
      throw new TypeVaultError('denied', `this grant cannot store ${input.name} in tier "${tier ?? '?'}"`)
    }
    const existing = await this.#vault.find(input.name)
    if (existing !== undefined && !allowsEntry(chain, state, existing.envelope.tier, input.name)) {
      throw new TypeVaultError('denied', `the name ${input.name} is not available to this grant`)
    }
    const code = matchCode()
    const handle = (await this.#prompt()).open({
      name: input.name,
      ...(input.preset === undefined ? {} : { preset: input.preset }),
      tier,
      reason: input.reason,
      requester: grant.label,
      code,
      recipients: [meta.recipient, state.owner.recipient],
      expiresAt: new Date(Date.now() + TTL_MS),
    })
    // Whoever holds the URL can submit, the requesting agent included, so the daemon checks what it got instead
    // of signing it blind: it must be exactly the requested entry, and the grant must still be live.
    const stored = handle.done.then(async (ciphertext) => {
      const key = (await this.#vault.keyring.unlock(tier)) ?? this.#vault.keyring.owner
      if (key === undefined) throw new TypeVaultError('denied', `no key here can read tier "${tier}"`)
      const payload = decodePayload(await unseal([key.identity], ciphertext))
      if (payload.name !== input.name || payload.env !== undefined || payload.needsRotation !== undefined) {
        throw new TypeVaultError('tampered', 'the submitted secret does not match the request')
      }
      if (!session.isLive()) throw new TypeVaultError('denied', 'the requesting grant is no longer live')
      await session.access.set({ name: input.name, fields: payload.fields, tier })
      await appendAudit(this.#vault.layout, {
        action: 'request.stored',
        mode: 'live',
        grant: grant.id,
        label: grant.label,
        entries: [input.name],
      })
      return input.name
    })
    // Forget the request a while after it settles, whether or not anyone waits for it.
    const forget = (): void => {
      setTimeout(() => this.#pending.delete(handle.id), TTL_MS).unref()
    }
    stored.then(forget, forget)
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
      tiers: [tier],
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

import { z } from 'zod'

import { EntrySummarySchema, EntryValueSchema, toEntryValue, toSummaryValue } from '../access/schemas'
import type { Access, EntrySummary, EntryValue, SetInput } from '../access/types'
import type { EntryName } from '../core/naming'
import { callDaemon } from './client'

const Ok = z.object({ ok: z.literal(true) })

/** Access through a live grant: every call goes to the daemon, which checks, audits and decrypts. */
export class LiveAccess implements Access {
  readonly #socket: string
  readonly #token: string

  constructor(socket: string, token: string) {
    this.#socket = socket
    this.#token = token
  }

  call<T>(path: string, body: unknown, schema: z.ZodType<T>, timeoutMs?: number): Promise<T> {
    return callDaemon(this.#socket, path, body, schema, {
      token: this.#token,
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    })
  }

  async list(): Promise<readonly EntrySummary[]> {
    return (await this.call('/v1/list', {}, z.array(EntrySummarySchema))).map(toSummaryValue)
  }

  async get(name: EntryName, reason?: string): Promise<EntryValue> {
    return toEntryValue(await this.call('/v1/get', { name, reason }, EntryValueSchema))
  }

  async values(only: readonly string[], reason?: string): Promise<readonly EntryValue[]> {
    return (await this.call('/v1/values', { only, reason }, z.array(EntryValueSchema))).map(toEntryValue)
  }

  async set(input: SetInput): Promise<EntrySummary> {
    return toSummaryValue(await this.call('/v1/set', input, EntrySummarySchema))
  }

  async remove(name: EntryName): Promise<void> {
    await this.call('/v1/remove', { name }, Ok)
  }

  async move(from: EntryName, to: EntryName): Promise<void> {
    await this.call('/v1/move', { from, to }, Ok)
  }

  async ownGroups(): Promise<readonly string[]> {
    return (await this.call('/v1/whoami', {}, z.object({ groups: z.array(z.string()) }))).groups
  }

  async readValues(): Promise<readonly string[]> {
    return this.call('/v1/read-values', {}, z.array(z.string()))
  }
}

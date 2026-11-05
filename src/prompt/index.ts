import { randomBytes } from 'node:crypto'

import { TypeVaultError } from '../core/errors'
import { pageAssets, promptPage, expiredPage, rejectedPage } from './page'
import type { PromptHandle, PromptServer, PromptView } from './types'

export type { PromptHandle, PromptServer, PromptView } from './types'

type Pending = {
  readonly id: string
  readonly view: PromptView
  readonly resolve: (bytes: Uint8Array) => void
  readonly reject: (error: TypeVaultError) => void
  readonly accepted: Promise<void>
  readonly accept: () => void
  readonly refuse: (error: TypeVaultError) => void
  readonly responded: Promise<void>
  readonly respond: () => void
  timer: ReturnType<typeof setTimeout> | undefined
  submitted: boolean
}

const MAX_BODY = 64 * 1024

const GONE_TTL_MS = 60 * 60_000

export async function startPromptServer(
  options: { readonly port?: number; readonly publicUrl?: string } = {},
): Promise<PromptServer> {
  const assets = await pageAssets()
  const pending = new Map<string, Pending>()
  const ids = new Map<string, string>()
  // Only token tombstones survive settlement, to distinguish gone from unknown URLs.
  const gone = new Set<string>()
  let stopped = false

  function response(status: number, body: string | null = null): Response {
    return new Response(body, {
      status,
      headers: { ...assets.headers, ...(body === null ? {} : { 'Content-Type': 'text/html; charset=utf-8' }) },
    })
  }

  function retire(token: string, entry: Pending): void {
    clearTimeout(entry.timer)
    pending.delete(token)
    ids.delete(entry.id)
    gone.add(token)
    // Remember a spent token only long enough to answer 410 to a late reload, then forget it.
    setTimeout(() => gone.delete(token), GONE_TTL_MS).unref()
  }

  function expire(token: string, entry: Pending): void {
    retire(token, entry)
    const error = new TypeVaultError('expired', 'Prompt expired or was cancelled')
    entry.reject(error)
    if (entry.submitted) entry.refuse(error)
  }

  function schedule(token: string, entry: Pending): void {
    const remaining = entry.view.expiresAt.getTime() - Date.now()
    if (remaining <= 0) {
      expire(token, entry)
      return
    }
    entry.timer = setTimeout(() => schedule(token, entry), Math.min(remaining, 2_147_483_647))
  }

  let server: Bun.Server<undefined>
  try {
    server = Bun.serve({
      hostname: '127.0.0.1',
      port: options.port ?? 0,
      // Enforce the limit while streaming so Bun's automatic 413 cannot omit security headers.
      maxRequestBodySize: Number.MAX_SAFE_INTEGER,
      async fetch(request) {
        const path = new URL(request.url).pathname
        const match = /^\/r\/([A-Za-z0-9_-]{22})$/.exec(path)
        const token = match?.[1]
        if (token === undefined || (request.method !== 'GET' && request.method !== 'POST')) return response(404)
        const entry = pending.get(token)
        if (entry === undefined) return gone.has(token) ? response(410, expiredPage()) : response(404)
        if (entry.view.expiresAt.getTime() <= Date.now()) {
          expire(token, entry)
          return response(410, expiredPage())
        }
        if (request.method === 'GET') return response(200, promptPage(entry.view, assets.script))
        if (entry.submitted) return response(410, expiredPage())
        if (Number(request.headers.get('content-length')) > MAX_BODY) return response(413)
        if (request.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/octet-stream') {
          return response(415)
        }
        const reader = request.body?.getReader()
        const chunks: Uint8Array[] = []
        let size = 0
        try {
          if (reader !== undefined) {
            while (true) {
              const chunk = await reader.read()
              if (chunk.done) break
              size += chunk.value.byteLength
              if (size > MAX_BODY) {
                await reader.cancel()
                return response(413)
              }
              chunks.push(chunk.value)
            }
          }
        } catch (error) {
          if (error instanceof Error) return response(400)
          throw error
        } finally {
          reader?.releaseLock()
        }
        // Another upload, cancellation or expiry may win while the body is being read.
        if (entry.submitted) return response(410, expiredPage())
        if (pending.get(token) !== entry) return response(410, expiredPage())
        if (entry.view.expiresAt.getTime() <= Date.now()) {
          expire(token, entry)
          return response(410, expiredPage())
        }
        const bytes = new Uint8Array(size)
        let offset = 0
        for (const chunk of chunks) {
          bytes.set(chunk, offset)
          offset += chunk.byteLength
        }
        entry.submitted = true
        clearTimeout(entry.timer)
        entry.timer = undefined
        entry.resolve(bytes)
        try {
          await entry.accepted
          retire(token, entry)
          const accepted = response(204)
          entry.respond()
          return accepted
        } catch (error) {
          retire(token, entry)
          if (error instanceof TypeVaultError) {
            const rejected = response(error.code === 'tampered' ? 422 : 403, rejectedPage())
            entry.respond()
            return rejected
          }
          throw error
        }
      },
      error() {
        return response(500)
      },
    })
  } catch (error) {
    if (!(error instanceof Error) || !('code' in error) || typeof error.code !== 'string') throw error
    throw new TypeVaultError(
      'unavailable',
      `The secret page could not listen on 127.0.0.1:${options.port ?? 0} (${error.code}); set TYPEVAULT_PROMPT_PORT to use another port`,
    )
  }

  const port = server.port
  if (port === undefined) {
    await server.stop(true)
    throw new TypeVaultError('unavailable', 'Prompt server has no listening port')
  }
  return {
    port,
    open(view, openOptions = {}): PromptHandle {
      if (stopped) throw new TypeVaultError('unavailable', 'Prompt server is stopped')
      if (!Number.isFinite(view.expiresAt.getTime())) throw new TypeVaultError('invalid', 'Invalid prompt expiry')
      const token = randomBytes(16).toString('base64url')
      const id = randomBytes(16).toString('base64url')
      const { promise: done, resolve, reject } = Promise.withResolvers<Uint8Array>()
      const { promise: accepted, resolve: accept, reject: refuse } = Promise.withResolvers<void>()
      const { promise: responded, resolve: respond } = Promise.withResolvers<void>()
      const entry: Pending = {
        id,
        view: { ...view, recipients: [...view.recipients], expiresAt: new Date(view.expiresAt) },
        resolve,
        reject,
        accepted,
        accept,
        refuse,
        responded,
        respond,
        timer: undefined,
        submitted: false,
      }
      pending.set(token, entry)
      ids.set(id, token)
      schedule(token, entry)
      if (openOptions.validate !== true) accept()
      return {
        id,
        url: `${options.publicUrl ?? `http://127.0.0.1:${port}`}/r/${token}`,
        done,
        accept: async () => {
          accept()
          await responded
        },
        reject: async (error) => {
          if (!entry.submitted) return
          refuse(error)
          await responded
        },
      }
    },
    cancel(id) {
      const token = ids.get(id)
      const entry = token === undefined ? undefined : pending.get(token)
      if (token !== undefined && entry !== undefined) expire(token, entry)
    },
    async stop() {
      stopped = true
      for (const [token, entry] of pending) expire(token, entry)
      gone.clear()
      await server.stop(true)
    },
  }
}

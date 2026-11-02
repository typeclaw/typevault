import { z } from 'zod'

import { TypeVaultError } from '../core/errors'

export type OAuthFields = Readonly<Record<string, string>>

const Expiry = z.iso.datetime({ offset: true })
const TokenResponse = z.object({
  access_token: z.string(),
  expires_in: z.number().optional(),
  refresh_token: z.string().optional(),
})

export function needsRefresh(fields: OAuthFields, now: Date, skewSeconds = 60): boolean {
  const expiry = Expiry.safeParse(fields['expires_at'])
  return (
    Boolean(fields['refresh_token'] && fields['token_url']) &&
    expiry.success &&
    Date.parse(expiry.data) <= now.getTime() + skewSeconds * 1000
  )
}

export async function refreshOAuth(
  fields: OAuthFields,
  now: Date,
  options?: { readonly timeoutMs?: number },
): Promise<Record<string, string>> {
  let url: URL
  try {
    url = new URL(fields['token_url'] ?? '')
  } catch (error) {
    if (error instanceof TypeError) throw new TypeVaultError('invalid', 'invalid OAuth token URL')
    throw error
  }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new TypeVaultError('invalid', 'OAuth token URL requires HTTPS except on loopback hosts')
  }
  if (!fields['refresh_token']) throw new TypeVaultError('invalid', 'missing OAuth refresh token')
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: fields['refresh_token'] })
  for (const key of ['client_id', 'client_secret'] as const) {
    const value = fields[key]
    if (value !== undefined) body.set(key, value)
  }

  let status: number | undefined
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(options?.timeoutMs ?? 10_000),
      redirect: 'manual',
    })
    status = response.status
    if (!response.ok) throw new TypeVaultError('unavailable', `OAuth refresh failed (HTTP ${status})`)
    const json: unknown = await response.json()
    const parsed = TokenResponse.safeParse(json)
    if (!parsed.success) throw new TypeVaultError('unavailable', `invalid OAuth response (HTTP ${status})`)
    const result: Record<string, string> = { ...fields, access_token: parsed.data.access_token }
    if (parsed.data.expires_in === undefined) {
      delete result['expires_at']
    } else {
      result['expires_at'] = new Date(now.getTime() + parsed.data.expires_in * 1000).toISOString()
    }
    if (parsed.data.refresh_token !== undefined) result['refresh_token'] = parsed.data.refresh_token
    return result
  } catch (error) {
    if (error instanceof TypeVaultError) throw error
    if (error instanceof Error) {
      throw new TypeVaultError('unavailable', `OAuth refresh failed (HTTP ${status ?? 'no response'})`)
    }
    throw error
  }
}

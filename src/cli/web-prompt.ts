import { generateX25519Identity, identityToRecipient } from 'age-encryption'

import { unseal } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import type { EntryName, Field, Preset } from '../core/naming'
import { decodePayload } from '../core/payload'
import { matchCode } from '../daemon/requests'
import { startPromptServer } from '../prompt'

const TTL_MS = 10 * 60_000

export type WebEntry = {
  readonly name: EntryName
  readonly preset?: Preset | undefined
  readonly tier: string | undefined
}

/**
 * Collects an entry's fields on the local one-time page. The page encrypts to a throwaway key held only by this
 * process, which then stores the fields like `--stdin` would, so it works whatever access the caller has.
 */
export async function promptFields(
  entry: WebEntry,
  show: (url: string, code: string) => void,
): Promise<Record<string, Field>> {
  const identity = await generateX25519Identity()
  const server = await startPromptServer()
  try {
    const code = matchCode()
    const handle = server.open({
      name: entry.name,
      ...(entry.preset === undefined ? {} : { preset: entry.preset }),
      tier: entry.tier ?? 'your default tier',
      reason: `Store ${entry.name} from your terminal`,
      requester: 'typevault set',
      code,
      recipients: [await identityToRecipient(identity)],
      expiresAt: new Date(Date.now() + TTL_MS),
    })
    show(handle.url, code)
    const payload = decodePayload(await unseal([identity], await handle.done))
    if (payload.name !== entry.name) {
      throw new TypeVaultError('tampered', 'the submitted secret does not match this entry')
    }
    return { ...payload.fields }
  } finally {
    await server.stop()
  }
}

export function openBrowser(url: string): boolean {
  const command =
    process.platform === 'darwin'
      ? ['open', url]
      : process.platform === 'win32'
        ? ['cmd', '/c', 'start', '', url]
        : ['xdg-open', url]
  try {
    Bun.spawn(command, { stdio: ['ignore', 'ignore', 'ignore'] }).unref()
    return true
  } catch (error) {
    if (error instanceof Error) return false
    throw error
  }
}

import { join } from 'node:path'

import { sha256Hex } from './crypto'
import { fromBase64, utf8 } from './encoding'
import { signCiphertext, signerOf } from './entries'
import { atomicWrite } from './fsx'
import { withLock } from './lock'
import type { EntryName } from './naming'
import type { Vault } from './vault'

/** A write whose certificate expired before adoption; `digest` pins this exact write, revision and content. */
export type ExpiredWrite = {
  readonly name: string
  readonly rev: number
  readonly at: string
  readonly digest: string
}

export type Adoption = {
  readonly adopted: readonly string[]
  readonly expired: readonly ExpiredWrite[]
}

/** A write the owner chose to keep, by its name and the digest `doctor` listed it with. */
export type ExpiredPin = { readonly name: EntryName; readonly digest: string }

const digestOf = (sig: string): string => sha256Hex(utf8(sig)).slice(0, 16)

/**
 * Re-signs entries written under a sealed grant's certificate with a key this process holds, so they outlive the
 * certificate: readers stop accepting a certificate once their own clock passes its expiry. Run by the daemon
 * periodically and by `doctor --fix`.
 *
 * A write whose certificate already expired is adopted only when the owner pins it in `expired`: its `at` is chosen
 * by the holder, who keeps the signing key after expiry, so nothing proves it was written before the expiry. A name
 * alone can't pin it: a later forgery under the same name replaces the file, so the pin also carries the digest of
 * the exact write the owner reviewed.
 */
export function adoptCertWrites(
  vault: Vault,
  options: { readonly expired?: readonly ExpiredPin[] } = {},
): Promise<Adoption> {
  return withLock(vault.layout.lockFile, 'exclusive', async () => {
    const keep = new Set((options.expired ?? []).map((pin) => `${pin.name}@${pin.digest}`))
    const { entries } = await vault.scan({ acceptExpiredCerts: true })
    const adopted: string[] = []
    const expired: ExpiredWrite[] = []
    for (const { envelope, payload } of entries) {
      if (envelope.signer.kind !== 'cert') continue
      const digest = digestOf(envelope.sig)
      if (Date.now() > Date.parse(envelope.signer.cert.exp) && !keep.has(`${payload.name}@${digest}`)) {
        expired.push({ name: payload.name, rev: envelope.rev, at: envelope.at, digest })
        continue
      }
      const key = (await vault.keyring.unlock(envelope.tier)) ?? vault.keyring.owner
      if (key === undefined) continue
      const draft = { id: envelope.id, tier: envelope.tier, rev: envelope.rev + 1, at: new Date().toISOString() }
      const resigned = signCiphertext(draft, fromBase64(envelope.payload), vault.state, signerOf(key))
      atomicWrite(join(vault.layout.entries, `${envelope.id}.json`), `${JSON.stringify(resigned, null, 2)}\n`)
      adopted.push(payload.name)
    }
    return { adopted, expired }
  })
}

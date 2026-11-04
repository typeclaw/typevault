import { join } from 'node:path'

import { fromBase64 } from './encoding'
import { signCiphertext, signerOf } from './entries'
import { atomicWrite } from './fsx'
import { withLock } from './lock'
import type { EntryName } from './naming'
import type { Vault } from './vault'

export type Adoption = {
  readonly adopted: readonly string[]
  readonly expired: readonly string[]
}

/**
 * Re-signs entries written under a sealed grant's certificate with a key this process holds, so they outlive the
 * certificate: readers stop accepting a certificate once their own clock passes its expiry. Run by the daemon
 * periodically and by `doctor --fix`.
 *
 * A write whose certificate already expired is adopted only when the owner names it in `expired`: its `at` is chosen
 * by the holder, who keeps the signing key after expiry, so nothing proves it was written before the expiry.
 */
export function adoptCertWrites(
  vault: Vault,
  options: { readonly expired?: readonly EntryName[] } = {},
): Promise<Adoption> {
  return withLock(vault.layout.lockFile, 'exclusive', async () => {
    const keep = new Set<string>(options.expired ?? [])
    const { entries } = await vault.scan({ acceptExpiredCerts: true })
    const adopted: string[] = []
    const expired: string[] = []
    for (const { envelope, payload } of entries) {
      if (envelope.signer.kind !== 'cert') continue
      if (Date.now() > Date.parse(envelope.signer.cert.exp) && !keep.has(payload.name)) {
        expired.push(payload.name)
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

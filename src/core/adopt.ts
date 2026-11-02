import { join } from 'node:path'

import { fromBase64 } from './encoding'
import { signCiphertext, signerOf } from './entries'
import { atomicWrite } from './fsx'
import { withLock } from './lock'
import type { Vault } from './vault'

/**
 * Re-signs entries written under a sealed grant's certificate with a key this process holds, so they outlive the
 * certificate: readers stop accepting a certificate once their own clock passes its expiry. Run by the daemon
 * periodically and by `doctor --fix`. Returns the adopted names.
 */
export function adoptCertWrites(vault: Vault): Promise<readonly string[]> {
  return withLock(vault.layout.lockFile, 'exclusive', async () => {
    const { entries } = await vault.scan()
    const adopted: string[] = []
    for (const { envelope, payload } of entries) {
      if (envelope.signer.kind !== 'cert') continue
      const key = (await vault.keyring.unlock(envelope.group)) ?? vault.keyring.operator
      if (key === undefined) continue
      const draft = { id: envelope.id, group: envelope.group, rev: envelope.rev + 1, at: new Date().toISOString() }
      const resigned = signCiphertext(draft, fromBase64(envelope.payload), vault.state, signerOf(key))
      atomicWrite(join(vault.layout.entries, `${envelope.id}.json`), `${JSON.stringify(resigned, null, 2)}\n`)
      adopted.push(payload.name)
    }
    return adopted
  })
}

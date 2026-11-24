import { join } from 'node:path'

import type { SignerContext } from './entries'
import { draftEntry } from './entry-draft'
import { TypeVaultError } from './errors'
import { atomicWrite } from './fsx'
import { withLock } from './lock'
import type { Field } from './naming'
import type { StoredEntry, Vault } from './vault'

/** Refresh can update only the exact signed revision it read, never the winner of a name lookup. */
export function storeRefreshedFields(
  vault: Vault,
  observed: StoredEntry,
  fields: Readonly<Record<string, Field>>,
  signer: SignerContext,
): Promise<StoredEntry> {
  return withLock(vault.layout.lockFile, 'exclusive', async () => {
    const { id, rev, sig, tier } = observed.envelope
    const { entries } = await vault.scan()
    const current = entries.find((entry) => entry.envelope.id === id)
    const name = observed.payload.name
    if (current?.envelope.rev !== rev || current.envelope.sig !== sig) {
      throw new TypeVaultError('conflict', `${name} changed during OAuth refresh`)
    }
    const { env, origin, tags } = current.payload
    const stored = await draftEntry(
      vault.state,
      { name, tier, fields, tags, ...(env === undefined ? {} : { env }), ...(origin === undefined ? {} : { origin }) },
      current,
      { ifRev: rev },
      signer,
    )
    if (stored.envelope.id !== id) throw new TypeVaultError('denied', 'OAuth refresh cannot change the entry identity')
    atomicWrite(join(vault.layout.entries, `${id}.json`), `${JSON.stringify(stored.envelope, null, 2)}\n`)
    return stored
  })
}

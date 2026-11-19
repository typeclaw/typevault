import { existsSync } from 'node:fs'
import { dirname } from 'node:path'

import { z } from 'zod'

import { type PublicKey, type SecretKey, sign, verifySignature } from './crypto'
import { canonicalJson, utf8 } from './encoding'
import { TypeVaultError } from './errors'
import { atomicWrite, ensureDir } from './fsx'
import { readJsonFile } from './json-file'
import type { Layout } from './layout'
import { holdLock } from './lock'

export const PublicKeySchema = z.object({ recipient: z.string().startsWith('age1'), signPublic: z.string() })
const Link = z.object({ from: z.string(), to: PublicKeySchema, sig: z.string() })
const Owner = PublicKeySchema.extend({ handovers: z.array(Link).default([]) })
type Link = z.infer<typeof Link>
export type Owner = z.infer<typeof Owner>
const Trust = z.object({ ownerSignPublic: z.string() })

const linkBytes = (from: string, to: PublicKey) => utf8(canonicalJson({ purpose: 'typevault:handover', from, to }))

export function handover(from: Owner, signing: SecretKey, to: PublicKey): readonly Link[] {
  return [
    ...from.handovers,
    { from: from.signPublic, to, sig: sign(signing.signSecret, linkBytes(from.signPublic, to)) },
  ]
}

export function ownerDoc(key: PublicKey, handovers: readonly Link[] = []): string {
  return `${JSON.stringify({ v: 1, ...key, handovers }, null, 2)}\n`
}

export function readOwner(layout: Layout): Owner {
  return readOwnerFile(layout.ownerFile)
}

export const firstOwnerSignPublic = (owner: Owner): string => owner.handovers[0]?.from ?? owner.signPublic

export function readOwnerFile(path: string): Owner {
  if (!existsSync(path)) throw new TypeVaultError('not_found', `no vault at ${dirname(path)} (run typevault init)`)
  const owner = readJsonFile(path, Owner)
  const seen = new Set([owner.signPublic])
  let expected = owner.signPublic
  for (const { from, to, sig } of owner.handovers.toReversed()) {
    if (to.signPublic !== expected || seen.has(from) || !verifySignature(from, linkBytes(from, to), sig)) {
      throw new TypeVaultError('tampered', 'invalid vault owner handover')
    }
    seen.add(from)
    expected = from
  }
  const last = owner.handovers.at(-1)
  if (last !== undefined && last.to.recipient !== owner.recipient)
    throw new TypeVaultError('tampered', 'invalid handover recipient')
  return owner
}

/** Both pins are forward-only. A static deployment pin may be an ancestor, but cannot override a newer local pin. */
export function trustOwner(layout: Layout, owner: Owner, pinned: string | undefined): void {
  const endorses = (key: string) => key === owner.signPublic || owner.handovers.some(({ from }) => from === key)
  if (pinned && !endorses(pinned)) throw new TypeVaultError('tampered', 'vault owner does not match TYPEVAULT_OWNER')
  const local = () => (existsSync(layout.trustFile) ? readJsonFile(layout.trustFile, Trust).ownerSignPublic : undefined)
  if (local() === owner.signPublic) return
  // Different processes may finish verifying different generations concurrently. Never overwrite a newer pin.
  ensureDir(layout.root, 0o700)
  const release = holdLock(`${layout.trustFile}.lock`)
  if (!release) throw new TypeVaultError('locked', 'another process is updating owner trust; retry')
  try {
    const current = local()
    if (current !== undefined && !endorses(current))
      throw new TypeVaultError('tampered', 'vault owner changed without a trusted handover')
    atomicWrite(layout.trustFile, JSON.stringify({ ownerSignPublic: owner.signPublic }), 0o600)
  } finally {
    release()
  }
}

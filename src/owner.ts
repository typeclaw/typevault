import { existsSync } from 'node:fs'

import { ScopedVault } from './access/scoped'
import type { Access } from './access/types'
import { Admin } from './core/admin'
import { decodeSecretKey, encodeSecretKey } from './core/crypto'
import { TypeVaultError } from './core/errors'
import { claimDaemon } from './core/holder'
import { createIdentity, decodeMemberPublic, encodeMemberPublic, memberPublicOfIdentity } from './core/identity'
import { initLocalVault } from './core/init'
import { localLayout } from './core/layout'
import { holdLock } from './core/lock'
import type { MemberKind } from './core/state'
import { Vault } from './core/vault'

export type { Access, EntrySummary, EntryValue, SetInput } from './access/types'
export { type ErrorCode, TypeVaultError } from './core/errors'

/** A machine member: no password, its key held by whoever runs it. */
export type MachineIdentity = {
  readonly name: string
  /** The secret member key (what `TYPEVAULT_KEY` takes). Keep it private. */
  readonly key: string
  /** The `tvp1:` public key an owner adds as a member. */
  readonly publicKey: string
}

/** Where a vault and its private state live. Nothing is read from or written to this user's config. */
export type VaultLocation = {
  /** The vault directory, e.g. `<project>/.typevault`. */
  readonly dir: string
  /** The vault's private state (trust pin, audit, run). One machine at a time may use it. */
  readonly stateDir: string
  /** Where the daemon's sockets live, for a `stateDir` too deep for a socket path. */
  readonly runDir?: string
}

export type TierInfo = { readonly name: string; readonly gen: number; readonly includes: readonly string[] }
export type MemberInfo = {
  readonly name: string
  readonly kind: MemberKind
  readonly owner: boolean
  readonly tiers: readonly string[]
}

export type OwnerVault = {
  readonly member: string
  readonly tiers: {
    add(name: string): Promise<void>
    /** `tier` reaches everything `included` reaches. */
    include(tier: string, included: string): Promise<void>
    list(): Promise<readonly TierInfo[]>
  }
  readonly ceilings: {
    /** The most the admin socket `name` may grant. */
    set(name: string, tier: string): Promise<void>
  }
  readonly members: {
    list(): Promise<readonly MemberInfo[]>
  }
  /** Entries, read and written with this member's own keys (direct mode, audited). */
  readonly entries: Access
}

/** A new machine identity, returned only: no file is written. */
export async function createMachineIdentity(options: { readonly name: string }): Promise<MachineIdentity> {
  const { identity, key } = await createIdentity(options.name, 'machine')
  return {
    name: identity.name,
    key: encodeSecretKey(key),
    publicKey: encodeMemberPublic(memberPublicOfIdentity(identity)),
  }
}

/**
 * Creates an empty vault at `dir` owned by a machine `founder`. Fails with `conflict` when a vault is already there
 * (it never initializes over one) or a daemon is using `stateDir`, and `in_use` when one on another machine is.
 */
export async function initVault(
  options: VaultLocation & { readonly founder: Pick<MachineIdentity, 'name' | 'publicKey'> },
): Promise<void> {
  const member = decodeMemberPublic(options.founder.publicKey)
  if (member.kind !== 'machine') throw new TypeVaultError('invalid', 'the founder must be a machine identity')
  const env = envOf(options)
  const layout = localLayout(options.dir, env)
  // Initializing resets the state directory's runtime state: no daemon may be using it, here or on another machine.
  const release = holdLock(layout.daemonLock)
  if (release === undefined) {
    throw new TypeVaultError('conflict', `a typevault daemon is using ${options.stateDir}; stop it first`)
  }
  try {
    const claim = claimDaemon(layout, env)
    try {
      await initLocalVault(options.dir, { name: options.founder.name, member }, env)
    } finally {
      claim.release()
    }
  } finally {
    release()
  }
}

/**
 * Opens the vault at `dir` with a member key held in memory. Fails with `no_vault` when there is no vault at `dir`,
 * and `not_member` when there is one but `key` is not among its members. Tier and ceiling changes need an owner.
 */
export async function openVault(options: VaultLocation & { readonly key: string }): Promise<OwnerVault> {
  const env = envOf(options)
  const layout = localLayout(options.dir, env)
  if (!existsSync(layout.ownerFile)) throw new TypeVaultError('no_vault', `no vault at ${options.dir}`)
  const key = decodeSecretKey(options.key)
  if (key.role.kind !== 'member') throw new TypeVaultError('invalid', 'the key must be a member key')
  const vault = await Vault.open(layout, [key], env)
  const member = vault.member
  if (member === undefined) {
    throw new TypeVaultError('not_member', `"${key.role.name}" is not a member of the vault at ${options.dir}`)
  }
  const admin = (): Admin => new Admin(vault)
  const current = async () => {
    vault.refresh()
    return vault.state
  }
  return {
    member,
    tiers: {
      add: (name) => admin().addTier(name),
      include: (tier, included) => admin().include(tier, included),
      list: async () =>
        Object.entries((await current()).tiers).map(([name, tier]) => ({
          name,
          gen: tier.gen,
          includes: tier.includes,
        })),
    },
    ceilings: { set: (name, tier) => admin().setCeiling(name, tier) },
    members: {
      list: async () =>
        Object.entries((await current()).members).map(([name, m]) => ({
          name,
          kind: m.kind,
          owner: m.owner,
          tiers: m.tiers,
        })),
    },
    entries: new ScopedVault(vault, [], { mode: 'direct', ownTiers: vault.state.members[member]?.tiers ?? [] }),
  }
}

function envOf(location: VaultLocation): Readonly<Record<string, string | undefined>> {
  if (location.stateDir === '') throw new TypeVaultError('invalid', 'stateDir is required')
  return {
    TYPEVAULT_STATE_DIR: location.stateDir,
    ...(location.runDir === undefined ? {} : { TYPEVAULT_RUN_DIR: location.runDir }),
    ...(process.env['TYPEVAULT_HOST_ID'] === undefined ? {} : { TYPEVAULT_HOST_ID: process.env['TYPEVAULT_HOST_ID'] }),
  }
}

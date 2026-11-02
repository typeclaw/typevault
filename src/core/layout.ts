import { homedir } from 'node:os'
import { join } from 'node:path'

export type Layout = {
  readonly root: string
  readonly vault: string
  readonly entries: string
  readonly groupsDir: string
  readonly operatorFile: string
  readonly groupsFile: string
  readonly signersFile: string
  readonly ceilingsFile: string
  readonly anchorsFile: string
  readonly txnDir: string
  readonly keys: string
  readonly operatorKey: string
  readonly groupKeys: string
  readonly trustFile: string
  readonly audit: string
  readonly auditLog: string
  readonly run: string
  readonly lockFile: string
  readonly auditLock: string
  readonly grantsFile: string
  readonly agentSocket: string
  readonly adminSocket: (ceiling: string) => string
}

/** `TYPEVAULT_DIR`, else `$XDG_CONFIG_HOME/typevault`, else `~/.config/typevault`. */
export function resolveRoot(env: Readonly<Record<string, string | undefined>> = process.env): string {
  const explicit = env['TYPEVAULT_DIR']
  if (explicit !== undefined && explicit !== '') return explicit
  const xdg = env['XDG_CONFIG_HOME']
  return join(xdg !== undefined && xdg !== '' ? xdg : join(homedir(), '.config'), 'typevault')
}

export function layoutOf(root: string): Layout {
  const vault = join(root, 'vault')
  const keys = join(root, 'keys')
  const audit = join(root, 'audit')
  const run = join(root, 'run')
  return {
    root,
    vault,
    entries: join(vault, 'entries'),
    groupsDir: join(vault, 'groups'),
    operatorFile: join(vault, 'operator.json'),
    groupsFile: join(vault, 'groups.json'),
    signersFile: join(vault, 'signers.json'),
    ceilingsFile: join(vault, 'ceilings.json'),
    anchorsFile: join(vault, 'audit-anchors.jsonl'),
    txnDir: join(vault, '.txn'),
    keys,
    operatorKey: join(keys, 'operator.key'),
    groupKeys: join(keys, 'groups'),
    trustFile: join(keys, 'trust.json'),
    audit,
    auditLog: join(audit, 'log.jsonl'),
    run,
    lockFile: join(run, 'lock'),
    auditLock: join(run, 'audit.lock'),
    grantsFile: join(run, 'grants.json'),
    agentSocket: join(run, 'agent.sock'),
    adminSocket: (ceiling: string) => join(run, `admin-${ceiling}.sock`),
  }
}

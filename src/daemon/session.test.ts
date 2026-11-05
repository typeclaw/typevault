import { afterEach, beforeEach, expect, it } from 'bun:test'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import { z } from 'zod'

import { Admin } from '../core/admin'
import { encodeSecretKey, type SecretKey } from '../core/crypto'
import { claimDaemon } from '../core/holder'
import { createIdentity } from '../core/identity'
import { founderOf, initGlobalVault } from '../core/init'
import { globalLayout, type Layout } from '../core/layout'
import { Vault } from '../core/vault'
import { callDaemon, isDaemonAlive } from './client'
import { type RunningDaemon, startDaemon } from './daemon'
import { GrantStore, SESSION_CEILING } from './grants'
import { LiveAccess } from './live-access'
import { stopDaemon } from './spawn'

const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })
const Token = z.object({ token: z.string(), exp: z.string() })
let base: string
let env: Record<string, string>
let layout: Layout
let owner: SecretKey
let daemon: RunningDaemon | undefined

beforeEach(async () => {
  daemon = undefined
  base = mkdtempSync(join(SHORT_TMP, 'tvs-'))
  env = { TYPEVAULT_DIR: join(base, 'vault'), XDG_CONFIG_HOME: base, HOME: base, TYPEVAULT_HOST_ID: 'test-host' }
  layout = globalLayout(env)
  const { identity } = await createIdentity('owner', 'machine')
  owner = (await initGlobalVault(founderOf(identity), env)).owner
  const admin = new Admin(await Vault.open(layout, [owner], env))
  await admin.addTier('default')
  await admin.setCeiling('bot', 'default')
})

afterEach(async () => {
  await daemon?.stop()
  rmSync(base, { recursive: true, force: true })
})

it.each(['default', 'bot'])('bounds grants from the %s socket to its unlocked session', async (ceiling) => {
  daemon = await startDaemon({ layout, env, keys: [owner], session: { ttlMs: 60_000 } })
  const sessionToken = readFileSync(layout.sessionFile, 'utf8')
  const session = new GrantStore(layout.grantsFile).resolve(sessionToken).record
  const issued = await callDaemon(layout.adminSocket(ceiling), '/v1/grant', { tiers: ['default'], ttl: '2h' }, Token)
  const parent = new LiveAccess(layout.agentSocket, issued.token)
  const child = await parent.call('/v1/derive', { ttl: '3h' }, Token)
  expect(issued.exp).toBe(session.exp)
  expect(child.exp).toBe(session.exp)
  expect(await parent.list()).toEqual([])
  expect(await new LiveAccess(layout.agentSocket, child.token).list()).toEqual([])

  await daemon.stop()
  daemon = await startDaemon({ layout, env, keys: [owner], session: { ttlMs: 60_000 } })

  for (const token of [sessionToken, issued.token, child.token]) {
    await expect(new LiveAccess(layout.agentSocket, token).list()).rejects.toMatchObject({ code: 'denied' })
  }
  expect(new GrantStore(layout.grantsFile).list().map((record) => record.label)).toEqual(['session'])
})

it.each([true, false])('invalidates abandoned sessions on startup (unlocked session: %p)', async (unlocked) => {
  const grants = new GrantStore(layout.grantsFile)
  const request = { tiers: ['default'], only: [], ttlMs: 60_000, label: 'session', ceiling: SESSION_CEILING }
  const old = grants.issue(request)
  const another = grants.issue(request)
  const child = grants.issue({ ...request, parent: old.record.id, label: 'derived', ceiling: 'bot' })
  const machine = grants.issue({ ...request, label: 'machine', ceiling: 'bot' })
  const machineChild = grants.issue({ ...request, parent: machine.record.id, label: 'machine/child', ceiling: 'bot' })
  writeFileSync(layout.sessionFile, old.token)

  daemon = await startDaemon({ layout, env, keys: [owner], ...(unlocked ? { session: { ttlMs: 60_000 } } : {}) })

  for (const { token } of [old, another, child]) {
    await expect(new LiveAccess(layout.agentSocket, token).list()).rejects.toMatchObject({ code: 'denied' })
  }
  for (const { token } of [machine, machineChild]) {
    expect(await new LiveAccess(layout.agentSocket, token).list()).toEqual([])
  }
  expect(existsSync(layout.sessionFile)).toBe(unlocked)
  expect(new GrantStore(layout.grantsFile).list().map((record) => record.label)).toEqual([
    'machine',
    'machine/child',
    ...(unlocked ? ['session'] : []),
  ])
})

it('ends abandoned sessions and their descendants even when no daemon runs', async () => {
  const grants = new GrantStore(layout.grantsFile)
  const request = { tiers: ['default'], only: [], ttlMs: 60_000, label: 'session', ceiling: SESSION_CEILING }
  const old = grants.issue(request)
  const child = grants.issue({ ...request, parent: old.record.id, ceiling: 'bot' })
  writeFileSync(layout.sessionFile, old.token)
  const abandonedClaim = claimDaemon(layout, env)

  try {
    await expect(stopDaemon(layout, env)).rejects.toMatchObject({ code: 'not_found' })

    const reopened = new GrantStore(layout.grantsFile)
    for (const { token } of [old, child]) expect(() => reopened.resolve(token)).toThrow()
    expect(reopened.list()).toEqual([])
    expect(existsSync(layout.sessionFile)).toBe(false)
    expect(existsSync(layout.daemonHolder)).toBe(false)
  } finally {
    abandonedClaim.release()
  }
})

it('leaves grants and the session token untouched when a foreign host claims the state', async () => {
  const grants = new GrantStore(layout.grantsFile)
  const old = grants.issue({
    tiers: ['default'],
    only: [],
    ttlMs: 60_000,
    label: 'session',
    ceiling: SESSION_CEILING,
  })
  writeFileSync(layout.sessionFile, old.token)
  const claim = claimDaemon(layout, { ...env, TYPEVAULT_HOST_ID: 'other-host' })
  const files = [layout.grantsFile, layout.sessionFile, layout.daemonHolder]
  const before = files.map((file) => readFileSync(file, 'utf8'))
  try {
    await expect(stopDaemon(layout, { ...env, TYPEVAULT_HOST_ID: 'local-host' })).rejects.toMatchObject({
      code: 'in_use',
    })
    expect(files.map((file) => readFileSync(file, 'utf8'))).toEqual(before)
  } finally {
    claim.release()
  }
})

it('preserves ceiling grants issued without a session across stops and unlocks', async () => {
  daemon = await startDaemon({ layout, env, keys: [owner] })
  const { token } = await callDaemon(layout.adminSocket('bot'), '/v1/grant', { tiers: ['default'], ttl: '2h' }, Token)
  const child = await new LiveAccess(layout.agentSocket, token).call('/v1/derive', {}, Token)
  await daemon.stop()
  await expect(stopDaemon(layout)).rejects.toMatchObject({ code: 'not_found' })
  daemon = await startDaemon({ layout, env, keys: [owner], session: { ttlMs: 60_000 } })
  await daemon.stop()
  daemon = await startDaemon({ layout, env, keys: [owner] })

  expect(await new LiveAccess(layout.agentSocket, token).list()).toEqual([])
  expect(await new LiveAccess(layout.agentSocket, child.token).list()).toEqual([])
})

it('ends issued and derived grants when the session daemon expires', async () => {
  // Run the real CLI timer; await its process exit rather than sleeping past the TTL.
  const proc = Bun.spawn(
    [process.execPath, join(import.meta.dir, '../cli/index.ts'), 'daemon', 'run', '--key-stdin', '--ttl', '2s'],
    { cwd: base, env, stdin: new TextEncoder().encode(encodeSecretKey(owner)), stdout: 'ignore', stderr: 'pipe' },
  )
  try {
    const deadline = Date.now() + 10_000
    while (!existsSync(layout.sessionFile) || !(await isDaemonAlive(layout.adminSocket('default')))) {
      if (proc.exitCode !== null || Date.now() > deadline) {
        throw new Error(`session did not start: ${await new Response(proc.stderr).text()}`)
      }
      await Bun.sleep(10)
    }
    const issued = await callDaemon(
      layout.adminSocket('default'),
      '/v1/grant',
      { tiers: ['default'], ttl: '2h' },
      Token,
    )
    const child = await new LiveAccess(layout.agentSocket, issued.token).call('/v1/derive', {}, Token)
    expect(await proc.exited).toBe(0)
    daemon = await startDaemon({ layout, env, keys: [owner], session: { ttlMs: 60_000 } })

    for (const token of [issued.token, child.token]) {
      await expect(new LiveAccess(layout.agentSocket, token).list()).rejects.toMatchObject({ code: 'denied' })
    }
    expect(new GrantStore(layout.grantsFile).list().map((record) => record.label)).toEqual(['session'])
  } finally {
    if (proc.exitCode === null) proc.kill('SIGKILL')
    await proc.exited
  }
}, 15_000)

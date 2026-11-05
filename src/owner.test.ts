import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import { createClient, parseEntryName } from 'typevault'
import { createAdmin } from 'typevault/admin'
import { createMachineIdentity, initVault, type MachineIdentity, openVault } from 'typevault/owner'
import { z } from 'zod'

import { anchorAudit, appendAudit, verifyAudit } from './audit/log'
import { Admin } from './core/admin'
import { decodeSecretKey } from './core/crypto'
import { claimDaemon } from './core/holder'
import { localLayout } from './core/layout'
import { holdLock, isLockHeld } from './core/lock'
import { Vault } from './core/vault'
import { callDaemon } from './daemon/client'
import { startDaemon } from './daemon/daemon'
import { LiveAccess } from './daemon/live-access'
import { endLiveGrants, stopDaemon } from './daemon/spawn'

// Unix socket paths are limited to ~104 bytes (108 on Windows), too short under the default temp dir on macOS and
// Windows CI runners.
const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })
const CLI = join(import.meta.dir, 'cli', 'index.ts')
const n = parseEntryName

let base: string
let agent: string
let dir: string
let stateDir: string

beforeEach(() => {
  base = mkdtempSync(join(SHORT_TMP, 'tvo-'))
  agent = join(base, 'agent')
  dir = join(agent, '.typevault')
  stateDir = join(agent, '.typeclaw', 'typevault', 'state')
})
afterEach(() => rmSync(base, { recursive: true, force: true }))

async function provision(): Promise<MachineIdentity> {
  const identity = await createMachineIdentity({ name: 'agent' })
  await initVault({ dir, stateDir, founder: identity })
  return identity
}

describe('a state directory shared by openers', () => {
  it('gives two paths and two homes one trust pin and one set of revision marks', async () => {
    // given the agent folder reached directly and through another path, each opener with its own config home
    const { key } = await provision()
    const mount = join(base, 'mount')
    symlinkSync(agent, mount)
    const hostEnv = {
      HOME: join(base, 'host'),
      XDG_CONFIG_HOME: join(base, 'host', '.config'),
      TYPEVAULT_STATE_DIR: stateDir,
    }
    const containerEnv = {
      HOME: join(base, 'ctr'),
      XDG_CONFIG_HOME: join(base, 'ctr', '.config'),
      TYPEVAULT_STATE_DIR: join(mount, '.typeclaw', 'typevault', 'state'),
    }
    const host = localLayout(dir, hostEnv)
    const container = localLayout(join(mount, '.typevault'), containerEnv)
    const seenTiers = readFileSync(host.tiersFile)

    // when the host moves tiers.json forward and an old copy is put back
    await new Admin(await Vault.open(host, [decodeSecretKey(key)], hostEnv)).addTier('member')
    writeFileSync(host.tiersFile, seenTiers)

    // then the container refuses the rollback, as does a restart with a fresh home
    await expect(Vault.open(container, [], containerEnv)).rejects.toMatchObject({ code: 'tampered' })
    const freshEnv = { ...containerEnv, HOME: join(base, 'fresh'), XDG_CONFIG_HOME: join(base, 'fresh', '.config') }
    await expect(Vault.open(localLayout(join(mount, '.typevault'), freshEnv), [], freshEnv)).rejects.toMatchObject({
      code: 'tampered',
    })
  })

  it('keeps the trust pin when a fresh home opens a vault whose owner was replaced', async () => {
    // given a vault pinned at init, and another vault's owner and manifests copied over it
    await provision()
    const other = join(base, 'other', '.typevault')
    await initVault({
      dir: other,
      stateDir: join(base, 'other-state'),
      founder: await createMachineIdentity({ name: 'x' }),
    })
    for (const file of ['owner.json', 'tiers.json', 'members.json', 'signers.json', 'ceilings.json']) {
      copyFileSync(join(other, file), join(dir, file))
    }

    // when an opener with a home it never used before opens it
    const env = {
      HOME: join(base, 'fresh'),
      XDG_CONFIG_HOME: join(base, 'fresh', '.config'),
      TYPEVAULT_STATE_DIR: stateDir,
    }

    // then the replaced owner is refused
    await expect(Vault.open(localLayout(dir, env), [], env)).rejects.toMatchObject({ code: 'tampered' })
  })

  it('anchors one audit chain whatever host or path opens it', async () => {
    // given openers on two hosts reaching the vault through two paths
    await provision()
    const mount = join(base, 'mount')
    symlinkSync(agent, mount)
    const openers = [
      localLayout(dir, { TYPEVAULT_STATE_DIR: stateDir, TYPEVAULT_HOST_ID: 'host-a' }),
      localLayout(join(mount, '.typevault'), { TYPEVAULT_STATE_DIR: stateDir, TYPEVAULT_HOST_ID: 'host-b' }),
    ]

    // when each appends and anchors
    for (const layout of openers) {
      await appendAudit(layout, { action: 'read', mode: 'direct' })
      await anchorAudit(layout)
    }

    // then there is one chain and one anchors file
    expect(readdirSync(join(dir, 'audit-anchors'))).toHaveLength(1)
    expect(openers.map(verifyAudit)).toEqual([
      { ok: true, records: 2 },
      { ok: true, records: 2 },
    ])
  })

  it('still checks the anchors after the audit directory is deleted', async () => {
    // given an anchored log
    await provision()
    const layout = localLayout(dir, { TYPEVAULT_STATE_DIR: stateDir })
    await appendAudit(layout, { action: 'read', mode: 'direct' })
    await anchorAudit(layout)

    // when the audit directory goes, log and all
    rmSync(join(stateDir, 'audit'), { recursive: true })

    // then the committed anchor no longer matches anything
    expect(verifyAudit(localLayout(dir, { TYPEVAULT_STATE_DIR: stateDir }))).toEqual({
      ok: false,
      reason: 'local log no longer matches the anchor at record 1',
    })
  })

  it('anchors per host and checkout without a state directory', async () => {
    // given a vault opened from two hosts with only a config home each
    await provision()
    const layouts = ['host-a', 'host-b'].map((host) =>
      localLayout(dir, { XDG_CONFIG_HOME: join(base, 'config'), TYPEVAULT_HOST_ID: host }),
    )

    // when each anchors its own log
    for (const layout of layouts) {
      await appendAudit(layout, { action: 'read', mode: 'direct' })
      await anchorAudit(layout)
    }

    // then each host keeps its own anchors file
    expect(readdirSync(join(dir, 'audit-anchors'))).toHaveLength(2)
  })
})

describe('daemons', () => {
  it('serve from a state directory too deep for a socket through a run directory', async () => {
    // given a state directory whose socket paths would pass the AF_UNIX limit
    stateDir = join(agent, 'd'.repeat(60), 'e'.repeat(60), 'state')
    const runDir = join(base, 'run')
    const { key } = await provision()
    const owner = await openVault({ dir, stateDir, runDir, key })
    await owner.tiers.add('member')
    await owner.entries.set({ name: n('openai'), fields: { key: { type: 'secret', value: 'sk-x' } }, tier: 'member' })
    const env = { TYPEVAULT_STATE_DIR: stateDir, TYPEVAULT_RUN_DIR: runDir }
    const daemon = await startDaemon({ layout: localLayout(dir, env), env, keys: [decodeSecretKey(key)] })

    try {
      // when a grant is issued and read through the SDK
      const at = { dir, stateDir, runDir, env: {} }
      const grant = await createAdmin(at).grant({ tiers: ['member'], label: 'deep' })
      const client = await createClient({ grant, ...at })

      // then the sockets live in the run directory and serve
      expect((await client.list()).map((entry): string => entry.name)).toEqual(['openai'])
      expect(readdirSync(runDir).sort()).toEqual(['admin-default.sock', 'agent.sock', 'control.sock'])
    } finally {
      await daemon.stop()
    }
  })

  it("refuse a second machine's direct open while one holds the state, until it stops", async () => {
    // given a daemon running on one machine
    const { key } = await provision()
    await (await openVault({ dir, stateDir, key })).tiers.add('member')
    const container = { TYPEVAULT_STATE_DIR: stateDir, TYPEVAULT_HOST_ID: 'container' }
    const host = { TYPEVAULT_STATE_DIR: stateDir, TYPEVAULT_HOST_ID: 'host' }
    const keys = [decodeSecretKey(key)]
    const daemon = await startDaemon({ layout: localLayout(dir, container), env: container, keys })

    // then the other machine's direct open and daemon start fail with in_use, while the same machine still opens
    try {
      await expect(Vault.open(localLayout(dir, host), keys, host)).rejects.toMatchObject({ code: 'in_use' })
      await expect(startDaemon({ layout: localLayout(dir, host), env: host, keys })).rejects.toMatchObject({
        code: 'in_use',
      })
      expect((await Vault.open(localLayout(dir, container), keys, container)).member).toBe('agent')
    } finally {
      await daemon.stop()
    }

    // and once it has stopped, the other machine opens
    expect((await Vault.open(localLayout(dir, host), keys, host)).member).toBe('agent')
  })

  it('starts from the CLI in a fresh home with its state and run dirs from env, honoring TYPEVAULT_PUBLIC_URL', async () => {
    // given a provisioned vault and a home that is new to typevault, as in a container
    stateDir = join(agent, 'd'.repeat(60), 'e'.repeat(60), 'state')
    const runDir = join(base, 'run')
    const home = join(base, 'home')
    mkdirSync(home)
    const { key } = await provision()
    const owner = await openVault({ dir, stateDir, runDir, key })
    await owner.tiers.add('member')

    // when the daemon runs from the agent folder with only environment configuration
    const daemon = Bun.spawn([process.execPath, CLI, 'daemon', 'run'], {
      cwd: agent,
      env: {
        PATH: process.env['PATH'] ?? '',
        HOME: home,
        // Bun's own transpiler cache would land in the home; this checks typevault's writes.
        BUN_RUNTIME_TRANSPILER_CACHE_PATH: '0',
        TYPEVAULT_KEY: key,
        TYPEVAULT_STATE_DIR: stateDir,
        TYPEVAULT_RUN_DIR: runDir,
        TYPEVAULT_PUBLIC_URL: 'https://vault.example.test',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    })
    try {
      await untilLine(daemon.stderr, 'typevault daemon ready')
      const at = { dir, stateDir, runDir, env: {} }
      const grant = await createAdmin(at).grant({ tiers: ['member'], label: 'session:1' })
      const Opened = z.object({ id: z.string(), url: z.string(), code: z.string() })
      const opened = await new LiveAccess(join(runDir, 'agent.sock'), grant).call(
        '/v1/request',
        { name: 'openai', reason: 'test' },
        Opened,
      )

      // then request pages are linked through the public URL, and nothing was written to the home
      expect(opened.url.startsWith('https://vault.example.test/r/')).toBe(true)
      expect(readdirSync(home)).toEqual([])
    } finally {
      // SIGTERM on Windows ends the process before its cleanup: stop it the way the CLI does.
      await stopDaemon(localLayout(dir, { TYPEVAULT_STATE_DIR: stateDir, TYPEVAULT_RUN_DIR: runDir }))
      await daemon.exited
    }
    expect(readdirSync(runDir)).toEqual([])
  }, 20_000)
})

describe('claims on a state directory', () => {
  const layoutOn = (host: string) => localLayout(dir, { TYPEVAULT_STATE_DIR: stateDir, TYPEVAULT_HOST_ID: host })

  let identity: MachineIdentity
  beforeEach(async () => {
    identity = await provision()
  })

  it('go to exactly one of two machines whose local locks both succeed', () => {
    // when two machines claim the state at once
    const first = claimDaemon(layoutOn('host-a'), { TYPEVAULT_HOST_ID: 'host-a' })
    let refused: unknown
    try {
      claimDaemon(layoutOn('host-b'), { TYPEVAULT_HOST_ID: 'host-b' })
    } catch (error) {
      refused = error
    }

    // then one holds it and the other is refused, until the first releases it
    expect(refused).toMatchObject({ code: 'in_use' })
    first.release()
    claimDaemon(layoutOn('host-b'), { TYPEVAULT_HOST_ID: 'host-b' }).release()
  })

  it('keep another machine from starting while lock deletes the grants', async () => {
    // given grants on disk, and an audit log busy enough to hold `lock` partway through
    const layout = layoutOn('host-a')
    mkdirSync(layout.run, { recursive: true })
    writeFileSync(layout.grantsFile, '[]')
    const releaseAudit = holdLock(layout.auditLock)

    // when lock is deleting them on one machine, and another machine claims the state
    const ending = endLiveGrants(layout, { TYPEVAULT_HOST_ID: 'host-a' })
    const claiming = () => claimDaemon(layoutOn('host-b'), { TYPEVAULT_HOST_ID: 'host-b' })

    // then that machine is refused until lock is done
    try {
      expect(claiming).toThrow(expect.objectContaining({ code: 'in_use' }))
    } finally {
      releaseAudit?.()
      await ending
    }
    expect(existsSync(layout.grantsFile)).toBe(false)
    claiming().release()
  })

  it("refuse another machine's claim however old, until it is cleared", async () => {
    // given a claim another machine left a day ago (crashed, or only paused: nothing here can tell)
    const layout = layoutOn('host-a')
    const old = {
      host: 'host-b',
      name: 'old-laptop',
      pid: 1,
      token: 'old',
      at: new Date(Date.now() - 86_400_000).toISOString(),
    }
    writeFileSync(layout.daemonHolder, JSON.stringify(old))

    // then neither a daemon nor a direct open on this machine goes ahead, and the claim stays
    expect(() => claimDaemon(layout, { TYPEVAULT_HOST_ID: 'host-a' })).toThrow(
      expect.objectContaining({ code: 'in_use', message: expect.stringContaining('old-laptop') }),
    )
    const env = { TYPEVAULT_STATE_DIR: stateDir, TYPEVAULT_HOST_ID: 'host-a' }
    await expect(Vault.open(layout, [], env)).rejects.toMatchObject({ code: 'in_use' })
    expect(JSON.parse(readFileSync(layout.daemonHolder, 'utf8'))).toEqual(old)

    // and once someone who knows that daemon is gone deletes it, this machine claims the state
    rmSync(layout.daemonHolder)
    claimDaemon(layout, { TYPEVAULT_HOST_ID: 'host-a' }).release()
  })

  it('replace a claim this machine left behind', () => {
    // given a claim from a daemon on this machine that is gone (the caller holds the daemon lock)
    const layout = layoutOn('host-a')
    writeFileSync(
      layout.daemonHolder,
      JSON.stringify({ host: 'host-a', name: 'renamed', pid: 1, token: 'old', at: new Date().toISOString() }),
    )

    // when this machine claims the state, then releases it
    const claim = claimDaemon(layout, { TYPEVAULT_HOST_ID: 'host-a' })
    expect(claim.owns()).toBe(true)
    claim.release()

    // then the claim is gone
    expect(existsSync(layout.daemonHolder)).toBe(false)
  })

  it("leave a successor's grants, session and run files alone when a daemon whose claim was replaced stops", async () => {
    // given a session daemon on one machine whose claim was cleared and taken by another machine
    const { key } = identity
    await (await openVault({ dir, stateDir, key })).tiers.add('member')
    const env = { TYPEVAULT_STATE_DIR: stateDir, TYPEVAULT_HOST_ID: 'host-a' }
    const layout = localLayout(dir, env)
    const daemon = await startDaemon({ layout, env, keys: [decodeSecretKey(key)], session: { ttlMs: 60_000 } })
    renameSync(layout.daemonHolder, `${layout.daemonHolder}.taken`)
    rmSync(`${layout.daemonHolder}.taken`)
    const successor = claimDaemon(layoutOn('host-b'), { TYPEVAULT_HOST_ID: 'host-b' })

    // when the successor issues its own grant and session, and the old daemon stops
    const files = [layout.grantsFile, layout.sessionFile, join(layout.run, 'daemon.pid')]
    for (const file of files) writeFileSync(file, `successor ${file}`)
    const claimed = readFileSync(layout.daemonHolder, 'utf8')
    await daemon.stop()

    // then everything the successor wrote is still there
    expect(files.map((file) => readFileSync(file, 'utf8'))).toEqual(files.map((file) => `successor ${file}`))
    expect(readFileSync(layout.daemonHolder, 'utf8')).toBe(claimed)
    successor.release()
  })

  it('never release a claim they no longer own', () => {
    // given a claim that was cleared and replaced by another machine's
    const layout = layoutOn('host-a')
    const claim = claimDaemon(layout, { TYPEVAULT_HOST_ID: 'host-a' })
    const theirs = JSON.stringify({
      host: 'host-b',
      name: 'their-laptop',
      pid: 1,
      token: 'theirs',
      at: new Date().toISOString(),
    })
    writeFileSync(layout.daemonHolder, theirs)

    // when the first one releases
    claim.release()

    // then the other machine's claim stays
    expect(readFileSync(layout.daemonHolder, 'utf8')).toBe(theirs)
  })
})

describe('provisioning', () => {
  it('runs end to end without writing to the home directory', async () => {
    // given a process whose home is empty and which has no config home set
    const home = join(base, 'home')
    mkdirSync(home)
    const script = join(base, 'provision.ts')
    await Bun.write(
      script,
      `import { createMachineIdentity, initVault, openVault } from ${JSON.stringify(join(import.meta.dir, 'owner.ts'))}
const location = { dir: ${JSON.stringify(dir)}, stateDir: ${JSON.stringify(stateDir)} }
const identity = await createMachineIdentity({ name: 'agent' })
await initVault({ ...location, founder: identity })
const vault = await openVault({ ...location, key: identity.key })
await vault.tiers.add('member')
await vault.tiers.add('trusted')
await vault.tiers.include('trusted', 'member')
await vault.ceilings.set('session', 'member')
await vault.entries.set({ name: 'openai', fields: { key: { type: 'secret', value: 'sk-x' } }, tier: 'member' })
const got = (await vault.entries.get('openai')).fields
const listed = (await vault.entries.list()).map((entry) => entry.name)
await vault.entries.remove('openai')
console.log(JSON.stringify({
  member: vault.member,
  tiers: await vault.tiers.list(),
  members: await vault.members.list(),
  got,
  listed,
  after: (await vault.entries.list()).length,
}))`,
    )

    // when it provisions a vault
    const run = Bun.spawn([process.execPath, script], {
      // Bun's own transpiler cache would land in the home; this checks typevault's writes.
      env: { HOME: home, PATH: process.env['PATH'] ?? '', BUN_RUNTIME_TRANSPILER_CACHE_PATH: '0' },
      stdout: 'pipe',
      stderr: 'pipe',
    })
    const [code, out, err] = await Promise.all([
      run.exited,
      new Response(run.stdout).text(),
      new Response(run.stderr).text(),
    ])

    // then every step worked and the home is untouched
    expect({ code, err }).toEqual({ code: 0, err: '' })
    expect(JSON.parse(out)).toEqual({
      member: 'agent',
      tiers: [
        { name: 'member', gen: 2, includes: [] },
        { name: 'trusted', gen: 1, includes: ['member'] },
      ],
      members: [{ name: 'agent', kind: 'machine', owner: true, tiers: [] }],
      got: { key: { type: 'secret', value: 'sk-x' } },
      listed: ['openai'],
      after: 0,
    })
    expect(readdirSync(home)).toEqual([])
  }, 20_000)

  it('refuses to re-initialize while a daemon still uses the state directory', async () => {
    // given a running daemon whose vault directory was deleted, its state directory kept
    const { key } = await provision()
    const env = { TYPEVAULT_STATE_DIR: stateDir }
    const layout = localLayout(dir, env)
    const daemon = await startDaemon({ layout, env, keys: [decodeSecretKey(key)] })
    await appendAudit(layout, { action: 'read', mode: 'direct' })
    rmSync(dir, { recursive: true })

    // when the vault is initialized again over the same state directory
    const again = initVault({ dir, stateDir, founder: await createMachineIdentity({ name: 'agent' }) })

    // then it is refused and the daemon keeps its runtime state
    try {
      await expect(again).rejects.toMatchObject({ code: 'conflict' })
      const Ok = z.object({ ok: z.literal(true) })
      expect(await callDaemon(layout.agentSocket, '/v1/ping', {}, Ok)).toMatchObject({ ok: true })
      expect(readdirSync(layout.run)).toContain('daemon.lock')
    } finally {
      await daemon.stop()
    }

    // and once it has stopped, its claim and lock are released and initialization goes ahead
    expect(existsSync(layout.daemonHolder)).toBe(false)
    expect(isLockHeld(layout.daemonLock)).toBe(false)
    await initVault({ dir, stateDir, founder: await createMachineIdentity({ name: 'agent' }) })
  })

  it('tells a missing vault, a stranger key and a member key apart, and never initializes over a vault', async () => {
    // given no vault yet, then a vault, and a key that is not one of its members
    const stranger = await createMachineIdentity({ name: 'stranger' })
    await expect(openVault({ dir, stateDir, key: stranger.key })).rejects.toMatchObject({ code: 'no_vault' })
    const identity = await provision()

    // then each case has its own outcome
    await expect(openVault({ dir, stateDir, key: stranger.key })).rejects.toMatchObject({ code: 'not_member' })
    expect((await openVault({ dir, stateDir, key: identity.key })).member).toBe('agent')
    await expect(initVault({ dir, stateDir, founder: stranger })).rejects.toMatchObject({ code: 'conflict' })
    expect((await openVault({ dir, stateDir, key: identity.key })).member).toBe('agent')
  })
})

async function untilLine(stream: ReadableStream<Uint8Array>, text: string): Promise<void> {
  const decoder = new TextDecoder()
  let seen = ''
  for await (const chunk of stream) {
    seen += decoder.decode(chunk, { stream: true })
    if (seen.includes(text)) return
  }
  throw new Error(`stream ended before "${text}": ${seen}`)
}

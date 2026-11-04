import { afterEach, beforeEach, expect, it } from 'bun:test'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

import type { Subprocess } from 'bun'

import { globalLayout, type Layout } from '../core/layout'
import { startBackground, stopDaemon } from './spawn'

const LOCK_MODULE = join(import.meta.dir, '..', 'core', 'lock.ts')

// Unix socket paths are limited to ~104 bytes (108 on Windows), too short under the default temp dir on macOS and
// Windows CI runners.
const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })

// Stands in for a daemon whose cleanup is slow. Like a real one it holds run/daemon.lock for its whole life and
// answers pings with its PID; on SIGTERM it stops answering at once, cleans up for a second, marks that it finished,
// and exits.
const SLOW_DAEMON = `
import { join } from 'node:path'
import { holdLock } from '${LOCK_MODULE}'
const run = process.argv[2]
if (holdLock(join(run, 'daemon.lock')) === undefined) process.exit(2)
const server = Bun.serve({ unix: join(run, 'agent.sock'), fetch: () => Response.json({ ok: true, pid: process.pid }) })
await Bun.write(join(run, 'daemon.pid'), String(process.pid))
process.once('SIGTERM', async () => {
  server.stop(true)
  console.log('closed')
  await Bun.sleep(1000)
  await Bun.write(join(run, 'cleaned'), '')
  process.exit(0)
})
console.log('ready')
`

// Stands in for a daemon from an older release: it answers pings, but holds no lock and reports no PID. On SIGTERM it
// closes its socket at once and keeps cleaning up, PID file still in place, for a second.
const OLDER_DAEMON = `
import { join } from 'node:path'
const run = process.argv[2]
const server = Bun.serve({ unix: join(run, 'agent.sock'), fetch: () => Response.json({ ok: true }) })
await Bun.write(join(run, 'daemon.pid'), String(process.pid))
process.once('SIGTERM', async () => {
  server.stop(true)
  console.log('closed')
  await Bun.sleep(1000)
  process.exit(0)
})
console.log('ready')
setInterval(() => {}, 1 << 30)
`

// Stands in for the daemon that won a race to start: it takes the daemon lock at once, but opens its socket only
// half a second later, as a real one does after opening its vault. It serves until killed.
const WINNING_DAEMON = `
import { join } from 'node:path'
import { holdLock } from '${LOCK_MODULE}'
const run = process.argv[2]
if (holdLock(join(run, 'daemon.lock')) === undefined) process.exit(2)
await Bun.write(join(run, 'winner.pid'), String(process.pid))
console.log('locked')
await Bun.sleep(500)
Bun.serve({ unix: join(run, 'agent.sock'), fetch: () => Response.json({ ok: true, pid: process.pid }) })
setInterval(() => {}, 1 << 30)
`

// Stands in for the start that lost the race: it exits with a lock conflict as soon as the winner holds the lock,
// before the winner serves.
const LOSING_START = `
const [run, winner] = process.argv.slice(2)
const other = Bun.spawn([process.execPath, winner, run], { stdout: 'pipe' })
await other.stdout.getReader().read()
other.unref()
console.error('a typevault daemon is still shutting down here')
process.exit(1)
`

let root: string
let layout: Layout
let standIns: Subprocess[] = []

beforeEach(() => {
  root = mkdtempSync(join(SHORT_TMP, 'tvp-'))
  layout = globalLayout({ TYPEVAULT_DIR: join(root, 'vault'), XDG_CONFIG_HOME: root })
  mkdirSync(layout.run, { recursive: true })
})

afterEach(() => {
  // A failing assertion must not leave a stand-in running past its test.
  for (const standIn of standIns) standIn.kill('SIGKILL')
  standIns = []
  rmSync(root, { recursive: true, force: true })
})

async function standIn(
  source: string,
): Promise<{ readonly process: Subprocess; readonly next: () => Promise<string> }> {
  const script = join(root, `stand-in-${standIns.length}.ts`)
  writeFileSync(script, source)
  const spawned = Bun.spawn([process.execPath, script, layout.run], { stdout: 'pipe' })
  standIns.push(spawned)
  const reader = spawned.stdout.getReader()
  const next = async (): Promise<string> => new TextDecoder().decode((await reader.read()).value)
  expect(await next()).toContain('ready')
  return { process: spawned, next }
}

const cleaned = (): boolean => existsSync(join(layout.run, 'cleaned'))

it('returns only once the daemon has finished cleaning up, not when its socket goes quiet', async () => {
  await standIn(SLOW_DAEMON)

  await stopDaemon(layout)

  expect(cleaned()).toBe(true)
})

it('waits, without signaling again, for a daemon that already closed its socket and is still cleaning up', async () => {
  // given a daemon told to stop elsewhere: its socket is closed, its cleanup still running
  const daemon = await standIn(SLOW_DAEMON)
  daemon.process.kill('SIGTERM')
  expect(await daemon.next()).toContain('closed')

  // when it is stopped again
  await stopDaemon(layout)

  // then this returns only after its cleanup finished, which a second signal would have cut short
  expect(cleaned()).toBe(true)
})

it('signals the daemon that answers, never a different process its PID file names', async () => {
  // given a serving daemon whose PID file now names an unrelated process
  await standIn(SLOW_DAEMON)
  const unrelated = Bun.spawn(['sleep', '30'])
  standIns.push(unrelated)
  writeFileSync(join(layout.run, 'daemon.pid'), String(unrelated.pid))

  // when it is stopped
  await stopDaemon(layout)

  // then the daemon finished and the unrelated process was left alone
  expect(cleaned()).toBe(true)
  expect(unrelated.exitCode).toBeNull()
})

it('refuses, rather than signals, a live process named by a PID file that holds no daemon lock', async () => {
  // given a PID file naming a running process that isn't a daemon holding the lock, and no socket
  const unrelated = Bun.spawn(['sleep', '30'])
  standIns.push(unrelated)
  writeFileSync(join(layout.run, 'daemon.pid'), String(unrelated.pid))

  // then stopping fails closed and leaves that process alone
  await expect(stopDaemon(layout)).rejects.toMatchObject({ code: 'conflict' })
  expect(unrelated.exitCode).toBeNull()
})

it('reports nothing running when the PID file names a process that is gone', async () => {
  const gone = Bun.spawn([process.execPath, '-e', ''])
  await gone.exited
  writeFileSync(join(layout.run, 'daemon.pid'), String(gone.pid))

  await expect(stopDaemon(layout)).rejects.toMatchObject({ code: 'not_found' })
})

it('refuses to guess at a daemon from an older release, and leaves it running', async () => {
  const older = await standIn(OLDER_DAEMON)

  await expect(stopDaemon(layout)).rejects.toMatchObject({ code: 'conflict' })

  expect(older.process.exitCode).toBeNull()
})

it('refuses to treat an older daemon that closed its socket but is still cleaning up as gone', async () => {
  // given an older daemon told to stop: socket closed, cleanup still running, no lock held
  const older = await standIn(OLDER_DAEMON)
  older.process.kill('SIGTERM')
  expect(await older.next()).toContain('closed')

  // then stopping fails closed instead of reporting that nothing runs, so init can't clear its state under it
  await expect(stopDaemon(layout)).rejects.toMatchObject({ code: 'conflict' })
})

it('keeps waiting for the daemon that won a race to start, even before it opens its socket', async () => {
  // given a start that exits with a lock conflict while the winning daemon holds the lock but doesn't serve yet
  writeFileSync(join(root, 'winner.ts'), WINNING_DAEMON)
  writeFileSync(join(root, 'losing.ts'), LOSING_START)

  try {
    // then the start waits for the winner and succeeds instead of reporting that the daemon did not start
    await startBackground(layout, {}, [process.execPath, join(root, 'losing.ts'), layout.run, join(root, 'winner.ts')])
  } finally {
    process.kill(Number(readFileSync(join(layout.run, 'winner.pid'), 'utf8')), 'SIGKILL')
  }
})

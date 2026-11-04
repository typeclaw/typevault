import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { layoutOf, type Layout } from '../core/layout'
import { stopDaemon } from './spawn'

// Stands in for a daemon whose cleanup is slow: it stops answering at once, then takes a second to exit.
const SLOW_DAEMON = `
import { join } from 'node:path'
const run = process.argv[2]
const server = Bun.serve({ unix: join(run, 'agent.sock'), fetch: () => Response.json({ ok: true }) })
await Bun.write(join(run, 'daemon.pid'), String(process.pid))
process.once('SIGTERM', async () => {
  server.stop(true)
  await Bun.sleep(1000)
  process.exit(0)
})
console.log('ready')
`

let root: string
let layout: Layout

beforeEach(() => {
  // Short root: unix socket paths are limited to ~104 bytes.
  root = mkdtempSync('/tmp/tvp-')
  layout = layoutOf(root)
  mkdirSync(layout.run, { recursive: true })
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

it('returns only once the old daemon has exited, not when its socket goes quiet', async () => {
  // given a daemon that keeps cleaning up after its socket closes
  const script = join(root, 'slow-daemon.ts')
  writeFileSync(script, SLOW_DAEMON)
  const daemon = Bun.spawn([process.execPath, script, layout.run], { stdout: 'pipe' })
  const reader = daemon.stdout.getReader()
  expect(new TextDecoder().decode((await reader.read()).value)).toContain('ready')

  // when it is stopped
  await stopDaemon(layout)

  // then it has already exited, so nothing it cleans up can touch a replacement
  expect(daemon.exitCode).toBe(0)
})

it('treats a PID file left by a daemon that is already gone as stopped', async () => {
  const gone = Bun.spawn([process.execPath, '-e', ''])
  await gone.exited
  writeFileSync(join(layout.run, 'daemon.pid'), String(gone.pid))

  await stopDaemon(layout)
})

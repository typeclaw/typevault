import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, parse } from 'node:path'

const SHORT_TMP = process.platform === 'win32' ? join(parse(tmpdir()).root, 'tmp') : '/tmp'
mkdirSync(SHORT_TMP, { recursive: true })
const CLI = join(import.meta.dir, 'index.ts')
let home: string
let project: string
let env: Record<string, string>

async function cli(args: readonly string[], input = '') {
  const proc = Bun.spawn([process.execPath, CLI, ...args], {
    cwd: project,
    env,
    stdin: Buffer.from(input),
    stdout: 'pipe',
    stderr: 'pipe',
    timeout: 5000,
  })
  const [code, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ])
  return { code, stdout, stderr }
}

beforeEach(async () => {
  home = realpathSync(mkdtempSync(join(SHORT_TMP, 'tv-redact-')))
  project = join(home, 'project')
  mkdirSync(project)
  env = { HOME: home, XDG_CONFIG_HOME: join(home, 'config'), PATH: process.env['PATH'] ?? '' }
  expect((await cli(['--vault-password-stdin', 'init', '--name', 'qa'], 'dummy-pass\ndummy-pass\n')).code).toBe(0)
  expect((await cli(['--vault-password-stdin', 'unlock', '--for', '30m'], 'dummy-pass\n')).code).toBe(0)
  expect((await cli(['set', 'svc', '--preset', 'api_key', '--stdin'], 'dummy-value-0001')).code).toBe(0)
  const grant = await cli(['grant', '--tier', 'default', '--label', 'agent:qa', '--ttl', '10m'])
  expect(grant.code).toBe(0)
  env['TYPEVAULT_GRANT'] = grant.stdout.trim()
})

afterEach(async () => {
  delete env['TYPEVAULT_GRANT']
  await cli(['lock'])
  rmSync(home, { recursive: true, force: true })
})

it('shows a prompt before the child receives input and preserves its exit status', async () => {
  const proc = Bun.spawn(
    [
      process.execPath,
      CLI,
      'run',
      '--',
      process.execPath,
      '-e',
      'process.stdout.write("Enter name: "); for await (const chunk of Bun.stdin.stream()) { console.log("hello " + Buffer.from(chunk)); break }; process.exitCode = 7',
    ],
    { cwd: project, env, stdin: 'pipe', stdout: 'pipe', stderr: 'pipe', timeout: 3000 },
  )
  const reader = proc.stdout.getReader()
  try {
    const prompt = await reader.read()
    expect(Buffer.from(prompt.value ?? []).toString()).toBe('Enter name: ')
    proc.stdin.write('Alice\n')
    proc.stdin.end()
    while (!(await reader.read()).done) {}
    expect(await proc.exited).toBe(7)
    expect(await new Response(proc.stderr).text()).toBe('')
  } finally {
    proc.kill()
    await proc.exited
  }
}, 10000)

it.each(['run', 'redact'])(
  'handles a closed output reader for %s without hanging or a stack trace',
  async (command) => {
    const args =
      command === 'run'
        ? ['run', '--', process.execPath, '-e', 'for (;;) await Bun.write(Bun.stdout, "output\\n".repeat(8192))']
        : ['redact']
    const proc = Bun.spawn([process.execPath, CLI, ...args], {
      cwd: project,
      env,
      stdin: command === 'redact' ? Buffer.alloc(2 * 1024 * 1024, 120) : 'ignore',
      stdout: 'pipe',
      stderr: 'pipe',
      timeout: 3000,
    })
    const reader = proc.stdout.getReader()
    try {
      expect((await reader.read()).done).toBe(false)
      await reader.cancel()
      expect(await new Response(proc.stderr).text()).toBe('')
      expect(await proc.exited).toBe(command === 'run' ? 137 : 0)
    } finally {
      proc.kill()
      await proc.exited
    }
  },
  10000,
)

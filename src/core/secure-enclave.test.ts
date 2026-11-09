import { afterEach, expect, it, spyOn } from 'bun:test'
import { appendFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { typevaultSignedRuntime } from './secure-enclave'

// codesign, stubbed: each call waits until the test settles it, and a successful one marks the file it signed.
type Signing = { readonly path: string; readonly settle: (code: number) => void }
const signings: Signing[] = []
let signingStarted: () => void = () => {}
const spawn = spyOn(Bun, 'spawn').mockImplementation(((command: string[]) => {
  const path = command.at(-1) ?? ''
  const { promise, resolve } = Promise.withResolvers<number>()
  signings.push({
    path,
    settle: (code) => {
      if (code === 0) appendFileSync(path, ' signed')
      resolve(code)
    },
  })
  signingStarted()
  return { exited: promise }
}) as unknown as typeof Bun.spawn)

const dirs: string[] = []
afterEach(() => {
  signings.length = 0
  spawn.mockClear()
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function setup(): { readonly env: { XDG_CONFIG_HOME: string }; readonly source: string; readonly bin: string } {
  const dir = mkdtempSync(join(tmpdir(), 'typevault-enclave-'))
  dirs.push(dir)
  const source = join(dir, 'bun')
  writeFileSync(source, 'bun')
  return { env: { XDG_CONFIG_HOME: dir }, source, bin: join(dir, 'typevault', 'bin') }
}

function settleNext(code: number): void {
  const signing = signings.shift()
  if (signing === undefined) throw new Error('no signing in flight')
  signing.settle(code)
}

it('overlapping calls publish only the copy that was signed', async () => {
  const { env, source, bin } = setup()
  const { promise: bothSigning, resolve } = Promise.withResolvers<void>()
  signingStarted = () => signings.length === 2 && resolve()

  const failing = typevaultSignedRuntime(env, source)
  const succeeding = typevaultSignedRuntime(env, source)
  await bothSigning
  settleNext(1)
  const failed = await failing
  settleNext(0)
  const runtime = await succeeding

  expect(failed).toBeUndefined()
  expect(runtime).toBe(join(bin, 'typevault'))
  expect(readFileSync(join(bin, 'typevault'), 'utf8')).toBe('bun signed')
  expect(readdirSync(bin)).toEqual(['typevault'])
})

it('reuses the signed copy when the source mtime has fractional milliseconds', async () => {
  const { env, source } = setup()
  utimesSync(source, 1_700_000_000.1234567, 1_700_000_000.1234567)
  signingStarted = () => settleNext(0)

  const first = await typevaultSignedRuntime(env, source)
  const second = await typevaultSignedRuntime(env, source)

  expect(second).toBe(first)
  expect(spawn).toHaveBeenCalledTimes(1)
})

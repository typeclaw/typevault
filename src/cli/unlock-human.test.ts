import { afterEach, beforeEach, expect, it, mock, spyOn, setDefaultTimeout } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { p256 } from '@noble/curves/nist.js'

import { publicKeyOf } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import { createIdentity, type Identity, sealMemberKeyForTouchId, writeIdentity } from '../core/identity'
import type { Passwords } from './password'

// Each test derives a human member key with Argon2, which a parallel run on a busy machine can stretch past the 5s
// default.
setDefaultTimeout(30_000)

// The Mac's enclave and its Touch ID dialog, mocked: tests never raise the real dialog.
let enclaveSecret = p256.utils.randomSecretKey()
let touchOutcome: 'touched' | TypeVaultError = 'touched'
let touches = 0
let touchReason = ''
let sensor: boolean | Error = true
mock.module('../core/secure-enclave', () => ({
  hasTouchId: () => {
    if (sensor instanceof Error) throw sensor
    return sensor
  },
  createEnclaveKey: () => {
    enclaveSecret = p256.utils.randomSecretKey()
    return { handle: new Uint8Array([7]), publicKey: p256.getPublicKey(enclaveSecret, false) }
  },
  exchangeWithEnclave: (_env: unknown, _handle: Uint8Array, ephemeral: Uint8Array, reason: string) => {
    touches += 1
    touchReason = reason
    if (touchOutcome !== 'touched') return Promise.reject(touchOutcome)
    return Promise.resolve(p256.getSharedSecret(enclaveSecret, ephemeral).slice(1))
  },
}))
let fromStdin = false
mock.module('./password', () => ({
  promptHidden: () => Promise.resolve(''),
  newPassword: () => Promise.resolve(''),
  passwords: () => ({ ask: () => Promise.resolve('') }),
  passwordsFromStdin: () => fromStdin,
}))

const { runAdmin, unlockHuman } = await import('./context')
const { commandIs, commandPath } = await import('./requester')
const { set } = await import('./commands/entries')
const { run } = await import('./commands/run')
const { tier } = await import('./commands/admin')

const platform = Object.getOwnPropertyDescriptor(process, 'platform')
const isTTY = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY')
const setPlatform = (value: NodeJS.Platform): void => {
  Object.defineProperty(process, 'platform', { value, configurable: true })
}
const setTerminal = (value: boolean): void => {
  Object.defineProperty(process.stdin, 'isTTY', { value, configurable: true })
}

let alice: Identity
let alicePublic: Awaited<ReturnType<typeof publicKeyOf>>
let asked: number
const password: Passwords = {
  ask: () => {
    asked += 1
    return Promise.resolve('pw')
  },
}

beforeEach(async () => {
  const created = await createIdentity('alice', 'human', 'pw')
  touchOutcome = 'touched'
  if (created.identity.kind !== 'human') throw new Error('expected a human identity')
  alice = { ...created.identity, touchId: await sealMemberKeyForTouchId({}, created.key) }
  alicePublic = await publicKeyOf(created.key)
  touches = 0
  asked = 0
  fromStdin = false
  sensor = true
  setPlatform('darwin')
  setTerminal(true)
})
afterEach(() => {
  commandIs({ words: [], args: [] })
  if (platform !== undefined) Object.defineProperty(process, 'platform', platform)
  if (isTTY === undefined) delete (process.stdin as { isTTY?: boolean }).isTTY
  else Object.defineProperty(process.stdin, 'isTTY', isTTY)
})

it('opens the member key with a touch, without asking for the password', async () => {
  const key = await unlockHuman({}, alice, password)

  expect(await publicKeyOf(key)).toEqual(alicePublic)
  expect({ touches, asked }).toEqual({ touches: 1, asked: 0 })
})

it('says which command asks, but never an argument value, whether set or run', async () => {
  const cases: readonly [readonly string[], string, string][] = [
    [['set', 'SENTINEL', '--field', 'password=SENTINEL', '--', 'SENTINEL'], 'typevault set', 'unlock your vault'],
    [['run', '--only', 'SENTINEL', '--', '/usr/bin/psql', 'SENTINEL'], 'typevault run -- psql', 'unlock your vault'],
    [['set', 'svc', '--reason', '--field=password=SENTINEL'], 'typevault set', 'unlock your vault'],
    // set declares no --reason, so citty takes the word after a bare one as its entry name
    [['set', '--reason', 'SENTINEL'], 'typevault set', 'unlock your vault'],
    // set declares no --reason, so nothing in its arguments is taken for one
    [['set', 'svc', '--field', '--reason=SENTINEL', '--reason=SENTINEL'], 'typevault set', 'unlock your vault'],
    // run declares --reason, so its reason leads both prompts
    [['run', '--reason', 'run migrations', '--', 'psql', 'SENTINEL'], 'typevault run -- psql', 'run migrations'],
  ]
  for (const [args, shown, wanted] of cases) {
    // given Touch ID that fails, so both prompts show, for a command whose arguments hold a secret
    touchOutcome = new TypeVaultError('denied', 'Touch ID was cancelled')
    // the shell gave a global flag after each --field, which the entry point takes out before dispatch
    const argv = process.argv
    process.argv = [...argv.slice(0, 2), ...args.flatMap((arg) => (arg === '--field' ? [arg, '-g'] : [arg]))]
    commandIs(commandPath({ subCommands: { set, run } }, args))
    const stderr = spyOn(process.stderr, 'write').mockImplementation(() => true)

    // when the key is asked for
    let written = ''
    await unlockHuman({}, alice, password).finally(() => {
      written = stderr.mock.calls.map(([text]) => String(text)).join('')
      stderr.mockRestore()
      process.argv = argv
    })

    // then both prompts name the purpose and the command, and the secret reaches neither
    expect(touchReason).toStartWith(wanted)
    expect(written).toContain(` wants to ${wanted}\n`)
    expect(written).toContain(`  command  ${shown}\n`)
    expect(touchReason + written).not.toContain('SENTINEL')
  }
})

it('asks to approve the owner change through a locked session or a grant', async () => {
  for (const grant of [{}, { TYPEVAULT_GRANT: 'tvl1.x.y' }]) {
    // given a person's identity, a global vault with no session running, and an owner command
    const home = mkdtempSync(join(tmpdir(), 'typevault-owner-prompt-'))
    const env = { HOME: home, XDG_CONFIG_HOME: join(home, 'config'), TYPEVAULT_DIR: join(home, 'vault'), ...grant }
    // Written under the real platform: Windows refuses the directory fsync a mocked macOS would do.
    if (platform !== undefined) Object.defineProperty(process, 'platform', platform)
    writeIdentity(env, alice)
    setPlatform('darwin')
    commandIs(commandPath({ subCommands: { tier } }, ['tier', 'add', 'ops']))
    touches = 0

    // when it runs (the vault itself is missing, so it fails right after the prompt)
    await expect(
      runAdmin(env, { op: 'tier.add', name: 'ops' }).finally(() => rmSync(home, { recursive: true, force: true })),
    ).rejects.toThrow()

    // then the one prompt that also approves the change says so first, and names the vault
    expect(touches).toBe(1)
    expect(touchReason).toStartWith('approve an owner change ')
    expect(touchReason).toEndWith(' in the global vault')
  }
})

it('asks for the password when Touch ID is cancelled or the enclave key no longer opens', async () => {
  for (const failure of [
    new TypeVaultError('denied', 'Touch ID was cancelled'),
    new TypeVaultError('denied', 'could not load the Secure Enclave key: biometry changed'),
  ]) {
    // given a touch that fails this way
    touchOutcome = failure
    touches = 0
    asked = 0

    // when the vault is unlocked
    const key = await unlockHuman({}, alice, password)

    // then the password opens it instead
    expect(await publicKeyOf(key)).toEqual(alicePublic)
    expect({ touches, asked }).toEqual({ touches: 1, asked: 1 })
  }
})

it('suggests turning on Touch ID only at a Mac with a sensor where it is off', async () => {
  const { touchId: _, ...withoutTouchId } = alice as Identity & { touchId?: unknown }
  const cases: readonly [string, Identity, () => void, boolean][] = [
    ['off, with a sensor', withoutTouchId as Identity, () => {}, true],
    ['already on', alice, () => {}, false],
    ['no sensor', withoutTouchId as Identity, () => (sensor = false), false],
    ['a probe that fails', withoutTouchId as Identity, () => (sensor = new Error('no LAContext')), false],
    ['no terminal', withoutTouchId as Identity, () => setTerminal(false), false],
    ['passwords on stdin', withoutTouchId as Identity, () => (fromStdin = true), false],
  ]
  for (const [name, identity, arrange, hinted] of cases) {
    // given
    sensor = true
    fromStdin = false
    setTerminal(true)
    arrange()
    const stderr = spyOn(process.stderr, 'write').mockImplementation(() => true)

    // when
    let written = ''
    const key = await unlockHuman({}, identity, password).finally(() => {
      written = stderr.mock.calls.map(([text]) => String(text)).join('')
      stderr.mockRestore()
    })

    // then
    expect(await publicKeyOf(key)).toEqual(alicePublic)
    expect([name, written.includes('typevault touch-id enable')]).toEqual([name, hinted])
  }
})

it('never asks for Touch ID without a terminal, with passwords on stdin, or off macOS', async () => {
  const cases: readonly (() => void)[] = [
    () => setTerminal(false),
    () => {
      fromStdin = true
    },
    () => setPlatform('linux'),
  ]
  for (const arrange of cases) {
    // given Touch ID turned on, in one of those settings
    setPlatform('darwin')
    setTerminal(true)
    fromStdin = false
    arrange()
    asked = 0

    // when the vault is unlocked
    const key = await unlockHuman({}, alice, password)

    // then only the password was asked
    expect(await publicKeyOf(key)).toEqual(alicePublic)
    expect(asked).toBe(1)
  }
  expect(touches).toBe(0)
})

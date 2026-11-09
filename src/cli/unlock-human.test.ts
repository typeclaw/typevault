import { afterEach, beforeEach, expect, it, mock } from 'bun:test'

import { p256 } from '@noble/curves/nist.js'

import { publicKeyOf } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import { createIdentity, type Identity, sealMemberKeyForTouchId } from '../core/identity'
import type { Passwords } from './password'

// The Mac's enclave and its Touch ID dialog, mocked: tests never raise the real dialog.
let enclaveSecret = p256.utils.randomSecretKey()
let touchOutcome: 'touched' | TypeVaultError = 'touched'
let touches = 0
mock.module('../core/secure-enclave', () => ({
  createEnclaveKey: () => {
    enclaveSecret = p256.utils.randomSecretKey()
    return { handle: new Uint8Array([7]), publicKey: p256.getPublicKey(enclaveSecret, false) }
  },
  exchangeWithEnclave: (_env: unknown, _handle: Uint8Array, ephemeral: Uint8Array) => {
    touches += 1
    if (touchOutcome !== 'touched') return Promise.reject(touchOutcome)
    return Promise.resolve(p256.getSharedSecret(enclaveSecret, ephemeral).slice(1))
  },
}))
let fromStdin = false
mock.module('./password', () => ({
  passwords: () => ({ ask: () => Promise.resolve('') }),
  passwordsFromStdin: () => fromStdin,
}))

const { unlockHuman } = await import('./context')

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
  setPlatform('darwin')
  setTerminal(true)
})
afterEach(() => {
  if (platform !== undefined) Object.defineProperty(process, 'platform', platform)
  if (isTTY === undefined) delete (process.stdin as { isTTY?: boolean }).isTTY
  else Object.defineProperty(process.stdin, 'isTTY', isTTY)
})

it('opens the member key with a touch, without asking for the password', async () => {
  const key = await unlockHuman({}, alice, password)

  expect(await publicKeyOf(key)).toEqual(alicePublic)
  expect({ touches, asked }).toEqual({ touches: 1, asked: 0 })
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

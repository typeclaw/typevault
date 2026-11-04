import { expect, it } from 'bun:test'

import { generateSecretKeyCode, openWithPassword, sealWithPassword } from './password'

const plaintext = new Uint8Array([1, 2, 3])

it('opens with the same password and Secret Key', async () => {
  const secretKey = generateSecretKeyCode()
  const sealed = await sealWithPassword(plaintext, 'correct horse', secretKey)

  expect(await openWithPassword(sealed, 'correct horse', secretKey)).toEqual(plaintext)
})

it('refuses the right password with another Secret Key, and the wrong password', async () => {
  const secretKey = generateSecretKeyCode()
  const sealed = await sealWithPassword(plaintext, 'correct horse', secretKey)

  await expect(openWithPassword(sealed, 'correct horse', generateSecretKeyCode())).rejects.toMatchObject({
    code: 'denied',
  })
  await expect(openWithPassword(sealed, 'wrong', secretKey)).rejects.toMatchObject({ code: 'denied' })
})

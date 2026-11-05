import { expect, test } from 'bun:test'

import { seal } from '../core/crypto'
import { TypeVaultError } from '../core/errors'
import { parseEntryName } from '../core/naming'
import { promptFields } from './web-prompt'

const name = parseEntryName('typevault://openai')

async function submit(url: string, payloadName: string, status: number): Promise<void> {
  const page = await (await fetch(url)).text()
  const data = /<script type="application\/json" id="tv-data">(.*?)<\/script>/s.exec(page)?.[1] ?? ''
  const { recipients } = JSON.parse(data) as { recipients: string[] }
  const now = new Date().toISOString()
  const payload = {
    v: 1,
    name: payloadName,

    fields: { key: { type: 'secret' as const, value: 'sk-web-1' } },
    tags: [],
    created: now,
    rotated: now,
  }
  const ciphertext = await seal(recipients, new TextEncoder().encode(JSON.stringify(payload)))
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: new Uint8Array(ciphertext),
  })
  expect(response.status).toBe(status)
}

test('returns the fields typed on the page', async () => {
  // given
  let code = ''
  let submitted = Promise.resolve()
  // when
  const fields = await promptFields({ name, preset: 'api_key', tier: undefined }, (url, shown) => {
    code = shown
    submitted = submit(url, name, 204)
  })
  await submitted
  // then
  expect(fields).toEqual({ key: { type: 'secret' as const, value: 'sk-web-1' } })
  expect(code).toMatch(/^[A-Z2-9]{6}$/)
})

test('rejects a submission for another entry', async () => {
  let submitted = Promise.resolve()
  const fields = promptFields({ name, preset: 'api_key', tier: 'default' }, (url) => {
    submitted = submit(url, 'typevault://stripe', 422)
  })
  await expect(fields).rejects.toMatchObject({ code: 'tampered' })
  await submitted
})

test('propagates expiry without a submission and closes the listener', async () => {
  let url: string | undefined
  const fields = promptFields(
    { name, preset: 'api_key', tier: 'default' },
    (shown) => {
      url = shown
    },
    { ttlMs: 0 },
  )

  await expect(fields).rejects.toMatchObject({ code: 'expired' })
  if (url === undefined) throw new TypeVaultError('invalid', 'prompt URL was not shown')
  await expect(fetch(url)).rejects.toThrow()
})

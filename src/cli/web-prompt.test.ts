import { expect, test } from 'bun:test'

import { seal } from '../core/crypto'
import { parseEntryName } from '../core/naming'
import { promptFields } from './web-prompt'

const name = parseEntryName('tv://openai')

async function submit(url: string, payloadName: string): Promise<void> {
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
  expect(response.status).toBe(204)
}

test('returns the fields typed on the page', async () => {
  // given
  let code = ''
  // when
  const fields = await promptFields({ name, preset: 'api_key', tier: undefined }, (url, shown) => {
    code = shown
    void submit(url, name)
  })
  // then
  expect(fields).toEqual({ key: { type: 'secret' as const, value: 'sk-web-1' } })
  expect(code).toMatch(/^[A-Z2-9]{6}$/)
})

test('rejects a submission for another entry', async () => {
  const fields = promptFields({ name, preset: 'api_key', tier: 'default' }, (url) => void submit(url, 'tv://stripe'))
  await expect(fields).rejects.toMatchObject({ code: 'tampered' })
})

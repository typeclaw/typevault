import { afterAll, afterEach, expect, test } from 'bun:test'

import { Decrypter, generateIdentity, identityToRecipient } from 'age-encryption'

import { TypeVaultError } from '../core/errors'
import { parseEntryName, type Preset } from '../core/naming'
import { decodePayload } from '../core/payload'
import { startPromptServer, type PromptServer } from './index'

// WebView is optional and not yet declared by every supported version of @types/bun.
type BrowserView = {
  readonly navigate: (url: string) => Promise<unknown>
  readonly evaluate: (script: string) => Promise<unknown>
  readonly close: () => void
}
type BrowserRuntime = {
  readonly WebView: new (options: {
    readonly backend: string
    readonly width: number
    readonly height: number
  }) => BrowserView
}

function hasWebView(value: unknown): value is BrowserRuntime {
  return typeof value === 'object' && value !== null && 'WebView' in value && typeof value.WebView === 'function'
}

let browser: BrowserView | undefined
let server: PromptServer | undefined
if (hasWebView(Bun)) {
  try {
    browser = new Bun.WebView({ backend: 'chrome', width: 800, height: 900 })
    await browser.navigate('about:blank')
  } catch (error) {
    if (!(error instanceof Error)) throw error
    console.info(`Skipping optional WebView tests: ${error.message}`)
    browser?.close()
    browser = undefined
  }
}

afterEach(async () => {
  await server?.stop()
  server = undefined
})
afterAll(() => browser?.close())

async function openPage(preset: Preset | null = 'password') {
  const current = browser
  if (current === undefined) throw new TypeVaultError('unavailable', 'WebView is unavailable')
  const identities = await Promise.all([generateIdentity(), generateIdentity()])
  const recipients = await Promise.all(identities.map(identityToRecipient))
  server = await startPromptServer()
  const handle = server.open({
    name: 'stripe',
    ...(preset === null ? {} : { preset }),
    tier: 'trusted',
    reason: 'Set up the integration.',
    requester: 'test-grant',
    code: 'MAPLE-74',
    recipients,
    expiresAt: new Date('2100-01-01T00:00:00.000Z'),
  })
  const outcome = handle.done.then(
    (bytes) => ({ bytes }),
    (error: unknown) => ({ error }),
  )
  await current.navigate(handle.url)
  await current.evaluate(`new Promise((resolve, reject) => {
    const ready = () => document.querySelector('#fields input,#fields textarea') !== null;
    if (ready()) { resolve(true); return; }
    const timeout = setTimeout(() => { observer.disconnect(); reject(new TypeError('Fields did not render')); }, 10000);
    const observer = new MutationObserver(() => {
      if (ready()) { clearTimeout(timeout); observer.disconnect(); resolve(true); }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  })`)
  return { current, identities, handle, outcome, server }
}

async function submitPage(
  current: BrowserView,
  values: Readonly<Record<string, string>> = { username: 'test-user', password: 'test-browser-secret' },
): Promise<unknown> {
  return current.evaluate(`new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { observer.disconnect(); reject(new TypeError('Submission did not settle')); }, 10000);
    const finish = (state) => { clearTimeout(timeout); observer.disconnect(); resolve(state); };
    const observer = new MutationObserver(() => {
      if (!document.querySelector('#success').hidden) finish('success');
      else if (document.querySelector('#status').textContent) finish('error');
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true });
    for (const [name, value] of Object.entries(${JSON.stringify(values)})) document.getElementById('field-' + name).value = value;
    document.querySelector('form').requestSubmit();
  })`)
}

test.skipIf(browser === undefined)(
  'browser encrypts the exact payload for every recipient and clears secrets',
  async () => {
    const { current, identities, handle } = await openPage()
    expect(await submitPage(current)).toBe('success')
    const ciphertext = await handle.done
    expect(new TextDecoder().decode(ciphertext)).not.toContain('test-browser-secret')
    for (const identity of identities) {
      const decrypter = new Decrypter()
      decrypter.addIdentity(identity)
      const payload = decodePayload(await decrypter.decrypt(ciphertext))
      expect(payload).toEqual({
        v: 1,
        name: parseEntryName('stripe'),
        fields: {
          username: { type: 'text' as const, value: 'test-user' },
          password: { type: 'secret' as const, value: 'test-browser-secret' },
        },
        tags: [],
        created: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
        rotated: payload.created,
      })
    }
    expect(
      await current.evaluate(`Array.from(document.querySelectorAll('input,textarea'), input => input.value)`),
    ).toEqual(['', '', '', ''])
  },
)

test.skipIf(browser === undefined)('expired submission shows an error without clearing the inputs', async () => {
  const { current, handle, outcome, server } = await openPage()
  server.cancel(handle.id)
  await outcome
  expect(await submitPage(current)).toBe('error')
  expect(
    await current.evaluate(`({
    successHidden: document.querySelector('#success').hidden,
    password: document.querySelector('#field-password').value,
    submitDisabled: document.querySelector('#submit').disabled
  })`),
  ).toEqual({ successHidden: true, password: 'test-browser-secret', submitDisabled: false })
})

test.skipIf(browser === undefined)('browser keeps the line breaks of a note', async () => {
  const { current, identities, handle } = await openPage('note')
  expect(await submitPage(current, { $default: 'line one\nline two' })).toBe('success')
  const decrypter = new Decrypter()
  for (const identity of identities) decrypter.addIdentity(identity)
  const payload = decodePayload(await decrypter.decrypt(await handle.done))
  expect(payload.fields['$default']).toEqual({ type: 'secret', value: 'line one\nline two' })
})

for (const preset of [null, 'oauth'] as const) {
  test.skipIf(browser === undefined)(`browser stores the default field for preset ${preset ?? 'none'}`, async () => {
    const { current, identities, handle } = await openPage(preset)
    const value = preset === 'oauth' ? { access_token: 'test-access', refresh_token: 'test-refresh' } : 'test-secret'
    const typed = typeof value === 'string' ? value : JSON.stringify(value)
    expect(await submitPage(current, { $default: typed })).toBe('success')
    const decrypter = new Decrypter()
    for (const identity of identities) decrypter.addIdentity(identity)
    const payload = decodePayload(await decrypter.decrypt(await handle.done))
    expect(payload.fields['$default']?.type).toBe(preset === 'oauth' ? 'oauth' : 'secret')
    expect(payload.fields['$default']?.value).toEqual(value)
  })
}

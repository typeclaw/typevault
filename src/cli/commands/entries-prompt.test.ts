import { expect, it } from 'bun:test'

import { CLI, cli, env, project } from './entries.harness'

// Runs `set` on a terminal and types `typed` once the hidden prompt appears.
async function setViaPrompt(args: readonly string[], typed: string): Promise<{ code: number; output: string }> {
  const decoder = new TextDecoder()
  let output = ''
  let sent = false
  const proc = Bun.spawn([process.execPath, CLI, 'set', ...args], {
    cwd: project,
    env,
    terminal: {
      cols: 200,
      rows: 40,
      data: (terminal, data) => {
        output += decoder.decode(data)
        if (sent || !output.includes('Secret for ')) return
        sent = true
        terminal.write(`${typed}\r`)
      },
    },
  })
  return { code: await proc.exited, output }
}

const PROMPT_KEY = 'sk-prompt-test-1'

it.each([
  ['a new entry', ['typevault://typed-in', '--preset', 'api_key'], 'typevault://typed-in'],
  ['an existing entry', ['typevault://svc', '--preset', 'password'], 'typevault://svc#password'],
])('stores what was typed at the hidden --prompt for %s without echoing it', async (_, args, ref) => {
  // when
  const result = await setViaPrompt([...args, '--prompt'], PROMPT_KEY)

  // then
  expect(result.code).toBe(0)
  expect(result.output).toContain('Secret for ')
  expect(result.output).not.toContain(PROMPT_KEY)
  expect(await cli(['get', ref, '--reveal'])).toMatchObject({ code: 0, stdout: `${PROMPT_KEY}\n` })
})
it('keeps the other fields of an entry updated with --prompt', async () => {
  expect((await setViaPrompt(['typevault://svc', '--preset', 'password', '--prompt'], PROMPT_KEY)).code).toBe(0)
  expect(await cli(['get', 'typevault://svc#username'])).toMatchObject({ code: 0, stdout: 'alice\n' })
})
it('refuses --prompt for an existing SSH key without --preset and keeps the key', async () => {
  // given
  const key = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----'
  expect(await cli(['set', 'typevault://box', '--preset', 'ssh', '--stdin'], key)).toMatchObject({ code: 0 })

  // when
  const result = await setViaPrompt(['typevault://box', '--prompt'], '-----BEGIN OPENSSH PRIVATE KEY-----')

  // then
  expect(result.code).toBe(1)
  expect(result.output).toContain('not --prompt')
  expect(await cli(['get', 'typevault://box#private_key', '--reveal'])).toMatchObject({ code: 0, stdout: `${key}\n` })
})
it.each([
  ['without a terminal', ['typevault://p', '--prompt'], '--prompt needs a terminal'],
  ['with --stdin', ['typevault://p', '--prompt', '--stdin'], 'cannot be combined'],
  ['with --web', ['typevault://p', '--prompt', '--web'], 'cannot be combined'],
  ['for an SSH key', ['typevault://p', '--preset', 'ssh', '--prompt'], 'not --prompt'],
  ['for OAuth', ['typevault://p', '--preset', 'oauth', '--prompt'], 'not --prompt'],
])('refuses --prompt %s', async (_, args, message) => {
  const result = await cli(['set', ...args])
  expect(result.code).toBe(1)
  expect(result.stderr).toContain(message)
})

it('stores a value without a preset and resolves its bare reference', async () => {
  expect(await cli(['set', 'typevault://simple', '--stdin'], 'private-value')).toMatchObject({ code: 0 })
  const result = await cli(['get', 'typevault://simple', '--json', '--reveal'])
  expect(JSON.parse(result.stdout)).toEqual({ $default: { type: 'secret', value: 'private-value' } })
  expect(await cli(['get', 'typevault://simple', '--reveal'])).toMatchObject({ code: 0, stdout: 'private-value\n' })
})
it.each([
  ['empty --stdin', ['typevault://empty', '--stdin'], ''],
  ['no fields', ['typevault://empty', '--no-web'], undefined],
])('refuses %s', async (_, args, stdin) => {
  const result = await cli(['set', ...args], stdin)
  expect(result.code).toBe(1)
  expect(await cli(['get', 'typevault://empty', '--json', '--reveal'])).toMatchObject({ code: 1 })
})
it('lists fields when a bare login reference is ambiguous', async () => {
  const result = await cli(['get', 'typevault://svc', '--reveal'])
  expect(result.code).toBe(1)
  expect(result.stderr).toContain('svc has several fields, name one: username, password, PIN')
})
it('preserves field types during merges and accepts explicit types', async () => {
  expect(
    await cli(
      ['set', 'typevault://typed', '--stdin-json'],
      JSON.stringify({ custom: { type: 'text', value: 'first' } }),
    ),
  ).toMatchObject({ code: 0 })
  expect(await cli(['set', 'typevault://typed', '--stdin'], 'second')).toMatchObject({ code: 0 })
  const result = await cli(['get', 'typevault://typed', '--json'])
  expect(JSON.parse(result.stdout)).toEqual({ custom: { type: 'text', value: 'second' } })
})
it('writes arbitrary argv fields as text', async () => {
  expect(await cli(['set', 'typevault://text', '--field', 'label=public'])).toMatchObject({ code: 0 })
  expect(await cli(['get', 'typevault://text#label'])).toMatchObject({ code: 0, stdout: 'public\n' })
})
it.each([
  ['an existing secret field', ['typevault://svc', '--field', 'password=leaked']],
  ["a preset's secret field", ['typevault://login', '--preset', 'password', '--field', 'password=leaked']],
])('refuses %s as an argument', async (_, args) => {
  const result = await cli(['set', ...args, '--no-web'])
  expect(result.code).toBe(1)
  expect(result.stderr).toContain('pass "password" on stdin')
})
it('refuses --env for an entry with several fields and no default', async () => {
  const result = await cli(['set', 'typevault://svc', '--env', 'SVC_TOKEN'])
  expect(result.code).toBe(1)
  expect(result.stderr).toContain('--env names the default field')
})
it('replaces expired OAuth credentials without refreshing them first', async () => {
  // given credentials past expiry whose token endpoint refuses connections
  const stale = {
    access_token: 'stale',
    refresh_token: 'revoked',
    expires_at: '2000-01-01T00:00:00.000Z',
    token_url: 'http://127.0.0.1:9/token',
  }
  expect(await cli(['set', 'typevault://google', '--preset', 'oauth', '--stdin'], JSON.stringify(stale))).toMatchObject(
    {
      code: 0,
    },
  )

  // when they are replaced
  const replacement = JSON.stringify({ access_token: 'replacement' })
  const result = await cli(['set', 'typevault://google', '--replace', '--preset', 'oauth', '--stdin'], replacement)

  // then the write succeeds and holds only the new token
  expect(result).toMatchObject({ code: 0 })
  expect(await cli(['get', 'typevault://google', '--reveal'])).toMatchObject({ code: 0, stdout: 'replacement\n' })
})
it('rejects malformed OAuth stdin and accepts typed fields through stdin JSON', async () => {
  expect(await cli(['set', 'typevault://oauth', '--preset', 'oauth', '--stdin'], 'token')).toMatchObject({ code: 1 })
  const fields = { session: { type: 'oauth', value: { access_token: 'access', refresh_token: 'refresh' } } }
  expect(await cli(['set', 'typevault://oauth', '--stdin-json'], JSON.stringify(fields))).toMatchObject({ code: 0 })
  expect(await cli(['get', 'typevault://oauth#session.refresh_token', '--reveal'])).toMatchObject({
    code: 0,
    stdout: 'refresh\n',
  })
})

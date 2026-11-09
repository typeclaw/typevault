import { expect, it } from 'bun:test'

import { cli, PASSWORD, PIN, setViaPage, expectNothingDerivedFrom } from './entries.harness'

it.each([
  ['the password field', 'typevault://svc#password', PASSWORD],
  ['a custom field', 'typevault://svc#PIN', PIN],
])('refuses to print %s without --reveal and leaks nothing about it', async (_, ref, secret) => {
  // when
  const result = await cli(['get', ref])

  // then
  expect(result.code).not.toBe(0)
  expect(result.stdout).toBe('')
  expect(result.stderr).toContain('--reveal')
  expectNothingDerivedFrom(result.stderr, secret)
})

it('prints a secret field with --reveal', async () => {
  expect(await cli(['get', 'typevault://svc#PIN', '--reveal'])).toMatchObject({ code: 0, stdout: `${PIN}\n` })
})

it('prints a plain field without --reveal', async () => {
  expect(await cli(['get', 'typevault://svc#username'])).toMatchObject({ code: 0, stdout: 'alice\n' })
})

it('redacts secret fields in --json without --reveal and leaks nothing about them', async () => {
  // when
  const result = await cli(['get', 'typevault://svc', '--json'])

  // then
  expect(result.code).toBe(0)
  expect(JSON.parse(result.stdout)).toEqual({
    username: { type: 'text', value: 'alice' },
    password: { type: 'secret', value: '<redacted>' },
    PIN: { type: 'secret', value: '<redacted>' },
  })
  for (const secret of [PASSWORD, PIN]) expectNothingDerivedFrom(result.stdout + result.stderr, secret)
})

const WEB_KEY = 'sk-web-test-1'

it('prompts on the page for a new entry from a terminal and stores what was typed there', async () => {
  // when
  const result = await setViaPage(['typevault://web', '--preset', 'api_key'], {
    tty: true,
    fields: { $default: WEB_KEY },
  })

  // then
  expect(result).toMatchObject({ code: 0, prompted: true })
  expect(result.output).not.toContain(WEB_KEY)
  expect(await cli(['get', 'typevault://web', '--reveal'])).toMatchObject({ code: 0, stdout: `${WEB_KEY}\n` })
})

it('prompts with --web without a terminal', async () => {
  // when
  const result = await setViaPage(['typevault://web', '--preset', 'api_key', '--web'], {
    tty: false,
    fields: { $default: WEB_KEY },
  })

  // then
  expect(result).toMatchObject({ code: 0, prompted: true })
  expect(result.output).not.toContain(WEB_KEY)
  expect(await cli(['get', 'typevault://web', '--reveal'])).toMatchObject({ code: 0, stdout: `${WEB_KEY}\n` })
})

it.each([
  ['an existing entry', ['typevault://svc', '--field', 'username=bob'], undefined],
  ['--stdin', ['typevault://web', '--preset', 'api_key', '--stdin'], WEB_KEY],
])('does not prompt from a terminal with %s', async (_, args, typed) => {
  expect(await setViaPage(args, { tty: true, typed })).toMatchObject({ code: 0, prompted: false })
})
it('refuses a new entry with --no-web and no fields without prompting', async () => {
  expect(await setViaPage(['typevault://web', '--preset', 'api_key', '--no-web'], { tty: true })).toMatchObject({
    code: 1,
    prompted: false,
  })
})

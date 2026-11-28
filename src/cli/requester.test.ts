import { afterEach, expect, it } from 'bun:test'

import { defineCommand } from 'citty'

import { globalLayout, localLayout } from '../core/layout'
import { commandIs, commandPath, programIn, promptHeader, touchIdReason, unlockRequest } from './requester'

afterEach(() => commandIs({ words: [], args: [] }))

const ps = [
  '    1     0 /sbin/launchd',
  '  100     1 /Applications/Ghostty.app/Contents/MacOS/ghostty',
  '  200   100 -zsh',
  '  300   200 /opt/homebrew/bin/claude --resume',
  '  400   300 /bin/zsh -c typevault get github/token',
  '  500   200 node /usr/local/lib/node_modules/@openai/codex/bin/codex.js',
  '  600   500 /usr/bin/env bash -lc typevault run -- npm test',
  '  700   200 node -e require("fs").readFileSync("/srv/secret")',
  '  800   200 python3 -c import os; os.system("typevault get x")',
  '  900   200 node /usr/local/bin/claude',
  '  920   200 bun --define K /srv/SENTINEL.js /srv/app.ts',
  `  710   200 node -e"console.log( 'secret/path.js' )"`,
  '  810   200 python3 -cimport os; os.system("/srv/secret.py")',
  '  910   200 node --require ./hook.js /srv/app.js',
].join('\n')

it('names the nearest program above the shells and launchers that ran typevault', () => {
  expect(programIn(ps, 400)).toBe('claude')
  expect(programIn(ps, 600)).toBe('codex')
  expect(programIn(ps, 200)).toBe('ghostty')
  expect(programIn(ps, 900)).toBe('claude')
})

it('names an interpreter running inline code by the interpreter, never by the code', () => {
  expect(programIn(ps, 700)).toBe('node')
  expect(programIn(ps, 800)).toBe('python3')
  expect(programIn(ps, 710)).toBe('node')
  expect(programIn(ps, 810)).toBe('python3')
  expect(programIn(ps, 910)).toBe('node')
})

it('names an interpreter given any option before its script by the interpreter, never by an option value', () => {
  expect(programIn(ps, 920)).toBe('bun')
})

it('names a command only by words that resolve to commands, never by an argument', () => {
  const leaf = defineCommand({ meta: { name: 'leaf' } })
  const tier = defineCommand({ args: { as: { type: 'string' } }, subCommands: { add: leaf } })
  const main = { subCommands: { set: leaf, run: leaf, tier } }

  const words = (args: readonly string[]): readonly string[] => commandPath(main, args).words

  expect(words(['set', 'svc', '--field', 'password=x'])).toEqual(['set'])
  expect(words(['tier', 'add', 'ops'])).toEqual(['tier', 'add'])
  expect(words(['run', '--only', 'x'])).toEqual(['run'])
  expect(words(['svc'])).toEqual([])
  expect(words(['--', 'run'])).toEqual([])
})

it('takes the reason only as citty parses it for a command that declares --reason', async () => {
  const set = defineCommand({ args: { name: { type: 'positional' }, field: { type: 'string' } } })
  const run = defineCommand({ args: { reason: { type: 'string' } } })
  const main = { subCommands: { set, run } }
  const reasonOf = async (args: readonly string[]): Promise<string | undefined> => {
    commandIs(commandPath(main, args))
    return (await unlockRequest('unlock your vault', undefined)).reason
  }

  expect(await reasonOf(['run', '--reason', 'deploy'])).toBe('deploy')
  expect(await reasonOf(['set', '--reason', 'svc'])).toBeUndefined()
  expect(await reasonOf(['set', 'svc', '--field', '--reason=SENTINEL'])).toBeUndefined()
  expect(await reasonOf(['set', 'svc', '--field', 'k=v', '--reason=add the key'])).toBeUndefined()
  expect(await reasonOf(['run', '--reason'])).toBeUndefined()
})

it('finds the command past options before it, as citty does when it dispatches', () => {
  const leaf = defineCommand({ meta: { name: 'leaf' } })
  const tier = defineCommand({ args: { as: { type: 'string' } }, subCommands: { add: leaf } })
  const main = { subCommands: { run: leaf, tier } }

  expect(commandPath(main, ['--reason=x', 'run', '--', 'psql']).words).toEqual(['run'])
  expect(commandPath(main, ['tier', '--as', 'add', 'add']).words).toEqual(['tier', 'add'])
})

it("takes the command's own --reason, not one after `--` that belongs to run's child", async () => {
  const main = { subCommands: { run: defineCommand({ args: { reason: { type: 'string' } } }), ls: defineCommand({}) } }
  for (const given of [['--reason', 'deploy to staging'], ['--reason=deploy to staging']]) {
    commandIs(commandPath(main, ['run', ...given, '--', 'echo', '--reason', 'x']))

    const request = await unlockRequest('unlock your vault', undefined)

    expect(request).toMatchObject({ command: 'typevault run -- echo', reason: 'deploy to staging' })
  }
  commandIs(commandPath(main, ['ls']))
  expect((await unlockRequest('unlock your vault', undefined)).reason).toBeUndefined()
})

it('keeps every outside field to one printable line, so none can add or redraw a prompt line', () => {
  const request = {
    purpose: 'unlock your vault',
    program: 'cl\naude\u001b[2K',
    vault: 'proj\u2028ect',
    where: '/tmp/a\nb',
    command: 'typevault\rfake',
    reason: 'run\r\nPassword for alice: \u202e',
  }

  const header = promptHeader(request)

  expect(header.split('\n')).toHaveLength(4)
  for (const line of [...header.split('\n'), touchIdReason(request)]) {
    expect(line).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u)
  }
})

it("names the vault being unlocked, not the caller's directory, and says when it is the global one", async () => {
  const env = { HOME: '/srv/alice', TYPEVAULT_DIR: '/srv/alice/.typevault' }

  const global = await unlockRequest('unlock your vault', globalLayout(env))
  const project = await unlockRequest('unlock your vault', localLayout('/work/my-project/.typevault', env))

  expect([global.vault, project.vault]).toEqual(['the global vault', 'my-project'])
})

it("leads the Touch ID dialog with the caller's reason, always followed by who gave it and where", () => {
  const request = { purpose: 'unlock your vault', program: 'claude', vault: 'foo', where: '~/work/foo', command: 'ls' }

  expect(touchIdReason({ ...request, reason: 'run migrations' })).toStartWith('run migrations ')
  expect(touchIdReason({ ...request, reason: 'run migrations' })).toEndWith(' claude in foo')
  expect(touchIdReason(request)).toStartWith('unlock your vault ')
})

it('never lets a reason hide an owner change, which the same touch approves', () => {
  const request = {
    purpose: 'approve an owner change',
    vault: 'foo',
    where: '~/work/foo',
    command: 'typevault tier add',
  }

  for (const text of [
    touchIdReason({ ...request, reason: 'read the docs' }),
    promptHeader({ ...request, reason: 'read the docs' }),
  ]) {
    expect(text).toContain('approve an owner change to read the docs')
  }
})

it('names nothing when the chain leaves the listing or reaches launchd', () => {
  expect(programIn(ps, 999)).toBeUndefined()
  expect(programIn('    1     0 /sbin/launchd\n   50     1 -zsh', 50)).toBeUndefined()
})

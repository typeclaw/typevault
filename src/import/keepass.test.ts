import { beforeAll, expect, test } from 'bun:test'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Consts, Credentials, Int64, Kdbx, ProtectedValue, VarDictionary } from 'kdbxweb'

import { importFrom } from './index'
import { parseKeepass } from './keepass'

let fixture: Uint8Array<ArrayBuffer>

function database(kdf: string): Kdbx {
  const db = Kdbx.create(new Credentials(ProtectedValue.fromString('test-password')), 'Root')
  db.setKdf(kdf)
  db.header.kdfParameters?.set('M', VarDictionary.ValueType.UInt64, Int64.from(1024 * 32))
  db.header.kdfParameters?.set('I', VarDictionary.ValueType.UInt64, Int64.from(1))
  db.header.kdfParameters?.set('P', VarDictionary.ValueType.UInt32, 1)
  return db
}

beforeAll(async () => {
  const db = database(Consts.KdfId.Argon2d)
  const root = db.getDefaultGroup()
  const work = db.createGroup(root, 'Work / Team')
  const nested = db.createGroup(work, 'Bots')
  const login = db.createEntry(work)
  login.fields.set('Title', 'GitHub')
  login.fields.set('UserName', ProtectedValue.fromString('user@example.com'))
  login.fields.set('Password', ProtectedValue.fromString('hunter2'))
  login.fields.set('URL', 'https://example.com:8443/path?q=secret')
  login.fields.set('otp', ProtectedValue.fromString('otpauth://totp/Example?secret=SEED'))
  login.fields.set('Notes', 'not a password field')
  login.tags = ['agent']
  const duplicate = db.createEntry(work)
  duplicate.fields.set('Title', 'GitHub')
  duplicate.fields.set('Password', 'second')
  const third = db.createEntry(work)
  third.fields.set('Title', 'GitHub')
  third.fields.set('Password', 'third')
  const note = db.createEntry(root)
  note.fields.set('Title', 'Memo')
  note.fields.set('Notes', ProtectedValue.fromString('private note'))
  const local = db.createEntry(nested)
  local.fields.set('Title', 'Local')
  local.fields.set('URL', 'ftp://example.com')
  const unsupported = db.createEntry(root)
  unsupported.fields.set('Title', 'Card')
  unsupported.fields.set('CardNumber', ProtectedValue.fromString('fake-card'))
  const deleted = db.createEntry(work)
  deleted.fields.set('Title', 'Deleted')
  deleted.fields.set('Password', 'recycled-secret')
  db.remove(deleted)
  const recycle = db.meta.recycleBinUuid && db.getGroup(db.meta.recycleBinUuid)
  if (recycle) {
    const child = db.createGroup(recycle, 'Deleted Group')
    db.createEntry(child).fields.set('Password', 'recycled-child-secret')
  }
  fixture = new Uint8Array(await db.save())
})

test('KeePass maps protected login and note fields, immediate groups, origins, and excludes recycled subtrees', async () => {
  const result = await parseKeepass(fixture, 'test-password')
  expect(result.entries.map((entry) => [entry.name, entry.fields, entry.origin])).toEqual([
    ['memo', { $default: { type: 'secret', value: 'private note' } }, undefined],
    [
      'github/work-team',
      {
        username: { type: 'text', value: 'user@example.com' },
        password: { type: 'secret', value: 'hunter2' },
        url: { type: 'text', value: 'https://example.com:8443/path?q=secret' },
        totp: { type: 'totp', value: 'otpauth://totp/Example?secret=SEED' },
      },
      'https://example.com:8443',
    ],
    ['github/work-team-2', { password: { type: 'secret', value: 'second' } }, undefined],
    ['github/work-team-3', { password: { type: 'secret', value: 'third' } }, undefined],
    ['local/bots', { url: { type: 'text', value: 'ftp://example.com' } }, undefined],
  ])
  expect(result.entries[1]?.tags).toEqual(['agent'])
  const sources = result.entries.map((entry) => entry.source ?? '')
  expect(sources.every((source) => /^keepass:.+/.test(source))).toBe(true)
  expect(new Set(sources).size).toBe(sources.length)
  expect(result.warnings).toHaveLength(3)
  expect(result.warnings.join()).toContain('"github/work-team"')
  expect(result.warnings.join()).toContain('"github/work-team-3"')
  expect(result.warnings.join()).not.toContain('hunter2')
})

test('KeePass dispatcher decrypts a file without modifying its bytes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'typevault-keepass-'))
  try {
    const path = join(directory, 'fixture.kdbx')
    await writeFile(path, fixture)
    const result = await importFrom('keepass', { path, password: 'test-password' })
    expect<readonly string[]>(result.entries.map((entry) => entry.name)).toEqual([
      'memo',
      'github/work-team',
      'github/work-team-2',
      'github/work-team-3',
      'local/bots',
    ])
    expect(new Uint8Array(await readFile(path))).toEqual(fixture)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('KeePass supports Argon2id databases and an empty but supplied password', async () => {
  const db = database(Consts.KdfId.Argon2id)
  db.credentials = new Credentials(ProtectedValue.fromString(''))
  const entry = db.createEntry(db.getDefaultGroup())
  entry.fields.set('Title', 'Example')
  entry.fields.set('Password', 'hunter2')
  const result = await parseKeepass(new Uint8Array(await db.save()), '')
  expect(result.entries[0]?.fields).toEqual({ password: { type: 'secret', value: 'hunter2' } })
})

test('KeePass reports missing passwords as invalid', async () => {
  await expect(parseKeepass(fixture)).rejects.toMatchObject({ code: 'invalid' })
})

test('KeePass reports incorrect passwords as denied', async () => {
  await expect(parseKeepass(fixture, 'wrong-password')).rejects.toMatchObject({ code: 'denied' })
})

test.each([new Uint8Array(), new Uint8Array([0, 1, 2, 3, 4])])(
  'KeePass rejects malformed databases with typed errors',
  async (bytes) => {
    await expect(parseKeepass(bytes, 'test-password')).rejects.toMatchObject({ code: 'invalid' })
  },
)

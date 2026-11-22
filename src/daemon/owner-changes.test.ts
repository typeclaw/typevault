import { expect, it } from 'bun:test'

import { OwnerChanges } from './owner-changes'

const deferred = () => Promise.withResolvers<string>()

it('runs changes one at a time, in the order they were admitted', async () => {
  // given two admitted changes, the first still running
  const changes = new OwnerChanges<string>()
  const first = deferred()
  const started: string[] = []
  const a = changes.admit('session', async () => {
    started.push('a')
    return first.promise
  })
  const b = changes.admit('session', async () => {
    started.push('b')
    return 'b done'
  })

  // then the second waits for the first
  expect(await changes.wait('session', b, 0)).toEqual({ done: false })
  expect(started).toEqual(['a'])

  // and once the first finishes, both report their outcomes
  first.resolve('a done')
  expect(await changes.wait('session', a, 1_000)).toEqual({ done: true, result: 'a done' })
  expect(await changes.wait('session', b, 1_000)).toEqual({ done: true, result: 'b done' })
})

it("reports a change's error to whoever collects it, and only to its own session", async () => {
  const changes = new OwnerChanges<string>()
  const id = changes.admit('session', async () => {
    throw new Error('rotation failed')
  })
  await expect(changes.wait('other', id, 1_000)).rejects.toMatchObject({ code: 'not_found' })
  await expect(changes.wait('session', id, 1_000)).rejects.toThrow('rotation failed')
})

it('stops by admitting nothing new, starting nothing queued, and waiting for the running change', async () => {
  // given a running change and one queued behind it
  const changes = new OwnerChanges<string>()
  const running = deferred()
  const started: string[] = []
  const a = changes.admit('session', async () => {
    started.push('a')
    return running.promise
  })
  const b = changes.admit('session', async () => {
    started.push('b')
    return 'b done'
  })
  expect(await changes.wait('session', a, 0)).toEqual({ done: false })
  expect(started).toEqual(['a'])

  // when it stops, nothing new is admitted, and stopping waits for the running change
  let stopped = false
  const stopping = changes.stop().then(() => {
    stopped = true
  })
  expect(() => changes.admit('session', async () => 'late')).toThrow('nothing changed')
  expect(await changes.wait('session', a, 0)).toEqual({ done: false })
  expect(stopped).toBe(false)

  // then the running change finishes, the queued one never starts, and stopping completes
  running.resolve('a done')
  await stopping
  expect(await changes.wait('session', a, 0)).toEqual({ done: true, result: 'a done' })
  await expect(changes.wait('session', b, 0)).rejects.toThrow('nothing changed')
  expect(started).toEqual(['a'])
})

import { afterEach, beforeEach, expect, it } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { z } from 'zod'

import { randomToken } from '../core/crypto'
import { OwnerChanges, readOutcome } from './owner-changes'

let run: string
const deferred = () => Promise.withResolvers<string>()
const queue = () => new OwnerChanges(run, z.string())
const id = () => randomToken(16)

beforeEach(() => {
  run = mkdtempSync(join(tmpdir(), 'tvo-'))
})
afterEach(() => rmSync(run, { recursive: true, force: true }))

it('runs changes one at a time, in the order they were admitted', async () => {
  // given two admitted changes, the first still running
  const changes = queue()
  const first = deferred()
  const started: string[] = []
  const [a, b] = [id(), id()]
  changes.admit(a, async () => {
    started.push('a')
    return first.promise
  })
  changes.admit(b, async () => {
    started.push('b')
    return 'b done'
  })

  // then the second waits for the first
  expect(await changes.wait(b, 0)).toEqual({ done: false })
  expect(started).toEqual(['a'])

  // and once the first finishes, both report their outcomes
  first.resolve('a done')
  expect(await changes.wait(a, 1_000)).toEqual({ done: true, result: 'a done' })
  expect(await changes.wait(b, 1_000)).toEqual({ done: true, result: 'b done' })
})

it('runs a change admitted twice under one id once', async () => {
  const changes = queue()
  const change = id()
  let runs = 0
  const run = async () => `run ${++runs}`
  changes.admit(change, run)
  changes.admit(change, run)
  expect(await changes.wait(change, 1_000)).toEqual({ done: true, result: 'run 1' })
  changes.admit(change, run)
  expect(await changes.wait(change, 1_000)).toEqual({ done: true, result: 'run 1' })
  expect(runs).toBe(1)
})

it('keeps an outcome readable after it was collected, and after its daemon is gone', async () => {
  // given a change that finished, and one that failed
  const changes = queue()
  const [done, failed] = [id(), id()]
  changes.admit(done, async () => 'committed')
  changes.admit(failed, async () => {
    throw new Error('rotation failed')
  })
  await changes.wait(done, 1_000)
  await expect(changes.wait(failed, 1_000)).rejects.toThrow('rotation failed')

  // then each can be collected again, by this queue and from the run directory
  expect(await changes.wait(done, 0)).toEqual({ done: true, result: 'committed' })
  expect(await changes.wait(done, 0)).toEqual({ done: true, result: 'committed' })
  expect(await queue().wait(done, 0)).toEqual({ done: true, result: 'committed' })
  expect(readOutcome(run, done, z.string())).toBe('committed')
  expect(() => readOutcome(run, failed, z.string())).toThrow('internal daemon error')
  await expect(queue().wait(id(), 0)).rejects.toMatchObject({ code: 'not_found' })
})

it('stops by admitting nothing new, starting nothing queued, and waiting for the running change', async () => {
  // given a running change and one queued behind it
  const changes = queue()
  const running = deferred()
  const started: string[] = []
  const [a, b] = [id(), id()]
  changes.admit(a, async () => {
    started.push('a')
    return running.promise
  })
  changes.admit(b, async () => {
    started.push('b')
    return 'b done'
  })
  expect(await changes.wait(a, 0)).toEqual({ done: false })

  // when it stops, admission closes at once, and stopping waits for the running change
  let stopped = false
  const stopping = changes.stop().then(() => {
    stopped = true
  })
  expect(() => changes.admit(id(), async () => 'late')).toThrow('nothing changed')
  expect(await changes.wait(a, 0)).toEqual({ done: false })
  expect(stopped).toBe(false)

  // then the running change finishes, the queued one never starts, and stopping completes
  running.resolve('a done')
  await stopping
  expect(await changes.wait(a, 0)).toEqual({ done: true, result: 'a done' })
  await expect(changes.wait(b, 0)).rejects.toThrow('nothing changed')
  expect(started).toEqual(['a'])
})

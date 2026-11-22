import type { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import type { Layout } from '../core/layout'
import { isDaemonAlive } from '../daemon/client'
import type { LiveAccess } from '../daemon/live-access'
import { OWNER_CHANGE_KEEP_MS, readOutcome, settledResult } from '../daemon/owner-changes'
import { AdminResultSchema, AdmittedSchema, AdminWaitedSchema } from '../daemon/protocol'

const TRANSPORT_RETRIES = 5

type Outcome = z.infer<typeof AdminResultSchema>

// The client wraps what the transport threw (fetch, a timeout, a cut-off body); an error of our own wrapping another is not.
const lostInTransport = (error: unknown): error is TypeVaultError =>
  error instanceof TypeVaultError && error.cause instanceof Error && !(error.cause instanceof TypeVaultError)

/**
 * Admits an owner change under the caller's own id and polls until its outcome arrives. After an answer lost in
 * transport, the id's receipt decides what happened before anything is sent again: a change the daemon already took
 * (which may have rotated the owner or outlived the session since) is collected, and only a definite miss within the
 * daemon's retry window is sent again. A change that failed is reported with its own error, never sent again. Once the
 * daemon is gone, the outcome it kept in the run directory answers. Without either, the outcome is unknown, never
 * reported as a failure.
 */
export async function ownerChange(
  access: Pick<LiveAccess, 'call'>,
  layout: Pick<Layout, 'run' | 'agentSocket'>,
  body: { readonly change: string },
): Promise<Outcome> {
  const { change } = body
  const sentAt = Date.now()
  let admission: 'unsent' | 'unsure' | 'admitted' = 'unsent'
  let resent = false
  let sentOnce = false
  const unknown = (cause: unknown) =>
    new TypeVaultError(
      'unavailable',
      "the session stopped answering, so this owner change's outcome is unknown: check the vault before running it again",
      { cause },
    )
  for (let failures = 0; ;) {
    try {
      if (admission === 'unsure') {
        const waited = await access.call('/v1/admin/wait', { change }, AdminWaitedSchema)
        if (waited.state === 'unknown') {
          if (resent || Date.now() - sentAt >= OWNER_CHANGE_KEEP_MS) throw unknown(undefined)
          admission = 'unsent'
        } else {
          admission = 'admitted'
          if (waited.state !== 'running') return settledResult(waited)
          failures = 0
          continue
        }
      }
      if (admission === 'unsent') {
        const resending = sentOnce
        sentOnce = true
        admission = 'unsure'
        try {
          await access.call('/v1/admin', body, AdmittedSchema)
        } catch (error) {
          // A refused resend says nothing of the original request, which may have been admitted late and changed what the
          // daemon accepts (an owner rotation): its receipt decides, and the resend is not tried again.
          if (!resending || lostInTransport(error)) throw error
          resent = true
          continue
        }
        admission = 'admitted'
      }
      const waited = await access.call('/v1/admin/wait', { change }, AdminWaitedSchema)
      // An admitted change has a receipt for as long as its window lasts: without one, nothing can say what happened.
      if (waited.state === 'unknown') throw unknown(undefined)
      if (waited.state !== 'running') return settledResult(waited)
      failures = 0
    } catch (error) {
      if (!lostInTransport(error)) throw error
      const kept = readOutcome(layout.run, change, AdminResultSchema)
      if (kept !== undefined) return settledResult(kept)
      if (++failures >= TRANSPORT_RETRIES || !(await isDaemonAlive(layout.agentSocket))) {
        // A draining daemon may have saved the outcome and closed while it was probed.
        const late = readOutcome(layout.run, change, AdminResultSchema)
        if (late !== undefined) return settledResult(late)
        throw unknown(error)
      }
    }
  }
}

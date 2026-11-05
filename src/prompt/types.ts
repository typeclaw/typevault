import type { TypeVaultError } from '../core/errors'
import type { Preset } from '../core/naming'

export type PromptView = {
  readonly name: string
  readonly preset?: Preset | undefined
  readonly tier: string
  readonly reason: string
  readonly requester: string
  readonly code: string
  readonly recipients: readonly string[]
  readonly expiresAt: Date
}

export type PromptHandle = {
  readonly id: string
  readonly url: string
  readonly done: Promise<Uint8Array>
  readonly accept: () => Promise<void>
  readonly reject: (error: TypeVaultError) => Promise<void>
}

export type PromptServer = {
  readonly port: number
  readonly open: (view: PromptView, options?: { readonly validate?: boolean }) => PromptHandle
  readonly cancel: (id: string) => void
  readonly stop: () => Promise<void>
}

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
}

export type PromptServer = {
  readonly port: number
  readonly open: (view: PromptView) => PromptHandle
  readonly cancel: (id: string) => void
  readonly stop: () => Promise<void>
}

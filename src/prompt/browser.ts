import { Encrypter } from 'age-encryption'
import { z } from 'zod'

import { TypeVaultError } from '../core/errors'
import { PRESETS, parseEntryName, parsePreset, type Field, type FieldType } from '../core/naming'
import { FieldSchema } from '../core/payload'
import type { EntryPayload } from '../core/payload'

const ViewSchema = z.object({
  name: z.string(),
  preset: z.string().optional(),
  recipients: z.array(z.string()).min(1),
})

function requiredElement<T extends HTMLElement>(selector: string, kind: { new (): T }): T {
  const element = document.querySelector(selector)
  if (element instanceof kind) return element
  throw new TypeVaultError('invalid', 'The request page is incomplete. Open a new request.')
}

const ACRONYMS = new Set(['url', 'totp', 'id', 'api', 'ssh'])

const form = requiredElement('#prompt', HTMLFormElement)
const fieldsRoot = requiredElement('#fields', HTMLDivElement)
const status = requiredElement('#status', HTMLParagraphElement)
const submit = requiredElement('#submit', HTMLButtonElement)
const success = requiredElement('#success', HTMLElement)

function initialize(): void {
  const data = requiredElement('#tv-data', HTMLScriptElement)
  const view = ViewSchema.parse(JSON.parse(data.textContent ?? ''))
  const preset =
    view.preset === undefined
      ? { fields: { $default: 'secret' } as const, input: '$default' }
      : PRESETS[parsePreset(view.preset)]
  const name = parseEntryName(view.name)
  const inputs: (HTMLInputElement | HTMLTextAreaElement)[] = []
  const types: Readonly<Record<string, FieldType>> = preset.fields
  for (const [field, type] of Object.entries(types)) {
    const secret = type !== 'text'
    const wrapper = document.createElement('div')
    wrapper.className = 'field'
    const label = document.createElement('label')
    label.htmlFor = `field-${field}`
    const fieldName = (field === '$default' ? (type === 'oauth' ? 'OAuth JSON' : 'Secret') : field)
      .split('_')
      .map((word) => (ACRONYMS.has(word) ? word.toUpperCase() : word))
      .join(' ')
      .replace(/^./, (char) => char.toUpperCase())
    label.textContent = fieldName
    const row = document.createElement('div')
    row.className = 'input-row'
    const input =
      type === 'oauth' ||
      (field === '$default' && view.preset === 'note') ||
      ['text', 'private_key', 'public_key'].includes(field)
        ? document.createElement('textarea')
        : document.createElement('input')
    input.id = label.htmlFor
    input.name = field
    input.autocomplete = 'off'
    input.spellcheck = false
    input.required = field === preset.input
    if (!input.required) {
      const optional = document.createElement('span')
      optional.className = 'optional'
      optional.textContent = 'Optional'
      label.append(optional)
    }
    if (input instanceof HTMLInputElement) input.type = secret ? 'password' : 'text'
    else if (secret) input.classList.add('concealed')
    inputs.push(input)
    row.append(input)
    if (secret) {
      const toggle = document.createElement('button')
      toggle.type = 'button'
      toggle.className = 'toggle'
      toggle.textContent = 'Show'
      toggle.setAttribute('aria-label', `Show ${fieldName.toLowerCase()}`)
      toggle.setAttribute('aria-pressed', 'false')
      toggle.addEventListener('click', () => {
        const show = toggle.getAttribute('aria-pressed') !== 'true'
        if (input instanceof HTMLInputElement) input.type = show ? 'text' : 'password'
        else input.classList.toggle('concealed', !show)
        toggle.setAttribute('aria-pressed', String(show))
        toggle.setAttribute('aria-label', `${show ? 'Hide' : 'Show'} ${fieldName.toLowerCase()}`)
        toggle.textContent = show ? 'Hide' : 'Show'
      })
      row.append(toggle)
    }
    wrapper.append(label, row)
    fieldsRoot.append(wrapper)
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    if (submit.disabled) return
    submit.disabled = true
    submit.textContent = 'Encrypting...'
    status.textContent = ''
    try {
      const now = new Date().toISOString()
      const payload: EntryPayload = {
        v: 1,
        name,
        fields: Object.fromEntries(
          inputs
            .filter((input) => input.value !== '')
            .map((input): [string, Field] => {
              const type = types[input.name] ?? 'secret'
              switch (type) {
                case 'oauth':
                  return [input.name, FieldSchema.parse({ type, value: JSON.parse(input.value) })]
                case 'secret':
                case 'text':
                case 'totp':
                  return [input.name, { type, value: input.value }]
                default:
                  throw new TypeVaultError('invalid', `unexpected field type ${type satisfies never}`)
              }
            }),
        ),
        tags: [],
        created: now,
        rotated: now,
      }
      const encrypter = new Encrypter()
      for (const recipient of view.recipients) encrypter.addRecipient(recipient)
      const ciphertext = await encrypter.encrypt(new TextEncoder().encode(JSON.stringify(payload)))
      const response = await fetch(location.pathname, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: new Uint8Array(ciphertext),
        credentials: 'omit',
        redirect: 'error',
      })
      if (response.status !== 204) {
        throw new TypeVaultError(
          response.status === 410 ? 'expired' : 'unavailable',
          response.status === 410
            ? 'This request expired or was already used. Ask the agent for a new link.'
            : `Submission failed (${response.status}). Your secret was not accepted.`,
        )
      }
      for (const input of inputs) input.value = ''
      form.reset()
      form.hidden = true
      success.hidden = false
      success.focus()
    } catch (error) {
      status.textContent =
        error instanceof TypeVaultError
          ? error.message
          : 'Could not encrypt or submit your secret. Check your connection and try again.'
    } finally {
      submit.disabled = false
      submit.textContent = 'Encrypt and submit'
    }
  })
}

try {
  initialize()
} catch (error) {
  status.textContent =
    error instanceof TypeVaultError ? error.message : 'This request could not be loaded. Ask the agent for a new link.'
  submit.disabled = true
}

// Renders the real secret request page to light and dark PNGs next to it: bun docs/diagrams/prompt.ts
import { join } from 'node:path'

import { startPromptServer } from '../../src/prompt'

const dir = import.meta.dir
const scale = 2
const width = 640

const server = await startPromptServer()
try {
  const { url, done } = server.open({
    name: 'resend',
    preset: 'api_key',
    tier: 'default',
    reason: 'send the weekly digest',
    requester: 'claude in ~/acme/newsletter',
    code: 'PLUM-4821',
    recipients: ['age1example'],
    expiresAt: new Date(Date.now() + 10 * 60_000),
  })
  done.catch(() => {})
  for (const theme of ['light', 'dark']) {
    await using view = new Bun.WebView({ width: width * scale, height: 1200 * scale })
    await view.navigate(url)
    // The page follows prefers-color-scheme, so pin the theme by rewriting the dark media rule.
    await view.evaluate(
      `(() => { for (const sheet of document.styleSheets) for (const rule of sheet.cssRules) if (rule.media?.mediaText.includes('prefers-color-scheme')) rule.media.mediaText = '${theme === 'dark' ? 'all' : 'not all'}' })()`,
    )
    await view.evaluate(`document.body.style.minHeight = '0'`)
    await view.evaluate(`document.documentElement.style.zoom = '${scale}'`)
    await view.evaluate(
      `new Promise((done) => { const wait = () => document.querySelector('#fields .field') ? done() : setTimeout(wait, 20); wait() })`,
    )
    const height = (await view.evaluate(`Math.ceil(document.body.getBoundingClientRect().height)`)) as number
    await view.resize(width * scale, height)
    await Bun.write(join(dir, `prompt-${theme}.png`), await view.screenshot())
    console.log(`prompt-${theme}.png`, `${width * scale}x${height}`)
  }
} finally {
  await server.stop()
}

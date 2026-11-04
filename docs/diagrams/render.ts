// Renders each diagram page to light and dark PNGs next to it: bun docs/diagrams/render.ts
import { join } from 'node:path'

const dir = import.meta.dir
const pages = ['overview', 'keys']
const scale = 2

const server = Bun.serve({
  port: 0,
  fetch: (request) => new Response(Bun.file(join(dir, new URL(request.url).pathname))),
})

try {
  for (const page of pages) {
    for (const theme of ['light', 'dark']) {
      await using view = new Bun.WebView({ width: 1024 * scale, height: 800 * scale })
      await view.navigate(`${server.url}${page}.html?theme=${theme}`)
      await view.evaluate(`document.documentElement.style.zoom = '${scale}'`)
      await view.evaluate(
        `new Promise((done) => { const wait = () => document.body.dataset.ready ? done() : setTimeout(wait, 20); wait() })`,
      )
      const size = (await view.evaluate(
        `(() => { const r = document.querySelector('.canvas').getBoundingClientRect(); return [Math.ceil(r.width), Math.ceil(r.height)] })()`,
      )) as [number, number]
      await view.resize(size[0], size[1])
      await Bun.write(join(dir, `${page}-${theme}.png`), await view.screenshot())
      console.log(`${page}-${theme}.png`, size.join('x'))
    }
  }
} finally {
  server.stop()
}

// Draws arrows between boxes after layout: link(fromId, fromSide, toId, toSide, label, options).
// Sides are 't', 'r', 'b', 'l'. options: { shift, toShift, cls, labelAt } where shift moves the start along its side
// (and toShift the end), labelAt (0..1) places the label along the path, and lift moves it up (or down) off the line.
const theme = new URLSearchParams(location.search).get('theme')
document.documentElement.dataset.theme =
  theme ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')

const links = []
export function link(from, fromSide, to, toSide, label, options = {}) {
  links.push({ from, fromSide, to, toSide, label, ...options })
}

function anchor(canvas, id, side, shift = 0) {
  const c = canvas.getBoundingClientRect()
  const ratio = c.width / canvas.offsetWidth
  const r = document.getElementById(id).getBoundingClientRect()
  const x = (r.left - c.left) / ratio
  const y = (r.top - c.top) / ratio
  const w = r.width / ratio
  const h = r.height / ratio
  if (side === 't') return [x + w / 2 + shift, y]
  if (side === 'b') return [x + w / 2 + shift, y + h]
  if (side === 'l') return [x, y + h / 2 + shift]
  return [x + w, y + h / 2 + shift]
}

const horizontal = (side) => side === 'l' || side === 'r'

function points(a, b, fromSide, toSide) {
  if (horizontal(fromSide) && horizontal(toSide)) {
    if (a[1] === b[1]) return [a, b]
    const mx = (a[0] + b[0]) / 2
    return [a, [mx, a[1]], [mx, b[1]], b]
  }
  if (!horizontal(fromSide) && !horizontal(toSide)) {
    if (a[0] === b[0]) return [a, b]
    const my = (a[1] + b[1]) / 2
    return [a, [a[0], my], [b[0], my], b]
  }
  return horizontal(fromSide) ? [a, [b[0], a[1]], b] : [a, [a[0], b[1]], b]
}

function along(pts, t) {
  const segs = pts.slice(1).map((p, i) => [pts[i], p, Math.hypot(p[0] - pts[i][0], p[1] - pts[i][1])])
  let left = segs.reduce((n, s) => n + s[2], 0) * t
  for (const [p, q, len] of segs) {
    if (left <= len) return [p[0] + ((q[0] - p[0]) * left) / len, p[1] + ((q[1] - p[1]) * left) / len]
    left -= len
  }
  return pts.at(-1)
}

export function draw() {
  const canvas = document.querySelector('.canvas')
  const ns = 'http://www.w3.org/2000/svg'
  const svg = document.createElementNS(ns, 'svg')
  svg.classList.add('links')
  const marker = (id, color) =>
    `<marker id="${id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">` +
    `<path d="M0,0 L10,5 L0,10 z" style="fill:var(${color});stroke:none"/></marker>`
  svg.innerHTML = `<defs>${marker('head', '--wire')}${marker('head-accent', '--accent')}${marker('head-key', '--key')}</defs>`
  canvas.prepend(svg)
  for (const l of links) {
    const a = anchor(canvas, l.from, l.fromSide, l.shift)
    const b = anchor(canvas, l.to, l.toSide, l.toShift ?? l.shift)
    const pts = points(a, b, l.fromSide, l.toSide)
    const path = document.createElementNS(ns, 'path')
    path.setAttribute('d', 'M' + pts.map((p) => p.join(',')).join(' L'))
    path.setAttribute('marker-end', l.cls ? `url(#head-${l.cls})` : 'url(#head)')
    if (l.cls) path.classList.add(l.cls)
    svg.append(path)
    if (l.label) {
      const [x, y] = along(pts, l.labelAt ?? 0.5)
      const div = document.createElement('div')
      div.className = 'label'
      div.innerHTML = l.label
      div.style.left = x + 'px'
      div.style.top = y - (l.lift ?? 0) + 'px'
      if (l.lift) div.classList.add('lifted')
      canvas.append(div)
    }
  }
  document.body.dataset.ready = 'true'
}

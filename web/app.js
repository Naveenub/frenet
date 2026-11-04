'use strict'
const $ = (s) => document.querySelector(s)
const el = (tag, props = {}, ...kids) => {
  const e = Object.assign(document.createElement(tag), props)
  for (const k of kids) e.append(k)
  return e
}
const api = async (path, body) => {
  const r = await fetch(path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined)
  const j = await r.json()
  if (!r.ok) throw new Error(j.error || r.statusText)
  return j
}
const short = (id) => id.slice(0, 6) + '…' + id.slice(-6)
const ago = (ms) => { const s = Math.floor(ms / 1000); return s < 60 ? s + 's' : s < 3600 ? Math.floor(s / 60) + 'm' : Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm' }

const SECTIONS = [
  ['overview', 'Network Overview'], ['peers', 'Connected Peers'], ['messages', 'Private Communications'],
  ['storage', 'Distributed Storage'], ['browser', 'Decentralized Browser', 'Phase 3'],
  ['identity', 'Identity and Keys'], ['nodes', 'Network Nodes', 'Phase 3'],
  ['privacy', 'Privacy Center'], ['security', 'Security Center'], ['governance', 'Community Governance', 'Phase 3']
]
const state = { view: 'overview', status: null, peers: [], dropped: [], chat: [], stop: null }

const nav = $('#nav')
for (const [id, name, phase] of SECTIONS) {
  const b = el('button', { type: 'button', onclick: () => go(id) }, name)
  b.dataset.id = id
  if (phase) b.append(el('small', {}, phase))
  nav.append(b)
}

function go (id) {
  state.view = id
  if (state.stop) { state.stop(); state.stop = null }
  for (const b of nav.children) b.setAttribute('aria-current', String(b.dataset.id === id))
  $('#title').textContent = SECTIONS.find((s) => s[0] === id)[1]
  const v = $('#view'); v.replaceChildren()
  const meta = SECTIONS.find((s) => s[0] === id)
  if (meta[2]) return v.append(el('div', { className: 'card' }, el('h3', {}, 'Not built yet'), el('p', { className: 'dim' }, `This section is planned for ${meta[2]}. Nothing here is simulated.`)))
  ;({ overview, peers, messages, storage, identity, privacy, security })[id](v)
}

function stat (label, value) { return el('div', { className: 'stat' }, el('b', {}, String(value)), el('span', {}, label)) }

function overview (v) {
  const s = state.status
  v.append(el('div', { className: 'grid' },
    stat('Connected peers', state.peers.length), stat('Uptime', ago(s.uptimeMs)),
    stat('DHT routing table', s.dht.routingTableSize), stat('Messages in / out', `${s.messages.in} / ${s.messages.out}`)))
  const c = el('canvas'); v.append(c)
  state.stop = drawNetwork(c)
  v.append(el('div', { className: 'card', style: 'margin-top:16px' }, el('h3', {}, 'Listening on'),
    ...s.addresses.map((a) => el('div', { className: 'mono' }, a))))
}

function drawNetwork (canvas) {
  const ctx = canvas.getContext('2d')
  let raf = 0; let t0 = performance.now()
  const frame = (t) => {
    const dpr = devicePixelRatio || 1
    const w = canvas.clientWidth; const h = canvas.clientHeight
    if (canvas.width !== w * dpr) { canvas.width = w * dpr; canvas.height = h * dpr }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h)
    const cx = w / 2; const cy = h / 2; const R = Math.min(w, h) * 0.34
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches
    const ph = reduce ? 0 : (t - t0) / 6000
    const n = state.peers.length
    state.peers.forEach((p, i) => {
      const a = ph + (i / n) * Math.PI * 2
      const x = cx + Math.cos(a) * R; const y = cy + Math.sin(a) * R * 0.8
      const g = ctx.createLinearGradient(cx, cy, x, y); g.addColorStop(0, '#2f7bff'); g.addColorStop(1, '#8b5cf6')
      ctx.strokeStyle = g; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(x, y); ctx.stroke()
      ctx.fillStyle = '#8b5cf6'; ctx.beginPath(); ctx.arc(x, y, 7, 0, 7); ctx.fill()
      ctx.fillStyle = '#8087b5'; ctx.font = '11px ui-monospace,monospace'; ctx.textAlign = 'center'; ctx.fillText(short(p.peer), x, y + 22)
    })
    ctx.fillStyle = '#2f7bff'; ctx.shadowColor = '#2f7bff'; ctx.shadowBlur = 18; ctx.beginPath(); ctx.arc(cx, cy, 11, 0, 7); ctx.fill(); ctx.shadowBlur = 0
    if (!n) { ctx.fillStyle = '#8087b5'; ctx.font = '14px system-ui'; ctx.textAlign = 'center'; ctx.fillText('No peers connected. Start another node on this network, or add a peer address.', cx, cy + 50) }
    raf = requestAnimationFrame(frame)
  }
  raf = requestAnimationFrame(frame)
  return () => cancelAnimationFrame(raf)
}

function peers (v) {
  const addr = el('input', { placeholder: '/ip4/192.168.1.20/tcp/4001/p2p/12D3Koo…', 'aria-label': 'Peer address' })
  const err = el('p', { className: 'err' })
  const add = el('button', { className: 'btn', type: 'button', onclick: async () => {
    err.textContent = ''
    try { await api('/api/dial', { addr: addr.value.trim() }); addr.value = ''; await refresh() } catch (e) { err.textContent = e.message }
  } }, 'Connect to peer')
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Add a peer'), el('div', { className: 'row' }, addr, add), err))
  const t = el('table', {}, el('thead', {}, el('tr', {}, ...['Peer', 'Address', 'Direction', 'Encryption', 'Latency'].map((h) => el('th', {}, h)))))
  const tb = el('tbody'); t.append(tb)
  for (const p of state.peers) {
    tb.append(el('tr', {}, el('td', { className: 'mono' }, p.peer), el('td', { className: 'mono' }, p.address), el('td', {}, p.direction),
      el('td', {}, (p.encryption || 'none') + (p.muxer ? ' + ' + p.muxer : '')), el('td', {}, p.latencyMs == null ? '–' : p.latencyMs + ' ms')))
  }
  v.append(state.peers.length ? t : el('p', { className: 'dim' }, 'No peers connected yet. Peers on your local network are found automatically.'))
}

async function messages (v) {
  const sel = el('select', { 'aria-label': 'Recipient' }, ...state.peers.map((p) => el('option', { value: p.peer }, short(p.peer))))
  const box = el('input', { placeholder: 'Write a message', maxLength: 4000, 'aria-label': 'Message' })
  const log = el('div', { className: 'msgs', role: 'log' })
  const err = el('p', { className: 'err' })
  const render = () => {
    log.replaceChildren(...state.chat.map((m) => el('div', { className: 'm ' + m.direction }, el('small', {}, `${m.direction === 'out' ? 'to' : 'from'} ${short(m.peer)} · ${new Date(m.ts).toLocaleTimeString()}`), m.body)))
    log.scrollTop = log.scrollHeight
  }
  const send = async () => {
    err.textContent = ''
    if (!sel.value || !box.value) { err.textContent = sel.value ? 'Write a message first.' : 'Connect to a peer first.'; return }
    try { await api('/api/send', { peer: sel.value, body: box.value }); box.value = '' } catch (e) { err.textContent = e.message }
  }
  box.addEventListener('keydown', (e) => { if (e.key === 'Enter') send() })
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Messages'), log, el('div', { className: 'row' }, sel, box, el('button', { className: 'btn', type: 'button', onclick: send }, 'Send message')), err,
    el('p', { className: 'dim' }, 'Messages travel directly between peers over Noise-encrypted connections and are stored only on this device.')))
  state.chat = await api('/api/messages'); render()
  state.onMessage = (m) => { state.chat.push(m); render() }
  state.stop = () => { state.onMessage = null }
}

const mb = (n) => (n / 1048576).toFixed(n < 1048576 ? 2 : 1) + ' MB'
const b64 = (buf) => { let s = ''; const u = new Uint8Array(buf); for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s) }

async function storage (v) {
  const b = state.status.blocks
  v.append(el('div', { className: 'grid' }, stat('Local blocks', b.count), stat('Used', mb(b.bytes) + ' of ' + mb(b.quotaBytes)), stat('Your files', state.status.files), stat('Replica lifetime', b.replicaTtlDays + ' days')))

  const pick = el('input', { type: 'file', 'aria-label': 'File to add' })
  const enc = el('input', { type: 'checkbox', checked: true, id: 'enc' })
  const ttl = el('input', { type: 'number', min: 1, placeholder: 'keep for N days (blank = until deleted)', 'aria-label': 'Retention in days' })
  const msg = el('p', { className: 'err' }); const out = el('div')
  const add = el('button', { className: 'btn', type: 'button', onclick: async () => {
    msg.textContent = ''; out.replaceChildren()
    const f = pick.files[0]
    if (!f) { msg.textContent = 'Choose a file first (max 16 MB).'; return }
    if (f.size > 16 * 1048576) { msg.textContent = 'File is larger than 16 MB.'; return }
    add.disabled = true; msg.textContent = 'Encrypting and publishing…'
    try {
      const r = await api('/api/files', { name: f.name, data: b64(await f.arrayBuffer()), encrypt: enc.checked, ttlDays: ttl.value ? Number(ttl.value) : undefined })
      msg.textContent = ''
      out.append(el('p', {}, r.announced ? 'Added. Peers can find it.' : 'Added locally. No peers announced it yet; connect to peers and add it again to share.'),
        el('div', { className: 'mono' }, r.link), el('p', { className: 'dim' }, r.key ? 'Anyone with this full link can read the file. The key is not stored on this node. Keep the link.' : 'Public file: anyone with the link can read it.'))
      await refresh(); go('storage')
    } catch (e) { msg.textContent = e.message } finally { add.disabled = false }
  } }, 'Add file')
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Add a file'), el('div', { className: 'row' }, pick), el('label', { className: 'row' }, enc, 'Encrypt (recommended)'), el('div', { className: 'row' }, ttl, add), msg, out))

  const link = el('input', { placeholder: 'frenet://bafk…#key', 'aria-label': 'File link' })
  const dmsg = el('p', { className: 'err' })
  const get = el('button', { className: 'btn', type: 'button', onclick: async () => {
    dmsg.textContent = ''
    try {
      const [cid, key] = link.value.trim().replace(/^frenet:\/\//, '').split('#')
      dmsg.textContent = 'Fetching from peers…'
      const r = await api('/api/files/get', { cid, key })
      const bytes = Uint8Array.from(atob(r.data), (c) => c.charCodeAt(0))
      const a = el('a', { href: URL.createObjectURL(new Blob([bytes])), download: r.name }); document.body.append(a); a.click(); a.remove()
      dmsg.textContent = `Downloaded ${r.name} (${mb(r.size)}).`
    } catch (e) { dmsg.textContent = e.message }
  } }, 'Download from network')
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Download a file'), el('div', { className: 'row' }, link, get), dmsg))

  const files = await api('/api/files')
  const t = el('table', {}, el('thead', {}, el('tr', {}, ...['Name', 'Size', 'Chunks', 'Encrypted', 'Retention', ''].map((h) => el('th', {}, h)))))
  const tb = el('tbody'); t.append(tb)
  for (const f of files) {
    tb.append(el('tr', {}, el('td', {}, f.name), el('td', {}, mb(f.size)), el('td', {}, String(f.chunks.length)), el('td', {}, f.encrypted ? 'yes' : 'no (public)'),
      el('td', {}, f.expires ? 'until ' + new Date(f.expires).toLocaleDateString() : 'until deleted'),
      el('td', {}, el('button', { className: 'btn', type: 'button', onclick: async () => { await api('/api/files/delete', { cid: f.cid }); await refresh(); go('storage') } }, 'Delete local copy'))))
  }
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Files you added'), files.length ? t : el('p', { className: 'dim' }, 'No files yet. Other peers may still hold copies of anything you shared.')))
}

function identity (v) {
  const s = state.status
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Your peer ID'), el('div', { className: 'mono' }, s.peerId),
    el('p', { className: 'dim' }, 'Ed25519 key pair. The private key is stored in your data directory (mode 0600) and is never sent anywhere. Back up the file identity.key to keep this identity.')))
}

function privacy (v) {
  const p = state.status.privacy
  v.append(el('div', { className: 'card' }, el('h3', {}, 'What this node does with your data'),
    el('table', {}, el('tbody', {}, ...Object.entries({ 'Transport encryption': p.transportEncryption, Identity: p.identity, Telemetry: p.telemetry, 'Control API': p.apiBind, 'Message storage': 'Local SQLite, this device only' }).map(([k, val]) => el('tr', {}, el('th', {}, k), el('td', {}, val)))))))
}

function security (v) {
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Active protections'),
    el('p', { className: 'dim' }, 'Noise-authenticated peers · replay protection (5 min window, duplicate IDs rejected) · per-peer rate limit (20 burst, 2/s) · 16 KB message cap · loopback-only API with Host and Origin checks.')))
  const t = el('table', {}, el('thead', {}, el('tr', {}, el('th', {}, 'Peer'), el('th', {}, 'Blocked because'))))
  const tb = el('tbody'); t.append(tb)
  for (const d of state.dropped.slice(-50).reverse()) tb.append(el('tr', {}, el('td', { className: 'mono' }, d.peer), el('td', {}, d.reason)))
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Blocked messages (this session)'), state.dropped.length ? t : el('p', { className: 'dim' }, 'Nothing blocked.')))
}

async function refresh () {
  try {
    const before = state.peers.map((p) => p.peer).join()
    ;[state.status, state.peers] = await Promise.all([api('/api/status'), api('/api/peers')])
    $('#me').textContent = state.status.peerId
    const changed = before !== state.peers.map((p) => p.peer).join()
    if (state.view === 'overview' || (changed && ['peers', 'messages'].includes(state.view))) go(state.view)
  } catch { /* shown via live indicator */ }
}

function connectEvents () {
  const live = $('#live')
  const es = new EventSource('/api/events')
  es.onopen = () => { live.textContent = 'node online'; live.className = 'live on' }
  es.onerror = () => { live.textContent = 'node unreachable'; live.className = 'live off' }
  es.addEventListener('peer', refresh)
  es.addEventListener('message', (e) => { const m = JSON.parse(e.data); if (state.onMessage && !(m.direction === 'out' && state.chat.some((c) => c.id === m.id))) state.onMessage(m) })
  es.addEventListener('dropped', (e) => { state.dropped.push(JSON.parse(e.data)); if (state.view === 'security') go('security') })
}

await refresh(); go('overview'); connectEvents(); setInterval(refresh, 5000)

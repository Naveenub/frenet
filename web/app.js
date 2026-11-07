'use strict'
const $ = (s) => document.querySelector(s)
const el = (tag, props = {}, ...kids) => {
  const e = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) { if (k.startsWith('aria-')) e.setAttribute(k, v); else e[k] = v } // aria-* are attributes, not DOM properties
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
  ['communities', 'Communities'], ['storage', 'Distributed Storage'], ['browser', 'Decentralized Browser'],
  ['identity', 'Identity and Keys'], ['anon', 'Anonymous Auth'], ['nodes', 'Network Nodes'],
  ['privacy', 'Privacy Center'], ['security', 'Security Center'], ['safety', 'Content Safety'], ['governance', 'Community Governance']
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
  ;({ overview, peers, messages, communities, storage, browser, identity, anon, nodes, privacy, security, safety, governance })[id](v)
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
  const ring = (video) => () => { err.textContent = ''; if (!sel.value) { err.textContent = 'Connect to a peer first.'; return }; startCall(sel.value, video) }
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Messages'), log, el('div', { className: 'row' }, sel, box, el('button', { className: 'btn', type: 'button', onclick: send }, 'Send message')),
    el('div', { className: 'row' }, el('button', { className: 'btn', type: 'button', onclick: ring(false) }, 'Voice call'), el('button', { className: 'btn', type: 'button', onclick: ring(true) }, 'Video call')), err,
    el('p', { className: 'dim' }, 'Messages travel directly between peers over Noise-encrypted connections and are stored only on this device. Calls are peer-to-peer (WebRTC): media is encrypted end to end, but the other side sees your network address.')))
  state.chat = await api('/api/messages'); render()
  state.onMessage = (m) => { state.chat.push(m); render() }
  state.stop = () => { state.onMessage = null }
}

const mb = (n) => (n / 1048576).toFixed(n < 1048576 ? 2 : 1) + ' MB'
const b64 = (buf) => { let s = ''; const u = new Uint8Array(buf); for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s) }

async function storage (v) {
  const b = state.status.blocks
  v.append(el('div', { className: 'grid' }, stat('Local blocks', b.count), stat('Used', mb(b.bytes) + ' of ' + mb(b.quotaBytes)), stat('Your files', state.status.files), stat('Replica lifetime', b.replicaTtlDays + ' days'), stat('Last re-announce', b.lastReannounce ? ago(Date.now() - b.lastReannounce.at) + ' ago' : 'not yet')))

  const pick = el('input', { type: 'file', 'aria-label': 'File to add' })
  const enc = el('input', { type: 'checkbox', checked: true, id: 'enc' })
  const ttl = el('input', { type: 'number', min: 1, placeholder: 'keep for N days (blank = until deleted)', 'aria-label': 'Retention in days' })
  const msg = el('p', { className: 'err' }); const out = el('div')
  const add = el('button', { className: 'btn', type: 'button', onclick: async () => {
    msg.textContent = ''; out.replaceChildren()
    const f = pick.files[0]
    if (!f) { msg.textContent = 'Choose a file first (max 1 GiB).'; return }
    if (f.size > 1024 * 1048576) { msg.textContent = 'File is larger than 1 GiB.'; return }
    add.disabled = true; msg.textContent = 'Encrypting and publishing…'
    try {
      // The File is sent as the raw request body (no base64, not read into the page's memory); the node encrypts it chunk by chunk.
      const qs = new URLSearchParams({ name: f.name, encrypt: String(enc.checked) }); if (ttl.value) qs.set('ttlDays', String(Number(ttl.value)))
      const up = await fetch('/api/files/stream?' + qs, { method: 'PUT', headers: { 'content-type': 'application/octet-stream' }, body: f })
      const r = await up.json()
      if (!up.ok) throw new Error(r.error || up.statusText)
      msg.textContent = ''
      out.append(el('p', {}, r.announced ? 'Added. Peers can find it.' : r.announcing ? 'Added. Large file: announcing it to peers in the background.' : 'Added locally. No peers announced it yet; connect to peers and add it again to share.'),
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
      const r = await fetch('/api/files/download', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ cid, key }) })
      if (!r.ok) throw new Error((await r.json()).error || r.statusText)
      const blob = await r.blob()   // a cut-off transfer (failed chunk) rejects here instead of saving a partial file
      const name = decodeURIComponent((/filename\*=UTF-8''([^;]+)/.exec(r.headers.get('content-disposition') || '') || [])[1] || 'download')
      const a = el('a', { href: URL.createObjectURL(blob), download: name }); document.body.append(a); a.click(); a.remove()
      dmsg.textContent = `Downloaded ${name} (${mb(blob.size)}).`
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

const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const PUB_RE = /^[a-z2-7]{52}$/

/** frenet-site://<id> or frenet-name://<name>.<key> -> gateway URL, or null if it is neither. */
function gatewayUrl (gw, input) {
  const t = input.trim()
  const site = t.replace(/^frenet-site:\/\//, '').replace(/\/.*$/, '')
  if (/^[a-z2-7]{20,63}$/.test(site)) return `http://${site}.localhost:${gw}/`
  const m = /^(?:frenet-name:\/\/)?([a-z0-9-]{1,63})\.([a-z2-7]{52})(?:\/.*)?$/.exec(t)
  if (m && NAME_RE.test(m[1]) && PUB_RE.test(m[2])) return `http://${m[1]}.${m[2]}.localhost:${gw}/`
  return null
}

function browser (v) {
  const gw = state.status.gatewayPort
  if (!gw) { v.append(el('div', { className: 'card' }, el('h3', {}, 'Gateway is off'), el('p', { className: 'dim' }, 'Restart the node without --no-gateway to publish and open sites.'))); return }
  const pick = el('input', { type: 'file', multiple: true, webkitdirectory: true, 'aria-label': 'Site folder' })
  const ttl = el('input', { type: 'number', min: 1, placeholder: 'keep for N days (blank = until deleted)', 'aria-label': 'Retention in days' })
  const name = el('input', { placeholder: 'name (optional, e.g. my-blog)', maxLength: 63, 'aria-label': 'Site name' })
  const title = el('input', { placeholder: 'title for search (optional)', maxLength: 80, 'aria-label': 'Site title' })
  const kws = el('input', { placeholder: 'keywords, comma separated (optional, max 8)', 'aria-label': 'Keywords' })
  const msg = el('p', { className: 'err' }); const out = el('div')
  const pub = el('button', { className: 'btn', type: 'button', onclick: async () => {
    msg.textContent = ''; out.replaceChildren()
    const fs = [...pick.files]
    if (!fs.length) { msg.textContent = 'Choose a folder containing index.html.'; return }
    const nm = name.value.trim()
    if (nm && !NAME_RE.test(nm)) { msg.textContent = 'Names use a-z, 0-9 and hyphens (not at the start or end), up to 63 characters.'; return }
    const prefix = fs[0].webkitRelativePath.split('/')[0] + '/'
    pub.disabled = true; msg.textContent = 'Publishing…'
    try {
      const files = []
      for (const f of fs) files.push({ path: (f.webkitRelativePath || f.name).replace(prefix, ''), data: b64(await f.arrayBuffer()) })
      const keywords = kws.value.split(',').map((k) => k.trim()).filter(Boolean)
      const r = await api('/api/sites', { files, ttlDays: ttl.value ? Number(ttl.value) : undefined, ...(nm ? { name: nm, title: title.value.trim(), keywords } : {}) })
      msg.textContent = ''
      out.append(el('p', {}, r.name ? `Published ${r.files} files as version ${r.name.seq} of “${nm}”.` : `Published ${r.files} files.`))
      if (r.name) out.append(el('div', { className: 'mono' }, r.name.link), el('p', { className: 'dim' }, 'Share this link: it keeps working when you update the site. Publish again with the same name to update it.'))
      out.append(el('div', { className: 'mono' }, r.link),
        el('p', {}, el('a', { href: r.url, target: '_blank', rel: 'noopener noreferrer' }, 'Open site')),
        el('p', { className: 'dim' }, 'Sites are public: anyone with the link can read every file.' + (r.name ? ' The frenet-site:// link is this exact version and never changes.' : ' Without a name, the site ID is the only address and an update means a new ID.')))
    } catch (e) { msg.textContent = e.message } finally { pub.disabled = false }
  } }, 'Publish site')
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Publish a site'), el('p', { className: 'dim' }, 'Static files only (max 64 files, 32 MB). Each site gets its own isolated origin and can only load its own files: no third-party requests, no tracking. A name is yours alone: it is tied to your identity key, signed, and can be updated by publishing again under the same name.'),
    el('div', { className: 'row' }, pick), el('div', { className: 'row' }, name, title), el('div', { className: 'row' }, kws), el('div', { className: 'row' }, ttl, pub), msg, out,
    el('p', { className: 'dim' }, 'What you publish is stored and served by other people’s nodes. Do not publish anything illegal or abusive: node operators can report it and block it (see Content Safety), and a block cannot be undone from your side.')))

  const link = el('input', { placeholder: 'frenet-name://my-blog.… or frenet-site://bafk…', 'aria-label': 'Site link' }); const omsg = el('p', { className: 'err' })
  const open = el('button', { className: 'btn', type: 'button', onclick: () => {
    omsg.textContent = ''
    const u = gatewayUrl(gw, link.value)
    if (!u) { omsg.textContent = 'That is not a valid site or name link.'; return }
    window.open(u, '_blank', 'noopener,noreferrer')
  } }, 'Open')
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Open a site'), el('div', { className: 'row' }, link, open), omsg,
    el('p', { className: 'dim' }, 'The node fetches the site from peers and verifies every block against its hash. A name link is resolved to the newest version signed by its publisher. Your browser must resolve *.localhost to this machine (Chrome, Firefox and Edge do).')))

  const q = el('input', { placeholder: 'search names by keyword, e.g. vegan recipes', 'aria-label': 'Search' }); const smsg = el('p', { className: 'dim' }); const sres = el('div')
  const doSearch = async () => {
    sres.replaceChildren(); smsg.textContent = 'Searching peers…'
    try {
      const r = await api('/api/search?q=' + encodeURIComponent(q.value))
      smsg.textContent = r.results.length ? '' : 'No named sites match. Only sites whose publisher added keywords can be found.'
      for (const h of r.results) {
        sres.append(el('div', { className: 'card' },
          el('h3', {}, h.title || h.name),
          el('p', {}, el('a', { href: `http://${h.name}.${h.pub}.localhost:${gw}/`, target: '_blank', rel: 'noopener noreferrer' }, h.name), h.own ? ' (yours)' : ''),
          el('div', { className: 'mono' }, h.link),
          el('p', { className: 'dim' }, `version ${h.seq} · ${h.keywords.join(', ')}`),
          h.own ? '' : el('button', { className: 'btn', type: 'button', onclick: () => { state.report = { kind: 'name', target: h.link }; go('safety') } }, 'Report')))
      }
    } catch (e) { smsg.textContent = ''; sres.append(el('p', { className: 'err' }, e.message)) }
  }
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Search'), el('div', { className: 'row' }, q, el('button', { className: 'btn', type: 'button', onclick: doSearch }, 'Search')), smsg,
    el('p', { className: 'dim' }, 'Matches names, titles and keywords that publishers announced on the network, checking each record’s signature. There is no central index and no ranking, so treat results as unvetted: anyone can publish under any keyword.'), sres))

  webBrowsing(v)
  sitePermissions(v)

  api('/api/names').then((r) => {
    const mine = r.names.filter((n) => n.own)
    if (!mine.length) return
    const card = el('div', { className: 'card' }, el('h3', {}, 'Your names'))
    for (const n of mine) card.append(el('p', {}, el('a', { href: `http://${n.name}.${n.pub}.localhost:${gw}/`, target: '_blank', rel: 'noopener noreferrer' }, n.name), ` · version ${n.seq}`), el('div', { className: 'mono' }, n.link))
    v.append(card)
  }).catch(() => {})
}

/** HTTPS browsing through the local proxy: setup, tracker blocking, counters. */
function webBrowsing (v) {
  const card = el('div', { className: 'card' }, el('h3', {}, 'Web browsing (HTTPS) and tracker blocking'))
  v.append(card)
  const draw = (b) => {
    card.replaceChildren(el('h3', {}, 'Web browsing (HTTPS) and tracker blocking'))
    if (!b.proxy) { card.append(el('p', { className: 'dim' }, 'The web proxy is off. Restart the node without --no-proxy to browse HTTPS sites through it.')); return }
    const st = b.proxy.stats
    card.append(
      el('p', { className: 'dim' }, 'Point your everyday browser at this node’s proxy to load normal https:// sites with tracker blocking. FRENET sites on *.localhost bypass it. The proxy only tunnels TLS: it never decrypts, re-signs or logs your traffic, refuses plain http://, and refuses to reach your own machine or LAN.'),
      el('p', {}, 'Proxy auto-config URL: '), el('div', { className: 'mono' }, b.proxy.pacUrl),
      el('p', { className: 'dim' }, `Or set an HTTPS proxy of 127.0.0.1 port ${b.proxy.port} by hand.`),
      el('table', {}, el('tbody', {}, ...Object.entries({ 'Tunnels opened': st.tunnels, 'Open now': st.active, 'Trackers blocked': st.trackersBlocked, 'Plain-HTTP refused': st.refusedHttp, 'Local/LAN targets refused': st.refusedPrivate, 'Other ports refused': st.refusedPort }).map(([k, val]) => el('tr', {}, el('th', {}, k), el('td', {}, String(val)))))),
      el('p', { className: 'dim' }, `Built-in list: ${b.trackers.builtinCount} well-known tracker and ad domains (short, hand-picked; it will miss many). Blocking is by host name only, because encrypted traffic cannot be inspected. It does not make you anonymous: sites and your network still see your IP address.`))
    const host = el('input', { placeholder: 'domain, e.g. ads.example.com', 'aria-label': 'Domain' }); const msg = el('p', { className: 'err' })
    const rule = (action) => async () => { msg.textContent = ''; try { draw(await api('/api/browser/trackers', { host: host.value, action })) } catch (e) { msg.textContent = e.message } }
    card.append(el('div', { className: 'row' }, host, el('button', { className: 'btn', type: 'button', onclick: rule('block') }, 'Block'), el('button', { className: 'btn', type: 'button', onclick: rule('allow') }, 'Always allow')), msg,
      el('p', { className: 'dim' }, 'A domain covers its subdomains. “Always allow” overrides the built-in list, for a site that breaks.'))
    if (b.trackers.rules.length) {
      const t = el('table', {}, el('thead', {}, el('tr', {}, el('th', {}, 'Your rules'), el('th', {}, ''), el('th', {}, ''))), el('tbody', {}, ...b.trackers.rules.map((r) => el('tr', {}, el('td', { className: 'mono' }, r.host), el('td', {}, r.action), el('td', {}, el('button', { className: 'btn', type: 'button', onclick: async () => { await api('/api/browser/trackers/remove', { host: r.host }); draw(await api('/api/browser')) } }, 'Remove'))))))
      card.append(t)
    }
    if (b.trackers.recent.length) {
      card.append(el('p', { className: 'dim' }, 'Recently blocked (kept in memory only, never saved):'),
        el('div', { className: 'mono' }, b.trackers.recent.map((r) => r.host).join('\n')),
        el('button', { className: 'btn', type: 'button', onclick: async () => { await api('/api/browser/trackers/clear-recent', {}); draw(await api('/api/browser')) } }, 'Clear'))
    }
  }
  api('/api/browser').then(draw).catch((e) => card.append(el('p', { className: 'err' }, e.message)))
}

/** Per-site permission manager: everything is off until you grant it, and every grant is listed here. */
function sitePermissions (v) {
  const card = el('div', { className: 'card' }, el('h3', {}, 'Site permissions'))
  v.append(card)
  const draw = (b) => {
    card.replaceChildren(el('h3', {}, 'Site permissions'),
      el('p', { className: 'dim' }, 'Every FRENET site starts with camera, microphone, location, fullscreen, clipboard and screen capture switched off. A grant here only lets that one site ask: your browser still shows its own prompt, and you can still say no. A name keeps its grants when its publisher updates the site, so grant only to names you trust.'))
    const origins = b.permissions.origins
    if (!origins.length) card.append(el('p', { className: 'dim' }, 'No site has any permission.'))
    for (const o of origins) {
      card.append(el('div', { className: 'mono' }, o.origin),
        el('p', {}, ...o.grants.map((g) => el('button', { className: 'btn', type: 'button', title: `granted ${new Date(g.since).toLocaleString()}; click to revoke`, onclick: async () => { await api('/api/browser/permissions/revoke', { origin: o.origin, feature: g.feature }); draw(await api('/api/browser')) } }, `${g.feature} ✕`)),
          el('button', { className: 'btn', type: 'button', onclick: async () => { await api('/api/browser/permissions/reset', { origin: o.origin }); draw(await api('/api/browser')) } }, 'Revoke all')))
    }
    const origin = el('input', { placeholder: 'site:<id> or name:<n>.<publisher-key>', 'aria-label': 'Site origin' })
    const feature = el('select', { 'aria-label': 'Permission' }, ...b.permissions.features.map((f) => el('option', { value: f }, f)))
    const msg = el('p', { className: 'err' })
    card.append(el('div', { className: 'row' }, origin, feature, el('button', { className: 'btn', type: 'button', onclick: async () => { msg.textContent = ''; try { draw(await api('/api/browser/permissions/grant', { origin: origin.value.trim(), feature: feature.value })) } catch (e) { msg.textContent = e.message } } }, 'Grant')), msg)
  }
  api('/api/browser').then(draw).catch((e) => card.append(el('p', { className: 'err' }, e.message)))
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
    el('p', { className: 'dim' }, 'Noise-authenticated peers · replay protection (5 min window, duplicate IDs rejected) · per-peer rate limit (20 burst, 2/s) · 16 KB message cap · loopback-only API with Host and Origin checks. Call signals and group events are signed per event and rate limited; operator-banned peers are refused at the connection level.')))
  const t = el('table', {}, el('thead', {}, el('tr', {}, el('th', {}, 'Peer'), el('th', {}, 'Blocked because'))))
  const tb = el('tbody'); t.append(tb)
  for (const d of state.dropped.slice(-50).reverse()) tb.append(el('tr', {}, el('td', { className: 'mono' }, d.peer), el('td', {}, d.reason)))
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Blocked messages (this session)'), state.dropped.length ? t : el('p', { className: 'dim' }, 'Nothing blocked.')))
}

// ---- Voice / video (WebRTC). Media flows browser to browser; the node only relays signed signalling. ----
const callBox = $('#call')
const call = { id: null, peer: null, pc: null, stream: null, offer: null, video: false, timer: 0 }
const media = { local: el('video', { autoplay: true, muted: true, playsInline: true, className: 'cv' }), remote: el('video', { autoplay: true, playsInline: true, className: 'cv' }) }
const sig = (kind, data, peer = call.peer, id = call.id) => api('/api/call/signal', { peer, call: id, kind, data: JSON.stringify(data ?? {}) })
const hangBtn = () => el('button', { className: 'btn', type: 'button', onclick: () => endCall(true) }, 'Hang up')
const muteBtn = () => el('button', { className: 'btn', type: 'button', onclick: (e) => { const t = call.stream?.getAudioTracks()[0]; if (t) { t.enabled = !t.enabled; e.target.textContent = t.enabled ? 'Mute' : 'Unmute' } } }, 'Mute')

function renderCall (text, ...btns) {
  callBox.hidden = false
  const vids = el('div', { className: 'vids' }, media.remote, media.local); vids.hidden = !call.video
  callBox.replaceChildren(el('h3', {}, text), vids, el('div', { className: 'row' }, ...btns))
}

function endCall (notify, note) {
  if (notify && call.id) sig('hangup').catch(() => {})
  clearTimeout(call.timer)
  call.stream?.getTracks().forEach((t) => t.stop())
  call.pc?.close()
  media.local.srcObject = media.remote.srcObject = null
  Object.assign(call, { id: null, peer: null, pc: null, stream: null, offer: null, video: false, timer: 0 })
  callBox.replaceChildren(); callBox.hidden = !note
  if (note) { callBox.append(el('p', { className: note.err ? 'err' : 'dim' }, note.text)); setTimeout(() => { if (!call.id) callBox.hidden = true }, 5000) }
}

function newPc () {
  const pc = new RTCPeerConnection({ iceServers: (state.status.calls?.iceServers ?? []).map((urls) => ({ urls })) })
  pc.ontrack = (e) => { media.remote.srcObject = e.streams[0] }
  pc.onconnectionstatechange = () => { if (pc.connectionState === 'failed' && call.pc === pc) endCall(true, { err: true, text: 'Call failed: no route between you and this peer. If you are behind NAT, start the node with --ice-server stun:HOST.' }) }
  call.pc = pc
  return pc
}

/** Wait (max 4 s) for ICE gathering so the SDP carries every candidate: one offer, one answer, no trickle races. */
const gathered = (pc) => new Promise((resolve) => {
  if (pc.iceGatheringState === 'complete') return resolve()
  const done = () => { clearTimeout(t); pc.removeEventListener('icegatheringstatechange', ch); resolve() }
  const ch = () => { if (pc.iceGatheringState === 'complete') done() }
  const t = setTimeout(done, 4000)
  pc.addEventListener('icegatheringstatechange', ch)
})

async function getMedia (video) {
  if (!navigator.mediaDevices?.getUserMedia) throw new Error('Microphone and camera access is not available in this browser context.')
  call.stream = await navigator.mediaDevices.getUserMedia({ audio: true, video })
  media.local.srcObject = call.stream
}

async function startCall (peer, video) {
  if (call.id) return
  Object.assign(call, { id: crypto.randomUUID(), peer, video })
  try {
    await getMedia(video)
    const pc = newPc()
    for (const t of call.stream.getTracks()) pc.addTrack(t, call.stream)
    renderCall(`Calling ${short(peer)}…`, hangBtn())
    await pc.setLocalDescription(await pc.createOffer())
    await gathered(pc)
    await sig('offer', { sdp: pc.localDescription.sdp, video })
    const id = call.id
    call.timer = setTimeout(() => { if (call.id === id) endCall(true, { text: 'No answer.' }) }, 45000)
  } catch (e) { endCall(true, { err: true, text: 'Call failed: ' + e.message }) }
}

async function acceptCall () {
  clearTimeout(call.timer)
  try {
    await getMedia(call.video)
    const pc = newPc()
    for (const t of call.stream.getTracks()) pc.addTrack(t, call.stream)
    renderCall('Connecting…', hangBtn())
    await pc.setRemoteDescription({ type: 'offer', sdp: call.offer.sdp })
    await pc.setLocalDescription(await pc.createAnswer())
    await gathered(pc)
    await sig('answer', { sdp: pc.localDescription.sdp })
    renderCall(`In call with ${short(call.peer)}`, muteBtn(), hangBtn())
  } catch (e) { endCall(true, { err: true, text: 'Call failed: ' + e.message }) }
}

/** Signals arrive signed and attributed to the authenticated peer; only that peer can steer the call it started. */
async function onSignal (s) {
  try {
    const data = JSON.parse(s.data)
    if (s.kind === 'offer') {
      if (call.id || typeof data.sdp !== 'string') { await sig('decline', {}, s.peer, s.call); return }
      Object.assign(call, { id: s.call, peer: s.peer, offer: data, video: data.video === true })
      renderCall(`Incoming ${call.video ? 'video' : 'voice'} call from ${short(s.peer)}`,
        el('button', { className: 'btn', type: 'button', onclick: acceptCall }, 'Accept'),
        el('button', { className: 'btn', type: 'button', onclick: () => { sig('decline').catch(() => {}); endCall(false) } }, 'Decline'))
      const id = call.id
      call.timer = setTimeout(() => { if (call.id === id && !call.pc) { sig('decline').catch(() => {}); endCall(false, { text: 'Missed call.' }) } }, 60000)
      return
    }
    if (s.call !== call.id || s.peer !== call.peer) return
    if (s.kind === 'answer' && call.pc && typeof data.sdp === 'string') {
      clearTimeout(call.timer)
      await call.pc.setRemoteDescription({ type: 'answer', sdp: data.sdp })
      renderCall(`In call with ${short(call.peer)}`, muteBtn(), hangBtn())
    } else if (s.kind === 'ice' && call.pc) await call.pc.addIceCandidate(data)
    else if (s.kind === 'hangup') endCall(false, { text: 'Call ended.' })
    else if (s.kind === 'decline') endCall(false, { text: 'Call declined.' })
  } catch (e) { if (call.id) endCall(true, { err: true, text: 'Call failed: ' + e.message }) }
}

// ---- shared helpers for the Phase 3 views ----
const btn = (label, fn) => el('button', { className: 'btn', type: 'button', onclick: async (e) => {
  e.target.disabled = true
  try { await fn() } catch (x) { $('#view').querySelector('.err.top')?.remove(); $('#view').prepend(el('p', { className: 'err top' }, x.message)) } finally { e.target.disabled = false }
} }, label)
const ids = (text) => text.split(/[\s,]+/).filter(Boolean)
const delivery = (r) => r.failed?.length ? `Not delivered to ${r.failed.length} member(s) who were unreachable; messages are not queued.` : ''
const STATE_LABEL = { invited: 'invitation pending', joined: 'member', removed: 'removed by the owner', left: 'left' }

async function communities (v) {
  const me = state.status.peerId
  const all = await api('/api/communities')
  if (!all.some((c) => c.id === state.cid && c.state === 'joined')) state.cid = all.find((c) => c.state === 'joined')?.id ?? null
  if (state.note) { v.append(el('p', { className: 'dim' }, state.note)); state.note = '' }

  const name = el('input', { placeholder: 'community name', maxLength: 60, 'aria-label': 'Community name' })
  const picks = state.peers.map((p) => ({ p: p.peer, box: el('input', { type: 'checkbox', style: 'flex:none' }) }))
  const extra = el('input', { placeholder: 'other peer IDs, comma separated (optional)', 'aria-label': 'Other members' })
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Create a community'),
    el('p', { className: 'dim' }, 'You become its owner and are the only one who can change who is a member. Everyone you add must accept before they receive anything. Up to 100 members. Messages are signed and sent over encrypted peer links, but there is no group-wide end-to-end encryption.'),
    el('div', { className: 'row' }, name),
    ...picks.map(({ p, box }) => el('label', { className: 'row mono' }, box, p)), el('div', { className: 'row' }, extra),
    el('div', { className: 'row' }, btn('Create', async () => {
      const r = await api('/api/communities', { name: name.value, members: [...picks.filter((x) => x.box.checked).map((x) => x.p), ...ids(extra.value)] })
      state.cid = r.community.id; state.note = delivery(r); go('communities')
    }))))

  const list = el('div')
  for (const c of all) {
    const acts = el('div', { className: 'row' })
    if (c.state === 'invited') acts.append(btn('Join', async () => { await api('/api/communities/join', { id: c.id }); state.cid = c.id; go('communities') }))
    if (c.state === 'joined' && c.id !== state.cid) acts.append(btn('Open', async () => { state.cid = c.id; go('communities') }))
    if (c.state === 'invited' || c.state === 'joined') acts.append(btn(c.state === 'invited' ? 'Decline' : 'Leave', async () => { await api('/api/communities/leave', { id: c.id }); go('communities') }))
    list.append(el('div', { className: 'card' }, el('h3', {}, c.name), el('p', { className: 'dim' }, `${STATE_LABEL[c.state]} · ${c.members.length} members · owner ${c.owner === me ? 'you' : short(c.owner)}`), acts))
  }
  v.append(all.length ? list : el('p', { className: 'dim' }, 'No communities yet. Create one, or wait for an invitation.'))

  const sel = all.find((c) => c.id === state.cid)
  if (!sel) return
  const log = el('div', { className: 'msgs', role: 'log' }); const box = el('input', { placeholder: 'Write to the community', maxLength: 4000, 'aria-label': 'Community message' }); const perr = el('p', { className: 'err' })
  const load = async () => {
    const ms = await api('/api/communities/messages?id=' + sel.id)
    log.replaceChildren(...ms.map((m) => el('div', { className: 'm ' + (m.own ? 'out' : 'in') }, el('small', {}, `${m.own ? 'you' : short(m.author)} · ${new Date(m.ts).toLocaleTimeString()}`), m.text)))
    log.scrollTop = log.scrollHeight
  }
  const send = async () => {
    perr.textContent = ''
    if (!box.value) return
    try { const r = await api('/api/communities/post', { id: sel.id, text: box.value }); box.value = ''; perr.textContent = delivery(r); await load() } catch (e) { perr.textContent = e.message }
  }
  box.addEventListener('keydown', (e) => { if (e.key === 'Enter') send() })
  const members = el('div', {}, ...sel.members.map((m) => el('div', { className: 'mono' }, m + (m === sel.owner ? ' (owner)' : m === me ? ' (you)' : ''))))
  const card = el('div', { className: 'card' }, el('h3', {}, sel.name), log, el('div', { className: 'row' }, box, el('button', { className: 'btn', type: 'button', onclick: send }, 'Send')), perr,
    el('p', { className: 'dim' }, 'Each message is signed by its author and delivered directly to every member that is online. There is no relay or history sync: members who were offline miss it.'),
    el('h3', { style: 'margin-top:14px' }, 'Members'), members)
  if (sel.owner === me) {
    const mem = el('input', { value: sel.members.filter((m) => m !== me).join(', '), 'aria-label': 'Members (peer IDs)' })
    card.append(el('div', { className: 'row' }, mem, btn('Update members', async () => { const r = await api('/api/communities/members', { id: sel.id, members: ids(mem.value) }); state.note = delivery(r); go('communities') })))
  }
  v.append(card)
  await load()
  state.onGroup = (e) => { if (e.community === sel.id && e.kind === 'msg') load() }
  state.stop = () => { state.onGroup = null }
}

async function governance (v) {
  const me = state.status.peerId
  const joined = (await api('/api/communities')).filter((c) => c.state === 'joined')
  if (!joined.length) { v.append(el('div', { className: 'card' }, el('h3', {}, 'No communities'), el('p', { className: 'dim' }, 'Join or create a community under Communities first.'))); return }
  if (!joined.some((c) => c.id === state.cid)) state.cid = joined[0].id
  const pick = el('select', { 'aria-label': 'Community', onchange: () => { state.cid = pick.value; go('governance') } }, ...joined.map((c) => el('option', { value: c.id, selected: c.id === state.cid }, c.name)))
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Community'), el('div', { className: 'row' }, pick),
    el('p', { className: 'dim' }, 'One member, one vote. A proposal freezes the member list when it is first seen; your latest ballot counts; it needs more than half of those members to vote. Ballots are signed and checked by every node, but results are advisory: nothing here enforces them, and only the owner can change membership.')))

  const title = el('input', { placeholder: 'proposal title', maxLength: 80, 'aria-label': 'Proposal title' })
  const text = el('textarea', { rows: 3, maxLength: 2000, placeholder: 'details (optional)', 'aria-label': 'Proposal details' })
  const hours = el('select', { 'aria-label': 'Voting period' }, ...[[1, '1 hour'], [24, '1 day'], [72, '3 days'], [168, '7 days']].map(([h, l]) => el('option', { value: h }, l)))
  v.append(el('div', { className: 'card' }, el('h3', {}, 'New proposal'), el('div', { className: 'row' }, title), el('div', { className: 'row' }, text),
    el('div', { className: 'row' }, hours, btn('Propose', async () => { await api('/api/communities/propose', { id: state.cid, title: title.value, text: text.value, hours: Number(hours.value) }); go('governance') }))))

  const props = await api('/api/communities/proposals?id=' + state.cid)
  if (!props.length) v.append(el('p', { className: 'dim' }, 'No proposals yet.'))
  for (const p of props) {
    const t = p.tally; const seg = (n, c) => el('i', { style: `width:${(n / Math.max(t.electorate, 1)) * 100}%;background:${c}` })
    const status = p.open ? `open until ${new Date(p.closes).toLocaleString()}` : ({ passed: 'closed: passed', rejected: 'closed: rejected', 'no-quorum': 'closed: no quorum' })[t.outcome]
    const acts = el('div', { className: 'row' })
    if (p.open) for (const c of ['yes', 'no', 'abstain']) acts.append(btn(c[0].toUpperCase() + c.slice(1) + (p.myVote === c ? ' ✓' : ''), async () => { await api('/api/communities/vote', { id: state.cid, proposal: p.id, choice: c }); go('governance') }))
    v.append(el('div', { className: 'card' }, el('h3', {}, p.title), p.text ? el('p', {}, p.text) : '',
      el('p', { className: 'dim' }, `by ${p.author === me ? 'you' : short(p.author)} · ${status}`),
      el('div', { className: 'bar', role: 'img', 'aria-label': `${t.yes} yes, ${t.no} no, ${t.abstain} abstain of ${t.electorate}` }, seg(t.yes, 'var(--ok)'), seg(t.no, 'var(--bad)'), seg(t.abstain, 'var(--dim)')),
      el('p', { className: 'dim' }, `yes ${t.yes} · no ${t.no} · abstain ${t.abstain} · ${t.voted} of ${t.electorate} voted · quorum ${t.quorum ? 'met' : 'not met'}` + (p.myVote ? ` · you voted ${p.myVote}` : '')), acts))
  }
  state.onGroup = (e) => { if (e.community === state.cid && ['proposal', 'vote'].includes(e.kind)) go('governance') }
  state.stop = () => { state.onGroup = null }
}

async function nodes (v) {
  const s = state.status; const o = await api('/api/operator')
  const c = o.connections; const pr = o.process
  v.append(el('div', { className: 'grid' }, stat('Connections', `${c.total} (${c.inbound} in / ${c.outbound} out)`), stat('Relayed links', c.relayed),
    stat('Memory (RSS)', pr.rssMb + ' MB'), stat('Load (1m)', `${pr.loadAvg[0]} on ${pr.cpus} cores`), stat('Uptime', ago(pr.uptimeS * 1000)), stat('Storage', mb(s.blocks.bytes) + ' of ' + mb(s.blocks.quotaBytes))))
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Relay and retention'),
    el('p', {}, s.nat.relayServer ? 'Relay server: on (up to 64 reservations, 2 min / 2 MiB per relayed connection).' : 'Relay server: off. Start with --relay-server on a publicly reachable address to help NATed peers.'),
    el('p', { className: 'dim' }, `NAT traversal ${s.nat.enabled ? 'on' : 'off'} · ${s.nat.relayedAddresses.length} relayed address(es) · replicas expire after ${s.blocks.replicaTtlDays} days`),
    el('p', { className: 'dim' }, s.blocks.reannounceHours > 0 ? `Stored blocks are announced to the network again at start-up and every ${s.blocks.reannounceHours} h, so content stays findable after a restart or while its publisher is offline.` : 'Re-announcing is off (--reannounce-hours 0): content is only findable until the network forgets it.'),
    el('div', { className: 'row' }, btn('Sweep expired data now', async () => { const r = await api('/api/operator/sweep', {}); $('#view').querySelector('.err.top')?.remove(); $('#view').prepend(el('p', { className: 'dim top' }, `Removed ${r.removed} expired block(s).`)) }),
      btn('Re-announce stored blocks now', async () => { const r = await api('/api/operator/reannounce', {}); await refresh(); $('#view').querySelector('.err.top')?.remove(); $('#view').prepend(el('p', { className: 'dim top' }, `Announced ${r.ok} of ${r.total} stored block(s).`)) }))))

  const reason = el('input', { placeholder: 'ban reason (optional)', maxLength: 200, 'aria-label': 'Ban reason' })
  const t = el('table', {}, el('thead', {}, el('tr', {}, ...['Peer', 'Direction', 'Route', 'Latency', ''].map((h) => el('th', {}, h)))))
  const tb = el('tbody'); t.append(tb)
  for (const p of state.peers) {
    tb.append(el('tr', {}, el('td', { className: 'mono' }, p.peer), el('td', {}, p.direction), el('td', {}, p.relayed ? 'relayed' : 'direct'), el('td', {}, p.latencyMs == null ? '–' : p.latencyMs + ' ms'),
      el('td', {}, el('div', { className: 'row', style: 'margin:0' },
        btn('Disconnect', async () => { await api('/api/operator/disconnect', { peer: p.peer }); await refresh(); go('nodes') }),
        btn('Ban', async () => { if (!confirm('Ban this peer? Its connections are closed and new ones refused until you unban it.')) return; await api('/api/operator/ban', { peer: p.peer, reason: reason.value }); await refresh(); go('nodes') })))))
  }
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Connected peers'), state.peers.length ? el('div', {}, t, el('div', { className: 'row' }, reason)) : el('p', { className: 'dim' }, 'No peers connected.')))

  const bt = el('table', {}, el('thead', {}, el('tr', {}, ...['Banned peer', 'Reason', 'Since', ''].map((h) => el('th', {}, h)))))
  const bb = el('tbody'); bt.append(bb)
  for (const b of o.bans) bb.append(el('tr', {}, el('td', { className: 'mono' }, b.peer), el('td', {}, b.reason || '–'), el('td', {}, new Date(b.ts).toLocaleString()), el('td', {}, btn('Unban', async () => { await api('/api/operator/unban', { peer: b.peer }); go('nodes') }))))
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Ban list'), o.bans.length ? bt : el('p', { className: 'dim' }, 'No banned peers. Bans are stored on this node and survive restarts.')))

  const dk = Object.entries(o.drops)
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Rejected traffic (since start)'), dk.length ? el('table', {}, el('tbody', {}, ...dk.sort((a, b) => b[1] - a[1]).map(([k, n]) => el('tr', {}, el('td', {}, k), el('td', {}, String(n)))))) : el('p', { className: 'dim' }, 'Nothing rejected.')))
}

const CATEGORY_LABEL = { illegal: 'Illegal content', 'child-safety': 'Child safety', malware: 'Malware', phishing: 'Phishing or scam', harassment: 'Harassment', spam: 'Spam', other: 'Other' }
const KIND_LABEL = { cid: 'File, site or block (content ID)', name: 'Name', publisher: 'Publisher key' }
/** What happened about the key of an encrypted file when something was blocked (a key is never stored). */
const keyNote = (s) => s === 'used' ? ' The key was used once to list and block every chunk, and was not saved.'
  : s === 'manifest-not-held' ? ' The file’s encrypted manifest is not on this node and no peer could provide it just now, so its chunks could not be listed: only the file ID is blocked. Use “Add key” on its blocklist entry to try again later.'
  : s === 'key-needed' ? ' This block could not be read without a key. If it is an encrypted file, only its ID is blocked and its chunks stay stored here until they expire. Use “Add key” on its blocklist entry to block them too.' : ''
/** The file key in pasted text: a bare 43-character key, or a link that ends in #key. */
const fileKeyFrom = (t) => (/(?:^|#)([A-Za-z0-9_-]{43})\s*$/.exec(t.trim()) || [])[1]

async function safety (v) {
  const m = await api('/api/moderation')
  if (state.note) { v.append(el('p', { className: 'dim' }, state.note)); state.note = '' }
  v.append(el('div', { className: 'grid' }, stat('Blocklist entries', m.blocklist.length), stat('Open reports', m.reports.filter((r) => r.status === 'open').length)))
  v.append(el('div', { className: 'card' }, el('h3', {}, 'You host what you store'),
    el('p', { className: 'dim' }, 'This node stores and serves content other people published, and nobody else can take it down for you. A block applies to this node only: it deletes the local copies, stops advertising them, and refuses to store, fetch, serve or open the same content again (matching is by exact hash, so an altered copy needs its own block). Nothing is sent anywhere: reports stay on this device. If you find illegal content, child sexual abuse material above all, also report it to your national hotline (see inhope.org) and to the authorities where the law requires it, and do not copy or forward the content itself.')))

  const pre = state.report; state.report = null
  const kind = el('select', { 'aria-label': 'What you are reporting' }, ...Object.entries(KIND_LABEL).map(([k, l]) => el('option', { value: k, selected: pre?.kind === k }, l)))
  const cat = el('select', { 'aria-label': 'Category' }, ...m.categories.map((c) => el('option', { value: c }, CATEGORY_LABEL[c] ?? c)))
  const target = el('input', { placeholder: 'frenet://…  frenet-site://…  frenet-name://name.key  or a publisher key', value: pre?.target ?? '', 'aria-label': 'Link or ID' })
  const note = el('textarea', { rows: 2, maxLength: 500, placeholder: 'what you saw (optional). Do not paste decryption keys or the content itself.', 'aria-label': 'Note' })
  const also = el('input', { type: 'checkbox', checked: true, style: 'flex:none' })
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Report content'),
    el('div', { className: 'row' }, kind, cat), el('div', { className: 'row' }, target), el('div', { className: 'row' }, note),
    el('label', { className: 'row' }, also, 'Also block it on this node now (deletes local copies, including the files of a site)'),
    el('p', { className: 'dim' }, 'A report never stores a file’s decryption key: the #key part of a link is dropped. If you tick “also block” and paste the full link of an encrypted file, the key is used once to find and block every chunk, then discarded. Reports are signed by this node’s identity, so you can pass one on and others can check it is genuine.'),
    el('div', { className: 'row' }, btn('File report', async () => {
      const r = await api('/api/moderation/report', { kind: kind.value, target: target.value, category: cat.value, note: note.value, block: also.checked })
      state.note = r.purged === null ? 'Report filed.' : `Report filed and blocked: ${r.purged} stored block(s) deleted.` + keyNote(r.keyStatus)
      go('safety')
    }))))

  const rt = el('table', {}, el('thead', {}, el('tr', {}, ...['When', 'Type', 'Target', 'Category', 'Note', 'Status', ''].map((h) => el('th', {}, h)))))
  const rb = el('tbody'); rt.append(rb)
  for (const r of m.reports) {
    const acts = el('div', { className: 'row', style: 'margin:0' })
    if (r.status === 'open') {
      acts.append(
        btn('Block', async () => {
          if (!confirm('Block this on your node? Local copies are deleted and cannot be restored except by fetching them again after you unblock.')) return
          let key
          if (r.kind === 'cid') {
            // Chunks of an encrypted file can only be listed with its key, which a report never keeps, so ask now (it can also be added later from the blocklist).
            const typed = prompt('Is this an encrypted file? Paste its key (the part of the link after #, or the whole link) so every chunk is blocked too. It is used once and not saved. Leave empty to block the file ID only; you can add the key later from the blocklist.')
            if (typed === null) return
            if (typed.trim()) {
              key = fileKeyFrom(typed)
              if (!key) { alert('That does not look like a file key: it is 43 characters, the part of the link after #.'); return }
            }
          }
          const x = await api('/api/moderation/resolve', { id: r.id, action: 'block', key })
          state.note = `Blocked: ${x.purged} stored block(s) deleted.` + keyNote(x.keyStatus); go('safety')
        }),
        btn('Dismiss', async () => { await api('/api/moderation/resolve', { id: r.id, action: 'dismiss' }); go('safety') }))
    }
    acts.append(el('button', { className: 'btn', type: 'button', onclick: async (e) => {
      try { await navigator.clipboard.writeText(JSON.stringify(r, null, 2)); e.target.textContent = 'Copied' } catch { e.target.textContent = 'Copy failed' }
    } }, 'Copy signed report'))
    rb.append(el('tr', {}, el('td', {}, new Date(r.ts).toLocaleString()), el('td', {}, r.kind), el('td', { className: 'mono' }, r.target), el('td', {}, CATEGORY_LABEL[r.category] ?? r.category), el('td', {}, r.note || '–'), el('td', {}, r.status), el('td', {}, acts)))
  }
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Reports'), m.reports.length ? rt : el('p', { className: 'dim' }, 'No reports. Use Report on a search result, or the form above.')))

  const bt = el('table', {}, el('thead', {}, el('tr', {}, ...['Type', 'Blocked', 'Reason', 'Since', 'Also covers', ''].map((h) => el('th', {}, h)))))
  const bb = el('tbody'); bt.append(bb)
  for (const b of m.blocklist) {
    bb.append(el('tr', {}, el('td', {}, b.kind), el('td', { className: 'mono' }, b.target), el('td', {}, b.reason || '–'), el('td', {}, new Date(b.ts).toLocaleString()), el('td', {}, b.derived ? `${b.derived} related item(s)` : '–'),
      el('td', {}, el('div', { className: 'row', style: 'margin:0' },
        ...(b.kind === 'cid' ? [btn('Add key', async () => {
          // For an encrypted file that was blocked without its key: the key opens the manifest (fetched from a peer if this node no longer has it) so every chunk gets blocked too.
          const typed = prompt('Paste the file’s key (the part of its link after #, or the whole link) to block every chunk of this encrypted file. It is used once and not saved.')
          if (typed === null || !typed.trim()) return
          const key = fileKeyFrom(typed)
          if (!key) { alert('That does not look like a file key: it is 43 characters, the part of the link after #.'); return }
          const x = await api('/api/moderation/block', { kind: 'cid', target: b.target, key })
          state.note = `Key applied: ${x.purged} more stored block(s) deleted.` + keyNote(x.keyStatus); go('safety')
        })] : []),
        btn('Unblock', async () => { await api('/api/moderation/unblock', { kind: b.kind, target: b.target }); go('safety') })))))
  }
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Blocklist'), m.blocklist.length ? bt : el('p', { className: 'dim' }, 'Nothing blocked. The blocklist is stored on this node and survives restarts. Unblocking lifts the entry and everything it pulled in, but deleted data is gone until it is fetched again.')))
}

// ---- Anonymous Auth: zero-knowledge membership proofs (linkable ring proofs, see SECURITY.md for what they do not hide) ----
function anon (v) {
  const MIN = 5
  const ta = (ph, rows, extra = {}) => el('textarea', { rows, placeholder: ph, spellcheck: false, className: 'mono', ...extra })
  const ring = ta('One DID (did:key:z6Mk…) or Ed25519 peer ID per line. The people who could have signed.', 6, { 'aria-label': 'Ring members' })
  const scope = el('input', { placeholder: 'scope, e.g. vote:42 (one tag per member per scope)', 'aria-label': 'Scope' })
  const audience = el('input', { placeholder: 'audience (optional): who this proof is for', 'aria-label': 'Audience' })
  const nonce = el('input', { placeholder: 'challenge from the verifier', 'aria-label': 'Challenge' })
  const minRing = el('input', { type: 'number', min: 2, max: 1024, value: String(MIN), 'aria-label': 'Minimum ring size', style: 'max-width:90px' })
  const proof = ta('proof (base64url)', 4, { 'aria-label': 'Proof' })
  const once = el('input', { type: 'checkbox', checked: true, style: 'flex:none' })
  const out = el('p', { className: 'dim', role: 'status' })
  const info = el('p', { className: 'dim' })
  const lines = () => ring.value.split('\n').map((l) => l.trim()).filter(Boolean)
  const say = (t, bad) => { out.textContent = t; out.style.color = bad ? '#ff6b81' : '' }
  const run = (fn) => async () => { try { await fn() } catch (e) { say(e.message, true) } }
  const describe = run(async () => {
    if (lines().length === 0) { info.textContent = ''; return }
    const r = await api('/api/zk/ring', { ring: lines() })
    const warn = r.ringSize < Number(minRing.value) ? ` Too small for your minimum of ${minRing.value}: a small ring hides little.` : ''
    info.textContent = `${r.ringSize} distinct members · fingerprint ${r.ringId.slice(0, 16)} · ${r.includesMe ? 'you are in this ring' : 'you are NOT in this ring (you can verify but not prove)'}.${warn} Check the fingerprint with the verifier: it changes if anyone is added or swapped.`
  })
  ring.onchange = describe; minRing.onchange = describe
  const params = () => ({ ring: lines(), scope: scope.value, nonce: nonce.value, minRing: Number(minRing.value), ...(audience.value ? { audience: audience.value } : {}) })

  v.append(el('div', { className: 'card' }, el('h3', {}, 'Prove you belong, without saying who you are'),
    el('p', { className: 'dim' }, 'A zero-knowledge membership proof shows you hold the key of one identity in a group without revealing which. The verifier learns that you are in the ring and a tag that is the same every time you act in this scope (so “once each” can be enforced) but cannot be linked to your tags in other scopes or to your identity. Your key never leaves this node. Anonymity is only as big as the ring: with few members, or a ring the verifier padded with keys of nobody, it hides little. It is not a general zero-knowledge system and has not been independently audited.')))
  v.append(el('div', { className: 'card' }, el('h3', {}, '1 · The ring'),
    el('div', { className: 'row' }, ring),
    el('div', { className: 'row' },
      btn('Add my DID', async () => { ring.value = (ring.value.trim() + '\n' + state.status.did).trim(); await describe() }),
      btn('Add connected peers', async () => { ring.value = (ring.value.trim() + '\n' + state.peers.map((p) => p.peer).join('\n')).trim(); await describe() }),
      el('label', { className: 'dim' }, 'minimum size ', minRing)),
    info))
  v.append(el('div', { className: 'card' }, el('h3', {}, '2 · Scope and challenge'),
    el('div', { className: 'row' }, scope), el('div', { className: 'row' }, audience),
    el('div', { className: 'row' }, nonce, btn('New challenge (I am the verifier)', run(async () => { nonce.value = (await api('/api/zk/challenge', {})).nonce; say('Challenge issued by this node: valid once, for 2 minutes. Give it to the prover.') }))),
    el('p', { className: 'dim' }, 'A challenge ties a proof to one request, so a copy of it is worthless later or elsewhere.')))
  v.append(el('div', { className: 'card' }, el('h3', {}, '3 · Prove or verify'),
    el('div', { className: 'row' }, proof),
    el('div', { className: 'row' },
      btn('Prove (I am the prover)', run(async () => {
        const r = await api('/api/zk/prove', params())
        proof.value = r.proof
        say(`Proof made over ${r.ringSize} members (ring ${r.ringId.slice(0, 16)}). Your tag in this scope: ${r.tag.slice(0, 16)}… It does not identify you, but it is the same each time you act in this scope.`)
      })),
      btn('Verify', run(async () => {
        const r = await api('/api/zk/verify', { ...params(), proof: proof.value.trim(), once: once.checked })
        if (r.valid) say(`Valid: a member of this ring of ${r.ringSize} signed, and no one can tell which. Tag ${r.tag.slice(0, 16)}…${once.checked ? ' Recorded: this member cannot act again in this scope.' : ''}`)
        else say(`Not valid: ${r.error}`, true)
      })),
      el('label', { className: 'row', style: 'margin:0' }, once, 'record the tag (once per scope)')),
    out,
    el('div', { className: 'row' }, btn('Forget this scope’s tags', run(async () => { const r = await api('/api/zk/forget', { scope: scope.value }); say(`Forgot ${r.removed} tag(s) in this scope.`) })))))
}

async function refresh () {
  try {
    const before = state.peers.map((p) => p.peer).join()
    ;[state.status, state.peers] = await Promise.all([api('/api/status'), api('/api/peers')])
    $('#me').textContent = state.status.peerId
    const changed = before !== state.peers.map((p) => p.peer).join()
    if (state.view === 'overview' || (changed && ['peers', 'messages', 'nodes'].includes(state.view))) go(state.view)
  } catch { /* shown via live indicator */ }
}

function connectEvents () {
  const live = $('#live')
  const es = new EventSource('/api/events')
  es.onopen = () => { live.textContent = 'node online'; live.className = 'live on' }
  es.onerror = () => { live.textContent = 'node unreachable'; live.className = 'live off' }
  es.addEventListener('peer', refresh)
  es.addEventListener('message', (e) => { const m = JSON.parse(e.data); if (state.onMessage && !(m.direction === 'out' && state.chat.some((c) => c.id === m.id))) state.onMessage(m) })
  es.addEventListener('signal', (e) => onSignal(JSON.parse(e.data)))
  es.addEventListener('group', (e) => state.onGroup?.(JSON.parse(e.data)))
  es.addEventListener('community', () => { if (['communities', 'governance'].includes(state.view)) go(state.view) })
  es.addEventListener('dropped', (e) => { state.dropped.push(JSON.parse(e.data)); if (state.view === 'security') go('security') })
}

await refresh(); go('overview'); connectEvents(); setInterval(refresh, 5000)

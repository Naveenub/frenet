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
  ['identity', 'Identity and Keys'], ['nodes', 'Network Nodes'],
  ['privacy', 'Privacy Center'], ['security', 'Security Center'], ['governance', 'Community Governance']
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
  ;({ overview, peers, messages, communities, storage, browser, identity, nodes, privacy, security, governance })[id](v)
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
    el('div', { className: 'row' }, pick), el('div', { className: 'row' }, name, title), el('div', { className: 'row' }, kws), el('div', { className: 'row' }, ttl, pub), msg, out))

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
          el('p', { className: 'dim' }, `version ${h.seq} · ${h.keywords.join(', ')}`)))
      }
    } catch (e) { smsg.textContent = ''; sres.append(el('p', { className: 'err' }, e.message)) }
  }
  v.append(el('div', { className: 'card' }, el('h3', {}, 'Search'), el('div', { className: 'row' }, q, el('button', { className: 'btn', type: 'button', onclick: doSearch }, 'Search')), smsg,
    el('p', { className: 'dim' }, 'Matches names, titles and keywords that publishers announced on the network, checking each record’s signature. There is no central index and no ranking, so treat results as unvetted: anyone can publish under any keyword.'), sres))

  api('/api/names').then((r) => {
    const mine = r.names.filter((n) => n.own)
    if (!mine.length) return
    const card = el('div', { className: 'card' }, el('h3', {}, 'Your names'))
    for (const n of mine) card.append(el('p', {}, el('a', { href: `http://${n.name}.${n.pub}.localhost:${gw}/`, target: '_blank', rel: 'noopener noreferrer' }, n.name), ` · version ${n.seq}`), el('div', { className: 'mono' }, n.link))
    v.append(card)
  }).catch(() => {})
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
    el('p', { className: 'dim' }, 'You become its owner and are the only one who can change who is a member. Everyone you add must accept before they receive anything. Up to 100 members.'),
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
    el('div', { className: 'row' }, btn('Sweep expired data now', async () => { const r = await api('/api/operator/sweep', {}); $('#view').querySelector('.err.top')?.remove(); $('#view').prepend(el('p', { className: 'dim top' }, `Removed ${r.removed} expired block(s).`)) }))))

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

import type { Store } from './store.js'

/**
 * Tracker blocking for the web proxy (see webproxy.ts).
 *
 * The proxy tunnels TLS end to end and never decrypts it, so blocking works on the **host name** a browser asks to
 * reach, not on URLs, cookies or page content. A blocked host is refused before any DNS lookup, so it also learns
 * nothing about you. Matching is by domain suffix on a label boundary: `doubleclick.net` blocks `ad.doubleclick.net`
 * but not `notdoubleclick.net`.
 *
 * Three layers, strongest last: the built-in list below, the user's own block rules, and the user's allow rules.
 * An allow rule beats everything (so a broken site can be fixed), and a user block rule beats the built-in list's
 * absence. The built-in list is short and hand-picked (large, well-known cross-site trackers and ad networks); it is
 * not a substitute for a maintained list and will miss most trackers. Add your own with `block`.
 */
export const BUILTIN_TRACKERS: readonly string[] = [
  // Google / Alphabet advertising and measurement
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'google-analytics.com', 'googletagmanager.com', 'googletagservices.com', 'adservice.google.com', 'app-measurement.com', 'admob.com', 'adsense.com', 'analytics.google.com', 'stats.g.doubleclick.net', '2mdn.net', 'adgoogle.net',
  // Meta, Microsoft, X, LinkedIn, TikTok, Snap, Pinterest, Reddit, Yahoo, Amazon, Apple/Verizon ads
  'connect.facebook.net', 'pixel.facebook.com', 'facebook.net', 'an.facebook.com', 'analytics.twitter.com', 'ads-twitter.com', 'ads-api.twitter.com', 'ads.linkedin.com', 'px.ads.linkedin.com', 'snap.licdn.com', 'analytics.tiktok.com', 'ads.tiktok.com', 'business-api.tiktok.com', 'sc-static.net', 'tr.snapchat.com', 'ads.snapchat.com', 'ct.pinterest.com', 'analytics.pinterest.com', 'ads.pinterest.com', 'events.redditmedia.com', 'alb.reddit.com', 'ads.reddit.com', 'analytics.yahoo.com', 'ads.yahoo.com', 'advertising.com', 'bat.bing.com', 'clarity.ms', 'ads.microsoft.com', 'amazon-adsystem.com', 'aax.amazon-adsystem.com', 'advertising.amazon.com',
  // Ad exchanges, DSPs, SSPs, retargeting
  'adnxs.com', 'adsrvr.org', 'criteo.com', 'criteo.net', 'taboola.com', 'outbrain.com', 'revcontent.com', 'mgid.com', 'rubiconproject.com', 'pubmatic.com', 'openx.net', 'casalemedia.com', 'indexww.com', 'smartadserver.com', 'sharethrough.com', 'triplelift.com', 'media.net', 'bidswitch.net', 'contextweb.com', 'lijit.com', 'sovrn.com', 'yieldmo.com', 'gumgum.com', 'adform.net', 'adition.com', 'teads.tv', 'spotxchange.com', 'springserve.com', 'tapad.com', 'bluekai.com', 'krxd.net', 'exelator.com', 'eyeota.net', 'rlcdn.com', 'liveramp.com', 'agkn.com', 'mathtag.com', 'turn.com', 'serving-sys.com', 'flashtalking.com', 'adroll.com', 'perfectaudience.com', 'rfihub.com', 'everesttech.net', 'adtechus.com', 'adtech.de', 'advertising.io', 'yieldlab.net', 'ml314.com', '33across.com', 'permutive.com', 'id5-sync.com', 'uidapi.com',
  // Measurement, audience, session replay, product analytics, fingerprinting
  'scorecardresearch.com', 'quantserve.com', 'quantcount.com', 'chartbeat.com', 'chartbeat.net', 'parsely.com', 'newrelic.com', 'nr-data.net', 'hotjar.com', 'hotjar.io', 'mixpanel.com', 'segment.io', 'segment.com', 'amplitude.com', 'heap.io', 'heapanalytics.com', 'fullstory.com', 'mouseflow.com', 'crazyegg.com', 'luckyorange.com', 'luckyorange.net', 'inspectlet.com', 'smartlook.com', 'logrocket.com', 'logrocket.io', 'sessioncam.com', 'clicktale.net', 'contentsquare.net', 'moatads.com', 'doubleverify.com', 'adsafeprotected.com', 'iasds01.com', 'omtrdc.net', 'demdex.net', '2o7.net', 'btstatic.com', 'bounceexchange.com', 'tags.tiqcdn.com', 'tealiumiq.com', 'ensighten.com', 'mookie1.com', 'branch.io', 'adjust.com', 'appsflyer.com', 'kochava.com', 'singular.net', 'braze.com', 'onesignal.com', 'optimizely.com', 'abtasty.com', 'vwo.com', 'visualwebsiteoptimizer.com', 'cdn.mxpnl.com', 'cloudflareinsights.com', 'stats.wp.com', 'pixel.wp.com', 'pippio.com', 'bizible.com', 'marketo.net', 'mktoresp.com', 'pardot.com', 'hubspot.com', 'hs-analytics.net', 'hs-scripts.com', 'hsadspixel.net', 'hsleadflows.net', 'intercom.io', 'drift.com', 'zdassets.com',
  // Telemetry/trackers of widely used platforms
  'sentry.io', 'bugsnag.com', 'datadoghq.com', 'browser-intake-datadoghq.com', 'mc.yandex.ru', 'metrika.yandex.ru', 'an.yandex.ru', 'top-fwz1.mail.ru', 'counter.yadro.ru', 'hm.baidu.com', 'cnzz.com', 'umeng.com'
]

const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
export const MAX_TRACKER_RULES = 300_000
export const MAX_IMPORT_BYTES = 8 * 1024 * 1024

/** Lower-case, strip one trailing dot, require a dotted DNS name. Returns null for anything else (IP literals included). */
export function normalizeHost (input: unknown): string | null {
  if (typeof input !== 'string') return null
  const h = input.trim().toLowerCase().replace(/\.$/, '')
  return HOST_RE.test(h) && !/^\d+(?:\.\d+)*$/.test(h) ? h : null
}

export type TrackerVerdict = { blocked: false } | { blocked: true, reason: 'builtin' | 'user', rule: string }

export class TrackerBlocker {
  private block = new Set<string>()
  private allow = new Set<string>()
  readonly counters = { blocked: 0, allowedOverrides: 0 }
  /** In memory only, never persisted: the last hosts that were refused (clearable). */
  private recent: Array<{ host: string, at: number, rule: string }> = []
  private builtin = new Set(BUILTIN_TRACKERS)

  constructor (private store: Store) {
    // Rows can come from an imported archive: keep only well-formed hosts.
    for (const r of store.listTrackerRules()) if (normalizeHost(r.host) === r.host) (r.action === 'block' ? this.block : this.allow).add(r.host)
  }

  /** The rule that covers `host` in `set`, matched on a label boundary, most specific first. */
  private match (set: Set<string>, host: string): string | null {
    let h = host
    for (;;) {
      if (set.has(h)) return h
      const i = h.indexOf('.')
      if (i < 0) return null
      h = h.slice(i + 1)
    }
  }

  check (host: string): TrackerVerdict {
    const h = normalizeHost(host)
    if (!h) return { blocked: false }
    const user = this.match(this.block, h)
    const builtin = user ? null : this.match(this.builtin, h)
    if (!user && !builtin) return { blocked: false }
    if (this.match(this.allow, h)) { this.counters.allowedOverrides++; return { blocked: false } }
    return { blocked: true, reason: user ? 'user' : 'builtin', rule: (user ?? builtin)! }
  }

  /** check() plus bookkeeping: counts the refusal and remembers the host (in memory) for the dashboard. */
  refuse (host: string): TrackerVerdict {
    const v = this.check(host)
    if (v.blocked) {
      this.counters.blocked++
      this.recent.unshift({ host: normalizeHost(host)!, at: Date.now(), rule: v.rule })
      if (this.recent.length > 50) this.recent.length = 50
    }
    return v
  }

  addRule (hostInput: unknown, action: 'block' | 'allow'): string {
    const host = normalizeHost(hostInput)
    if (!host) throw new Error('not a valid domain name (e.g. ads.example.com)')
    if (this.block.size + this.allow.size >= MAX_TRACKER_RULES && !this.block.has(host) && !this.allow.has(host)) throw new Error('too many rules')
    this.block.delete(host); this.allow.delete(host)
    ;(action === 'block' ? this.block : this.allow).add(host)
    this.store.setTrackerRule(host, action)
    return host
  }

  removeRule (hostInput: unknown): boolean {
    const host = normalizeHost(hostInput)
    if (!host) return false
    this.block.delete(host); this.allow.delete(host)
    return this.store.removeTrackerRule(host)
  }

  /**
   * Add a maintained blocklist the user obtained themselves (the node never downloads one). Accepted per line:
   * hosts format (`0.0.0.0 ads.example.com`, `127.0.0.1 ...`), a bare domain, or an Adblock domain rule (`||ads.example.com^`).
   * Comments (`#`, `!`), cosmetic/URL rules and anything that is not a plain domain are skipped and counted. Domains the user
   * has an allow rule for are never overridden. Nothing is fetched and nothing leaves the machine.
   */
  importList (text: unknown): { added: number, skipped: number, total: number } {
    if (typeof text !== 'string') throw new Error('list must be text')
    if (Buffer.byteLength(text) > MAX_IMPORT_BYTES) throw new Error(`list is larger than ${MAX_IMPORT_BYTES} bytes`)
    const hosts = new Set<string>(); let skipped = 0
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/\s+#.*$/, '').trim()
      if (!line || line.startsWith('#') || line.startsWith('!') || line.startsWith('[')) continue
      let cand: string | undefined
      const adb = /^\|\|([a-z0-9.-]+)\^(?:\$third-party)?$/i.exec(line)
      const parts = line.split(/\s+/)
      if (adb) cand = adb[1]
      else if (parts.length === 2 && /^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(parts[0]!)) cand = parts[1]
      else if (parts.length === 1) cand = parts[0]
      const h = normalizeHost(cand)
      if (!h || h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.arpa')) { skipped++; continue }
      if (!this.allow.has(h) && !this.block.has(h)) hosts.add(h)
    }
    if (this.block.size + this.allow.size + hosts.size > MAX_TRACKER_RULES) throw new Error(`too many rules (max ${MAX_TRACKER_RULES})`)
    const list = [...hosts]
    this.store.setTrackerRules(list, 'block')
    for (const h of list) this.block.add(h)
    return { added: list.length, skipped, total: this.block.size }
  }

  /** Remove every rule of one kind (e.g. an imported list you no longer want). */
  clearRules (action: 'block' | 'allow'): number {
    ;(action === 'block' ? this.block : this.allow).clear()
    return this.store.clearTrackerRules(action)
  }

  clearRecent (): void { this.recent = [] }

  snapshot (): { builtinCount: number, rules: Array<{ host: string, action: 'block' | 'allow' }>, ruleCount: number, blocked: number, allowedOverrides: number, recent: Array<{ host: string, at: number, rule: string }> } {
    return {
      builtinCount: this.builtin.size,
      rules: this.store.listTrackerRules().slice(0, 200).map((r) => ({ host: r.host, action: r.action })),
      ruleCount: this.store.countTrackerRules(),
      blocked: this.counters.blocked,
      allowedOverrides: this.counters.allowedOverrides,
      recent: [...this.recent]
    }
  }
}

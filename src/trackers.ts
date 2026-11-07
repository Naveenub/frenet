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
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
  'adservice.google.com', 'connect.facebook.net', 'pixel.facebook.com', 'facebook.net', 'analytics.twitter.com', 'ads-twitter.com',
  'static.ads-twitter.com', 'ads.linkedin.com', 'analytics.tiktok.com', 'ads.tiktok.com', 'analytics.yahoo.com', 'ads.yahoo.com',
  'adnxs.com', 'adsrvr.org', 'criteo.com', 'criteo.net', 'taboola.com', 'outbrain.com', 'scorecardresearch.com', 'quantserve.com',
  'hotjar.com', 'mixpanel.com', 'segment.io', 'fullstory.com', 'mouseflow.com', 'crazyegg.com', 'bat.bing.com', 'clarity.ms',
  'amazon-adsystem.com', 'rubiconproject.com', 'pubmatic.com', 'openx.net', 'casalemedia.com', 'moatads.com', 'omtrdc.net', 'demdex.net'
]

const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
export const MAX_TRACKER_RULES = 5000

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
    for (const r of store.listTrackerRules()) (r.action === 'block' ? this.block : this.allow).add(r.host)
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

  clearRecent (): void { this.recent = [] }

  snapshot (): { builtinCount: number, rules: Array<{ host: string, action: 'block' | 'allow' }>, blocked: number, allowedOverrides: number, recent: Array<{ host: string, at: number, rule: string }> } {
    return {
      builtinCount: this.builtin.size,
      rules: this.store.listTrackerRules().map((r) => ({ host: r.host, action: r.action })),
      blocked: this.counters.blocked,
      allowedOverrides: this.counters.allowedOverrides,
      recent: [...this.recent]
    }
  }
}

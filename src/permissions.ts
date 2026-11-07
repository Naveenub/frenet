import { NAME_RE, validPub } from './names.js'
import { validCid } from './sites.js'
import type { Store } from './store.js'

/**
 * Transparent permission management for sites served by the gateway.
 *
 * Every FRENET site is its own browser origin and starts with **nothing**: the gateway sends a `Permissions-Policy`
 * that switches every powerful feature off. This manager is the only way to switch one on, per origin and per
 * feature, and it is all visible in the dashboard: what each origin may use, since when, and a one-click revoke.
 *
 * What a grant does, exactly: it changes the `Permissions-Policy` the gateway sends for that origin from `feature=()`
 * to `feature=(self)`, so the site's own page is *allowed to ask*. The browser still shows its own prompt (camera,
 * microphone, location) and the user can still say no there; FRENET adds a second, earlier gate, not a bypass. A grant
 * never extends to embedded frames (the CSP already forbids framing and any third-party load).
 *
 * Origins are `site:<site CID>` (one exact version of a site) or `name:<name>.<publisher key>` (a mutable name, which
 * keeps its grants when the publisher updates it: grant only to names whose publisher you trust to stay trustworthy).
 */
export const PERMISSION_FEATURES = ['camera', 'microphone', 'geolocation', 'fullscreen', 'clipboard-write', 'display-capture'] as const
export type PermissionFeature = (typeof PERMISSION_FEATURES)[number]

/** Always off, never grantable: advertising/profiling and hardware access FRENET has no use case for. */
const ALWAYS_OFF = ['interest-cohort', 'browsing-topics', 'payment', 'usb', 'serial', 'bluetooth', 'hid'] as const

export function isFeature (f: unknown): f is PermissionFeature { return typeof f === 'string' && (PERMISSION_FEATURES as readonly string[]).includes(f) }

/** `site:<cid>` or `name:<name>.<pub>`; the same strings the gateway derives from the Host header. */
export function validOrigin (o: unknown): o is string {
  if (typeof o !== 'string' || o.length > 200) return false
  if (o.startsWith('site:')) return validCid(o.slice(5))
  if (o.startsWith('name:')) {
    const m = /^([a-z0-9-]{1,63})\.([a-z2-7]{52})$/.exec(o.slice(5))
    return !!m && NAME_RE.test(m[1]!) && validPub(m[2]!)
  }
  return false
}

export const siteOrigin = (cid: string): string => `site:${cid}`
export const nameOrigin = (name: string, pub: string): string => `name:${name}.${pub}`

export class SitePermissions {
  constructor (private store: Store) {}

  granted (origin: string): PermissionFeature[] {
    return this.store.listPermissions(origin).map((r) => r.feature).filter(isFeature)
  }

  /** The Permissions-Policy header value the gateway sends for this origin. */
  policy (origin: string): string {
    const on = new Set(this.granted(origin))
    return [...PERMISSION_FEATURES.map((f) => `${f}=${on.has(f) ? '(self)' : '()'}`), ...ALWAYS_OFF.map((f) => `${f}=()`)].join(', ')
  }

  grant (origin: unknown, feature: unknown): void {
    if (!validOrigin(origin)) throw new Error('invalid origin (site:<id> or name:<name>.<publisher-key>)')
    if (!isFeature(feature)) throw new Error(`unknown permission (one of: ${PERMISSION_FEATURES.join(', ')})`)
    this.store.grantPermission(origin, feature)
  }

  revoke (origin: unknown, feature: unknown): boolean {
    if (!validOrigin(origin) || !isFeature(feature)) return false
    return this.store.revokePermission(origin, feature)
  }

  /** Remove every grant of an origin. Returns how many were removed. */
  reset (origin: unknown): number { return validOrigin(origin) ? this.store.revokeAllPermissions(origin) : 0 }

  list (): Array<{ origin: string, grants: Array<{ feature: PermissionFeature, since: number }> }> {
    const by = new Map<string, Array<{ feature: PermissionFeature, since: number }>>()
    for (const r of this.store.listPermissions()) if (isFeature(r.feature)) { const l = by.get(r.origin) ?? []; l.push({ feature: r.feature, since: r.ts }); by.set(r.origin, l) }
    return [...by].map(([origin, grants]) => ({ origin, grants }))
  }
}

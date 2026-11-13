// Pure formatting helpers: sizes, rates, times and the block meters the terminal look uses.
import type { TFn } from './i18n'

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'] as const
export const DASH = '–'

/** Binary units, as the server counts traffic: 1536 → "1.5 KB". */
export function bytes(n: number | null | undefined, digits = 1): string {
  if (n == null || !Number.isFinite(n) || n < 0) return DASH
  let value = n
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit++
  }
  const places = unit === 0 || value >= 100 ? 0 : digits
  return `${value.toFixed(places)} ${UNITS[unit]}`
}

export const rate = (perSecond: number | undefined): string => `${bytes(perSecond ?? 0)}/s`

/** part/whole as 0–100, safe for a zero or missing whole. */
export function percent(part: number, whole: number): number {
  if (!(whole > 0)) return 0
  return Math.min(100, Math.max(0, (part / whole) * 100))
}

/** "[██████░░░░]"-style meter body: `width` cells, at least one filled once anything is used. */
export function blocks(pct: number, width = 10): string {
  const p = Math.min(100, Math.max(0, pct))
  const filled = p === 0 ? 0 : Math.max(1, Math.round((p / 100) * width))
  return '█'.repeat(filled) + '░'.repeat(width - filled)
}

export function uptime(seconds: number, t: TFn): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return t('time.dh', { d, h })
  if (h > 0) return t('time.hm', { h, m })
  return t('time.m', { m })
}

/** Parses a server timestamp. Go's zero time (year 1) and garbage both mean "never". */
export function toDate(s: string | null | undefined): Date | null {
  if (!s) return null
  const d = new Date(s)
  return Number.isNaN(d.getTime()) || d.getUTCFullYear() < 1971 ? null : d
}

const two = '2-digit' as const

export function dateTime(s: string | null | undefined, locale?: string): string {
  return toDate(s)?.toLocaleString(locale, { year: 'numeric', month: two, day: two, hour: two, minute: two }) ?? DASH
}

export function date(s: string | null | undefined, locale?: string): string {
  return toDate(s)?.toLocaleDateString(locale, { year: 'numeric', month: two, day: two }) ?? DASH
}

/** "5 min ago" / "in 2 h". Anything within 45 seconds is "just now". */
export function relative(s: string | null | undefined, now: Date, t: TFn): string {
  const d = toDate(s)
  if (!d) return DASH
  const delta = Math.round((now.getTime() - d.getTime()) / 1000)
  const abs = Math.abs(delta)
  if (abs < 45) return t('rel.now')
  const frame = delta >= 0 ? 'rel.ago' : 'rel.in'
  if (abs < 3600) return t(frame, { v: t('rel.min', { n: Math.max(1, Math.round(abs / 60)) }) })
  if (abs < 86400) return t(frame, { v: t('rel.hour', { n: Math.round(abs / 3600) }) })
  return t(frame, { v: t('rel.day', { n: Math.round(abs / 86400) }) })
}

/** "a, b，c" → unique trimmed tags (ASCII and CJK separators, case-insensitive). */
export function tags(input: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of input.split(/[,，、\n]/)) {
    const tag = raw.trim()
    const key = tag.toLowerCase()
    if (tag && !seen.has(key)) {
      seen.add(key)
      out.push(tag)
    }
  }
  return out
}

const POWER: Record<string, number> = { B: 0, K: 1, M: 2, G: 3, T: 4 }

/**
 * "10", "10GB", "1.5 TB" → bytes (a bare number is GB). Empty or "0" is 0, meaning unlimited;
 * null means the text is not a size.
 */
export function parseSize(input: string): number | null {
  const s = input.trim().toUpperCase().replace(/\s+/g, '')
  if (s === '' || s === '0') return 0
  const m = /^(\d+(?:\.\d+)?)(B|KB?|MB?|GB?|TB?)?$/.exec(s)
  if (!m) return null
  const n = Math.round(Number(m[1]) * 1024 ** POWER[(m[2] ?? 'G')[0]])
  return Number.isSafeInteger(n) ? n : null
}

/** HH:MM:SS for the status bar. */
export function clock(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/** What a port field keeps of the typed text: digits only, five at most. */
export const portDigits = (typed: string): string => typed.replace(/\D/g, '').slice(0, 5)

/** True for the text of a usable TCP/UDP port (1–65535). */
export function isPort(text: string): boolean {
  const n = Number(text)
  return /^\d+$/.test(text) && n >= 1 && n <= 65535
}

/** host:port with IPv6 literals bracketed. */
export function hostPort(host: string, port: number | string): string {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]:${port}` : `${host}:${port}`
}

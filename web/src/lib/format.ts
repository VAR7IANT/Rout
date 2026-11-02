// Number and time formatting shared by the pages. Pure functions so they are easy to test.
import type { TFn } from '../i18n'

const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

export function formatBytes(n: number | undefined | null, digits = 1): string {
  if (n == null || !Number.isFinite(n) || n < 0) return '–'
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  const d = i === 0 ? 0 : v >= 100 ? 0 : digits
  return `${v.toFixed(d)} ${units[i]}`
}

export function formatRate(bytesPerSec: number | undefined): string {
  return `${formatBytes(bytesPerSec ?? 0)}/s`
}

export function formatPercent(part: number, whole: number): number {
  if (!whole || whole <= 0) return 0
  return Math.max(0, Math.min(100, (part / whole) * 100))
}

export function formatUptime(sec: number, t: TFn): string {
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  if (d > 0) return t('time.dh', { d, h })
  if (h > 0) return t('time.hm', { h, m })
  return t('time.m', { m })
}

export function parseDate(s: string | undefined | null): Date | null {
  if (!s) return null
  const d = new Date(s)
  // Go's zero time is year 1: treat it as "never".
  if (Number.isNaN(d.getTime()) || d.getUTCFullYear() < 1971) return null
  return d
}

export function formatDateTime(s: string | undefined | null, locale?: string): string {
  const d = parseDate(s)
  if (!d) return '–'
  return d.toLocaleString(locale, { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

export function formatDate(s: string | undefined | null, locale?: string): string {
  const d = parseDate(s)
  if (!d) return '–'
  return d.toLocaleDateString(locale, { year: 'numeric', month: '2-digit', day: '2-digit' })
}

export function formatRelative(s: string | undefined | null, now: Date, t: TFn): string {
  const d = parseDate(s)
  if (!d) return '–'
  const sec = Math.round((now.getTime() - d.getTime()) / 1000)
  const abs = Math.abs(sec)
  const key = sec >= 0 ? 'rel.ago' : 'rel.in'
  if (abs < 45) return t('rel.now')
  if (abs < 3600) return t(key, { v: t('rel.min', { n: Math.max(1, Math.round(abs / 60)) }) })
  if (abs < 86400) return t(key, { v: t('rel.hour', { n: Math.round(abs / 3600) }) })
  return t(key, { v: t('rel.day', { n: Math.round(abs / 86400) }) })
}

/** Splits "a, b ,c" into trimmed non-empty unique tags. */
export function splitTags(s: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const part of s.split(/[,，、\n]/)) {
    const t = part.trim()
    if (t && !seen.has(t.toLowerCase())) {
      seen.add(t.toLowerCase())
      out.push(t)
    }
  }
  return out
}

/** Parses "10", "10GB", "1.5 TB" (binary units, as the server counts) into bytes; 0 means unlimited. */
export function parseSize(input: string): number | null {
  const s = input.trim().toUpperCase().replace(/\s+/g, '')
  if (s === '' || s === '0') return 0
  const m = /^(\d+(?:\.\d+)?)(B|KB?|MB?|GB?|TB?)?$/.exec(s)
  if (!m) return null
  const n = Number(m[1])
  const unit = (m[2] ?? 'G')[0]
  const pow = { B: 0, K: 1, M: 2, G: 3, T: 4 }[unit as 'B' | 'K' | 'M' | 'G' | 'T']
  const bytes = Math.round(n * 1024 ** pow)
  return Number.isSafeInteger(bytes) ? bytes : null
}

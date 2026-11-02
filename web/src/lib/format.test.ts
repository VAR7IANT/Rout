import { describe, expect, it } from 'vitest'
import { formatBytes, formatPercent, formatRate, formatRelative, formatUptime, parseDate, parseSize, splitTags } from './format'
import { translate } from '../i18n'

const t = (k: Parameters<typeof translate>[1], v?: Record<string, string | number>) => translate('en', k, v)

describe('formatBytes', () => {
  it('uses binary units and trims digits', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1023)).toBe('1023 B')
    expect(formatBytes(1024)).toBe('1.0 KB')
    expect(formatBytes(1536)).toBe('1.5 KB')
    expect(formatBytes(150 * 1024 ** 2)).toBe('150 MB')
    expect(formatBytes(5 * 1024 ** 5)).toBe('5.0 PB')
  })
  it('shows a dash for values that are not usable', () => {
    expect(formatBytes(undefined)).toBe('–')
    expect(formatBytes(null)).toBe('–')
    expect(formatBytes(-1)).toBe('–')
    expect(formatBytes(Number.NaN)).toBe('–')
  })
  it('formats a rate', () => {
    expect(formatRate(2048)).toBe('2.0 KB/s')
    expect(formatRate(undefined)).toBe('0 B/s')
  })
})

describe('formatPercent', () => {
  it('clamps and tolerates a zero whole', () => {
    expect(formatPercent(50, 200)).toBe(25)
    expect(formatPercent(300, 200)).toBe(100)
    expect(formatPercent(1, 0)).toBe(0)
    expect(formatPercent(-5, 10)).toBe(0)
  })
})

describe('time', () => {
  it('treats Go zero time as never', () => {
    expect(parseDate('0001-01-01T00:00:00Z')).toBeNull()
    expect(parseDate('')).toBeNull()
    expect(parseDate('garbage')).toBeNull()
    expect(parseDate('2026-11-02T00:00:00Z')?.getUTCFullYear()).toBe(2026)
  })
  it('formats uptime in the largest sensible units', () => {
    expect(formatUptime(90_000, t)).toBe('1 d 1 h')
    expect(formatUptime(3 * 3600 + 120, t)).toBe('3 h 2 min')
    expect(formatUptime(300, t)).toBe('5 min')
  })
  it('formats relative times in both directions', () => {
    const now = new Date('2026-11-02T12:00:00Z')
    expect(formatRelative('2026-11-02T11:59:50Z', now, t)).toBe('just now')
    expect(formatRelative('2026-11-02T11:30:00Z', now, t)).toBe('30 min ago')
    expect(formatRelative('2026-11-02T14:00:00Z', now, t)).toBe('in 2 h')
    expect(formatRelative('2026-10-30T12:00:00Z', now, t)).toBe('3 d ago')
    expect(formatRelative(undefined, now, t)).toBe('–')
  })
})

describe('splitTags', () => {
  it('trims, drops empties and de-duplicates case-insensitively', () => {
    expect(splitTags('a, b ,，c\n A,')).toEqual(['a', 'b', 'c'])
    expect(splitTags('  ')).toEqual([])
  })
})

describe('parseSize', () => {
  it('reads binary sizes and defaults to gigabytes', () => {
    expect(parseSize('10')).toBe(10 * 1024 ** 3)
    expect(parseSize('1.5 TB')).toBe(Math.round(1.5 * 1024 ** 4))
    expect(parseSize('512m')).toBe(512 * 1024 ** 2)
    expect(parseSize('0')).toBe(0)
    expect(parseSize('')).toBe(0)
  })
  it('rejects nonsense', () => {
    expect(parseSize('ten')).toBeNull()
    expect(parseSize('-1')).toBeNull()
    expect(parseSize('1e9')).toBeNull()
  })
})

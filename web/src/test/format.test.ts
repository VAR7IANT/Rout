import { describe, expect, it } from 'vitest'
import { blocks, bytes, clock, date, hostPort, isPort, parseSize, percent, portDigits, rate, relative, tags, toDate, uptime } from '../core/format'
import { translate } from '../core/i18n'

const t = (key: Parameters<typeof translate>[1], vars?: Parameters<typeof translate>[2]) => translate('en', key, vars)

describe('sizes', () => {
  it('uses binary units and drops decimals where they add nothing', () => {
    expect(bytes(0)).toBe('0 B')
    expect(bytes(1023)).toBe('1023 B')
    expect(bytes(1536)).toBe('1.5 KB')
    expect(bytes(150 * 1024 ** 2)).toBe('150 MB')
    expect(bytes(1024 ** 4)).toBe('1.0 TB')
    expect(rate(2048)).toBe('2.0 KB/s')
    expect(rate(undefined)).toBe('0 B/s')
  })
  it('shows a dash for values that are not sizes', () => {
    for (const bad of [null, undefined, -1, NaN, Infinity]) expect(bytes(bad)).toBe('–')
  })
  it('parses what an administrator types; a bare number is GB', () => {
    expect(parseSize('')).toBe(0)
    expect(parseSize('0')).toBe(0)
    expect(parseSize('10')).toBe(10 * 1024 ** 3)
    expect(parseSize('1.5 TB')).toBe(1.5 * 1024 ** 4)
    expect(parseSize('500m')).toBe(500 * 1024 ** 2)
    expect(parseSize('12kb')).toBe(12 * 1024)
    expect(parseSize('lots')).toBeNull()
    expect(parseSize('-1')).toBeNull()
    expect(parseSize('99999999999999TB')).toBeNull()
  })
})

describe('meters', () => {
  it('clamps percentages and survives a zero whole', () => {
    expect(percent(1, 4)).toBe(25)
    expect(percent(9, 4)).toBe(100)
    expect(percent(-1, 4)).toBe(0)
    expect(percent(1, 0)).toBe(0)
  })
  it('draws block bars with at least one cell once anything is used', () => {
    expect(blocks(0, 10)).toBe('░░░░░░░░░░')
    expect(blocks(1, 10)).toBe('█░░░░░░░░░')
    expect(blocks(50, 10)).toBe('█████░░░░░')
    expect(blocks(100, 10)).toBe('██████████')
    expect(blocks(250, 4)).toBe('████')
  })
})

describe('times', () => {
  it('treats Go zero time and garbage as never', () => {
    expect(toDate('0001-01-01T00:00:00Z')).toBeNull()
    expect(toDate('nope')).toBeNull()
    expect(toDate(undefined)).toBeNull()
    expect(date(null)).toBe('–')
    expect(toDate('2026-11-11T10:00:00Z')?.getUTCFullYear()).toBe(2026)
  })
  it('words durations and distances', () => {
    expect(uptime(90061, t)).toBe('1 d 1 h')
    expect(uptime(3700, t)).toBe('1 h 1 min')
    expect(uptime(59, t)).toBe('0 min')
    const now = new Date('2026-11-11T12:00:00Z')
    expect(relative('2026-11-11T11:59:40Z', now, t)).toBe('just now')
    expect(relative('2026-11-11T11:55:00Z', now, t)).toBe('5 min ago')
    expect(relative('2026-11-11T15:00:00Z', now, t)).toBe('in 3 h')
    expect(relative('2026-11-09T12:00:00Z', now, t)).toBe('2 d ago')
    expect(relative('', now, t)).toBe('–')
  })
  it('pads the clock', () => {
    expect(clock(new Date(2026, 0, 2, 3, 4, 5))).toBe('03:04:05')
  })
})

describe('small parsers', () => {
  it('splits tags on ASCII and CJK separators, once each', () => {
    expect(tags('hk, jp，HK、us\n jp ')).toEqual(['hk', 'jp', 'us'])
    expect(tags('  ')).toEqual([])
  })
  it('validates ports', () => {
    expect(portDigits('44a3 x99999')).toBe('44399')
    expect(isPort('443')).toBe(true)
    expect(isPort('0')).toBe(false)
    expect(isPort('65536')).toBe(false)
    expect(isPort('')).toBe(false)
    expect(isPort('4.3')).toBe(false)
  })
  it('brackets IPv6 hosts', () => {
    expect(hostPort('example.com', 443)).toBe('example.com:443')
    expect(hostPort('2001:db8::1', 443)).toBe('[2001:db8::1]:443')
    expect(hostPort('[2001:db8::1]', 443)).toBe('[2001:db8::1]:443')
  })
})

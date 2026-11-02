import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { catalog } from './catalog'
import { detectLang, translate, translateOr } from './index'

const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!).sort()
const entries = Object.entries(catalog) as [string, readonly [string, string, string]][]

describe('message catalog', () => {
  it('has simplified, traditional and English text for every key', () => {
    const bad = entries.filter(([, v]) => v.length !== 3 || v.some((s) => typeof s !== 'string' || s.trim() === ''))
    expect(bad.map(([k]) => k)).toEqual([])
  })
  it('uses the same placeholders in all three languages', () => {
    const bad = entries.filter(([, [a, b, c]]) => JSON.stringify(placeholders(a)) !== JSON.stringify(placeholders(b)) || JSON.stringify(placeholders(a)) !== JSON.stringify(placeholders(c)))
    expect(bad.map(([k]) => k)).toEqual([])
  })
  it('keeps Chinese text out of the English column', () => {
    const han = /[㐀-鿿]/
    const bad = entries.filter(([, v]) => han.test(v[2]))
    expect(bad.map(([k]) => k)).toEqual([])
  })
  it('does not leave simplified-only forms in the traditional column for common words', () => {
    const simplifiedOnly = /[设们录检测订阅节点显这续网络协议权]/
    const bad = entries.filter(([, v]) => simplifiedOnly.test(v[1]))
    expect(bad.map(([k]) => k)).toEqual([])
  })
  it('has no duplicate keys across the message modules', () => {
    const dir = join(dirname(fileURLToPath(import.meta.url)), 'messages')
    const seen = new Map<string, string>()
    const dup: string[] = []
    for (const f of readdirSync(dir)) {
      for (const m of readFileSync(join(dir, f), 'utf8').matchAll(/^\s+'([\w.]+)':/gm)) {
        const key = m[1]!
        if (seen.has(key)) dup.push(`${key} (${seen.get(key)} and ${f})`)
        seen.set(key, f)
      }
    }
    expect(dup).toEqual([])
    expect(seen.size).toBe(entries.length)
  })
})

// The run-time keys the pages build from server codes must exist, or the interface would show
// a raw code. The codes are read from the Go source so a new alert cannot slip in untranslated.
describe('server codes are translated', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '../../../internal/rout')
  const views = readFileSync(join(root, 'web_views.go'), 'utf8')
  const routes = readFileSync(join(root, 'web_routes.go'), 'utf8')
  it('covers every alert code', () => {
    const codes = [...(views + routes).matchAll(/Alert\{[^}]*Code: "(\w+)"/g)].map((m) => m[1]!)
    expect(codes.length).toBeGreaterThanOrEqual(8)
    expect(codes.filter((c) => !(`alert.${c}` in catalog))).toEqual([])
  })
  it('covers every node warning', () => {
    const codes = [...views.matchAll(/Warnings = append\(v\.Warnings, "(\w+)"\)/g)].map((m) => m[1]!)
    expect(codes.length).toBeGreaterThan(3)
    expect(codes.filter((c) => !(`warn.${c}` in catalog))).toEqual([])
  })
})

describe('translate', () => {
  it('fills placeholders and keeps unknown ones visible', () => {
    expect(translate('en', 'common.selected', { n: 3 })).toBe('3 selected')
    expect(translate('zh-CN', 'common.selected', { n: 3 })).toBe('已选 3 项')
    expect(translate('zh-TW', 'common.selected', { n: 3 })).toBe('已選 3 項')
    expect(translate('en', 'common.selected')).toBe('{n} selected')
  })
  it('falls back for run-time keys that do not exist', () => {
    expect(translateOr('en', 'alert.nope', 'raw')).toBe('raw')
    expect(translateOr('en', 'alert.disk_high', 'raw')).not.toBe('raw')
  })
})

describe('detectLang', () => {
  it('honours a saved choice first', () => {
    expect(detectLang('en', ['zh-CN'])).toBe('en')
    expect(detectLang('zh-TW', ['en-US'])).toBe('zh-TW')
  })
  it('maps browser languages', () => {
    expect(detectLang(null, ['zh-TW'])).toBe('zh-TW')
    expect(detectLang(null, ['zh-HK'])).toBe('zh-TW')
    expect(detectLang(null, ['zh-Hant-TW'])).toBe('zh-TW')
    expect(detectLang(null, ['zh-CN'])).toBe('zh-CN')
    expect(detectLang(null, ['zh'])).toBe('zh-CN')
    expect(detectLang(null, ['en-GB'])).toBe('en')
    expect(detectLang(null, ['fr-FR', 'zh-CN'])).toBe('zh-CN')
    expect(detectLang(null, ['fr-FR'])).toBe('en')
    expect(detectLang('klingon', [])).toBe('en')
  })
})

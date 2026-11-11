import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { pickLang, translate } from '../core/i18n'
import { catalog } from '../i18n/catalog'

const here = dirname(fileURLToPath(import.meta.url))
const src = join(here, '..')
const entries = Object.entries(catalog) as [string, readonly string[]][]
const holes = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',')
const keysOf = (rows: [string, readonly string[]][]) => rows.map(([k]) => k)

function sources(dir: string, out: string[] = []): string[] {
  for (const f of readdirSync(dir, { withFileTypes: true })) {
    if (f.isDirectory()) sources(join(dir, f.name), out)
    else if (/\.tsx?$/.test(f.name) && !/\.test\.tsx?$/.test(f.name)) out.push(join(dir, f.name))
  }
  return out
}

describe('message catalog', () => {
  it('has text in all three languages for every key', () => {
    expect(keysOf(entries.filter(([, v]) => v.length !== 3 || v.some((s) => typeof s !== 'string' || s.trim() === '')))).toEqual([])
  })
  it('uses the same placeholders in all three languages', () => {
    expect(keysOf(entries.filter(([, [a, b, c]]) => holes(a) !== holes(b) || holes(a) !== holes(c)))).toEqual([])
  })
  it('keeps Chinese out of the English column', () => {
    expect(keysOf(entries.filter(([, v]) => /[㐀-鿿]/.test(v[2])))).toEqual([])
  })
  it('keeps common simplified-only characters out of the traditional column', () => {
    expect(keysOf(entries.filter(([, v]) => /[设们录检测订阅节点显这续网络协议权]/.test(v[1])))).toEqual([])
  })
  it('defines each key in exactly one message module', () => {
    const dir = join(src, 'i18n', 'messages')
    const owner = new Map<string, string>()
    const twice: string[] = []
    for (const file of readdirSync(dir)) {
      for (const m of readFileSync(join(dir, file), 'utf8').matchAll(/^\s+'([\w.]+)':/gm)) {
        if (owner.has(m[1])) twice.push(`${m[1]} (${owner.get(m[1])} and ${file})`)
        owner.set(m[1], file)
      }
    }
    expect(twice).toEqual([])
    expect(owner.size).toBe(entries.length)
  })
})

// Keys built at run time from server codes must exist, or the page would show the raw code.
// The codes are read from the Go source so a new one cannot slip in untranslated.
describe('server codes', () => {
  const go = (name: string) => readFileSync(join(src, '../../internal/rout', name), 'utf8')
  it('covers every alert code', () => {
    const codes = [...(go('web_views.go') + go('web_routes.go')).matchAll(/Alert\{[^}]*Code: "(\w+)"/g)].map((m) => m[1])
    expect(codes.length).toBeGreaterThanOrEqual(8)
    expect(codes.filter((c) => !(`alert.${c}` in catalog))).toEqual([])
  })
  it('covers every node warning', () => {
    const codes = [...go('web_views.go').matchAll(/Warnings = append\(v\.Warnings, "(\w+)"\)/g)].map((m) => m[1])
    expect(codes.length).toBeGreaterThan(3)
    expect(codes.filter((c) => !(`warn.${c}` in catalog))).toEqual([])
  })
})

describe('keys used by the interface', () => {
  it('are all in the catalog', () => {
    const files = sources(src)
    const missing: string[] = []
    for (const file of files) {
      for (const m of readFileSync(file, 'utf8').matchAll(/\bt\(\s*'([a-z]+\.[\w.]+)'/g)) if (!(m[1] in catalog)) missing.push(`${m[1]} (${file.slice(src.length + 1)})`)
    }
    expect(files.length).toBeGreaterThan(20)
    expect(missing).toEqual([])
  })
})

describe('translate', () => {
  it('fills placeholders and leaves unknown ones visible', () => {
    expect(translate('en', 'common.selected', { n: 3 })).toBe('3 selected')
    expect(translate('zh-CN', 'common.selected', { n: 3 })).toBe('已选 3 项')
    expect(translate('zh-TW', 'common.selected', { n: 3 })).toBe('已選 3 項')
    expect(translate('en', 'common.selected')).toBe('{n} selected')
  })
  it('returns the key itself when it is unknown', () => {
    expect(translate('en', 'no.such.key')).toBe('no.such.key')
  })
})

describe('pickLang', () => {
  it('prefers a saved choice', () => {
    expect(pickLang('en', ['zh-CN'])).toBe('en')
    expect(pickLang('zh-TW', ['en-US'])).toBe('zh-TW')
  })
  it('maps browser languages, first match wins', () => {
    expect(pickLang(null, ['zh-TW'])).toBe('zh-TW')
    expect(pickLang(null, ['zh-HK'])).toBe('zh-TW')
    expect(pickLang(null, ['zh-Hant-TW'])).toBe('zh-TW')
    expect(pickLang(null, ['zh-CN'])).toBe('zh-CN')
    expect(pickLang(null, ['zh'])).toBe('zh-CN')
    expect(pickLang(null, ['en-GB'])).toBe('en')
    expect(pickLang(null, ['fr-FR', 'zh-CN'])).toBe('zh-CN')
  })
  it('falls back to English', () => {
    expect(pickLang(null, ['fr-FR'])).toBe('en')
    expect(pickLang('klingon', [])).toBe('en')
  })
})

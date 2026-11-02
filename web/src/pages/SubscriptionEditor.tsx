import { useEffect, useMemo, useState } from 'react'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { useRunner } from '../lib/session'
import type { SourceNode, SourceView, SubNodeChoice, SubscriptionView, SubItemInput } from '../lib/types'
import { Modal } from '../components/overlay'
import { Icon } from '../components/icons'
import { Badge, Button, Check, Field, IconButton, Input, Notice, SearchInput, Segmented, Select, Spinner, Toggle } from '../components/ui'

/** One row in the subscription being edited. */
interface Entry {
  key: string
  kind: 'local' | 'remote'
  nodeId: string // local node id, or the node id inside the source
  sourceId?: string
  source?: string
  name: string // the original name
  custom: string // the name used only in this subscription
  protocol: string
  base64: boolean | null // null = not known yet (not saved)
  mihomo: boolean | null
  base64Why?: string
  mihomoWhy?: string
  skipped?: string
}

interface PoolItem {
  key: string
  kind: 'local' | 'remote'
  nodeId: string
  sourceId?: string
  source?: string
  name: string
  protocol: string
  label: string
  detail: string
  base64: boolean | null
  tag?: string
  disabled?: boolean
}

const localKey = (id: string) => `l:${id}`
const remoteKey = (s: string, id: string) => `r:${s}:${id}`

function entriesFrom(sub: SubscriptionView): Entry[] {
  return sub.items.map((it) => ({
    key: it.kind === 'local' ? localKey(it.node_id) : remoteKey(it.source_id ?? '', it.node_id),
    kind: it.kind,
    nodeId: it.node_id,
    sourceId: it.source_id,
    source: it.source,
    name: it.name,
    custom: it.custom_name ?? '',
    protocol: it.protocol ?? '',
    base64: it.status === 'skipped' ? false : it.base64_ok,
    mihomo: it.status === 'skipped' ? false : it.mihomo_ok,
    base64Why: it.base64_why,
    mihomoWhy: it.mihomo_why,
    skipped: it.skipped,
  }))
}

interface Props {
  sub?: SubscriptionView
  choices: SubNodeChoice[]
  onClose: () => void
  onSaved: (created: boolean) => Promise<void>
}

export function SubscriptionEditor({ sub, choices, onClose, onSaved }: Props) {
  const { t } = useI18n()
  const run = useRunner()
  const editing = !!sub
  const [name, setName] = useState(sub?.name ?? '')
  const [aggregate, setAggregate] = useState(sub?.aggregate ?? false)
  const [dedupe, setDedupe] = useState(sub?.dedupe ?? false)
  const [insecure, setInsecure] = useState(sub?.allow_insecure ?? false)
  const [entries, setEntries] = useState<Entry[]>(() => (sub ? entriesFrom(sub) : []))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Third-party nodes are loaded once, when the editor is allowed to use them.
  const [sources, setSources] = useState<SourceView[]>([])
  const [remote, setRemote] = useState<Record<string, SourceNode[]>>({})
  const [loadingSources, setLoadingSources] = useState(false)
  useEffect(() => {
    if (!aggregate) return
    let alive = true
    setLoadingSources(true)
    ;(async () => {
      try {
        const { sources: list } = await api.get<{ sources: SourceView[] }>('/api/sources')
        if (!alive) return
        setSources(list)
        const got = await Promise.all(list.map(async (s) => [s.id, (await api.get<{ nodes: SourceNode[] }>(`/api/sources/${s.id}/nodes`)).nodes] as const))
        if (alive) setRemote(Object.fromEntries(got))
      } catch {
        // The pool then lists local nodes only; the error is not blocking.
      } finally {
        if (alive) setLoadingSources(false)
      }
    })()
    return () => {
      alive = false
    }
  }, [aggregate])

  const pool = useMemo<PoolItem[]>(() => {
    const out: PoolItem[] = choices.map((c) => ({
      key: localKey(c.id),
      kind: 'local',
      nodeId: c.id,
      name: c.name,
      protocol: c.protocol,
      label: c.label,
      detail: c.kind === 'relay' ? t('subs.pool.relay') : t('subs.sel.origLocal'),
      base64: true,
      tag: !c.enabled ? t('subs.pool.stopped') : undefined,
      disabled: !c.enabled,
    }))
    if (aggregate) {
      for (const s of sources) {
        for (const n of remote[s.id] ?? []) {
          if (!n.enabled) continue
          out.push({
            key: remoteKey(s.id, n.id),
            kind: 'remote',
            nodeId: n.id,
            sourceId: s.id,
            source: s.name,
            name: n.name,
            protocol: n.protocol,
            label: n.protocol.toUpperCase(),
            detail: s.name,
            base64: n.link_ok,
          })
        }
      }
    }
    return out
  }, [choices, sources, remote, aggregate, t])

  const disabledInSources = useMemo(() => Object.values(remote).reduce((n, l) => n + l.filter((x) => !x.enabled).length, 0), [remote])

  // ---- pool filters
  const [query, setQuery] = useState('')
  const [origin, setOrigin] = useState('all')
  const [proto, setProto] = useState('all')
  const [pick, setPick] = useState<Set<string>>(new Set())
  const inList = useMemo(() => new Set(entries.map((e) => e.key)), [entries])
  const protocols = useMemo(() => [...new Set(pool.map((p) => p.protocol))].sort(), [pool])
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    return pool.filter((p) => {
      if (origin === 'local' && p.kind !== 'local') return false
      if (origin.startsWith('source:') && p.sourceId !== origin.slice(7)) return false
      if (proto !== 'all' && p.protocol !== proto) return false
      if (q && !`${p.name} ${p.label} ${p.detail}`.toLowerCase().includes(q)) return false
      return true
    })
  }, [pool, query, origin, proto])
  const LIMIT = 300
  const visible = shown.slice(0, LIMIT)
  const addable = visible.filter((p) => !inList.has(p.key) && !p.disabled)

  const addItems = (items: PoolItem[]) => {
    setEntries((cur) => {
      const have = new Set(cur.map((e) => e.key))
      const add: Entry[] = items
        .filter((p) => !have.has(p.key) && !p.disabled)
        .map((p) => ({ key: p.key, kind: p.kind, nodeId: p.nodeId, sourceId: p.sourceId, source: p.source, name: p.name, custom: '', protocol: p.protocol, base64: p.kind === 'local' ? true : p.base64, mihomo: p.kind === 'local' ? null : null }))
      return [...cur, ...add]
    })
    setPick(new Set())
  }

  // ---- selection list
  const [sel, setSel] = useState<Set<string>>(new Set())
  const [dragKey, setDragKey] = useState<string | null>(null)
  const move = (key: string, delta: number) =>
    setEntries((cur) => {
      const i = cur.findIndex((e) => e.key === key)
      const j = i + delta
      if (i < 0 || j < 0 || j >= cur.length) return cur
      const next = [...cur]
      ;[next[i], next[j]] = [next[j]!, next[i]!]
      return next
    })
  const dropOn = (target: string) => {
    if (!dragKey || dragKey === target) return
    setEntries((cur) => {
      const from = cur.findIndex((e) => e.key === dragKey)
      const to = cur.findIndex((e) => e.key === target)
      if (from < 0 || to < 0) return cur
      const next = [...cur]
      const [m] = next.splice(from, 1)
      next.splice(to, 0, m!)
      return next
    })
    setDragKey(null)
  }
  const setCustom = (key: string, custom: string) => setEntries((cur) => cur.map((e) => (e.key === key ? { ...e, custom } : e)))
  const removeKeys = (keys: Set<string>) => {
    setEntries((cur) => cur.filter((e) => !keys.has(e.key)))
    setSel(new Set())
  }

  const hasRemote = entries.some((e) => e.kind === 'remote')
  const nothing = entries.length === 0

  const save = async () => {
    if (!editing && !name.trim()) {
      setError(t('subs.needName'))
      return
    }
    if (nothing) {
      setError(t('subs.needNodes'))
      return
    }
    setError(null)
    setBusy(true)
    const items: SubItemInput[] = entries.map((e) =>
      e.kind === 'local' ? { kind: 'local', node_id: e.nodeId, ...(e.custom.trim() ? { name: e.custom.trim() } : {}) } : { kind: 'remote', source_id: e.sourceId, remote_id: e.nodeId, ...(e.custom.trim() ? { name: e.custom.trim() } : {}) },
    )
    const body = aggregate ? { items, aggregate: true, dedupe, allow_insecure: insecure && hasRemote } : { node_ids: entries.map((e) => e.nodeId) }
    const r = await run(() => (editing ? api.put(`/api/subscriptions/${sub!.id}/items`, body) : api.post('/api/subscriptions', { name: name.trim(), ...body })))
    setBusy(false)
    if (r !== undefined) await onSaved(!editing)
  }

  const fmt = (ok: boolean | null, why: string | undefined, label: string) => {
    if (ok === null) return <span className="fmt fmt-unknown" title={t('subs.fmt.unknown')}>{label} ?</span>
    return (
      <span className={`fmt ${ok ? 'fmt-ok' : 'fmt-bad'}`} title={ok ? undefined : why}>
        {label} {ok ? '✓' : '✗'}
      </span>
    )
  }

  return (
    <Modal
      title={editing ? t('subs.edit.title', { name: sub!.name }) : t('subs.create.title')}
      onClose={onClose}
      busy={busy}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void save()} busy={busy}>
            {editing ? t('common.save') : t('common.create')}
          </Button>
        </>
      }
    >
      <div className="stack">
        {!editing ? (
          <Field label={t('subs.edit.name')} required>
            {(id) => <Input id={id} data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}
          </Field>
        ) : null}

        <Field label={t('subs.edit.mode')} hint={sub?.aggregate ? t('subs.edit.modeLocked') : editing ? t('subs.edit.modeUpgrade') : undefined}>
          {() => (
            <Segmented
              label={t('subs.edit.mode')}
              value={aggregate ? 'aggregate' : 'standard'}
              onChange={(v) => setAggregate(v === 'aggregate')}
              options={[
                { value: 'standard', label: t('subs.edit.modeStandard'), disabled: !!sub?.aggregate },
                { value: 'aggregate', label: t('subs.edit.modeAggregate') },
              ]}
            />
          )}
        </Field>

        {aggregate ? (
          <div className="option-box">
            <Toggle checked={dedupe} onChange={setDedupe} hint={t('subs.edit.dedupeHint')}>
              {t('subs.edit.dedupe')}
            </Toggle>
            {hasRemote ? (
              <Toggle checked={insecure} onChange={setInsecure} hint={t('subs.edit.insecureHint')}>
                {t('subs.edit.insecure')}
              </Toggle>
            ) : null}
          </div>
        ) : null}

        {error ? <Notice tone="error">{error}</Notice> : null}

        <div className="picker">
          <section className="picker-pane" aria-label={t('subs.pool.title')}>
            <h3 className="section-title">{t('subs.pool.title')}</h3>
            <div className="picker-filters">
              <SearchInput value={query} onChange={setQuery} placeholder={t('subs.pool.search')} label={t('common.search')} />
              <div className="grid-fields">
                <Select aria-label={t('subs.pool.origin')} value={origin} onChange={(e) => setOrigin(e.target.value)}>
                  <option value="all">{t('subs.pool.originAll')}</option>
                  <option value="local">{t('subs.pool.originLocal')}</option>
                  {sources.map((s) => (
                    <option key={s.id} value={`source:${s.id}`}>
                      {s.name}
                    </option>
                  ))}
                </Select>
                <Select aria-label={t('subs.pool.protocol')} value={proto} onChange={(e) => setProto(e.target.value)}>
                  <option value="all">{t('subs.pool.protocolAll')}</option>
                  {protocols.map((p) => (
                    <option key={p} value={p}>
                      {p.toUpperCase()}
                    </option>
                  ))}
                </Select>
              </div>
            </div>
            {loadingSources ? <Spinner label={t('subs.pool.loadingSources')} /> : null}
            <div className="picker-actions">
              <Button size="sm" disabled={pick.size === 0} onClick={() => addItems(pool.filter((p) => pick.has(p.key)))}>
                {t('subs.pool.addSelected', { n: pick.size })}
              </Button>
              <Button size="sm" disabled={addable.length === 0} onClick={() => addItems(addable)}>
                {t('subs.pool.addAll')}
              </Button>
            </div>
            <ul className="picker-list">
              {visible.length === 0 ? <li className="muted pad">{t('subs.pool.empty')}</li> : null}
              {visible.map((p) => {
                const added = inList.has(p.key)
                return (
                  <li key={p.key} className={added ? 'is-added' : ''}>
                    <Check checked={pick.has(p.key)} disabled={added || p.disabled} label={p.name} onChange={(on) => setPick((cur) => { const n = new Set(cur); if (on) n.add(p.key); else n.delete(p.key); return n })} />
                    <div className="picker-main">
                      <span className="picker-name">{p.name}</span>
                      <span className="muted small">
                        <Badge>{p.label}</Badge> {p.detail} {p.tag ? <Badge tone="warn">{p.tag}</Badge> : null}
                      </span>
                    </div>
                    {added ? <Badge tone="ok">{t('subs.pool.added')}</Badge> : <IconButton icon="plus" size="sm" label={t('common.add')} disabled={p.disabled} onClick={() => addItems([p])} />}
                  </li>
                )
              })}
            </ul>
            {shown.length > LIMIT ? <p className="muted small">{t('subs.pool.limit', { n: LIMIT })}</p> : null}
            {aggregate && disabledInSources > 0 ? <p className="muted small">{t('subs.pool.disabledInSource', { n: disabledInSources })}</p> : null}
          </section>

          <section className="picker-pane" aria-label={t('subs.sel.title', { n: entries.length })}>
            <h3 className="section-title">{t('subs.sel.title', { n: entries.length })}</h3>
            <p className="muted small">{t('subs.sel.hint')}</p>
            <div className="picker-actions">
              <Button size="sm" disabled={sel.size === 0} onClick={() => removeKeys(sel)}>
                {t('subs.sel.removeSelected')}
              </Button>
              <Button size="sm" variant="ghost" disabled={nothing} onClick={() => removeKeys(new Set(entries.map((e) => e.key)))}>
                {t('subs.sel.clear')}
              </Button>
            </div>
            <ol className="sel-list">
              {nothing ? <li className="muted pad">{t('subs.sel.empty')}</li> : null}
              {entries.map((e, i) => (
                <li
                  key={e.key}
                  className={`${dragKey === e.key ? 'dragging' : ''} ${e.skipped ? 'is-skipped' : ''}`}
                  draggable
                  onDragStart={() => setDragKey(e.key)}
                  onDragOver={(ev) => ev.preventDefault()}
                  onDrop={() => dropOn(e.key)}
                  onDragEnd={() => setDragKey(null)}
                >
                  <span className="sel-handle" title={t('subs.sel.drag')} aria-hidden="true">
                    <Icon name="drag" size={16} />
                  </span>
                  <Check checked={sel.has(e.key)} label={e.name} onChange={(on) => setSel((cur) => { const n = new Set(cur); if (on) n.add(e.key); else n.delete(e.key); return n })} />
                  <div className="sel-main">
                    <div className="sel-title">
                      <span className="sel-index mono">{i + 1}</span>
                      <strong>{e.custom.trim() || e.name}</strong>
                      {e.custom.trim() && e.custom.trim() !== e.name ? <span className="muted small">({e.name})</span> : null}
                    </div>
                    <div className="sel-meta muted small">
                      <Badge>{e.protocol.toUpperCase()}</Badge> {e.kind === 'local' ? t('subs.sel.origLocal') : e.source}
                      {e.skipped ? <Badge tone="warn">{e.skipped}</Badge> : null}
                    </div>
                    <div className="sel-fmt">
                      {fmt(e.base64, e.base64Why, t('subs.fmt.base64'))} {fmt(e.mihomo, e.mihomoWhy, t('subs.fmt.mihomo'))}
                    </div>
                    {aggregate ? (
                      <input className="input input-sm" aria-label={t('subs.sel.rename')} placeholder={`${t('subs.sel.rename')}: ${e.name}`} value={e.custom} maxLength={64} onChange={(ev) => setCustom(e.key, ev.target.value)} title={t('subs.sel.renameHint')} />
                    ) : null}
                  </div>
                  <div className="sel-move">
                    <IconButton icon="up" size="sm" label={t('common.moveUp')} disabled={i === 0} onClick={() => move(e.key, -1)} />
                    <IconButton icon="down" size="sm" label={t('common.moveDown')} disabled={i === entries.length - 1} onClick={() => move(e.key, 1)} />
                    <IconButton icon="close" size="sm" label={t('common.remove')} onClick={() => removeKeys(new Set([e.key]))} />
                  </div>
                </li>
              ))}
            </ol>
          </section>
        </div>
      </div>
    </Modal>
  )
}

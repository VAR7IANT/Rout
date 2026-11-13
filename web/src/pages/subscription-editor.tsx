// Create a subscription or edit which nodes it hands out, in which order and under which names.
import { useEffect, useMemo, useState } from 'react'
import { api } from '../core/api'
import { useI18n } from '../core/i18n'
import { useAct } from '../core/session'
import type { SourceNode, SourceView, SubItemInput, SubNodeChoice, SubscriptionView } from '../core/types'
import { Icon } from '../ui/icons'
import { Button, Checkbox, Field, IconButton, Input, Notice, Search, Segmented, Select, Spinner, Tag, cx } from '../ui/kit'
import { Dialog } from '../ui/overlay'

/** Whether an output format can carry a node: yes, no, or not known until the server has seen it. */
type Support = boolean | null

/** A node that could be put into the subscription. */
interface Candidate {
  key: string
  kind: 'local' | 'remote'
  nodeId: string // local node id, or the node's id inside its source
  sourceId?: string
  source?: string
  name: string
  protocol: string
  label: string
  origin: string
  base64: Support
  stopped?: boolean
}

/** A node that is in the subscription. */
interface Entry {
  key: string
  kind: 'local' | 'remote'
  nodeId: string
  sourceId?: string
  source?: string
  name: string
  /** The name used in this subscription only; empty keeps the original. */
  custom: string
  protocol: string
  base64: Support
  mihomo: Support
  base64Why?: string
  mihomoWhy?: string
  skipped?: string
}

const localKey = (id: string) => `l:${id}`
const remoteKey = (source: string, id: string) => `r:${source}:${id}`
const POOL_LIMIT = 300 // rows drawn at once; the filters narrow the rest

function savedEntries(sub: SubscriptionView): Entry[] {
  return sub.items.map((it) => {
    const usable = it.status !== 'skipped'
    return {
      key: it.kind === 'local' ? localKey(it.node_id) : remoteKey(it.source_id ?? '', it.node_id),
      kind: it.kind,
      nodeId: it.node_id,
      sourceId: it.source_id,
      source: it.source,
      name: it.name,
      custom: it.custom_name ?? '',
      protocol: it.protocol ?? '',
      base64: usable && it.base64_ok,
      mihomo: usable && it.mihomo_ok,
      base64Why: it.base64_why,
      mihomoWhy: it.mihomo_why,
      skipped: it.skipped,
    }
  })
}

const toggled = (set: Set<string>, key: string, on: boolean): Set<string> => {
  const next = new Set(set)
  if (on) next.add(key)
  else next.delete(key)
  return next
}

/** Moves the item at `from` so that it ends up at index `to`. */
export function reorder<T>(list: T[], from: number, to: number): T[] {
  if (from === to || from < 0 || to < 0 || from >= list.length || to >= list.length) return list
  const next = [...list]
  next.splice(to, 0, ...next.splice(from, 1))
  return next
}

interface Props {
  /** The subscription to edit; absent when creating. */
  sub?: SubscriptionView
  /** This server's nodes and relays. */
  choices: SubNodeChoice[]
  onClose: () => void
  onSaved: (created: boolean) => Promise<void>
}

export function SubscriptionEditor({ sub, choices, onClose, onSaved }: Props) {
  const { t } = useI18n()
  const act = useAct()
  const [name, setName] = useState(sub?.name ?? '')
  const [aggregate, setAggregate] = useState(sub?.aggregate ?? false)
  const [dedupe, setDedupe] = useState(sub?.dedupe ?? false)
  const [insecure, setInsecure] = useState(sub?.allow_insecure ?? false)
  const [entries, setEntries] = useState<Entry[]>(() => (sub ? savedEntries(sub) : []))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Third-party nodes are only fetched once the subscription may contain them.
  const [sources, setSources] = useState<SourceView[]>([])
  const [imported, setImported] = useState<Record<string, SourceNode[]>>({})
  const [loadingSources, setLoadingSources] = useState(false)
  useEffect(() => {
    if (!aggregate) return
    let mounted = true
    setLoadingSources(true)
    ;(async () => {
      try {
        const { sources: list } = await api.get<{ sources: SourceView[] }>('/api/sources')
        if (!mounted) return
        setSources(list)
        const pairs = await Promise.all(list.map(async (s) => [s.id, (await api.get<{ nodes: SourceNode[] }>(`/api/sources/${s.id}/nodes`)).nodes] as const))
        if (mounted) setImported(Object.fromEntries(pairs))
      } catch {
        // Not blocking: the pool then offers local nodes only.
      } finally {
        if (mounted) setLoadingSources(false)
      }
    })()
    return () => {
      mounted = false
    }
  }, [aggregate])

  const pool = useMemo<Candidate[]>(() => {
    const local: Candidate[] = choices.map((c) => ({
      key: localKey(c.id),
      kind: 'local',
      nodeId: c.id,
      name: c.name,
      protocol: c.protocol,
      label: c.label,
      origin: t(c.kind === 'relay' ? 'subs.pool.relay' : 'subs.sel.origLocal'),
      base64: true,
      stopped: !c.enabled,
    }))
    if (!aggregate) return local
    const remote: Candidate[] = sources.flatMap((s) =>
      (imported[s.id] ?? [])
        .filter((n) => n.enabled)
        .map((n) => ({ key: remoteKey(s.id, n.id), kind: 'remote' as const, nodeId: n.id, sourceId: s.id, source: s.name, name: n.name, protocol: n.protocol, label: n.protocol.toUpperCase(), origin: s.name, base64: n.link_ok })),
    )
    return [...local, ...remote]
  }, [choices, sources, imported, aggregate, t])
  const disabledAtSource = useMemo(() => Object.values(imported).reduce((n, list) => n + list.filter((x) => !x.enabled).length, 0), [imported])

  // ---- left pane: what can be added
  const [query, setQuery] = useState('')
  const [origin, setOrigin] = useState('all')
  const [protocol, setProtocol] = useState('all')
  const [toAdd, setToAdd] = useState<Set<string>>(new Set())
  const taken = useMemo(() => new Set(entries.map((e) => e.key)), [entries])
  const protocols = useMemo(() => [...new Set(pool.map((p) => p.protocol))].sort(), [pool])
  const matching = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return pool.filter(
      (p) =>
        (origin === 'all' || (origin === 'local' ? p.kind === 'local' : p.sourceId === origin.slice('source:'.length))) &&
        (protocol === 'all' || p.protocol === protocol) &&
        (!needle || `${p.name} ${p.label} ${p.origin}`.toLowerCase().includes(needle)),
    )
  }, [pool, query, origin, protocol])
  const listed = matching.slice(0, POOL_LIMIT)
  const addable = listed.filter((p) => !taken.has(p.key) && !p.stopped)

  const add = (items: Candidate[]) => {
    setEntries((cur) => {
      const have = new Set(cur.map((e) => e.key))
      const fresh = items.filter((p) => !have.has(p.key) && !p.stopped)
      // Mihomo support is only known after the server has rendered the subscription.
      return [...cur, ...fresh.map((p): Entry => ({ key: p.key, kind: p.kind, nodeId: p.nodeId, sourceId: p.sourceId, source: p.source, name: p.name, custom: '', protocol: p.protocol, base64: p.base64, mihomo: null }))]
    })
    setToAdd(new Set())
  }

  // ---- right pane: what is in, and in which order
  const [toRemove, setToRemove] = useState<Set<string>>(new Set())
  const [dragging, setDragging] = useState<string | null>(null)
  const indexOf = (list: Entry[], key: string) => list.findIndex((e) => e.key === key)
  const shift = (key: string, by: number) => setEntries((cur) => reorder(cur, indexOf(cur, key), indexOf(cur, key) + by))
  const dropOn = (target: string) => {
    if (dragging && dragging !== target) setEntries((cur) => reorder(cur, indexOf(cur, dragging), indexOf(cur, target)))
    setDragging(null)
  }
  const remove = (keys: Set<string>) => {
    setEntries((cur) => cur.filter((e) => !keys.has(e.key)))
    setToRemove(new Set())
  }
  const rename = (key: string, custom: string) => setEntries((cur) => cur.map((e) => (e.key === key ? { ...e, custom } : e)))

  const hasRemote = entries.some((e) => e.kind === 'remote')

  const save = async () => {
    if (!sub && !name.trim()) return setError(t('subs.needName'))
    if (entries.length === 0) return setError(t('subs.needNodes'))
    setError(null)
    setBusy(true)
    const items: SubItemInput[] = entries.map((e) => {
      const custom = e.custom.trim() ? { name: e.custom.trim() } : {}
      return e.kind === 'local' ? { kind: 'local', node_id: e.nodeId, ...custom } : { kind: 'remote', source_id: e.sourceId, remote_id: e.nodeId, ...custom }
    })
    // A standard subscription is just an ordered list of local node ids.
    const body = aggregate ? { items, aggregate: true, dedupe, allow_insecure: insecure && hasRemote } : { node_ids: entries.map((e) => e.nodeId) }
    const r = await act(() => (sub ? api.put(`/api/subscriptions/${sub.id}/items`, body) : api.post('/api/subscriptions', { name: name.trim(), ...body })))
    setBusy(false)
    if (r !== undefined) await onSaved(!sub)
  }

  const support = (ok: Support, why: string | undefined, label: string) =>
    ok === null ? (
      <span className="fmt" title={t('subs.fmt.unknown')}>
        {label} ?
      </span>
    ) : (
      <span className={cx('fmt', ok ? 'fmt--ok' : 'fmt--bad')} title={ok ? undefined : why}>
        {label} {ok ? '✓' : '✗'}
      </span>
    )

  return (
    <Dialog
      wide
      title={sub ? t('subs.edit.title', { name: sub.name }) : t('subs.create.title')}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void save()} busy={busy}>
            {t(sub ? 'common.save' : 'common.create')}
          </Button>
        </>
      }
    >
      <div className="stack">
        {sub ? null : (
          <Field label={t('subs.edit.name')} required>
            {(id) => <Input id={id} data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}
          </Field>
        )}

        <Field label={t('subs.edit.mode')} hint={sub?.aggregate ? t('subs.edit.modeLocked') : sub ? t('subs.edit.modeUpgrade') : undefined}>
          {() => (
            <Segmented
              label={t('subs.edit.mode')}
              value={aggregate ? 'aggregate' : 'standard'}
              onChange={(v) => setAggregate(v === 'aggregate')}
              options={[
                { value: 'standard', label: t('subs.edit.modeStandard'), disabled: !!sub?.aggregate }, // an aggregate cannot go back
                { value: 'aggregate', label: t('subs.edit.modeAggregate') },
              ]}
            />
          )}
        </Field>

        {aggregate ? (
          <div className="stack stack--tight">
            <Checkbox checked={dedupe} onChange={setDedupe} hint={t('subs.edit.dedupeHint')}>
              {t('subs.edit.dedupe')}
            </Checkbox>
            {hasRemote ? (
              <Checkbox checked={insecure} onChange={setInsecure} hint={t('subs.edit.insecureHint')}>
                {t('subs.edit.insecure')}
              </Checkbox>
            ) : null}
          </div>
        ) : null}

        {error ? <Notice tone="error">{error}</Notice> : null}

        <div className="picker">
          <section className="picker__pane" aria-label={t('subs.pool.title')}>
            <h3 className="section__title">{t('subs.pool.title')}</h3>
            <Search value={query} onChange={setQuery} placeholder={t('subs.pool.search')} label={t('common.search')} />
            <div className="cols-2">
              <Select aria-label={t('subs.pool.origin')} value={origin} onChange={(e) => setOrigin(e.target.value)}>
                <option value="all">{t('subs.pool.originAll')}</option>
                <option value="local">{t('subs.pool.originLocal')}</option>
                {sources.map((s) => (
                  <option key={s.id} value={`source:${s.id}`}>
                    {s.name}
                  </option>
                ))}
              </Select>
              <Select aria-label={t('subs.pool.protocol')} value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                <option value="all">{t('subs.pool.protocolAll')}</option>
                {protocols.map((p) => (
                  <option key={p} value={p}>
                    {p.toUpperCase()}
                  </option>
                ))}
              </Select>
            </div>
            {loadingSources ? <Spinner label={t('subs.pool.loadingSources')} /> : null}
            <div className="row">
              <Button size="sm" disabled={toAdd.size === 0} onClick={() => add(pool.filter((p) => toAdd.has(p.key)))}>
                {t('subs.pool.addSelected', { n: toAdd.size })}
              </Button>
              <Button size="sm" disabled={addable.length === 0} onClick={() => add(addable)}>
                {t('subs.pool.addAll')}
              </Button>
            </div>
            <ul className="picker__list">
              {listed.length === 0 ? <li className="picker__none dim">{t('subs.pool.empty')}</li> : null}
              {listed.map((p) => {
                const added = taken.has(p.key)
                return (
                  <li key={p.key} className={cx('picker__row', added && 'is-added')}>
                    <Checkbox checked={toAdd.has(p.key)} disabled={added || p.stopped} label={p.name} onChange={(on) => setToAdd((cur) => toggled(cur, p.key, on))} />
                    <div className="picker__main">
                      <span>{p.name}</span>
                      <span className="row dim small">
                        <Tag>{p.label}</Tag>
                        {p.origin}
                        {p.stopped ? <Tag tone="warn">{t('subs.pool.stopped')}</Tag> : null}
                      </span>
                    </div>
                    {added ? <Tag tone="ok">{t('subs.pool.added')}</Tag> : <IconButton icon="plus" size="sm" label={`${t('common.add')}: ${p.name}`} disabled={p.stopped} onClick={() => add([p])} />}
                  </li>
                )
              })}
            </ul>
            {matching.length > POOL_LIMIT ? <p className="dim small">{t('subs.pool.limit', { n: POOL_LIMIT })}</p> : null}
            {aggregate && disabledAtSource > 0 ? <p className="dim small">{t('subs.pool.disabledInSource', { n: disabledAtSource })}</p> : null}
          </section>

          <section className="picker__pane" aria-label={t('subs.sel.title', { n: entries.length })}>
            <h3 className="section__title">{t('subs.sel.title', { n: entries.length })}</h3>
            <p className="dim small">{t('subs.sel.hint')}</p>
            <div className="row">
              <Button size="sm" disabled={toRemove.size === 0} onClick={() => remove(toRemove)}>
                {t('subs.sel.removeSelected')}
              </Button>
              <Button size="sm" variant="ghost" disabled={entries.length === 0} onClick={() => remove(new Set(entries.map((e) => e.key)))}>
                {t('subs.sel.clear')}
              </Button>
            </div>
            <ol className="picker__list">
              {entries.length === 0 ? <li className="picker__none dim">{t('subs.sel.empty')}</li> : null}
              {entries.map((e, i) => {
                const shownName = e.custom.trim() || e.name
                return (
                  <li
                    key={e.key}
                    className={cx('picker__row', 'picker__row--entry', dragging === e.key && 'is-dragging', e.skipped && 'is-skipped')}
                    draggable
                    onDragStart={() => setDragging(e.key)}
                    onDragOver={(ev) => ev.preventDefault()}
                    onDrop={() => dropOn(e.key)}
                    onDragEnd={() => setDragging(null)}
                  >
                    <span className="picker__grip" title={t('subs.sel.drag')} aria-hidden="true">
                      <Icon name="grip" size={14} />
                    </span>
                    <Checkbox checked={toRemove.has(e.key)} label={e.name} onChange={(on) => setToRemove((cur) => toggled(cur, e.key, on))} />
                    <div className="picker__main">
                      <span>
                        <span className="dim">{String(i + 1).padStart(2, '0')}</span> <strong>{shownName}</strong>
                        {shownName !== e.name ? <span className="dim small"> ({e.name})</span> : null}
                      </span>
                      <span className="row dim small">
                        <Tag>{e.protocol.toUpperCase()}</Tag>
                        {e.kind === 'local' ? t('subs.sel.origLocal') : e.source}
                        {e.skipped ? <Tag tone="warn">{e.skipped}</Tag> : null}
                      </span>
                      <span className="row small">
                        {support(e.base64, e.base64Why, t('subs.fmt.base64'))}
                        {support(e.mihomo, e.mihomoWhy, t('subs.fmt.mihomo'))}
                      </span>
                      {aggregate ? <input className="input" aria-label={`${t('subs.sel.rename')}: ${e.name}`} title={t('subs.sel.renameHint')} placeholder={`${t('subs.sel.rename')}: ${e.name}`} value={e.custom} maxLength={64} onChange={(ev) => rename(e.key, ev.target.value)} /> : null}
                    </div>
                    <div className="picker__move">
                      <IconButton icon="up" size="sm" label={t('common.moveUp')} disabled={i === 0} onClick={() => shift(e.key, -1)} />
                      <IconButton icon="down" size="sm" label={t('common.moveDown')} disabled={i === entries.length - 1} onClick={() => shift(e.key, 1)} />
                      <IconButton icon="close" size="sm" label={t('common.remove')} onClick={() => remove(new Set([e.key]))} />
                    </div>
                  </li>
                )
              })}
            </ol>
          </section>
        </div>
      </div>
    </Dialog>
  )
}

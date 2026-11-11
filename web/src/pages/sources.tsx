// Third-party subscriptions imported as sources: add, refresh, enable nodes, read parse issues.
import { useMemo, useState } from 'react'
import { api } from '../core/api'
import { bytes, relative, tags as splitTags } from '../core/format'
import { useDebounced, useHotkey, useNow, useRemote } from '../core/hooks'
import { useI18n, type MessageKey } from '../core/i18n'
import { useAct, useReauth } from '../core/session'
import { useToast } from '../core/toast'
import type { RefreshResult, SourceIssue, SourceNode, SourceView } from '../core/types'
import { LoadState, Reveal } from '../ui/domain'
import { Button, Checkbox, Empty, Field, Input, Notice, Panel, Search, Segmented, Select, Spinner, Switch, Tabs, Tag, Textarea, cx, type Tone } from '../ui/kit'
import { Dialog, Drawer, Menu } from '../ui/overlay'
import { DataTable, type Column } from '../ui/table'

const stateTone: Record<string, Tone> = { ok: 'ok', error: 'error' }
const MIN_INTERVAL = 15 // minutes; 0 turns scheduled refresh off

export function SourcesTab() {
  const { t } = useI18n()
  const act = useAct()
  const toast = useToast()
  const now = useNow(30000)
  const res = useRemote<{ sources: SourceView[] }>('/api/sources', { every: 15000 })
  const [query, setQuery] = useState('')
  const needle = useDebounced(query, 150).trim().toLowerCase()
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<SourceView | null>(null)
  const [openId, setOpenId] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<SourceView | null>(null)
  const [refreshing, setRefreshing] = useState<Set<string>>(new Set())

  useHotkey('/', (e) => {
    e.preventDefault()
    document.getElementById('sources-filter')?.focus()
  })

  const sources = useMemo(() => res.data?.sources ?? [], [res.data])
  const shown = useMemo(() => sources.filter((s) => !needle || `${s.name} ${s.note ?? ''} ${s.tags.join(' ')}`.toLowerCase().includes(needle)), [sources, needle])
  if (!res.data) return <LoadState res={res} />
  const open = openId ? (sources.find((s) => s.id === openId) ?? null) : null

  const refresh = async (s: SourceView) => {
    setRefreshing((cur) => new Set(cur).add(s.id))
    const r = await act(() => api.post<RefreshResult>(`/api/sources/${s.id}/refresh`))
    setRefreshing((cur) => {
      const next = new Set(cur)
      next.delete(s.id)
      return next
    })
    if (r) toast.push('ok', t('src.refreshed', { v: r.valid, a: r.added, r: r.removed, e: r.errors, s: r.skipped }))
    await res.reload()
  }

  const columns: Column<SourceView>[] = [
    {
      key: 'name',
      head: t('src.col.name'),
      primary: true,
      cell: (s) => (
        <div className="cell-name">
          <strong>{s.name}</strong>
          <div className="cell-tags">
            <Tag>{t(s.kind === 'url' ? 'src.kind.url' : 'src.kind.static')}</Tag>
            {s.format ? <Tag>{s.format}</Tag> : null}
            {s.tags.map((tag) => (
              <Tag key={tag} tone="accent">
                {tag}
              </Tag>
            ))}
          </div>
          {s.url_masked ? <span className="dim small">{s.url_masked}</span> : null}
          {s.note ? <span className="dim small">{s.note}</span> : null}
        </div>
      ),
    },
    {
      key: 'status',
      head: t('src.col.status'),
      label: t('src.col.status'),
      cell: (s) => (
        <div className="stack stack--tight">
          <span>{s.enabled ? <Tag tone={stateTone[s.status.state] ?? 'neutral'}>{t(`src.state.${s.status.state}` as MessageKey)}</Tag> : <Tag>{t('src.state.off')}</Tag>}</span>
          {s.status.last_success ? <span className="dim small">{t('src.lastOk', { v: relative(s.status.last_success, now, t) })}</span> : null}
          {s.status.state === 'error' ? (
            <span className="small">
              <span className="err">
                {s.status.last_error} {s.status.failures ? `(${t('src.failures', { n: s.status.failures })})` : ''}
              </span>
              <br />
              <span className="dim">{t('src.keptOld')}</span>
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'nodes',
      head: t('src.col.nodes'),
      label: t('src.col.nodes'),
      cell: (s) => (
        <div className="stack stack--tight small">
          <strong>{t('src.nodesValid', { v: s.valid, e: s.entries })}</strong>
          {s.errors > 0 ? <span className="err">{t('src.nodesProblems', { n: s.errors })}</span> : null}
          {s.skipped > 0 ? <span className="warn">{t('src.nodesSkipped', { n: s.skipped })}</span> : null}
          {s.duplicates > 0 ? <span className="dim">{t('src.nodesDup', { n: s.duplicates })}</span> : null}
          {s.disabled > 0 ? <span className="dim">{t('src.nodesDisabled', { n: s.disabled })}</span> : null}
          {s.user_info && s.user_info.total > 0 ? <span className="dim">{t('src.provider', { u: bytes(s.user_info.upload + s.user_info.download), t: bytes(s.user_info.total) })}</span> : null}
        </div>
      ),
    },
    {
      key: 'refresh',
      head: t('src.col.refresh'),
      label: t('src.col.refresh'),
      cell: (s) => (
        <div className="stack stack--tight small">
          <span>{s.kind === 'url' && s.interval_min > 0 ? t('src.every', { m: s.interval_min }) : t('src.manualOnly')}</span>
          {s.next_refresh && s.enabled ? <span className="dim">{t('src.next', { v: relative(s.next_refresh, now, t) })}</span> : null}
          <span className="dim">{s.refs.length > 0 ? t('src.refs', { names: s.refs.join(', ') }) : t('src.unused')}</span>
        </div>
      ),
    },
    {
      key: 'actions',
      head: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (s) => (
        <span className="row row--end nowrap" onClick={(e) => e.stopPropagation()}>
          {s.kind === 'url' ? (
            <Button size="sm" icon="refresh" busy={refreshing.has(s.id)} onClick={() => void refresh(s)}>
              {t('src.action.refresh')}
            </Button>
          ) : null}
          <Menu
            label={t('common.more')}
            items={[
              { label: t('src.action.nodes'), icon: 'nodes', onSelect: () => setOpenId(s.id) },
              { label: t('common.edit'), icon: 'edit', onSelect: () => setEditing(s) },
              { label: t('common.delete'), icon: 'trash', danger: true, onSelect: () => setDeleting(s) },
            ]}
          />
        </span>
      ),
    },
  ]

  const addButton = (
    <Button variant="primary" icon="plus" onClick={() => setAdding(true)}>
      {t('src.new')}
    </Button>
  )

  return (
    <>
      <Panel flush>
        <div className="toolbar">
          <Search id="sources-filter" value={query} onChange={setQuery} placeholder={t('src.search')} label={t('common.search')} />
          <span className="toolbar__count dim small">{t('common.total', { n: shown.length })}</span>
          {addButton}
        </div>
        <DataTable
          caption={t('src.tableCaption')}
          rows={shown}
          rowKey={(s) => s.id}
          columns={columns}
          onRowClick={(s) => setOpenId(s.id)}
          empty={
            sources.length === 0 ? (
              <Empty icon="link" title={t('src.empty')} action={addButton}>
                {t('src.emptyHint')}
              </Empty>
            ) : (
              <Empty icon="search" title={t('common.noMatch')} />
            )
          }
        />
      </Panel>

      {adding ? (
        <SourceForm
          onClose={() => setAdding(false)}
          onSaved={async (source) => {
            setAdding(false)
            // A URL source is empty until its first fetch; the refresh reports what it found.
            if (source.kind === 'url') await refresh(source)
            else {
              toast.push('ok', t('src.add.created'))
              await res.reload()
            }
            setOpenId(source.id)
          }}
        />
      ) : null}

      {editing ? (
        <SourceForm
          source={editing}
          onClose={() => setEditing(null)}
          onSaved={async (source, urlChanged) => {
            setEditing(null)
            toast.push('ok', t('src.edit.saved'))
            if (urlChanged) {
              toast.push('info', t('src.edit.urlChanged'))
              await refresh(source)
            } else await res.reload()
          }}
        />
      ) : null}

      {open ? <SourceNodes source={open} onClose={() => setOpenId(null)} onChanged={() => void res.reload()} /> : null}

      {deleting ? (
        <DeleteSource
          source={deleting}
          onClose={() => setDeleting(null)}
          onDeleted={async () => {
            setDeleting(null)
            await res.reload()
          }}
        />
      ) : null}
    </>
  )
}

/** Deleting a source that subscriptions still use needs an explicit "remove it from them too". */
function DeleteSource({ source, onClose, onDeleted }: { source: SourceView; onClose: () => void; onDeleted: () => Promise<void> }) {
  const { t } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const [detach, setDetach] = useState(false)
  const [busy, setBusy] = useState(false)
  const used = source.refs.length > 0

  const run = async () => {
    setBusy(true)
    const r = await act(() => guard(() => api.del(`/api/sources/${source.id}${detach ? '?detach=1' : ''}`)), { ok: t('src.delete.done') })
    setBusy(false)
    if (r !== undefined) await onDeleted()
  }

  return (
    <Dialog
      title={t('src.delete.title', { name: source.name })}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="danger" onClick={() => void run()} busy={busy} disabled={used && !detach}>
            {t('common.delete')}
          </Button>
        </>
      }
    >
      <div className="stack">
        <p>{t('src.delete.msg')}</p>
        {used ? (
          <>
            <Notice tone="error" title={t('confirm.impact')}>
              {t('src.delete.used', { names: source.refs.join(', ') })}
            </Notice>
            <Checkbox checked={detach} onChange={setDetach} hint={detach ? undefined : t('src.delete.detachNeeded')}>
              {t('src.delete.detach')}
            </Checkbox>
          </>
        ) : null}
      </div>
    </Dialog>
  )
}

// ---- add / edit ------------------------------------------------------------------------

interface FormProps {
  /** The source to edit; absent when adding. */
  source?: SourceView
  onClose: () => void
  onSaved: (source: SourceView, urlChanged: boolean) => Promise<void>
}

function SourceForm({ source, onClose, onSaved }: FormProps) {
  const { t } = useI18n()
  const act = useAct()
  const [kind, setKind] = useState<'url' | 'static'>(source?.kind ?? 'url')
  const [name, setName] = useState(source?.name ?? '')
  const [note, setNote] = useState(source?.note ?? '')
  const [tagText, setTagText] = useState(source?.tags.join(', ') ?? '')
  const [url, setUrl] = useState('')
  const [content, setContent] = useState('')
  const [agent, setAgent] = useState(source?.user_agent ?? '')
  const [interval, setInterval] = useState(String(source?.interval_min ?? 360))
  const [enabled, setEnabled] = useState(source?.enabled ?? true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const byUrl = kind === 'url'
  const minutes = Number(interval)
  const intervalBad = byUrl && (interval === '' || (minutes > 0 && minutes < MIN_INTERVAL))

  const submit = async () => {
    if (!source && byUrl && !url.trim()) return setError(t('src.add.needUrl'))
    if (!source && !byUrl && !content.trim()) return setError(t('src.add.needContent'))
    if (intervalBad) return setError(t('src.add.intervalBad'))
    setError(null)
    setBusy(true)
    const common = { name: name.trim(), note: note.trim(), tags: splitTags(tagText), user_agent: agent.trim(), enabled }
    if (source) {
      // An empty URL keeps the stored one; pasted content of a static source cannot be replaced.
      const r = await act(() => api.patch<{ url_changed: boolean }>(`/api/sources/${source.id}`, { ...common, ...(byUrl ? { interval_min: minutes, ...(url.trim() ? { url: url.trim() } : {}) } : {}) }))
      setBusy(false)
      if (r) await onSaved(source, r.url_changed)
      return
    }
    const r = await act(() => api.post<{ source: SourceView }>('/api/sources', { ...common, url: byUrl ? url.trim() : '', content: byUrl ? '' : content, interval_min: byUrl ? minutes : 0 }))
    setBusy(false)
    if (r) await onSaved(r.source, false)
  }

  return (
    <Dialog
      wide
      title={t(source ? 'src.edit.title' : 'src.add.title')}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={intervalBad}>
            {t(source ? 'common.save' : 'src.new')}
          </Button>
        </>
      }
    >
      <div className="stack">
        {source ? null : (
          <Field label={t('src.add.mode')}>
            {() => (
              <Segmented
                label={t('src.add.mode')}
                value={kind}
                onChange={setKind}
                options={[
                  { value: 'url', label: t('src.add.url') },
                  { value: 'static', label: t('src.add.content') },
                ]}
              />
            )}
          </Field>
        )}
        {error ? <Notice tone="error">{error}</Notice> : null}

        <Field label={`${t('src.add.name')} ${t('common.optional')}`}>{(id) => <Input id={id} data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}</Field>

        {byUrl ? (
          <Field label={t('src.add.urlLabel')} hint={t(source ? 'src.add.urlKeep' : 'src.add.urlHint')} required={!source}>
            {(id, note2) => <Input id={id} aria-describedby={note2} type="url" autoComplete="off" autoCapitalize="none" placeholder="https://example.com/sub?token=…" value={url} onChange={(e) => setUrl(e.target.value)} />}
          </Field>
        ) : source ? (
          <Notice>{t('src.edit.staticNote')}</Notice>
        ) : (
          <Field label={t('src.add.contentLabel')} hint={t('src.add.contentHint')} required>
            {(id, note2) => <Textarea id={id} aria-describedby={note2} rows={7} autoCapitalize="none" value={content} onChange={(e) => setContent(e.target.value)} />}
          </Field>
        )}

        {source && byUrl ? (
          <Reveal<{ value: string }> label={t('src.edit.currentHidden')} load={() => api.get(`/api/sources/${source.id}/url`)}>
            {(stored) => (
              <div className="stack stack--tight">
                <span className="dim small">{t('src.edit.current')}</span>
                <textarea className="input input--area secret__text" readOnly rows={2} value={stored.value} onFocus={(e) => e.currentTarget.select()} aria-label={t('src.edit.current')} />
              </div>
            )}
          </Reveal>
        ) : null}

        <div className="cols-2">
          <Field label={`${t('src.add.tags')} ${t('common.optional')}`} hint={t('src.add.tagsHint')}>
            {(id, note2) => <Input id={id} aria-describedby={note2} value={tagText} onChange={(e) => setTagText(e.target.value)} />}
          </Field>
          <Field label={`${t('src.add.note')} ${t('common.optional')}`}>{(id) => <Input id={id} maxLength={120} value={note} onChange={(e) => setNote(e.target.value)} />}</Field>
        </div>

        {byUrl ? (
          <>
            <div className="cols-2">
              <Field label={t('src.add.interval')} hint={t('src.add.intervalHint')} error={intervalBad ? t('src.add.intervalBad') : null}>
                {(id, note2) => <Input id={id} aria-describedby={note2} inputMode="numeric" value={interval} onChange={(e) => setInterval(e.target.value.replace(/\D/g, '').slice(0, 5))} />}
              </Field>
              <Field label={`${t('src.add.ua')} ${t('common.optional')}`} hint={t('src.add.uaHint')}>
                {(id, note2) => <Input id={id} aria-describedby={note2} value={agent} onChange={(e) => setAgent(e.target.value)} placeholder="clash-verge/v2" autoCapitalize="none" />}
              </Field>
            </div>
            <Checkbox checked={enabled} onChange={setEnabled}>
              {t('src.add.enabled')}
            </Checkbox>
          </>
        ) : null}
        <p className="dim small">{t('src.add.limits')}</p>
      </div>
    </Dialog>
  )
}

// ---- nodes and parse report ------------------------------------------------------------

const issueLevel = (level: string): { tone: Tone; key: MessageKey } => (level === 'error' ? { tone: 'error', key: 'src.nodes.levelError' } : { tone: 'warn', key: level === 'skipped' ? 'src.nodes.levelSkipped' : 'src.nodes.levelWarn' })

function SourceNodes({ source, onClose, onChanged }: { source: SourceView; onClose: () => void; onChanged: () => void }) {
  const { t } = useI18n()
  const act = useAct()
  const res = useRemote<{ nodes: SourceNode[]; issues: SourceIssue[] }>(`/api/sources/${source.id}/nodes`)
  const [tab, setTab] = useState<'nodes' | 'issues'>('nodes')
  const [query, setQuery] = useState('')
  const [protocol, setProtocol] = useState('all')
  const [saving, setSaving] = useState(false)
  const nodes = res.data?.nodes ?? []
  const issues = res.data?.issues ?? []
  const protocols = [...new Set(nodes.map((n) => n.protocol))].sort()
  const needle = query.trim().toLowerCase()
  const shown = nodes.filter((n) => (protocol === 'all' || n.protocol === protocol) && (!needle || `${n.name} ${n.server} ${n.protocol}`.toLowerCase().includes(needle)))

  /** The server stores the ids that are switched off; everything else is on. */
  const setEnabled = async (ids: Set<string>, on: boolean) => {
    const next = nodes.map((n) => (ids.has(n.id) ? { ...n, enabled: on } : n))
    setSaving(true)
    const r = await act(() => api.put(`/api/sources/${source.id}/nodes`, { disabled: next.filter((n) => !n.enabled).map((n) => n.id) }), { ok: t('src.nodes.saved') })
    setSaving(false)
    if (r === undefined) return
    res.set({ nodes: next, issues })
    onChanged()
  }
  const shownIds = () => new Set(shown.map((n) => n.id))

  return (
    <Drawer wide title={t('src.nodes.title', { name: source.name })} onClose={onClose}>
      <div className="stack">
        {res.loading && !res.data ? <Spinner label={t('common.loading')} /> : null}
        <Tabs
          label={t('src.nodes.title', { name: source.name })}
          value={tab}
          onChange={setTab}
          tabs={[
            { value: 'nodes', label: t('src.nodes.tab', { n: nodes.length }) },
            { value: 'issues', label: t('src.nodes.issues', { n: issues.length }) },
          ]}
        />
        {tab === 'issues' ? (
          <div className="stack">
            <p className="dim">{t('src.nodes.issuesIntro')}</p>
            {issues.length === 0 ? (
              <Notice tone="ok">{t('src.nodes.noIssues')}</Notice>
            ) : (
              <ul className="rows">
                {issues.map((issue, i) => (
                  <li key={i} className="rows__item">
                    <Tag tone={issueLevel(issue.level).tone}>{t(issueLevel(issue.level).key)}</Tag>
                    <div className="grow">
                      {issue.name || issue.protocol ? (
                        <strong>
                          {issue.name} {issue.protocol ? <span className="dim">({issue.protocol})</span> : null}
                        </strong>
                      ) : null}
                      <div className="small">{issue.reason}</div>
                      {issue.line ? <div className="dim small">{t('src.nodes.line', { n: issue.line })}</div> : null}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : nodes.length === 0 && !res.loading ? (
          <Empty icon="nodes" title={t('src.nodes.none')} />
        ) : (
          <>
            <div className="toolbar toolbar--bare">
              <Search value={query} onChange={setQuery} placeholder={t('src.nodes.search')} label={t('src.nodes.search')} />
              <Select className="toolbar__select" aria-label={t('src.nodes.protocol')} value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                <option value="all">{t('subs.pool.protocolAll')}</option>
                {protocols.map((p) => (
                  <option key={p} value={p}>
                    {p.toUpperCase()}
                  </option>
                ))}
              </Select>
              <Button size="sm" disabled={saving || shown.length === 0} onClick={() => void setEnabled(shownIds(), true)}>
                {t('src.nodes.enableAll')}
              </Button>
              <Button size="sm" disabled={saving || shown.length === 0} onClick={() => void setEnabled(shownIds(), false)}>
                {t('src.nodes.disableAll')}
              </Button>
            </div>
            <ul className="rows">
              {shown.map((n) => (
                <li key={n.id} className={cx('rows__item', !n.enabled && 'is-off')}>
                  <Switch checked={n.enabled} disabled={saving} label={n.name} onChange={(on) => void setEnabled(new Set([n.id]), on)} />
                  <div className="grow stack stack--tight">
                    <strong>{n.name}</strong>
                    <div className="row dim small">
                      <Tag>{n.protocol.toUpperCase()}</Tag>
                      <span>
                        {[`${n.server}:${n.port}`, n.transport, n.security, n.sni ? `SNI ${n.sni}` : '', n.udp ? 'UDP' : ''].filter(Boolean).join(' · ')}
                      </span>
                      {n.from_clash ? <Tag>{t('src.nodes.clash')}</Tag> : null}
                      {n.link_ok ? null : <Tag tone="warn">{t('src.nodes.noShare')}</Tag>}
                    </div>
                    {n.link_issue ? <div className="warn small">{n.link_issue}</div> : null}
                    {(n.notes ?? []).map((line) => (
                      <div key={line} className="dim small">
                        {line}
                      </div>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </Drawer>
  )
}

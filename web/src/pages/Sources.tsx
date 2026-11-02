import { useMemo, useState } from 'react'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatRelative, splitTags } from '../lib/format'
import { useDebounced, useNow, useResource } from '../lib/hooks'
import { Cancelled, useReauth, useRunner } from '../lib/session'
import { useToast } from '../lib/toast'
import type { RefreshResult, SourceIssue, SourceNode, SourceView } from '../lib/types'
import { DataTable, type Column } from '../components/table'
import { ConfirmDialog, Drawer, Menu, Modal } from '../components/overlay'
import { Reveal } from '../components/shared'
import { Badge, Button, Card, Check, EmptyState, Field, Input, Notice, SearchInput, Segmented, Select, Spinner, Switch, Tabs, Textarea, Toggle } from '../components/ui'

export function SourcesTab() {
  const { t } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const { guard } = useReauth()
  const now = useNow(30000)
  const res = useResource<{ sources: SourceView[] }>('/api/sources', { interval: 15000 })
  const [query, setQuery] = useState('')
  const q = useDebounced(query, 150).trim().toLowerCase()
  const [adding, setAdding] = useState(false)
  const [edit, setEdit] = useState<SourceView | null>(null)
  const [nodes, setNodes] = useState<string | null>(null)
  const [del, setDel] = useState<SourceView | null>(null)
  const [detach, setDetach] = useState(false)
  const [refreshing, setRefreshing] = useState<Set<string>>(new Set())

  const sources = res.data?.sources ?? []
  const filtered = useMemo(() => sources.filter((s) => !q || `${s.name} ${s.note ?? ''} ${s.tags.join(' ')}`.toLowerCase().includes(q)), [sources, q])
  const nodesSource = nodes ? sources.find((s) => s.id === nodes) ?? null : null

  const refresh = async (s: SourceView, quiet?: boolean) => {
    setRefreshing((cur) => new Set(cur).add(s.id))
    const r = await run(() => api.post<RefreshResult>(`/api/sources/${s.id}/refresh`))
    setRefreshing((cur) => {
      const n = new Set(cur)
      n.delete(s.id)
      return n
    })
    if (r && !quiet) toast.push('ok', t('src.refreshed', { v: r.valid, a: r.added, r: r.removed, e: r.errors, s: r.skipped }))
    await res.reload()
    return r
  }

  const columns: Column<SourceView>[] = [
    {
      key: 'name',
      header: t('src.col.name'),
      primary: true,
      cell: (s) => (
        <div className="name-cell">
          <strong>{s.name}</strong>
          <div className="badges">
            <Badge>{s.kind === 'url' ? t('src.kind.url') : t('src.kind.static')}</Badge>
            {s.format ? <Badge>{s.format}</Badge> : null}
            {s.tags.map((tag) => (
              <Badge key={tag} tone="accent">
                {tag}
              </Badge>
            ))}
          </div>
          {s.url_masked ? <span className="mono small muted">{s.url_masked}</span> : null}
          {s.note ? <span className="small muted">{s.note}</span> : null}
        </div>
      ),
    },
    {
      key: 'status',
      header: t('src.col.status'),
      label: t('src.col.status'),
      cell: (s) => (
        <div className="stack-tight">
          {!s.enabled ? <Badge>{t('src.state.off')}</Badge> : <Badge tone={s.status.state === 'ok' ? 'ok' : s.status.state === 'error' ? 'error' : 'neutral'}>{t(`src.state.${s.status.state}` as 'src.state.ok')}</Badge>}
          {s.status.last_success ? <span className="small muted">{t('src.lastOk', { v: formatRelative(s.status.last_success, now, t) })}</span> : null}
          {s.status.state === 'error' ? (
            <span className="small err-text" title={s.status.last_error}>
              {s.status.last_error} {s.status.failures ? `(${t('src.failures', { n: s.status.failures })})` : ''}
              <br />
              <span className="muted">{t('src.keptOld')}</span>
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'nodes',
      header: t('src.col.nodes'),
      label: t('src.col.nodes'),
      cell: (s) => (
        <div className="stack-tight small">
          <strong>{t('src.nodesValid', { v: s.valid, e: s.entries })}</strong>
          {s.errors > 0 ? <span className="err-text">{t('src.nodesProblems', { n: s.errors })}</span> : null}
          {s.skipped > 0 ? <span className="warn-text">{t('src.nodesSkipped', { n: s.skipped })}</span> : null}
          {s.duplicates > 0 ? <span className="muted">{t('src.nodesDup', { n: s.duplicates })}</span> : null}
          {s.disabled > 0 ? <span className="muted">{t('src.nodesDisabled', { n: s.disabled })}</span> : null}
          {s.user_info && s.user_info.total > 0 ? <span className="muted">{t('src.provider', { u: formatBytes(s.user_info.upload + s.user_info.download), t: formatBytes(s.user_info.total) })}</span> : null}
        </div>
      ),
    },
    {
      key: 'refresh',
      header: t('src.col.refresh'),
      label: t('src.col.refresh'),
      cell: (s) => (
        <div className="stack-tight small">
          <span>{s.kind === 'url' && s.interval_min > 0 ? t('src.every', { m: s.interval_min }) : t('src.manualOnly')}</span>
          {s.next_refresh && s.enabled ? <span className="muted">{t('src.next', { v: formatRelative(s.next_refresh, now, t) })}</span> : null}
          <span className="muted">{s.refs.length > 0 ? t('src.refs', { names: s.refs.join('、') }) : t('src.unused')}</span>
        </div>
      ),
    },
    {
      key: 'actions',
      header: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (s) => (
        <div className="row-nowrap" onClick={(e) => e.stopPropagation()}>
          {s.kind === 'url' ? (
            <Button size="sm" icon="refresh" busy={refreshing.has(s.id)} onClick={() => void refresh(s)} title={t('src.action.refresh')}>
              <span className="hide-narrow">{t('src.action.refresh')}</span>
            </Button>
          ) : null}
          <Menu
            label={t('common.more')}
            items={[
              { label: t('src.action.nodes'), icon: 'nodes', onSelect: () => setNodes(s.id) },
              { label: t('common.edit'), icon: 'edit', onSelect: () => setEdit(s) },
              { label: t('common.delete'), icon: 'trash', danger: true, onSelect: () => { setDetach(false); setDel(s) } },
            ]}
          />
        </div>
      ),
    },
  ]

  if (res.loading && !res.data) return <Spinner label={t('common.loading')} />
  if (!res.data) {
    return (
      <EmptyState icon="warn" title={t('common.loadFailed')} action={<Button onClick={() => void res.reload()}>{t('common.retry')}</Button>}>
        {res.error?.message}
      </EmptyState>
    )
  }

  return (
    <>
      <Card flush>
        <div className="toolbar">
          <SearchInput value={query} onChange={setQuery} placeholder={t('src.search')} label={t('common.search')} />
          <span className="toolbar-count muted small">{t('common.total', { n: filtered.length })}</span>
          <Button variant="primary" icon="plus" onClick={() => setAdding(true)}>
            {t('src.new')}
          </Button>
        </div>
        <DataTable
          caption={t('src.tableCaption')}
          rows={filtered}
          rowKey={(s) => s.id}
          columns={columns}
          onRowClick={(s) => setNodes(s.id)}
          empty={
            sources.length === 0 ? (
              <EmptyState icon="link" title={t('src.empty')} action={<Button variant="primary" icon="plus" onClick={() => setAdding(true)}>{t('src.new')}</Button>}>
                {t('src.emptyHint')}
              </EmptyState>
            ) : (
              <EmptyState icon="search" title={t('common.noMatch')} />
            )
          }
        />
      </Card>

      {adding ? (
        <SourceForm
          onClose={() => setAdding(false)}
          onSaved={async (src) => {
            setAdding(false)
            await res.reload()
            if (src.kind === 'url') {
              const r = await refresh(src, true)
              if (r) toast.push('ok', t('src.refreshed', { v: r.valid, a: r.added, r: r.removed, e: r.errors, s: r.skipped }))
            } else toast.push('ok', t('src.add.created'))
            setNodes(src.id)
          }}
        />
      ) : null}

      {edit ? (
        <SourceForm
          source={edit}
          onClose={() => setEdit(null)}
          onSaved={async (src, urlChanged) => {
            setEdit(null)
            toast.push('ok', t('src.edit.saved'))
            await res.reload()
            if (urlChanged) {
              toast.push('info', t('src.edit.urlChanged'))
              await refresh(src, false)
            }
          }}
        />
      ) : null}

      {nodesSource ? <SourceNodes source={nodesSource} onClose={() => setNodes(null)} onChanged={() => void res.reload()} /> : null}

      {del ? (
        <ConfirmDialog
          title={t('src.delete.title', { name: del.name })}
          message={t('src.delete.msg')}
          impact={del.refs.length > 0 ? [t('src.delete.used', { names: del.refs.join('、') })] : undefined}
          confirmLabel={t('common.delete')}
          danger
          onCancel={() => setDel(null)}
          onConfirm={async () => {
            if (del.refs.length > 0 && !detach) {
              toast.push('error', t('src.delete.detachNeeded'))
              return
            }
            try {
              await guard(() => api.del(`/api/sources/${del.id}${detach ? '?detach=1' : ''}`))
              setDel(null)
              toast.push('ok', t('src.delete.done'))
              await res.reload()
            } catch (e) {
              if (!(e instanceof Cancelled)) await run(() => Promise.reject(e))
            }
          }}
        />
      ) : null}
      {del && del.refs.length > 0 ? (
        <div className="detach-float">
          <Toggle checked={detach} onChange={setDetach}>
            {t('src.delete.detach')}
          </Toggle>
        </div>
      ) : null}
    </>
  )
}

// ---- add / edit ------------------------------------------------------------------------

function SourceForm({ source, onClose, onSaved }: { source?: SourceView; onClose: () => void; onSaved: (s: SourceView, urlChanged: boolean) => Promise<void> }) {
  const { t } = useI18n()
  const run = useRunner()
  const editing = !!source
  const [mode, setMode] = useState<'url' | 'static'>(source?.kind ?? 'url')
  const [name, setName] = useState(source?.name ?? '')
  const [note, setNote] = useState(source?.note ?? '')
  const [tags, setTags] = useState(source?.tags.join(', ') ?? '')
  const [url, setUrl] = useState('')
  const [content, setContent] = useState('')
  const [ua, setUa] = useState(source?.user_agent ?? '')
  const [interval, setIntervalMin] = useState(String(source?.interval_min ?? 360))
  const [enabled, setEnabled] = useState(source?.enabled ?? true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const iv = Number(interval)
  const ivBad = mode === 'url' && (!Number.isInteger(iv) || iv < 0 || (iv > 0 && iv < 15))

  const submit = async () => {
    if (!editing) {
      if (mode === 'url' && !url.trim()) return setError(t('src.add.needUrl'))
      if (mode === 'static' && !content.trim()) return setError(t('src.add.needContent'))
    }
    if (ivBad) return setError(t('src.add.intervalBad'))
    setError(null)
    setBusy(true)
    let result: { source: SourceView } | { url_changed: boolean } | undefined
    if (editing && source) {
      const patch: Record<string, unknown> = { name: name.trim(), note: note.trim(), tags: splitTags(tags), user_agent: ua.trim(), enabled }
      if (source.kind === 'url') {
        patch.interval_min = iv
        if (url.trim()) patch.url = url.trim()
      }
      result = await run(() => api.patch<{ url_changed: boolean }>(`/api/sources/${source.id}`, patch))
      setBusy(false)
      if (result) await onSaved(source, (result as { url_changed: boolean }).url_changed)
      return
    }
    result = await run(() =>
      api.post<{ source: SourceView }>('/api/sources', {
        name: name.trim(),
        note: note.trim(),
        tags: splitTags(tags),
        url: mode === 'url' ? url.trim() : '',
        content: mode === 'static' ? content : '',
        user_agent: ua.trim(),
        interval_min: mode === 'url' ? iv : 0,
        enabled,
      }),
    )
    setBusy(false)
    if (result) await onSaved((result as { source: SourceView }).source, false)
  }

  return (
    <Modal
      title={editing ? t('src.edit.title') : t('src.add.title')}
      onClose={onClose}
      busy={busy}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={ivBad}>
            {editing ? t('common.save') : t('src.new')}
          </Button>
        </>
      }
    >
      <div className="stack">
        {!editing ? (
          <Field label={t('src.add.mode')}>
            {() => (
              <Segmented
                label={t('src.add.mode')}
                value={mode}
                onChange={setMode}
                options={[
                  { value: 'url', label: t('src.add.url') },
                  { value: 'static', label: t('src.add.content') },
                ]}
              />
            )}
          </Field>
        ) : null}
        {error ? <Notice tone="error">{error}</Notice> : null}

        <Field label={`${t('src.add.name')} ${t('common.optional')}`}>{(id) => <Input id={id} data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}</Field>

        {mode === 'url' ? (
          <Field label={t('src.add.urlLabel')} hint={editing ? t('src.add.urlKeep') : t('src.add.urlHint')} required={!editing}>
            {(id, d) => <Input id={id} aria-describedby={d} type="url" autoComplete="off" autoCapitalize="none" spellCheck={false} placeholder="https://example.com/sub?token=…" value={url} onChange={(e) => setUrl(e.target.value)} />}
          </Field>
        ) : editing ? (
          <Notice tone="neutral">{t('src.edit.staticNote')}</Notice>
        ) : (
          <Field label={t('src.add.contentLabel')} hint={t('src.add.contentHint')} required>
            {(id, d) => <Textarea id={id} aria-describedby={d} rows={7} className="mono" spellCheck={false} autoCapitalize="none" value={content} onChange={(e) => setContent(e.target.value)} />}
          </Field>
        )}

        {editing && source?.kind === 'url' ? (
          <Reveal<{ value: string }> label={t('src.edit.currentHidden')} load={() => api.get(`/api/sources/${source.id}/url`)}>
            {(v) => (
              <div>
                <div className="muted small">{t('src.edit.current')}</div>
                <textarea className="input textarea mono" readOnly rows={2} value={v.value} onFocus={(e) => e.currentTarget.select()} aria-label={t('src.edit.current')} />
              </div>
            )}
          </Reveal>
        ) : null}

        <div className="grid-fields">
          <Field label={`${t('src.add.tags')} ${t('common.optional')}`} hint={t('src.add.tagsHint')}>
            {(id, d) => <Input id={id} aria-describedby={d} value={tags} onChange={(e) => setTags(e.target.value)} />}
          </Field>
          <Field label={`${t('src.add.note')} ${t('common.optional')}`}>{(id) => <Input id={id} maxLength={120} value={note} onChange={(e) => setNote(e.target.value)} />}</Field>
        </div>

        {mode === 'url' ? (
          <>
            <div className="grid-fields">
              <Field label={t('src.add.interval')} hint={t('src.add.intervalHint')} error={ivBad ? t('src.add.intervalBad') : null}>
                {(id, d) => <Input id={id} aria-describedby={d} inputMode="numeric" value={interval} onChange={(e) => setIntervalMin(e.target.value.replace(/\D/g, '').slice(0, 5))} />}
              </Field>
              <Field label={`${t('src.add.ua')} ${t('common.optional')}`} hint={t('src.add.uaHint')}>
                {(id, d) => <Input id={id} aria-describedby={d} value={ua} onChange={(e) => setUa(e.target.value)} placeholder="clash-verge/v2" autoCapitalize="none" spellCheck={false} />}
              </Field>
            </div>
            <Toggle checked={enabled} onChange={setEnabled}>
              {t('src.add.enabled')}
            </Toggle>
          </>
        ) : null}
        <p className="muted small">{t('src.add.limits')}</p>
      </div>
    </Modal>
  )
}

// ---- nodes and parse report ------------------------------------------------------------

function SourceNodes({ source, onClose, onChanged }: { source: SourceView; onClose: () => void; onChanged: () => void }) {
  const { t } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const res = useResource<{ nodes: SourceNode[]; issues: SourceIssue[] }>(`/api/sources/${source.id}/nodes`)
  const [tab, setTab] = useState<'nodes' | 'issues'>('nodes')
  const [query, setQuery] = useState('')
  const [proto, setProto] = useState('all')
  const [saving, setSaving] = useState(false)
  const nodes = res.data?.nodes ?? []
  const issues = res.data?.issues ?? []
  const protocols = [...new Set(nodes.map((n) => n.protocol))].sort()
  const q = query.trim().toLowerCase()
  const shown = nodes.filter((n) => (proto === 'all' || n.protocol === proto) && (!q || `${n.name} ${n.server} ${n.protocol}`.toLowerCase().includes(q)))

  const save = async (next: SourceNode[]) => {
    setSaving(true)
    const disabled = next.filter((n) => !n.enabled).map((n) => n.id)
    const r = await run(() => api.put(`/api/sources/${source.id}/nodes`, { disabled }))
    setSaving(false)
    if (r !== undefined) {
      res.setData({ nodes: next, issues })
      toast.push('ok', t('src.nodes.saved'))
      onChanged()
    }
  }
  const setMany = (ids: Set<string>, on: boolean) => void save(nodes.map((n) => (ids.has(n.id) ? { ...n, enabled: on } : n)))

  return (
    <Drawer title={t('src.nodes.title', { name: source.name })} onClose={onClose} wide>
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
        {tab === 'nodes' ? (
          nodes.length === 0 && !res.loading ? (
            <EmptyState icon="nodes" title={t('src.nodes.none')} />
          ) : (
            <>
              <div className="toolbar toolbar-plain">
                <SearchInput value={query} onChange={setQuery} placeholder={t('src.nodes.search')} label={t('src.nodes.search')} />
                <Select aria-label={t('src.nodes.protocol')} value={proto} onChange={(e) => setProto(e.target.value)}>
                  <option value="all">{t('subs.pool.protocolAll')}</option>
                  {protocols.map((p) => (
                    <option key={p} value={p}>
                      {p.toUpperCase()}
                    </option>
                  ))}
                </Select>
                <Button size="sm" disabled={saving || shown.length === 0} onClick={() => setMany(new Set(shown.map((n) => n.id)), true)}>
                  {t('src.nodes.enableAll')}
                </Button>
                <Button size="sm" disabled={saving || shown.length === 0} onClick={() => setMany(new Set(shown.map((n) => n.id)), false)}>
                  {t('src.nodes.disableAll')}
                </Button>
              </div>
              <ul className="node-rows">
                {shown.map((n) => (
                  <li key={n.id} className={n.enabled ? '' : 'is-off'}>
                    <Switch checked={n.enabled} disabled={saving} label={n.name} onChange={(on) => void save(nodes.map((x) => (x.id === n.id ? { ...x, enabled: on } : x)))} />
                    <div className="node-row-main">
                      <strong>{n.name}</strong>
                      <div className="small muted">
                        <Badge>{n.protocol.toUpperCase()}</Badge> <span className="mono">{n.server}:{n.port}</span>
                        {n.transport ? <> · {n.transport}</> : null}
                        {n.security ? <> · {n.security}</> : null}
                        {n.sni ? <> · SNI {n.sni}</> : null}
                        {n.udp ? <> · UDP</> : null}
                      </div>
                      <div className="badges">
                        {n.from_clash ? <Badge>{t('src.nodes.clash')}</Badge> : null}
                        {!n.link_ok ? (
                          <Badge tone="warn" title={n.link_issue}>
                            {t('src.nodes.noShare')}
                          </Badge>
                        ) : null}
                      </div>
                      {n.link_issue ? <div className="small warn-text">{n.link_issue}</div> : null}
                      {(n.notes ?? []).map((x) => (
                        <div key={x} className="small muted">
                          {x}
                        </div>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )
        ) : (
          <div className="stack">
            <p className="muted">{t('src.nodes.issuesIntro')}</p>
            {issues.length === 0 ? (
              <Notice tone="ok">{t('src.nodes.noIssues')}</Notice>
            ) : (
              <ul className="issue-list">
                {issues.map((is, i) => (
                  <li key={i}>
                    <Badge tone={is.level === 'error' ? 'error' : 'warn'}>{is.level === 'error' ? t('src.nodes.levelError') : is.level === 'skipped' ? t('src.nodes.levelSkipped') : t('src.nodes.levelWarn')}</Badge>
                    <div>
                      {is.name || is.protocol ? (
                        <strong>
                          {is.name} {is.protocol ? <span className="muted">({is.protocol})</span> : null}
                        </strong>
                      ) : null}
                      <div className="small">{is.reason}</div>
                      {is.line ? <div className="small muted">{t('src.nodes.line', { n: is.line })}</div> : null}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </Drawer>
  )
}

export { Check }

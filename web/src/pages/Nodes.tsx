import { useMemo, useState } from 'react'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { useDebounced, useResource } from '../lib/hooks'
import { formatDateTime } from '../lib/format'
import { Cancelled, useReauth, useRunner } from '../lib/session'
import type { ExitRef, HostInfo, NodeList, NodeView, ProtocolInfo } from '../lib/types'
import { DataTable, type Column } from '../components/table'
import { ConfirmDialog, Drawer, Menu, Modal } from '../components/overlay'
import { DiagPanel, SecretBox, StateBadge, TrafficCell, WarningBadges } from '../components/shared'
import { Badge, Button, Card, EmptyState, Field, Input, KV, PageHead, SearchInput, Segmented, Select, Spinner } from '../components/ui'
import { Icon } from '../components/icons'

type StateFilter = 'all' | 'running' | 'stopped' | 'disabled' | 'warn'

export function NodesPage() {
  const { t, locale } = useI18n()
  const run = useRunner()
  const { guard } = useReauth()
  const res = useResource<NodeList>('/api/nodes', { interval: 10000 })
  const [query, setQuery] = useState('')
  const q = useDebounced(query, 150).trim().toLowerCase()
  const [protocol, setProtocol] = useState('')
  const [state, setState] = useState<StateFilter>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [creating, setCreating] = useState(false)
  const [detail, setDetail] = useState<string | null>(null)
  const [rename, setRename] = useState<NodeView | null>(null)
  const [del, setDel] = useState<NodeView[] | null>(null)
  const [bind, setBind] = useState(false)

  const list = res.data
  const nodes = list?.nodes ?? []
  const filtered = useMemo(
    () =>
      nodes.filter((n) => {
        if (protocol && n.protocol !== protocol) return false
        if (state === 'running' && n.state !== 'running') return false
        if (state === 'stopped' && n.state !== 'stopped') return false
        if (state === 'disabled' && n.enabled) return false
        if (state === 'warn' && n.warnings.length === 0) return false
        if (q) {
          const hay = `${n.name} ${n.label} ${n.protocol} ${n.public_host}:${n.public_port} ${n.exit_name ?? ''}`.toLowerCase()
          if (!hay.includes(q)) return false
        }
        return true
      }),
    [nodes, protocol, state, q],
  )
  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes])
  const chosen = [...selected].map((id) => byId.get(id)).filter((n): n is NodeView => !!n)
  const detailNode = detail ? byId.get(detail) ?? null : null
  const filtering = protocol !== '' || state !== 'all' || q !== ''

  const act = async (fn: () => Promise<unknown>, ok?: string) => {
    const r = await run(fn, ok ? { ok } : undefined)
    await res.reload()
    return r
  }
  const bulk = (action: string, ids: string[], extra?: Record<string, string>) => api.post<{ count: number }>('/api/nodes/bulk', { action, ids, ...extra })

  const columns: Column<NodeView>[] = [
    {
      key: 'name',
      header: t('nodes.col.name'),
      primary: true,
      cell: (n) => (
        <div className="name-cell">
          <strong>{n.name}</strong>
          <div className="badges">
            <WarningBadges warnings={n.warnings} />
          </div>
        </div>
      ),
    },
    { key: 'proto', header: t('nodes.col.protocol'), label: t('nodes.col.protocol'), cell: (n) => <Badge>{n.label}</Badge> },
    { key: 'state', header: t('nodes.col.state'), label: t('nodes.col.state'), cell: (n) => <StateBadge state={n.state} /> },
    {
      key: 'addr',
      header: t('nodes.col.address'),
      label: t('nodes.col.address'),
      cell: (n) => (
        <span className="mono small">
          {n.public_host}:{n.public_port} {n.family ? <Badge>{t(`family.${n.family}` as 'family.ipv4')}</Badge> : null}
        </span>
      ),
    },
    { key: 'exit', header: t('nodes.col.exit'), label: t('nodes.col.exit'), cell: (n) => n.exit_name ?? <span className="muted">{t('nodes.direct')}</span> },
    { key: 'traffic', header: t('nodes.col.traffic'), label: t('nodes.col.traffic'), cell: (n) => <TrafficCell traffic={n.traffic} /> },
    {
      key: 'actions',
      header: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (n) => (
        <div onClick={(e) => e.stopPropagation()}>
          <Menu
            label={t('common.more')}
            items={[
              { label: t('nodes.action.test'), icon: 'test', onSelect: () => setDetail(n.id) },
              { label: t('nodes.action.link'), icon: 'qr', onSelect: () => setDetail(n.id), hidden: !n.has_link },
              { label: t('nodes.action.restart'), icon: 'refresh', disabled: !n.enabled, onSelect: () => void act(() => api.post(`/api/nodes/${n.id}/restart`), t('nodes.restarted')) },
              { label: n.enabled ? t('common.disable') : t('common.enable'), icon: n.enabled ? 'stop' : 'play', onSelect: () => void act(() => bulk(n.enabled ? 'disable' : 'enable', [n.id]), n.enabled ? t('nodes.disabledOk') : t('nodes.enabled')) },
              { label: t('common.rename'), icon: 'edit', onSelect: () => setRename(n) },
              { label: t('common.delete'), icon: 'trash', danger: true, onSelect: () => setDel([n]) },
            ]}
          />
        </div>
      ),
    },
  ]

  if (res.loading && !list) return <Spinner label={t('common.loading')} />
  if (!list) {
    return (
      <EmptyState icon="warn" title={t('common.loadFailed')} action={<Button onClick={() => void res.reload()}>{t('common.retry')}</Button>}>
        {res.error?.message}
      </EmptyState>
    )
  }

  return (
    <div className="page">
      <PageHead
        title={t('nodes.title')}
        subtitle={t('nodes.subtitle')}
        actions={
          <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
            {t('nodes.new')}
          </Button>
        }
      />

      <Card flush>
        <div className="toolbar">
          <SearchInput value={query} onChange={setQuery} placeholder={t('nodes.search')} label={t('common.search')} />
          <Select aria-label={t('nodes.filterProtocol')} value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            <option value="">{t('nodes.allProtocols')}</option>
            {list.protocols.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </Select>
          <Select aria-label={t('nodes.filterState')} value={state} onChange={(e) => setState(e.target.value as StateFilter)}>
            <option value="all">{t('nodes.state.all')}</option>
            <option value="running">{t('nodes.state.running')}</option>
            <option value="stopped">{t('nodes.state.stopped')}</option>
            <option value="disabled">{t('nodes.state.disabled')}</option>
            <option value="warn">{t('nodes.state.warn')}</option>
          </Select>
          {filtering ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setQuery('')
                setProtocol('')
                setState('all')
              }}
            >
              {t('common.clearFilters')}
            </Button>
          ) : null}
          <span className="toolbar-count muted small">{t('common.total', { n: filtered.length })}</span>
        </div>

        {chosen.length > 0 ? (
          <div className="bulkbar" role="region" aria-label={t('common.selected', { n: chosen.length })}>
            <strong>{t('common.selected', { n: chosen.length })}</strong>
            <Button size="sm" icon="play" onClick={() => void act(() => bulk('enable', [...selected]), t('nodes.bulk.done', { n: chosen.length }))}>
              {t('nodes.bulk.enable')}
            </Button>
            <Button size="sm" icon="stop" onClick={() => void act(() => bulk('disable', [...selected]), t('nodes.bulk.done', { n: chosen.length }))}>
              {t('nodes.bulk.disable')}
            </Button>
            <Button size="sm" icon="link" onClick={() => setBind(true)} disabled={list.exits.length === 0}>
              {t('nodes.bulk.bind')}
            </Button>
            <Button size="sm" onClick={() => void act(() => bulk('unbind_exit', [...selected]), t('nodes.bulk.done', { n: chosen.length }))}>
              {t('nodes.bulk.unbind')}
            </Button>
            <Button size="sm" variant="danger" icon="trash" onClick={() => setDel(chosen)}>
              {t('nodes.bulk.delete')}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
              {t('common.clearSelection')}
            </Button>
          </div>
        ) : null}

        <DataTable
          caption={t('nodes.tableCaption')}
          rows={filtered}
          rowKey={(n) => n.id}
          columns={columns}
          selected={selected}
          onSelect={setSelected}
          selectLabel={t('common.selectRow')}
          selectAllLabel={t('common.selectAll')}
          onRowClick={(n) => setDetail(n.id)}
          empty={
            nodes.length === 0 ? (
              <EmptyState icon="nodes" title={t('nodes.empty')} action={<Button variant="primary" icon="plus" onClick={() => setCreating(true)}>{t('nodes.new')}</Button>}>
                {t('nodes.emptyHint')}
              </EmptyState>
            ) : (
              <EmptyState icon="search" title={t('common.noMatch')} />
            )
          }
        />
      </Card>

      {creating ? (
        <CreateNodes
          protocols={list.protocols}
          exits={list.exits}
          host={list.host}
          onClose={() => setCreating(false)}
          onCreated={async (n) => {
            setCreating(false)
            await res.reload()
            if (n > 0) run(async () => undefined, { ok: t('nodes.create.done', { n }) })
          }}
        />
      ) : null}

      {detailNode ? (
        <NodeDetail
          node={detailNode}
          locale={locale}
          onClose={() => setDetail(null)}
          onRename={() => setRename(detailNode)}
          onDelete={() => setDel([detailNode])}
          onToggle={() => void act(() => bulk(detailNode.enabled ? 'disable' : 'enable', [detailNode.id]), detailNode.enabled ? t('nodes.disabledOk') : t('nodes.enabled'))}
          onRestart={() => void act(() => api.post(`/api/nodes/${detailNode.id}/restart`), t('nodes.restarted'))}
        />
      ) : null}

      {rename ? (
        <RenameDialog
          current={rename.name}
          onClose={() => setRename(null)}
          onSave={async (name) => {
            const ok = await run(() => api.patch(`/api/nodes/${rename.id}`, { name }), { ok: t('nodes.renamed') })
            if (ok !== undefined) {
              setRename(null)
              await res.reload()
            }
          }}
        />
      ) : null}

      {del ? (
        <ConfirmDialog
          title={del.length === 1 ? t('nodes.deleteTitle', { name: del[0]!.name }) : t('nodes.bulk.deleteTitle', { n: del.length })}
          message={t('nodes.deleteMsg')}
          impact={[
            t('nodes.deleteImpact.link'),
            ...[...new Set(del.flatMap((n) => n.subscriptions))].slice(0, 6).map((s) => t('nodes.deleteImpact.subs', { names: s })),
            t('nodes.deleteImpact.port'),
          ]}
          confirmLabel={t('common.delete')}
          danger
          onCancel={() => setDel(null)}
          onConfirm={async () => {
            const ids = del.map((n) => n.id)
            try {
              await guard(() => (ids.length === 1 ? api.del(`/api/nodes/${ids[0]}`) : bulk('delete', ids)))
              setDel(null)
              setSelected(new Set())
              setDetail(null)
              await res.reload()
              await run(async () => undefined, { ok: t('nodes.deleted') })
            } catch (e) {
              if (!(e instanceof Cancelled)) await run(() => Promise.reject(e))
            }
          }}
        />
      ) : null}

      {bind ? (
        <BindExit
          count={chosen.length}
          exits={list.exits}
          onClose={() => setBind(false)}
          onBind={async (exitId) => {
            const r = await act(() => bulk('bind_exit', [...selected], { exit_id: exitId }), t('nodes.bulk.done', { n: chosen.length }))
            if (r !== undefined) setBind(false)
          }}
        />
      ) : null}
    </div>
  )
}

// ---- dialogs ---------------------------------------------------------------------------

function RenameDialog({ current, onClose, onSave }: { current: string; onClose: () => void; onSave: (name: string) => Promise<void> }) {
  const { t } = useI18n()
  const [name, setName] = useState(current)
  const [busy, setBusy] = useState(false)
  return (
    <Modal
      title={t('nodes.rename.title')}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            busy={busy}
            disabled={!name.trim() || name.trim() === current}
            onClick={async () => {
              setBusy(true)
              await onSave(name.trim())
              setBusy(false)
            }}
          >
            {t('common.save')}
          </Button>
        </>
      }
    >
      <Field label={t('common.name')}>{(id) => <Input id={id} data-autofocus value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />}</Field>
    </Modal>
  )
}

function BindExit({ count, exits, onClose, onBind }: { count: number; exits: ExitRef[]; onClose: () => void; onBind: (id: string) => Promise<void> }) {
  const { t } = useI18n()
  const [exit, setExit] = useState(exits[0]?.id ?? '')
  const [busy, setBusy] = useState(false)
  return (
    <Modal
      title={t('nodes.bulk.bindTitle', { n: count })}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            busy={busy}
            disabled={!exit}
            onClick={async () => {
              setBusy(true)
              await onBind(exit)
              setBusy(false)
            }}
          >
            {t('nodes.bulk.bind')}
          </Button>
        </>
      }
    >
      <p className="muted">{t('nodes.bulk.bindHint')}</p>
      <Field label={t('nodes.create.exit')}>
        {(id) => (
          <Select id={id} value={exit} onChange={(e) => setExit(e.target.value)}>
            {exits.map((x) => (
              <option key={x.id} value={x.id}>
                {x.name}
              </option>
            ))}
          </Select>
        )}
      </Field>
    </Modal>
  )
}

function CreateNodes({ protocols, exits, host, onClose, onCreated }: { protocols: ProtocolInfo[]; exits: ExitRef[]; host: HostInfo; onClose: () => void; onCreated: (n: number) => Promise<void> }) {
  const { t } = useI18n()
  const run = useRunner()
  const [base, setBase] = useState('')
  const [picked, setPicked] = useState<string[]>(protocols[0] ? [protocols[0].id] : [])
  const [inbound, setInbound] = useState<'' | 'ipv4' | 'ipv6' | 'dual'>('')
  const [sni, setSni] = useState('')
  const [exit, setExit] = useState('')
  const [port, setPort] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const usesReality = picked.some((p) => p === 'vless' || p === 'anytls')
  const portNum = port.trim() === '' ? 0 : Number(port)
  const portBad = port.trim() !== '' && (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535)
  const toggle = (id: string, on: boolean) => setPicked((l) => (on ? [...l, id] : l.filter((x) => x !== id)))

  const submit = async () => {
    if (picked.length === 0) {
      setError(t('nodes.create.needProtocol'))
      return
    }
    setError(null)
    setBusy(true)
    const r = await run(() => api.post<{ nodes: NodeView[] }>('/api/nodes', { base_name: base.trim(), protocols: picked, inbound, reality_sni: usesReality ? sni.trim() : '', exit_id: exit, port: picked.length === 1 ? portNum : 0 }))
    setBusy(false)
    if (r) await onCreated(r.nodes.length)
  }

  return (
    <Modal
      title={t('nodes.create.title')}
      onClose={onClose}
      busy={busy}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={picked.length === 0 || portBad}>
            {t('common.create')}
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label={t('nodes.create.name')} hint={t('nodes.create.nameHint')}>
          {(id, d) => <Input id={id} aria-describedby={d} data-autofocus placeholder="Rout" maxLength={40} value={base} onChange={(e) => setBase(e.target.value)} />}
        </Field>

        <fieldset className="fieldset">
          <legend>{t('nodes.create.protocols')}</legend>
          <div className="choice-grid">
            {protocols.map((p) => (
              <label key={p.id} className={`choice ${picked.includes(p.id) ? 'on' : ''}`}>
                <input type="checkbox" checked={picked.includes(p.id)} onChange={(e) => toggle(p.id, e.target.checked)} />
                <span className="choice-title">{p.label}</span>
                <span className="choice-sub">{p.networks.map((n) => n.toUpperCase()).join(' + ')}</span>
              </label>
            ))}
          </div>
          {error ? (
            <p className="err" role="alert">
              {error}
            </p>
          ) : null}
        </fieldset>

        <Field label={t('nodes.create.inbound')} hint={t('nodes.create.inboundHint')}>
          {() => (
            <Segmented
              label={t('nodes.create.inbound')}
              value={inbound}
              onChange={setInbound}
              options={[
                { value: '', label: t('common.auto') },
                { value: 'ipv4', label: 'IPv4', disabled: !host.ipv4, title: host.ipv4 ? undefined : t('nodes.create.noV4') },
                { value: 'ipv6', label: 'IPv6', disabled: !host.ipv6, title: host.ipv6 ? undefined : t('nodes.create.noV6') },
                { value: 'dual', label: t('family.dual'), disabled: !(host.ipv4 && host.ipv6), title: host.ipv4 && host.ipv6 ? undefined : t('nodes.create.dualNeeds') },
              ]}
            />
          )}
        </Field>

        {usesReality ? (
          <Field label={t('nodes.create.sni')} hint={t('nodes.create.sniHint')}>
            {(id, d) => <Input id={id} aria-describedby={d} placeholder="www.example.com" value={sni} onChange={(e) => setSni(e.target.value)} autoCapitalize="none" spellCheck={false} />}
          </Field>
        ) : null}

        <div className="grid-fields">
          <Field label={t('nodes.create.exit')} hint={t('nodes.create.exitHint')}>
            {(id, d) => (
              <Select id={id} aria-describedby={d} value={exit} onChange={(e) => setExit(e.target.value)}>
                <option value="">{t('nodes.direct')}</option>
                {exits.map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          {picked.length === 1 ? (
            <Field label={`${t('nodes.create.port')} ${t('common.optional')}`} hint={t('nodes.create.portHint')} error={portBad ? t('nodes.create.portHint') : null}>
              {(id, d) => <Input id={id} aria-describedby={d} inputMode="numeric" placeholder={t('common.auto')} value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, '').slice(0, 5))} />}
            </Field>
          ) : null}
        </div>
      </div>
    </Modal>
  )
}

// ---- detail ----------------------------------------------------------------------------

function NodeDetail({ node, locale, onClose, onRename, onDelete, onToggle, onRestart }: { node: NodeView; locale: string; onClose: () => void; onRename: () => void; onDelete: () => void; onToggle: () => void; onRestart: () => void }) {
  const { t } = useI18n()
  const tr = node.traffic
  return (
    <Drawer title={node.name} onClose={onClose}>
      <div className="stack">
        <div className="row-wrap">
          <StateBadge state={node.state} />
          <Badge>{node.label}</Badge>
          <WarningBadges warnings={node.warnings} />
        </div>
        <div className="row-wrap">
          <Button size="sm" icon={node.enabled ? 'stop' : 'play'} onClick={onToggle}>
            {node.enabled ? t('common.disable') : t('common.enable')}
          </Button>
          <Button size="sm" icon="refresh" onClick={onRestart} disabled={!node.enabled}>
            {t('nodes.action.restart')}
          </Button>
          <Button size="sm" icon="edit" onClick={onRename}>
            {t('common.rename')}
          </Button>
          <Button size="sm" variant="danger" icon="trash" onClick={onDelete}>
            {t('common.delete')}
          </Button>
        </div>

        <section>
          <h3 className="section-title">{t('nodes.detail.info')}</h3>
          <KV
            items={[
              { k: t('nodes.detail.public'), v: `${node.public_host}:${node.public_port}`, mono: true },
              { k: t('nodes.detail.listen'), v: `${node.listen}:${node.port}`, mono: true },
              { k: t('nodes.detail.networks'), v: node.networks.map((n) => n.toUpperCase()).join(' + ') },
              ...(node.inbound ? [{ k: t('nodes.detail.inbound'), v: t(`family.${node.inbound}` as 'family.ipv4') }] : []),
              ...(node.sni ? [{ k: 'SNI', v: node.sni, mono: true }] : []),
              { k: t('nodes.col.exit'), v: node.exit_name ?? t('nodes.direct') },
              ...(node.cert ? [{ k: t('nodes.detail.cert'), v: node.cert.days < 0 ? t('dash.certExpired', { n: -node.cert.days }) : t('dash.certDays', { n: node.cert.days }) + (node.cert.self_signed ? ` · ${t('dash.selfSigned')}` : '') }] : []),
              { k: t('nodes.detail.sub'), v: node.subscriptions.length ? node.subscriptions.join('、') : t('common.none') },
              { k: t('nodes.detail.created'), v: formatDateTime(node.created_at, locale) },
            ]}
          />
        </section>

        {tr ? (
          <section>
            <h3 className="section-title">{t('nodes.detail.traffic')}</h3>
            <TrafficCell traffic={tr} />
            {tr.active ? (
              <KV
                items={[
                  { k: t('dash.down'), v: `${(tr.down / 1024 ** 3).toFixed(2)} GB`, mono: true },
                  { k: t('dash.up'), v: `${(tr.up / 1024 ** 3).toFixed(2)} GB`, mono: true },
                  { k: t('nodes.detail.trafficStatus'), v: t(`nodes.traffic.${tr.status}` as 'nodes.traffic.ok') },
                ]}
              />
            ) : null}
            {tr.incomplete ? <p className="muted small">{t('nodes.traffic.incomplete')}</p> : null}
          </section>
        ) : null}

        <section>
          <h3 className="section-title">{t('nodes.detail.share')}</h3>
          {node.has_link ? (
            <SecretBox label={t('nodes.detail.shareHidden')} qrLabel={`${node.name} QR`} load={async () => (await api.get<{ link: string }>(`/api/nodes/${node.id}/link`)).link} />
          ) : (
            <p className="muted">{t('nodes.detail.noLink')}</p>
          )}
        </section>

        <section>
          <h3 className="section-title">
            <Icon name="test" size={16} /> {t('nodes.detail.test')}
          </h3>
          <DiagPanel path={`/api/nodes/${node.id}/test`} />
        </section>
      </div>
    </Drawer>
  )
}

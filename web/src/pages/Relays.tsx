import { useMemo, useState, type ReactNode } from 'react'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { useDebounced, useResource } from '../lib/hooks'
import { Cancelled, useReauth, useRunner } from '../lib/session'
import { useToast } from '../lib/toast'
import { useRouter } from '../lib/router'
import type { ExitView, HostInfo, RelayList, RelayView } from '../lib/types'
import { DataTable, type Column } from '../components/table'
import { ConfirmDialog, Drawer, Menu, Modal } from '../components/overlay'
import { DiagPanel, HopPath, PathChain, SecretBox, StateBadge, WarningBadges } from '../components/shared'
import { Badge, Button, Card, EmptyState, Field, Input, KV, Notice, PageHead, SearchInput, Segmented, Select, Spinner, Tabs, Textarea, Toggle } from '../components/ui'

export function RelaysPage({ tab }: { tab: 'relays' | 'exits' }) {
  const { t } = useI18n()
  const { navigate } = useRouter()
  return (
    <div className="page">
      <PageHead title={t('relays.title')} subtitle={t('relays.subtitle')} />
      <Tabs label={t('relays.title')} value={tab} onChange={(v) => navigate(v === 'relays' ? '/relays' : '/exits')} tabs={[{ value: 'relays', label: t('relays.tab.relays') }, { value: 'exits', label: t('relays.tab.exits') }]} />
      <p className="muted small tab-explain">{t(tab === 'relays' ? 'relays.explain' : 'exits.explain')}</p>
      {tab === 'relays' ? <RelaysTab /> : <ExitsTab />}
    </div>
  )
}

const transportKey = (p: string) => (p === 'udp' ? 'relays.transport.udp' : p === 'both' ? 'relays.transport.both' : 'relays.transport.tcp')

function relayPath(r: RelayView, t: ReturnType<typeof useI18n>['t']) {
  const items: { label: ReactNode; kind: 'entry' | 'relay' | 'target' | 'exit' }[] = [
    { label: <span className="mono">{r.public_host}:{r.public_port}</span>, kind: 'entry' },
    { label: r.name, kind: 'relay' },
    { label: <span className="mono">{r.target}</span>, kind: 'target' },
  ]
  if (r.target_node) items.push({ label: t('relays.path.node', { name: r.target_node }), kind: 'target' })
  return items
}

// ---- relays ----------------------------------------------------------------------------

function RelaysTab() {
  const { t } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const { guard } = useReauth()
  const res = useResource<RelayList>('/api/relays', { interval: 10000 })
  const [query, setQuery] = useState('')
  const q = useDebounced(query, 150).trim().toLowerCase()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [creating, setCreating] = useState(false)
  const [detail, setDetail] = useState<string | null>(null)
  const [edit, setEdit] = useState<RelayView | null>(null)
  const [del, setDel] = useState<RelayView[] | null>(null)

  const list = res.data
  const relays = list?.relays ?? []
  const filtered = useMemo(() => relays.filter((r) => !q || `${r.name} ${r.public_host}:${r.public_port} ${r.target}`.toLowerCase().includes(q)), [relays, q])
  const byId = useMemo(() => new Map(relays.map((r) => [r.id, r])), [relays])
  const chosen = [...selected].map((id) => byId.get(id)).filter((r): r is RelayView => !!r)
  const detailRelay = detail ? byId.get(detail) ?? null : null

  const act = async (fn: () => Promise<unknown>, ok?: string) => {
    const r = await run(fn, ok ? { ok } : undefined)
    await res.reload()
    return r
  }
  const bulk = (action: string, ids: string[]) => api.post('/api/relays/bulk', { action, ids })

  const columns: Column<RelayView>[] = [
    {
      key: 'name',
      header: t('relays.col.name'),
      primary: true,
      cell: (r) => (
        <div className="name-cell">
          <strong>{r.name}</strong>
          <div className="badges">
            <WarningBadges warnings={r.warnings} />
            {r.target_network === 'tcp' ? <Badge tone="warn">{t('relays.natTcp')}</Badge> : null}
            {r.chain_exits?.length ? <Badge title={r.chain_exits.join('、')}>{t('relays.chainUsers', { n: r.chain_exits.length })}</Badge> : null}
            {r.ai_chain ? <Badge tone="accent">{t('relays.aiChain')}</Badge> : null}
          </div>
        </div>
      ),
    },
    { key: 'mode', header: t('relays.col.mode'), label: t('relays.col.mode'), cell: (r) => <Badge>{t(r.mode === 'local' ? 'relays.mode.local' : 'relays.mode.remote')}</Badge> },
    {
      key: 'entry',
      header: t('relays.col.entry'),
      label: t('relays.col.entry'),
      cell: (r) => (
        <span className="mono small">
          {r.public_host}:{r.public_port} {r.family ? <Badge>{t(`family.${r.family}` as 'family.ipv4')}</Badge> : null}
        </span>
      ),
    },
    { key: 'transport', header: t('relays.col.transport'), label: t('relays.col.transport'), cell: (r) => t(transportKey(r.transport)) },
    { key: 'path', header: t('relays.col.path'), label: t('relays.col.path'), cell: (r) => <PathChain items={relayPath(r, t)} /> },
    { key: 'state', header: t('relays.col.state'), label: t('relays.col.state'), cell: (r) => <StateBadge state={r.state} /> },
    {
      key: 'actions',
      header: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (r) => (
        <div onClick={(e) => e.stopPropagation()}>
          <Menu
            label={t('common.more')}
            items={[
              { label: t('nodes.action.test'), icon: 'test', onSelect: () => setDetail(r.id) },
              { label: t('nodes.action.restart'), icon: 'refresh', disabled: !r.enabled, onSelect: () => void act(() => api.post(`/api/relays/${r.id}/restart`), t('nodes.restarted')) },
              { label: r.enabled ? t('common.disable') : t('common.enable'), icon: r.enabled ? 'stop' : 'play', onSelect: () => void act(() => bulk(r.enabled ? 'disable' : 'enable', [r.id])) },
              { label: t('common.edit'), icon: 'edit', onSelect: () => setEdit(r) },
              { label: t('common.delete'), icon: 'trash', danger: true, onSelect: () => setDel([r]) },
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
    <>
      <Card flush>
        <div className="toolbar">
          <SearchInput value={query} onChange={setQuery} placeholder={t('relays.search')} label={t('common.search')} />
          <span className="toolbar-count muted small">{t('common.total', { n: filtered.length })}</span>
          <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
            {t('relays.new')}
          </Button>
        </div>
        {chosen.length > 0 ? (
          <div className="bulkbar">
            <strong>{t('common.selected', { n: chosen.length })}</strong>
            <Button size="sm" icon="play" onClick={() => void act(() => bulk('enable', [...selected]), t('nodes.bulk.done', { n: chosen.length }))}>
              {t('nodes.bulk.enable')}
            </Button>
            <Button size="sm" icon="stop" onClick={() => void act(() => bulk('disable', [...selected]), t('nodes.bulk.done', { n: chosen.length }))}>
              {t('nodes.bulk.disable')}
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
          caption={t('relays.tableCaption')}
          rows={filtered}
          rowKey={(r) => r.id}
          columns={columns}
          selected={selected}
          onSelect={setSelected}
          selectLabel={t('common.selectRow')}
          selectAllLabel={t('common.selectAll')}
          onRowClick={(r) => setDetail(r.id)}
          empty={
            relays.length === 0 ? (
              <EmptyState icon="relay" title={t('relays.empty')} action={<Button variant="primary" icon="plus" onClick={() => setCreating(true)}>{t('relays.new')}</Button>}>
                {t('relays.emptyHint')}
              </EmptyState>
            ) : (
              <EmptyState icon="search" title={t('common.noMatch')} />
            )
          }
        />
      </Card>

      {creating ? (
        <CreateRelay
          nodes={list.nodes}
          host={list.host}
          onClose={() => setCreating(false)}
          onCreated={async () => {
            setCreating(false)
            toast.push('ok', t('relays.create.done'))
            await res.reload()
          }}
        />
      ) : null}

      {detailRelay ? (
        <Drawer title={detailRelay.name} onClose={() => setDetail(null)} wide>
          <RelayDetail
            relay={detailRelay}
            onEdit={() => setEdit(detailRelay)}
            onDelete={() => setDel([detailRelay])}
            onToggle={() => void act(() => bulk(detailRelay.enabled ? 'disable' : 'enable', [detailRelay.id]))}
            onRestart={() => void act(() => api.post(`/api/relays/${detailRelay.id}/restart`), t('nodes.restarted'))}
          />
        </Drawer>
      ) : null}

      {edit ? (
        <EditRelay
          relay={edit}
          onClose={() => setEdit(null)}
          onSaved={async () => {
            setEdit(null)
            toast.push('ok', t('relays.edit.saved'))
            await res.reload()
          }}
        />
      ) : null}

      {del ? (
        <ConfirmDialog
          title={del.length === 1 ? t('relays.deleteTitle', { name: del[0]!.name }) : t('nodes.bulk.deleteTitle', { n: del.length })}
          message={t('relays.deleteMsg')}
          impact={[
            t('relays.deleteImpact.clients'),
            ...[...new Set(del.flatMap((r) => r.subscriptions))].slice(0, 6).map((s) => t('relays.deleteImpact.subs', { names: s })),
            ...(del.some((r) => r.chain_exits?.length) ? [t('relays.deleteImpact.chain', { names: [...new Set(del.flatMap((r) => r.chain_exits ?? []))].join('、') })] : []),
            ...(del.some((r) => r.ai_chain) ? [t('relays.deleteImpact.ai')] : []),
            t('nodes.deleteImpact.port'),
          ]}
          confirmLabel={t('common.delete')}
          danger
          onCancel={() => setDel(null)}
          onConfirm={async () => {
            const ids = del.map((r) => r.id)
            try {
              await guard(() => (ids.length === 1 ? api.del(`/api/relays/${ids[0]}`) : bulk('delete', ids)))
              setDel(null)
              setSelected(new Set())
              setDetail(null)
              toast.push('ok', t('relays.deleted'))
              await res.reload()
            } catch (e) {
              if (!(e instanceof Cancelled)) await run(() => Promise.reject(e))
            }
          }}
        />
      ) : null}
    </>
  )
}

function RelayDetail({ relay, onEdit, onDelete, onToggle, onRestart }: { relay: RelayView; onEdit: () => void; onDelete: () => void; onToggle: () => void; onRestart: () => void }) {
  const { t } = useI18n()
  return (
    <div className="stack">
      <div className="row-wrap">
        <StateBadge state={relay.state} />
        <Badge>{t(relay.mode === 'local' ? 'relays.mode.local' : 'relays.mode.remote')}</Badge>
        <Badge>{t(transportKey(relay.transport))}</Badge>
        <WarningBadges warnings={relay.warnings} />
        {relay.ai_chain ? <Badge tone="accent">{t('relays.aiChain')}</Badge> : null}
      </div>
      <div className="row-wrap">
        <Button size="sm" icon={relay.enabled ? 'stop' : 'play'} onClick={onToggle}>
          {relay.enabled ? t('common.disable') : t('common.enable')}
        </Button>
        <Button size="sm" icon="refresh" onClick={onRestart} disabled={!relay.enabled}>
          {t('nodes.action.restart')}
        </Button>
        <Button size="sm" icon="edit" onClick={onEdit}>
          {t('common.edit')}
        </Button>
        <Button size="sm" variant="danger" icon="trash" onClick={onDelete}>
          {t('common.delete')}
        </Button>
      </div>
      <section>
        <h3 className="section-title">{t('exits.detail.path')}</h3>
        <PathChain items={relayPath(relay, t)} />
      </section>
      <section className="stack-tight">
        <h3 className="section-title">{t('relays.detail.chain')}</h3>
        {relay.chain_exits?.length ? (
          <Notice tone={relay.ai_chain ? 'accent' : 'neutral'} title={relay.chain_exits.join('、')}>
            {t('relays.detail.chainHint')}
            {relay.ai_chain ? ` ${t('relays.deleteImpact.ai')}` : ''}
          </Notice>
        ) : (
          <p className="muted small">{t('relays.detail.chainNone')}</p>
        )}
      </section>
      <section>
        <KV
          items={[
            { k: t('relays.col.entry'), v: `${relay.public_host}:${relay.public_port}`, mono: true },
            { k: t('nodes.detail.listen'), v: `${relay.listen}:${relay.port}`, mono: true },
            { k: t('relays.create.inbound'), v: relay.inbound ? t(`family.${relay.inbound}` as 'family.ipv4') : t('common.auto') },
            { k: t('relays.create.outbound'), v: t(`relays.outbound.${relay.outbound_policy || 'auto'}` as 'relays.outbound.auto') },
            { k: t('relays.col.transport'), v: t(transportKey(relay.transport)) },
            { k: t('relays.path.target'), v: relay.target, mono: true },
            { k: t('relays.detail.engine'), v: relay.engine },
            { k: t('nodes.detail.sub'), v: relay.subscriptions.length ? relay.subscriptions.join('、') : t('common.none') },
          ]}
        />
      </section>
      <section>
        <h3 className="section-title">{t('relays.detail.share')}</h3>
        {relay.has_link ? <SecretBox label={t('relays.detail.shareHidden')} qrLabel={`${relay.name} QR`} load={async () => (await api.get<{ link: string }>(`/api/relays/${relay.id}/link`)).link} /> : <p className="muted">{t('relays.detail.noLink')}</p>}
      </section>
      <section>
        <h3 className="section-title">{t('relays.detail.test')}</h3>
        <p className="muted small">{t('relays.detail.testHint')}</p>
        <DiagPanel path={`/api/relays/${relay.id}/test`} />
      </section>
    </div>
  )
}

type Policy = 'auto' | 'ipv4_first' | 'ipv6_first' | 'ipv4_only' | 'ipv6_only'
const policies: Policy[] = ['auto', 'ipv4_first', 'ipv6_first', 'ipv4_only', 'ipv6_only']

function PolicySelect({ id, value, onChange, describedBy }: { id?: string; value: string; onChange: (v: string) => void; describedBy?: string }) {
  const { t } = useI18n()
  return (
    <Select id={id} aria-describedby={describedBy} value={value || 'auto'} onChange={(e) => onChange(e.target.value)}>
      {policies.map((p) => (
        <option key={p} value={p}>
          {t(`relays.outbound.${p}` as 'relays.outbound.auto')}
        </option>
      ))}
    </Select>
  )
}

function CreateRelay({ nodes, host, onClose, onCreated }: { nodes: { id: string; name: string; kind: string }[]; host: HostInfo; onClose: () => void; onCreated: () => Promise<void> }) {
  const { t } = useI18n()
  const run = useRunner()
  const [name, setName] = useState('')
  const [mode, setMode] = useState<'local' | 'remote'>(nodes.length > 0 ? 'local' : 'remote')
  const [localNode, setLocalNode] = useState(nodes[0]?.id ?? '')
  const [localPort, setLocalPort] = useState('')
  const [target, setTarget] = useState('')
  const [natTcp, setNatTcp] = useState(false)
  const [transport, setTransport] = useState('')
  const [inbound, setInbound] = useState<'' | 'ipv4' | 'ipv6' | 'dual'>('')
  const [outbound, setOutbound] = useState('auto')
  const [port, setPort] = useState('')
  const [busy, setBusy] = useState(false)

  const custom = mode === 'local' && (localNode === '' || nodes.length === 0)
  const ready = mode === 'remote' ? target.trim().length > 0 : custom ? Number(localPort) > 0 : !!localNode

  const submit = async () => {
    setBusy(true)
    const r = await run(() =>
      api.post('/api/relays', {
        name: name.trim(),
        mode,
        local_node_id: mode === 'local' && !custom ? localNode : '',
        local_port: custom ? Number(localPort) : 0,
        target: mode === 'remote' ? target.trim() : '',
        protocol: transport,
        inbound,
        outbound: outbound === 'auto' ? '' : outbound,
        listen_port: port ? Number(port) : 0,
        target_network: mode === 'remote' && natTcp ? 'tcp' : '',
      }),
    )
    setBusy(false)
    if (r !== undefined) await onCreated()
  }

  return (
    <Modal
      title={t('relays.create.title')}
      onClose={onClose}
      busy={busy}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!ready}>
            {t('common.create')}
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label={`${t('relays.create.name')} ${t('common.optional')}`} hint={t('relays.create.nameHint')}>
          {(id, d) => <Input id={id} aria-describedby={d} data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}
        </Field>
        <Field label={t('relays.create.mode')}>
          {() => (
            <Segmented
              label={t('relays.create.mode')}
              value={mode}
              onChange={setMode}
              options={[
                { value: 'local', label: t('relays.mode.local') },
                { value: 'remote', label: t('relays.mode.remote') },
              ]}
            />
          )}
        </Field>
        {mode === 'local' ? (
          <>
            <Field label={t('relays.create.localNode')} hint={t('relays.create.localHint')}>
              {(id, d) => (
                <Select id={id} aria-describedby={d} value={localNode} onChange={(e) => setLocalNode(e.target.value)}>
                  {nodes.length === 0 ? null : (
                    <option value="" disabled>
                      {t('relays.create.localPick')}
                    </option>
                  )}
                  {nodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name}
                    </option>
                  ))}
                  <option value="">{t('relays.create.localCustom')}</option>
                </Select>
              )}
            </Field>
            {custom ? (
              <Field label={t('relays.create.localPort')}>
                {(id) => <Input id={id} inputMode="numeric" value={localPort} onChange={(e) => setLocalPort(e.target.value.replace(/\D/g, '').slice(0, 5))} />}
              </Field>
            ) : null}
          </>
        ) : (
          <>
            <Field label={t('relays.create.target')} hint={t('relays.create.targetHint')}>
              {(id, d) => <Textarea id={id} aria-describedby={d} rows={3} spellCheck={false} autoCapitalize="none" className="mono" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="203.0.113.10:443" />}
            </Field>
            <Toggle checked={natTcp} onChange={setNatTcp} hint={t('relays.create.natTcpHint')}>
              {t('relays.create.natTcp')}
            </Toggle>
          </>
        )}

        <div className="grid-fields">
          <Field label={t('relays.create.transport')}>
            {(id) => (
              <Select id={id} value={transport} onChange={(e) => setTransport(e.target.value)}>
                <option value="">{t('relays.create.transportAuto')}</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="both">TCP + UDP</option>
              </Select>
            )}
          </Field>
          <Field label={`${t('relays.create.port')} ${t('common.optional')}`} hint={t('relays.create.portHint')}>
            {(id, d) => <Input id={id} aria-describedby={d} inputMode="numeric" placeholder={t('common.auto')} value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, '').slice(0, 5))} />}
          </Field>
        </div>

        <Field label={t('relays.create.inbound')}>
          {() => (
            <Segmented
              label={t('relays.create.inbound')}
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
        <Field label={t('relays.create.outbound')} hint={t('relays.create.outboundHint')}>
          {(id, d) => <PolicySelect id={id} describedBy={d} value={outbound} onChange={setOutbound} />}
        </Field>
      </div>
    </Modal>
  )
}

function EditRelay({ relay, onClose, onSaved }: { relay: RelayView; onClose: () => void; onSaved: () => Promise<void> }) {
  const { t } = useI18n()
  const run = useRunner()
  const [name, setName] = useState(relay.name)
  const [target, setTarget] = useState('')
  const [transport, setTransport] = useState(relay.transport)
  const [outbound, setOutbound] = useState(relay.outbound_policy || 'auto')
  const [busy, setBusy] = useState(false)
  const remote = relay.mode === 'remote'

  const submit = async () => {
    const patch: Record<string, string> = {}
    if (name.trim() !== relay.name) patch.name = name.trim()
    if (remote && target.trim()) patch.target = target.trim()
    if (transport !== relay.transport) patch.protocol = transport
    if (outbound !== (relay.outbound_policy || 'auto')) patch.outbound = outbound === 'auto' ? '' : outbound
    if (Object.keys(patch).length === 0) {
      onClose()
      return
    }
    setBusy(true)
    const r = await run(() => api.patch(`/api/relays/${relay.id}`, patch))
    setBusy(false)
    if (r !== undefined) await onSaved()
  }

  return (
    <Modal
      title={t('relays.edit.title')}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!name.trim()}>
            {t('common.save')}
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label={t('common.name')}>{(id) => <Input id={id} data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
        {remote ? (
          <Field label={t('relays.create.target')} hint={`${t('relays.create.targetHint')} (${relay.target})`}>
            {(id, d) => <Textarea id={id} aria-describedby={d} rows={3} className="mono" spellCheck={false} autoCapitalize="none" value={target} placeholder={relay.target} onChange={(e) => setTarget(e.target.value)} />}
          </Field>
        ) : (
          <Notice tone="neutral">{t('relays.edit.targetLocked')}</Notice>
        )}
        <div className="grid-fields">
          <Field label={t('relays.create.transport')}>
            {(id) => (
              <Select id={id} value={transport} onChange={(e) => setTransport(e.target.value)}>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="both">TCP + UDP</option>
              </Select>
            )}
          </Field>
          <Field label={t('relays.create.outbound')}>{(id) => <PolicySelect id={id} value={outbound} onChange={setOutbound} />}</Field>
        </div>
      </div>
    </Modal>
  )
}

// ---- exits -----------------------------------------------------------------------------

function exitAddress(x: ExitView): string {
  return x.host.includes(':') && !x.host.startsWith('[') ? `[${x.host}]:${x.port}` : `${x.host}:${x.port}`
}

function ExitsTab() {
  const { t } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const { guard } = useReauth()
  const res = useResource<{ exits: ExitView[] }>('/api/exits', { interval: 15000 })
  const [query, setQuery] = useState('')
  const q = useDebounced(query, 150).trim().toLowerCase()
  const [creating, setCreating] = useState(false)
  const [detail, setDetail] = useState<string | null>(null)
  const [edit, setEdit] = useState<ExitView | null>(null)
  const [del, setDel] = useState<ExitView | null>(null)

  const exits = res.data?.exits ?? []
  const filtered = useMemo(() => exits.filter((x) => !q || `${x.name} ${x.host} ${x.label} ${x.protocol}`.toLowerCase().includes(q)), [exits, q])
  const detailExit = detail ? exits.find((x) => x.id === detail) ?? null : null

  const columns: Column<ExitView>[] = [
    {
      key: 'name',
      header: t('exits.col.name'),
      primary: true,
      cell: (x) => (
        <div className="name-cell">
          <strong>{x.name}</strong>
          <div className="badges">
            {x.kind === 'chain' ? <Badge tone="accent">{t('exits.kind.chain')}</Badge> : null}
            {x.ai ? <Badge tone="ok">{t('exits.ai')}</Badge> : null}
            {x.warning ? <Badge tone="warn" title={x.warning}>{x.warning}</Badge> : null}
          </div>
        </div>
      ),
    },
    { key: 'type', header: t('exits.col.type'), label: t('exits.col.type'), cell: (x) => <Badge>{x.label}</Badge> },
    {
      key: 'addr',
      header: t('exits.col.address'),
      label: t('exits.col.address'),
      cell: (x) => (
        <span className="mono small">
          {exitAddress(x)} <span className="muted">· {x.has_auth ? t('exits.auth') : t('exits.noAuth')}</span>
          {x.kind === 'chain' ? <span className="muted"> · {t('exits.via', { name: x.via_relay_name || x.via_address || '?' })}</span> : null}
        </span>
      ),
    },
    {
      key: 'path',
      header: t('exits.col.path'),
      label: t('exits.col.path'),
      className: 'col-path',
      cell: (x) => (x.path?.length ? <HopPath hops={x.path} /> : <span className="muted">–</span>),
    },
    {
      key: 'refs',
      header: t('exits.col.usedBy'),
      label: t('exits.col.usedBy'),
      cell: (x) =>
        x.refs === 0 ? (
          <span className="muted">{t('exits.unused')}</span>
        ) : (
          <span title={x.nodes.join('、')}>
            <Badge tone="accent">{t('exits.refs', { n: x.refs })}</Badge> <span className="muted small">{[...x.nodes.slice(0, 2), ...(x.ai ? [t('exits.ai')] : [])].join('、')}{x.nodes.length > 2 ? '…' : ''}</span>
          </span>
        ),
    },
    {
      key: 'actions',
      header: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (x) => (
        <div onClick={(e) => e.stopPropagation()}>
          <Menu
            label={t('common.more')}
            items={[
              { label: t('nodes.action.test'), icon: 'test', onSelect: () => setDetail(x.id) },
              { label: t('common.edit'), icon: 'edit', onSelect: () => setEdit(x) },
              { label: t('common.delete'), icon: 'trash', danger: true, disabled: x.refs > 0, onSelect: () => setDel(x) },
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
          <SearchInput value={query} onChange={setQuery} placeholder={t('exits.search')} label={t('common.search')} />
          <span className="toolbar-count muted small">{t('common.total', { n: filtered.length })}</span>
          <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
            {t('exits.new')}
          </Button>
        </div>
        <DataTable
          caption={t('exits.tableCaption')}
          rows={filtered}
          rowKey={(x) => x.id}
          columns={columns}
          onRowClick={(x) => setDetail(x.id)}
          empty={
            exits.length === 0 ? (
              <EmptyState icon="server" title={t('exits.empty')} action={<Button variant="primary" icon="plus" onClick={() => setCreating(true)}>{t('exits.new')}</Button>}>
                {t('exits.emptyHint')}
              </EmptyState>
            ) : (
              <EmptyState icon="search" title={t('common.noMatch')} />
            )
          }
        />
      </Card>

      {creating ? (
        <ExitForm
          onClose={() => setCreating(false)}
          onSaved={async () => {
            setCreating(false)
            toast.push('ok', t('exits.create.done'))
            await res.reload()
          }}
        />
      ) : null}
      {edit ? (
        <ExitForm
          exit={edit}
          onClose={() => setEdit(null)}
          onSaved={async () => {
            setEdit(null)
            toast.push('ok', t('relays.edit.saved'))
            await res.reload()
          }}
        />
      ) : null}

      {detailExit ? (
        <Drawer title={detailExit.name} onClose={() => setDetail(null)}>
          <div className="stack">
            <div className="row-wrap">
              <Badge>{detailExit.label}</Badge>
              {detailExit.kind === 'chain' ? <Badge tone="accent">{t('exits.kind.chain')}</Badge> : detailExit.kind === 'remote' ? <Badge>{t('exits.kind.remote')}</Badge> : null}
              {detailExit.warning ? <Badge tone="warn">{detailExit.warning}</Badge> : null}
            </div>
            {detailExit.path?.length ? (
              <section className="stack-tight">
                <h3 className="section-title">{t('exits.detail.path')}</h3>
                <HopPath hops={detailExit.path} />
              </section>
            ) : null}
            {detailExit.ai_usable === false ? <Notice tone="warn">{t('exits.detail.aiBad', { why: detailExit.ai_problem ?? '' })}</Notice> : detailExit.ai_usable ? <p className="small ok-text">{t('exits.detail.aiOk')}</p> : null}
            <div className="row-wrap">
              <Button size="sm" icon="edit" onClick={() => setEdit(detailExit)}>
                {t('common.edit')}
              </Button>
              <Button size="sm" variant="danger" icon="trash" onClick={() => setDel(detailExit)} disabled={detailExit.refs > 0} title={detailExit.refs > 0 ? t('exits.deleteBlocked', { n: detailExit.refs }) : undefined}>
                {t('common.delete')}
              </Button>
            </div>
            {detailExit.refs > 0 ? <Notice tone="neutral">{t('exits.deleteBlocked', { n: detailExit.refs })}</Notice> : null}
            <KV
              items={[
                { k: t('exits.col.address'), v: exitAddress(detailExit), mono: true },
                { k: t('exits.col.type'), v: detailExit.label },
                { k: t('relays.col.transport'), v: detailExit.transport.toUpperCase() },
                { k: t('exits.auth'), v: detailExit.has_auth ? t('common.yes') : t('common.no') },
                ...(detailExit.kind === 'chain' ? [{ k: t('relays.path.relay'), v: detailExit.via_relay_name || detailExit.via_address || '–', mono: !detailExit.via_relay_name }] : []),
              ]}
            />
            <section>
              <h3 className="section-title">{t('exits.detail.nodes')}</h3>
              {detailExit.nodes.length === 0 && !detailExit.ai ? (
                <p className="muted">{t('exits.unused')}</p>
              ) : (
                <ul className="plain-list">
                  {detailExit.nodes.map((n) => (
                    <li key={n}>
                      <PathChain items={[{ label: n, kind: 'entry' }, { label: detailExit.name, kind: 'exit' }, { label: <span className="mono">{exitAddress(detailExit)}</span>, kind: 'target' }]} />
                    </li>
                  ))}
                  {detailExit.ai ? <li><Badge>{t('exits.ai')}</Badge></li> : null}
                </ul>
              )}
            </section>
            <section>
              <h3 className="section-title">{t('exits.detail.test')}</h3>
              <DiagPanel path={`/api/exits/${detailExit.id}/test`} canFull={false} />
            </section>
          </div>
        </Drawer>
      ) : null}

      {del ? (
        <ConfirmDialog
          title={t('exits.deleteTitle', { name: del.name })}
          message={t('exits.deleteMsg')}
          impact={[t('exits.deleteImpact')]}
          confirmLabel={t('common.delete')}
          danger
          onCancel={() => setDel(null)}
          onConfirm={async () => {
            try {
              await guard(() => api.del(`/api/exits/${del.id}`))
              setDel(null)
              setDetail(null)
              toast.push('ok', t('exits.deleted'))
              await res.reload()
            } catch (e) {
              if (!(e instanceof Cancelled)) await run(() => Promise.reject(e))
            }
          }}
        />
      ) : null}
    </>
  )
}

type ExitType = 'socks5' | 'http' | 'https' | 'remote'

function ExitForm({ exit, onClose, onSaved }: { exit?: ExitView; onClose: () => void; onSaved: () => Promise<void> }) {
  const { t } = useI18n()
  const run = useRunner()
  const editing = !!exit
  const plainProxy = exit ? ['socks5', 'http', 'https'].includes(exit.protocol) : true
  const [type, setType] = useState<ExitType>('socks5')
  const [name, setName] = useState(exit?.name ?? '')
  const [host, setHost] = useState(exit?.host ?? '')
  const [port, setPort] = useState(exit ? String(exit.port) : '')
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [link, setLink] = useState('')
  const [tcpOnly, setTcpOnly] = useState(exit?.remote_network === 'tcp')
  const [busy, setBusy] = useState(false)

  const isLink = editing ? !plainProxy : type === 'remote'
  const portNum = Number(port)
  const portOK = Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535
  const ready = isLink ? (editing ? true : link.trim().length > 0) : host.trim().length > 0 && portOK

  const submit = async () => {
    setBusy(true)
    let r: unknown
    if (editing && exit) {
      const patch: Record<string, unknown> = { name: name.trim() }
      if (isLink) {
        if (link.trim()) patch.link = link.trim()
      } else {
        patch.host = host.trim()
        patch.port = portNum
        if (user) patch.username = user
        if (pass) patch.password = pass
      }
      r = await run(() => api.patch(`/api/exits/${exit.id}`, patch))
    } else {
      r = await run(() =>
        api.post('/api/exits', {
          name: name.trim(),
          protocol: type,
          host: host.trim(),
          port: portNum || 0,
          username: user,
          password: pass,
          link: type === 'remote' ? link.trim() : '',
          remote_network: type === 'remote' && tcpOnly ? 'tcp' : '',
        }),
      )
    }
    setBusy(false)
    if (r !== undefined) await onSaved()
  }

  return (
    <Modal
      title={editing ? t('exits.edit.title') : t('exits.create.title')}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!ready}>
            {editing ? t('common.save') : t('common.create')}
          </Button>
        </>
      }
    >
      <div className="stack">
        {!editing ? (
          <Field label={t('exits.create.type')}>
            {() => (
              <Segmented
                label={t('exits.create.type')}
                value={type}
                onChange={setType}
                options={[
                  { value: 'socks5', label: t('exits.create.socks5') },
                  { value: 'http', label: t('exits.create.http') },
                  { value: 'https', label: t('exits.create.https') },
                  { value: 'remote', label: t('exits.create.remote') },
                ]}
              />
            )}
          </Field>
        ) : null}
        <Field label={`${t('exits.create.name')} ${t('common.optional')}`}>{(id) => <Input id={id} data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
        {isLink ? (
          <>
            <Field label={t('exits.create.link')} hint={editing ? t('exits.create.linkKeep') : t('exits.create.linkHint')}>
              {(id, d) => <Textarea id={id} aria-describedby={d} rows={3} className="mono" spellCheck={false} autoCapitalize="none" autoComplete="off" value={link} onChange={(e) => setLink(e.target.value)} placeholder="vless://… hy2://… tuic://…" />}
            </Field>
            {!editing ? (
              <Toggle checked={tcpOnly} onChange={setTcpOnly}>
                {t('exits.create.tcpOnly')}
              </Toggle>
            ) : null}
          </>
        ) : (
          <>
            <div className="grid-fields">
              <Field label={t('exits.create.host')} required>
                {(id) => <Input id={id} value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="none" spellCheck={false} />}
              </Field>
              <Field label={t('exits.create.port')} required>
                {(id) => <Input id={id} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, '').slice(0, 5))} />}
              </Field>
            </div>
            <div className="grid-fields">
              <Field label={`${t('exits.create.user')} ${t('common.optional')}`}>{(id) => <Input id={id} autoComplete="off" value={user} onChange={(e) => setUser(e.target.value)} />}</Field>
              <Field label={`${t('exits.create.pass')} ${t('common.optional')}`} hint={editing ? t('exits.create.passKeep') : undefined}>
                {(id, d) => <Input id={id} aria-describedby={d} type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />}
              </Field>
            </div>
          </>
        )}
      </div>
    </Modal>
  )
}

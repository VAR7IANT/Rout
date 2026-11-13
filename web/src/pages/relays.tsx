import { useMemo, useState } from 'react'
import { api } from '../core/api'
import { portDigits } from '../core/format'
import { useDebounced, useHotkey, useRemote } from '../core/hooks'
import { useI18n, type MessageKey, type TFn } from '../core/i18n'
import { useRouter } from '../core/router'
import { useAct, useReauth } from '../core/session'
import type { ExitRef, HostInfo, RelayList, RelayView } from '../core/types'
import { DiagRunner, InboundPicker, LoadState, Route, Section, SecretBox, StateTag, WarningTags, type HopKind, type Inbound } from '../ui/domain'
import { Button, Checkbox, Empty, Field, Input, KV, Notice, PageHead, Panel, Search, Segmented, Select, Tabs, Tag, Textarea } from '../ui/kit'
import { Confirm, Dialog, Drawer, Menu } from '../ui/overlay'
import { DataTable, type Column } from '../ui/table'
import { ExitsTab } from './exits'

type Tab = 'relays' | 'exits'

/** Relays (port forwarding) and exits (where traffic leaves) share one page with two tabs. */
export function RelaysPage({ tab }: { tab: Tab }) {
  const { t } = useI18n()
  const { go } = useRouter()
  return (
    <div className="page">
      <PageHead title={t('relays.title')} sub={t('relays.subtitle')} />
      <Tabs<Tab>
        label={t('relays.title')}
        value={tab}
        onChange={(v) => go(v === 'relays' ? '/relays' : '/exits')}
        tabs={[
          { value: 'relays', label: t('relays.tab.relays') },
          { value: 'exits', label: t('relays.tab.exits') },
        ]}
      />
      <p className="dim small">{t(tab === 'relays' ? 'relays.explain' : 'exits.explain')}</p>
      {tab === 'relays' ? <RelaysTab /> : <ExitsTab />}
    </div>
  )
}

const transportKey = (p: string): MessageKey => (p === 'udp' ? 'relays.transport.udp' : p === 'both' ? 'relays.transport.both' : 'relays.transport.tcp')
const modeKey = (r: RelayView): MessageKey => (r.mode === 'local' ? 'relays.mode.local' : 'relays.mode.remote')

function relayHops(r: RelayView, t: TFn): { label: string; kind: HopKind }[] {
  const hops: { label: string; kind: HopKind }[] = [
    { label: `${r.public_host}:${r.public_port}`, kind: 'entry' },
    { label: r.name, kind: 'relay' },
    { label: r.target, kind: 'target' },
  ]
  if (r.target_node) hops.push({ label: t('relays.path.node', { name: r.target_node }), kind: 'target' })
  return hops
}

function RelaysTab() {
  const { t } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const res = useRemote<RelayList>('/api/relays', { every: 10000 })
  const [query, setQuery] = useState('')
  const needle = useDebounced(query, 150).trim().toLowerCase()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [creating, setCreating] = useState(false)
  const [openId, setOpenId] = useState<string | null>(null)
  const [editing, setEditing] = useState<RelayView | null>(null)
  const [deleting, setDeleting] = useState<RelayView[] | null>(null)

  useHotkey('/', (e) => {
    e.preventDefault()
    document.getElementById('relays-filter')?.focus()
  })

  const list = res.data
  const relays = useMemo(() => list?.relays ?? [], [list])
  const byId = useMemo(() => new Map(relays.map((r) => [r.id, r])), [relays])
  const shown = useMemo(() => relays.filter((r) => !needle || `${r.name} ${r.public_host}:${r.public_port} ${r.target}`.toLowerCase().includes(needle)), [relays, needle])
  if (!list) return <LoadState res={res} />

  const picked = [...selected].map((id) => byId.get(id)).filter((r): r is RelayView => !!r)
  const pickedIds = picked.map((r) => r.id)
  const open = openId ? (byId.get(openId) ?? null) : null

  const change = async (fn: () => Promise<unknown>, ok?: string) => {
    const r = await act(fn, ok ? { ok } : undefined)
    await res.reload()
    return r
  }
  const bulk = (action: string, ids: string[]) => api.post('/api/relays/bulk', { action, ids })
  const toggle = (r: RelayView) => void change(() => bulk(r.enabled ? 'disable' : 'enable', [r.id]), t(r.enabled ? 'nodes.disabledOk' : 'nodes.enabled'))
  const restart = (r: RelayView) => void change(() => api.post(`/api/relays/${r.id}/restart`), t('nodes.restarted'))
  const bulkDone = t('nodes.bulk.done', { n: picked.length })

  const columns: Column<RelayView>[] = [
    {
      key: 'name',
      head: t('relays.col.name'),
      primary: true,
      cell: (r) => (
        <div className="cell-name">
          <strong>{r.name}</strong>
          <div className="cell-tags">
            <WarningTags warnings={r.warnings} />
            {r.target_network === 'tcp' ? <Tag tone="warn">{t('relays.natTcp')}</Tag> : null}
            {r.chain_exits?.length ? <Tag title={r.chain_exits.join(', ')}>{t('relays.chainUsers', { n: r.chain_exits.length })}</Tag> : null}
            {r.ai_chain ? <Tag tone="accent">{t('relays.aiChain')}</Tag> : null}
          </div>
        </div>
      ),
    },
    { key: 'mode', head: t('relays.col.mode'), label: t('relays.col.mode'), cell: (r) => <Tag>{t(modeKey(r))}</Tag> },
    {
      key: 'entry',
      head: t('relays.col.entry'),
      label: t('relays.col.entry'),
      cell: (r) => (
        <span className="row">
          {r.public_host}:{r.public_port}
          {r.family ? <Tag>{t(`family.${r.family}` as MessageKey)}</Tag> : null}
        </span>
      ),
    },
    { key: 'transport', head: t('relays.col.transport'), label: t('relays.col.transport'), cell: (r) => t(transportKey(r.transport)) },
    { key: 'path', head: t('relays.col.path'), label: t('relays.col.path'), cell: (r) => <Route hops={relayHops(r, t)} /> },
    { key: 'state', head: t('relays.col.state'), label: t('relays.col.state'), cell: (r) => <StateTag state={r.state} /> },
    {
      key: 'actions',
      head: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (r) => (
        <Menu
          label={t('common.more')}
          items={[
            { label: t('nodes.action.test'), icon: 'play', onSelect: () => setOpenId(r.id) },
            { label: t('nodes.action.restart'), icon: 'refresh', disabled: !r.enabled, onSelect: () => restart(r) },
            { label: t(r.enabled ? 'common.disable' : 'common.enable'), icon: r.enabled ? 'stop' : 'play', onSelect: () => toggle(r) },
            { label: t('common.edit'), icon: 'edit', onSelect: () => setEditing(r) },
            { label: t('common.delete'), icon: 'trash', danger: true, onSelect: () => setDeleting([r]) },
          ]}
        />
      ),
    },
  ]

  const createButton = (
    <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
      {t('relays.new')}
    </Button>
  )
  const chainExits = deleting ? [...new Set(deleting.flatMap((r) => r.chain_exits ?? []))] : []

  return (
    <>
      <Panel flush>
        <div className="toolbar">
          <Search id="relays-filter" value={query} onChange={setQuery} placeholder={t('relays.search')} label={t('common.search')} />
          <span className="toolbar__count dim small">{t('common.total', { n: shown.length })}</span>
          {createButton}
        </div>
        {picked.length > 0 ? (
          <div className="bulkbar" role="region" aria-label={t('common.selected', { n: picked.length })}>
            <strong>{t('common.selected', { n: picked.length })}</strong>
            <Button size="sm" icon="play" onClick={() => void change(() => bulk('enable', pickedIds), bulkDone)}>
              {t('nodes.bulk.enable')}
            </Button>
            <Button size="sm" icon="stop" onClick={() => void change(() => bulk('disable', pickedIds), bulkDone)}>
              {t('nodes.bulk.disable')}
            </Button>
            <Button size="sm" variant="danger" icon="trash" onClick={() => setDeleting(picked)}>
              {t('nodes.bulk.delete')}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
              {t('common.clearSelection')}
            </Button>
          </div>
        ) : null}
        <DataTable
          caption={t('relays.tableCaption')}
          rows={shown}
          rowKey={(r) => r.id}
          columns={columns}
          selected={selected}
          onSelect={setSelected}
          selectLabel={(r) => `${t('common.selectRow')}: ${r.name}`}
          selectAllLabel={t('common.selectAll')}
          onRowClick={(r) => setOpenId(r.id)}
          empty={
            relays.length === 0 ? (
              <Empty icon="relay" title={t('relays.empty')} action={createButton}>
                {t('relays.emptyHint')}
              </Empty>
            ) : (
              <Empty icon="search" title={t('common.noMatch')} />
            )
          }
        />
      </Panel>

      {creating ? (
        <CreateRelay
          nodes={list.nodes}
          host={list.host}
          onClose={() => setCreating(false)}
          onCreated={async () => {
            setCreating(false)
            await res.reload()
          }}
        />
      ) : null}

      {open ? (
        <Drawer title={open.name} onClose={() => setOpenId(null)} wide>
          <RelayDetail relay={open} onEdit={() => setEditing(open)} onDelete={() => setDeleting([open])} onToggle={() => toggle(open)} onRestart={() => restart(open)} />
        </Drawer>
      ) : null}

      {editing ? (
        <EditRelay
          relay={editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null)
            await res.reload()
          }}
        />
      ) : null}

      {deleting ? (
        <Confirm
          danger
          title={deleting.length === 1 ? t('relays.deleteTitle', { name: deleting[0].name }) : t('nodes.bulk.deleteTitle', { n: deleting.length })}
          message={t('relays.deleteMsg')}
          impact={[
            t('relays.deleteImpact.clients'),
            ...[...new Set(deleting.flatMap((r) => r.subscriptions))].slice(0, 6).map((names) => t('relays.deleteImpact.subs', { names })),
            ...(chainExits.length > 0 ? [t('relays.deleteImpact.chain', { names: chainExits.join(', ') })] : []),
            ...(deleting.some((r) => r.ai_chain) ? [t('relays.deleteImpact.ai')] : []),
            t('nodes.deleteImpact.port'),
          ]}
          confirmLabel={t('common.delete')}
          onCancel={() => setDeleting(null)}
          onConfirm={async () => {
            const ids = deleting.map((r) => r.id)
            const r = await act(() => guard(() => (ids.length === 1 ? api.del(`/api/relays/${ids[0]}`) : bulk('delete', ids))), { ok: t('relays.deleted') })
            if (r === undefined) return
            setDeleting(null)
            setSelected(new Set())
            setOpenId(null)
            await res.reload()
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
      <div className="row">
        <StateTag state={relay.state} />
        <Tag>{t(modeKey(relay))}</Tag>
        <Tag>{t(transportKey(relay.transport))}</Tag>
        <WarningTags warnings={relay.warnings} />
        {relay.ai_chain ? <Tag tone="accent">{t('relays.aiChain')}</Tag> : null}
      </div>
      <div className="row">
        <Button size="sm" icon={relay.enabled ? 'stop' : 'play'} onClick={onToggle}>
          {t(relay.enabled ? 'common.disable' : 'common.enable')}
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

      <Section title={t('exits.detail.path')}>
        <Route hops={relayHops(relay, t)} />
      </Section>

      <Section title={t('relays.detail.chain')}>
        {relay.chain_exits?.length ? (
          <Notice tone={relay.ai_chain ? 'accent' : 'neutral'} title={relay.chain_exits.join(', ')}>
            {t('relays.detail.chainHint')}
            {relay.ai_chain ? ` ${t('relays.deleteImpact.ai')}` : ''}
          </Notice>
        ) : (
          <p className="dim small">{t('relays.detail.chainNone')}</p>
        )}
      </Section>

      <Section title={t('nodes.detail.info')}>
        <KV
          rows={[
            { k: t('relays.col.entry'), v: `${relay.public_host}:${relay.public_port}` },
            { k: t('nodes.detail.listen'), v: `${relay.listen}:${relay.port}` },
            { k: t('relays.create.inbound'), v: relay.inbound ? t(`family.${relay.inbound}` as MessageKey) : t('common.auto') },
            { k: t('relays.create.outbound'), v: t(`relays.outbound.${relay.outbound_policy || 'auto'}` as MessageKey) },
            { k: t('relays.col.transport'), v: t(transportKey(relay.transport)) },
            { k: t('relays.path.target'), v: relay.target },
            { k: t('relays.detail.engine'), v: relay.engine },
            { k: t('nodes.detail.sub'), v: relay.subscriptions.length > 0 ? relay.subscriptions.join(', ') : t('common.none') },
          ]}
        />
      </Section>

      <Section title={t('relays.detail.share')}>
        {relay.has_link ? (
          <SecretBox label={t('relays.detail.shareHidden')} qrLabel={`${relay.name} QR`} load={async () => (await api.get<{ link: string }>(`/api/relays/${relay.id}/link`)).link} />
        ) : (
          <p className="dim">{t('relays.detail.noLink')}</p>
        )}
      </Section>

      <Section title={t('relays.detail.test')}>
        <p className="dim small">{t('relays.detail.testHint')}</p>
        <DiagRunner path={`/api/relays/${relay.id}/test`} />
      </Section>
    </div>
  )
}

const POLICIES = ['auto', 'ipv4_first', 'ipv6_first', 'ipv4_only', 'ipv6_only'] as const

function PolicySelect({ id, describedBy, value, onChange }: { id?: string; describedBy?: string; value: string; onChange: (v: string) => void }) {
  const { t } = useI18n()
  return (
    <Select id={id} aria-describedby={describedBy} value={value || 'auto'} onChange={(e) => onChange(e.target.value)}>
      {POLICIES.map((p) => (
        <option key={p} value={p}>
          {t(`relays.outbound.${p}`)}
        </option>
      ))}
    </Select>
  )
}

const CUSTOM = '~custom' // not a possible node id

function CreateRelay({ nodes, host, onClose, onCreated }: { nodes: ExitRef[]; host: HostInfo; onClose: () => void; onCreated: () => Promise<void> }) {
  const { t } = useI18n()
  const act = useAct()
  const [name, setName] = useState('')
  const [mode, setMode] = useState<'local' | 'remote'>(nodes.length > 0 ? 'local' : 'remote')
  const [localNode, setLocalNode] = useState(nodes[0]?.id ?? CUSTOM)
  const [localPort, setLocalPort] = useState('')
  const [target, setTarget] = useState('')
  const [natTcp, setNatTcp] = useState(false)
  const [transport, setTransport] = useState('')
  const [inbound, setInbound] = useState<Inbound>('')
  const [outbound, setOutbound] = useState('auto')
  const [port, setPort] = useState('')
  const [busy, setBusy] = useState(false)

  const local = mode === 'local'
  const custom = local && localNode === CUSTOM
  const ready = !local ? target.trim() !== '' : custom ? Number(localPort) > 0 : true

  const submit = async () => {
    setBusy(true)
    const r = await act(
      () =>
        api.post('/api/relays', {
          name: name.trim(),
          mode,
          local_node_id: local && !custom ? localNode : '',
          local_port: custom ? Number(localPort) : 0,
          target: local ? '' : target.trim(),
          protocol: transport,
          inbound,
          outbound: outbound === 'auto' ? '' : outbound,
          listen_port: port ? Number(port) : 0,
          target_network: !local && natTcp ? 'tcp' : '',
        }),
      { ok: t('relays.create.done') },
    )
    setBusy(false)
    if (r !== undefined) await onCreated()
  }

  return (
    <Dialog
      wide
      title={t('relays.create.title')}
      onClose={onClose}
      busy={busy}
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
          {(id, note) => <Input id={id} aria-describedby={note} data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}
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

        {local ? (
          <>
            <Field label={t('relays.create.localNode')} hint={t('relays.create.localHint')}>
              {(id, note) => (
                <Select id={id} aria-describedby={note} value={localNode} onChange={(e) => setLocalNode(e.target.value)}>
                  {nodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name}
                    </option>
                  ))}
                  <option value={CUSTOM}>{t('relays.create.localCustom')}</option>
                </Select>
              )}
            </Field>
            {custom ? <Field label={t('relays.create.localPort')}>{(id) => <Input id={id} inputMode="numeric" value={localPort} onChange={(e) => setLocalPort(portDigits(e.target.value))} />}</Field> : null}
          </>
        ) : (
          <>
            <Field label={t('relays.create.target')} hint={t('relays.create.targetHint')}>
              {(id, note) => <Textarea id={id} aria-describedby={note} rows={3} autoCapitalize="none" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="203.0.113.10:443" />}
            </Field>
            <Checkbox checked={natTcp} onChange={setNatTcp} hint={t('relays.create.natTcpHint')}>
              {t('relays.create.natTcp')}
            </Checkbox>
          </>
        )}

        <div className="cols-2">
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
            {(id, note) => <Input id={id} aria-describedby={note} inputMode="numeric" placeholder={t('common.auto')} value={port} onChange={(e) => setPort(portDigits(e.target.value))} />}
          </Field>
        </div>

        <Field label={t('relays.create.inbound')}>{() => <InboundPicker label={t('relays.create.inbound')} value={inbound} onChange={setInbound} host={host} />}</Field>
        <Field label={t('relays.create.outbound')} hint={t('relays.create.outboundHint')}>
          {(id, note) => <PolicySelect id={id} describedBy={note} value={outbound} onChange={setOutbound} />}
        </Field>
      </div>
    </Dialog>
  )
}

function EditRelay({ relay, onClose, onSaved }: { relay: RelayView; onClose: () => void; onSaved: () => Promise<void> }) {
  const { t } = useI18n()
  const act = useAct()
  const was = { name: relay.name, transport: relay.transport, outbound: relay.outbound_policy || 'auto' }
  const [name, setName] = useState(was.name)
  const [target, setTarget] = useState('')
  const [transport, setTransport] = useState(was.transport)
  const [outbound, setOutbound] = useState(was.outbound)
  const [busy, setBusy] = useState(false)
  const remote = relay.mode === 'remote'

  const submit = async () => {
    // Send only what changed: the server restarts the relay for some fields.
    const patch: Record<string, string> = {}
    if (name.trim() !== was.name) patch.name = name.trim()
    if (remote && target.trim()) patch.target = target.trim()
    if (transport !== was.transport) patch.protocol = transport
    if (outbound !== was.outbound) patch.outbound = outbound === 'auto' ? '' : outbound
    if (Object.keys(patch).length === 0) {
      onClose()
      return
    }
    setBusy(true)
    const r = await act(() => api.patch(`/api/relays/${relay.id}`, patch), { ok: t('relays.edit.saved') })
    setBusy(false)
    if (r !== undefined) await onSaved()
  }

  return (
    <Dialog
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
            {(id, note) => <Textarea id={id} aria-describedby={note} rows={3} autoCapitalize="none" value={target} placeholder={relay.target} onChange={(e) => setTarget(e.target.value)} />}
          </Field>
        ) : (
          <Notice>{t('relays.edit.targetLocked')}</Notice>
        )}
        <div className="cols-2">
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
    </Dialog>
  )
}

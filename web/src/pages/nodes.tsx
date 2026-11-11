import { useMemo, useState } from 'react'
import { api } from '../core/api'
import { dateTime, isPort, portDigits } from '../core/format'
import { useDebounced, useHotkey, useRemote } from '../core/hooks'
import { useI18n, type MessageKey } from '../core/i18n'
import { useAct, useReauth } from '../core/session'
import type { ExitRef, HostInfo, NodeList, NodeView, PolicyChoice, ProtocolInfo } from '../core/types'
import { DiagRunner, InboundPicker, LoadState, NameDialog, Section, SecretBox, StateTag, Traffic, WarningTags, type Inbound } from '../ui/domain'
import { Button, Checkbox, Empty, Field, Input, KV, PageHead, Panel, Search, Select, Tag } from '../ui/kit'
import { Confirm, Dialog, Drawer, Menu } from '../ui/overlay'
import { DataTable, type Column } from '../ui/table'
import { EgressSection, PolicyPicker, needsConfirm, policyLabel } from './node-egress'

type StateFilter = 'all' | 'running' | 'stopped' | 'disabled' | 'warn'

const matchesState = (n: NodeView, f: StateFilter): boolean => f === 'all' || (f === 'disabled' ? !n.enabled : f === 'warn' ? n.warnings.length > 0 : n.state === f)
const transports = (networks: string[]) => networks.map((n) => n.toUpperCase()).join(' + ')
const gb = (n: number) => `${(n / 1024 ** 3).toFixed(2)} GB`

export function NodesPage() {
  const { t } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const res = useRemote<NodeList>('/api/nodes', { every: 10000 })
  const [query, setQuery] = useState('')
  const needle = useDebounced(query, 150).trim().toLowerCase()
  const [protocol, setProtocol] = useState('')
  const [state, setState] = useState<StateFilter>('all')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [creating, setCreating] = useState(false)
  const [openId, setOpenId] = useState<string | null>(null)
  const [renaming, setRenaming] = useState<NodeView | null>(null)
  const [deleting, setDeleting] = useState<NodeView[] | null>(null)
  const [binding, setBinding] = useState(false)

  useHotkey('/', (e) => {
    e.preventDefault()
    document.getElementById('nodes-filter')?.focus()
  })

  const list = res.data
  const nodes = useMemo(() => list?.nodes ?? [], [list])
  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes])
  const shown = useMemo(
    () =>
      nodes.filter(
        (n) =>
          (!protocol || n.protocol === protocol) &&
          matchesState(n, state) &&
          (!needle || `${n.name} ${n.label} ${n.protocol} ${n.public_host}:${n.public_port} ${n.exit_name ?? ''}`.toLowerCase().includes(needle)),
      ),
    [nodes, protocol, state, needle],
  )
  if (!list) return <LoadState res={res} />

  const picked = [...selected].map((id) => byId.get(id)).filter((n): n is NodeView => !!n)
  const pickedIds = picked.map((n) => n.id)
  const open = openId ? (byId.get(openId) ?? null) : null
  const filtering = protocol !== '' || state !== 'all' || needle !== ''

  /** Runs a write, then refreshes the list whatever the outcome. */
  const change = async (fn: () => Promise<unknown>, ok: string) => {
    const r = await act(fn, { ok })
    await res.reload()
    return r
  }
  const bulk = (action: string, ids: string[], extra?: Record<string, string>) => api.post<{ count: number }>('/api/nodes/bulk', { action, ids, ...extra })
  const toggle = (n: NodeView) => void change(() => bulk(n.enabled ? 'disable' : 'enable', [n.id]), t(n.enabled ? 'nodes.disabledOk' : 'nodes.enabled'))
  const restart = (n: NodeView) => void change(() => api.post(`/api/nodes/${n.id}/restart`), t('nodes.restarted'))
  const bulkDone = t('nodes.bulk.done', { n: picked.length })

  const columns: Column<NodeView>[] = [
    {
      key: 'name',
      head: t('nodes.col.name'),
      primary: true,
      cell: (n) => (
        <div className="cell-name">
          <strong>{n.name}</strong>
          <div className="cell-tags">
            <WarningTags warnings={n.warnings} />
          </div>
        </div>
      ),
    },
    { key: 'protocol', head: t('nodes.col.protocol'), label: t('nodes.col.protocol'), cell: (n) => <Tag>{n.label}</Tag> },
    { key: 'state', head: t('nodes.col.state'), label: t('nodes.col.state'), cell: (n) => <StateTag state={n.state} /> },
    {
      key: 'address',
      head: t('nodes.col.address'),
      label: t('nodes.col.address'),
      cell: (n) => (
        <span className="row">
          {n.public_host}:{n.public_port}
          {n.family ? <Tag>{t(`family.${n.family}` as MessageKey)}</Tag> : null}
        </span>
      ),
    },
    {
      key: 'exit',
      head: t('nodes.col.exit'),
      label: t('nodes.col.exit'),
      cell: (n) => (
        <span className="row">
          {n.exit_name ?? <span className="dim">{t('nodes.direct')}</span>}
          {n.outbound_policy && n.outbound_policy !== 'auto' ? <Tag tone="accent">{policyLabel(t, n.outbound_policy)}</Tag> : null}
        </span>
      ),
    },
    { key: 'traffic', head: t('nodes.col.traffic'), label: t('nodes.col.traffic'), cell: (n) => <Traffic traffic={n.traffic} /> },
    {
      key: 'actions',
      head: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (n) => (
        <Menu
          label={t('common.more')}
          items={[
            { label: t('nodes.action.test'), icon: 'play', onSelect: () => setOpenId(n.id) },
            { label: t('nodes.action.link'), icon: 'qr', onSelect: () => setOpenId(n.id), hidden: !n.has_link },
            { label: t('nodes.action.restart'), icon: 'refresh', disabled: !n.enabled, onSelect: () => restart(n) },
            { label: t(n.enabled ? 'common.disable' : 'common.enable'), icon: n.enabled ? 'stop' : 'play', onSelect: () => toggle(n) },
            { label: t('common.rename'), icon: 'edit', onSelect: () => setRenaming(n) },
            { label: t('common.delete'), icon: 'trash', danger: true, onSelect: () => setDeleting([n]) },
          ]}
        />
      ),
    },
  ]

  const createButton = (
    <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
      {t('nodes.new')}
    </Button>
  )

  return (
    <div className="page">
      <PageHead title={t('nodes.title')} sub={t('nodes.subtitle')} actions={createButton} />

      <Panel flush>
        <div className="toolbar">
          <Search id="nodes-filter" value={query} onChange={setQuery} placeholder={t('nodes.search')} label={t('common.search')} />
          <Select className="toolbar__select" aria-label={t('nodes.filterProtocol')} value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            <option value="">{t('nodes.allProtocols')}</option>
            {list.protocols.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </Select>
          <Select className="toolbar__select" aria-label={t('nodes.filterState')} value={state} onChange={(e) => setState(e.target.value as StateFilter)}>
            {(['all', 'running', 'stopped', 'disabled', 'warn'] as const).map((s) => (
              <option key={s} value={s}>
                {t(`nodes.state.${s}`)}
              </option>
            ))}
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
          <span className="toolbar__count dim small">{t('common.total', { n: shown.length })}</span>
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
            <Button size="sm" icon="link" onClick={() => setBinding(true)} disabled={list.exits.length === 0}>
              {t('nodes.bulk.bind')}
            </Button>
            <Button size="sm" onClick={() => void change(() => bulk('unbind_exit', pickedIds), bulkDone)}>
              {t('nodes.bulk.unbind')}
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
          caption={t('nodes.tableCaption')}
          rows={shown}
          rowKey={(n) => n.id}
          columns={columns}
          selected={selected}
          onSelect={setSelected}
          selectLabel={(n) => `${t('common.selectRow')}: ${n.name}`}
          selectAllLabel={t('common.selectAll')}
          onRowClick={(n) => setOpenId(n.id)}
          empty={
            nodes.length === 0 ? (
              <Empty icon="nodes" title={t('nodes.empty')} action={createButton}>
                {t('nodes.emptyHint')}
              </Empty>
            ) : (
              <Empty icon="search" title={t('common.noMatch')} />
            )
          }
        />
      </Panel>

      {creating ? (
        <CreateNodes
          protocols={list.protocols}
          exits={list.exits}
          host={list.host}
          policies={list.outbound_policies}
          onClose={() => setCreating(false)}
          onCreated={async () => {
            setCreating(false)
            await res.reload()
          }}
        />
      ) : null}

      {open ? (
        <NodeDrawer
          node={open}
          policies={list.outbound_policies}
          onChanged={res.reload}
          onClose={() => setOpenId(null)}
          onRename={() => setRenaming(open)}
          onDelete={() => setDeleting([open])}
          onToggle={() => toggle(open)}
          onRestart={() => restart(open)}
        />
      ) : null}

      {renaming ? (
        <NameDialog
          title={t('nodes.rename.title')}
          current={renaming.name}
          onClose={() => setRenaming(null)}
          onSave={async (name) => (await change(() => api.patch(`/api/nodes/${renaming.id}`, { name }), t('nodes.renamed'))) !== undefined}
        />
      ) : null}

      {deleting ? (
        <Confirm
          danger
          title={deleting.length === 1 ? t('nodes.deleteTitle', { name: deleting[0].name }) : t('nodes.bulk.deleteTitle', { n: deleting.length })}
          message={t('nodes.deleteMsg')}
          impact={[
            t('nodes.deleteImpact.link'),
            ...[...new Set(deleting.flatMap((n) => n.subscriptions))].slice(0, 6).map((names) => t('nodes.deleteImpact.subs', { names })),
            t('nodes.deleteImpact.port'),
          ]}
          confirmLabel={t('common.delete')}
          onCancel={() => setDeleting(null)}
          onConfirm={async () => {
            const ids = deleting.map((n) => n.id)
            const r = await act(() => guard(() => (ids.length === 1 ? api.del(`/api/nodes/${ids[0]}`) : bulk('delete', ids))), { ok: t('nodes.deleted') })
            if (r === undefined) return
            setDeleting(null)
            setSelected(new Set())
            setOpenId(null)
            await res.reload()
          }}
        />
      ) : null}

      {binding ? (
        <BindExit
          count={picked.length}
          exits={list.exits}
          onClose={() => setBinding(false)}
          onBind={async (exitId) => {
            if ((await change(() => bulk('bind_exit', pickedIds, { exit_id: exitId }), bulkDone)) !== undefined) setBinding(false)
          }}
        />
      ) : null}
    </div>
  )
}

function BindExit({ count, exits, onClose, onBind }: { count: number; exits: ExitRef[]; onClose: () => void; onBind: (id: string) => Promise<void> }) {
  const { t } = useI18n()
  const [exit, setExit] = useState(exits[0]?.id ?? '')
  const [busy, setBusy] = useState(false)
  const bind = async () => {
    setBusy(true)
    await onBind(exit)
    setBusy(false)
  }
  return (
    <Dialog
      title={t('nodes.bulk.bindTitle', { n: count })}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" busy={busy} disabled={!exit} onClick={() => void bind()}>
            {t('nodes.bulk.bind')}
          </Button>
        </>
      }
    >
      <div className="stack">
        <p className="dim">{t('nodes.bulk.bindHint')}</p>
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
      </div>
    </Dialog>
  )
}

interface CreateProps {
  protocols: ProtocolInfo[]
  exits: ExitRef[]
  host: HostInfo
  policies: PolicyChoice[]
  onClose: () => void
  onCreated: () => Promise<void>
}

function CreateNodes({ protocols, exits, host, policies, onClose, onCreated }: CreateProps) {
  const { t } = useI18n()
  const act = useAct()
  const [prefix, setPrefix] = useState('')
  const [picked, setPicked] = useState<string[]>(protocols[0] ? [protocols[0].id] : [])
  const [inbound, setInbound] = useState<Inbound>('')
  const [sni, setSni] = useState('')
  const [exit, setExit] = useState('')
  const [port, setPort] = useState('')
  const [policy, setPolicy] = useState('auto')
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)

  const reality = picked.some((p) => p === 'vless' || p === 'anytls')
  const single = picked.length === 1 // a fixed port only makes sense for one node
  const portNumber = port === '' ? 0 : Number(port)
  const portBad = port !== '' && !isPort(port)

  const submit = async () => {
    setBusy(true)
    const r = await act(() =>
      api.post<{ nodes: NodeView[] }>('/api/nodes', {
        base_name: prefix.trim(),
        protocols: picked,
        inbound,
        reality_sni: reality ? sni.trim() : '',
        exit_id: exit,
        port: single ? portNumber : 0,
        outbound_policy: policy === 'auto' ? '' : policy,
        force: confirmed,
      }),
    )
    setBusy(false)
    if (!r) return
    if (r.nodes.length > 0) await act(async () => null, { ok: t('nodes.create.done', { n: r.nodes.length }) })
    await onCreated()
  }

  return (
    <Dialog
      wide
      title={t('nodes.create.title')}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={picked.length === 0 || portBad || needsConfirm(policies, policy, confirmed)}>
            {t('common.create')}
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label={t('nodes.create.name')} hint={t('nodes.create.nameHint')}>
          {(id, note) => <Input id={id} aria-describedby={note} data-autofocus placeholder="Rout" maxLength={40} value={prefix} onChange={(e) => setPrefix(e.target.value)} />}
        </Field>

        <fieldset className="fieldset">
          <legend>{t('nodes.create.protocols')}</legend>
          <div className="choices">
            {protocols.map((p) => (
              <Checkbox key={p.id} checked={picked.includes(p.id)} onChange={(on) => setPicked((l) => (on ? [...l, p.id] : l.filter((x) => x !== p.id)))} hint={transports(p.networks)}>
                {p.label}
              </Checkbox>
            ))}
          </div>
          {picked.length === 0 ? (
            <p className="field__error" role="alert">
              {t('nodes.create.needProtocol')}
            </p>
          ) : null}
        </fieldset>

        <Field label={t('nodes.create.inbound')} hint={t('nodes.create.inboundHint')}>
          {() => <InboundPicker label={t('nodes.create.inbound')} value={inbound} onChange={setInbound} host={host} />}
        </Field>

        {reality ? (
          <Field label={t('nodes.create.sni')} hint={t('nodes.create.sniHint')}>
            {(id, note) => <Input id={id} aria-describedby={note} placeholder="www.example.com" value={sni} onChange={(e) => setSni(e.target.value)} autoCapitalize="none" />}
          </Field>
        ) : null}

        <div className="cols-2">
          <Field label={t('nodes.create.exit')} hint={t('nodes.create.exitHint')}>
            {(id, note) => (
              <Select id={id} aria-describedby={note} value={exit} onChange={(e) => setExit(e.target.value)}>
                <option value="">{t('nodes.direct')}</option>
                {exits.map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          {single ? (
            <Field label={`${t('nodes.create.port')} ${t('common.optional')}`} hint={t('nodes.create.portHint')} error={portBad ? t('nodes.create.portHint') : null}>
              {(id, note) => <Input id={id} aria-describedby={note} inputMode="numeric" placeholder={t('common.auto')} value={port} onChange={(e) => setPort(portDigits(e.target.value))} />}
            </Field>
          ) : null}
        </div>

        <Field label={t('egress.title')} hint={t('egress.hint')}>
          {(id, note) => <PolicyPicker id={id} describedBy={note} value={policy} onChange={setPolicy} choices={policies} confirmed={confirmed} onConfirm={setConfirmed} />}
        </Field>
      </div>
    </Dialog>
  )
}

interface DrawerProps {
  node: NodeView
  policies: PolicyChoice[]
  onChanged: () => Promise<void>
  onClose: () => void
  onRename: () => void
  onDelete: () => void
  onToggle: () => void
  onRestart: () => void
}

function NodeDrawer({ node, policies, onChanged, onClose, onRename, onDelete, onToggle, onRestart }: DrawerProps) {
  const { t, locale } = useI18n()
  const traffic = node.traffic
  const cert = node.cert
  return (
    <Drawer title={node.name} onClose={onClose}>
      <div className="stack">
        <div className="row">
          <StateTag state={node.state} />
          <Tag>{node.label}</Tag>
          <WarningTags warnings={node.warnings} />
        </div>
        <div className="row">
          <Button size="sm" icon={node.enabled ? 'stop' : 'play'} onClick={onToggle}>
            {t(node.enabled ? 'common.disable' : 'common.enable')}
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

        <Section title={t('nodes.detail.info')}>
          <KV
            rows={[
              { k: t('nodes.detail.public'), v: `${node.public_host}:${node.public_port}` },
              { k: t('nodes.detail.listen'), v: `${node.listen}:${node.port}` },
              { k: t('nodes.detail.networks'), v: transports(node.networks) },
              node.inbound && { k: t('nodes.detail.inbound'), v: t(`family.${node.inbound}` as MessageKey) },
              node.sni && { k: 'SNI', v: node.sni },
              { k: t('nodes.col.exit'), v: node.exit_name ?? t('nodes.direct') },
              cert && { k: t('nodes.detail.cert'), v: cert.days < 0 ? t('dash.certExpired', { n: -cert.days }) : `${t('dash.certDays', { n: cert.days })}${cert.self_signed ? ` · ${t('dash.selfSigned')}` : ''}` },
              { k: t('nodes.detail.sub'), v: node.subscriptions.length > 0 ? node.subscriptions.join(', ') : t('common.none') },
              { k: t('nodes.detail.created'), v: dateTime(node.created_at, locale) },
            ]}
          />
        </Section>

        {traffic ? (
          <Section title={t('nodes.detail.traffic')}>
            <Traffic traffic={traffic} />
            {traffic.active ? (
              <KV
                rows={[
                  { k: t('dash.down'), v: gb(traffic.down) },
                  { k: t('dash.up'), v: gb(traffic.up) },
                  { k: t('nodes.detail.trafficStatus'), v: t(`nodes.traffic.${traffic.status}` as MessageKey) },
                ]}
              />
            ) : null}
            {traffic.incomplete ? <p className="dim small">{t('nodes.traffic.incomplete')}</p> : null}
          </Section>
        ) : null}

        <Section title={t('nodes.detail.share')}>
          {node.has_link ? (
            <SecretBox label={t('nodes.detail.shareHidden')} qrLabel={`${node.name} QR`} load={async () => (await api.get<{ link: string }>(`/api/nodes/${node.id}/link`)).link} />
          ) : (
            <p className="dim">{t('nodes.detail.noLink')}</p>
          )}
        </Section>

        <Section title={t('egress.title')}>
          {/* Remounts when the saved policy changes so the picker starts from the new value. */}
          <EgressSection key={`${node.id}:${node.outbound_policy ?? 'auto'}`} node={node} choices={policies} onChanged={onChanged} />
        </Section>

        <Section title={t('nodes.detail.test')}>
          <DiagRunner path={`/api/nodes/${node.id}/test`} />
        </Section>
      </div>
    </Drawer>
  )
}

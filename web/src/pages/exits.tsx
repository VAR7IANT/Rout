// Exits: where traffic really leaves — SOCKS5 / HTTP(S) proxies, remote nodes, relay chains.
import { useMemo, useState } from 'react'
import { api } from '../core/api'
import { hostPort, isPort, portDigits } from '../core/format'
import { useDebounced, useHotkey, useRemote } from '../core/hooks'
import { useI18n } from '../core/i18n'
import { useAct, useReauth } from '../core/session'
import type { ExitView } from '../core/types'
import { DiagRunner, ExitRoute, LoadState, Route, Section } from '../ui/domain'
import { Button, Checkbox, Empty, Field, Input, KV, Notice, Panel, Search, Segmented, Tag, Textarea } from '../ui/kit'
import { Confirm, Dialog, Drawer, Menu } from '../ui/overlay'
import { DataTable, type Column } from '../ui/table'

const address = (x: ExitView) => hostPort(x.host, x.port)

export function ExitsTab() {
  const { t } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const res = useRemote<{ exits: ExitView[] }>('/api/exits', { every: 15000 })
  const [query, setQuery] = useState('')
  const needle = useDebounced(query, 150).trim().toLowerCase()
  const [creating, setCreating] = useState(false)
  const [openId, setOpenId] = useState<string | null>(null)
  const [editing, setEditing] = useState<ExitView | null>(null)
  const [deleting, setDeleting] = useState<ExitView | null>(null)

  useHotkey('/', (e) => {
    e.preventDefault()
    document.getElementById('exits-filter')?.focus()
  })

  const exits = useMemo(() => res.data?.exits ?? [], [res.data])
  const shown = useMemo(() => exits.filter((x) => !needle || `${x.name} ${x.host} ${x.label} ${x.protocol}`.toLowerCase().includes(needle)), [exits, needle])
  if (!res.data) return <LoadState res={res} />
  const open = openId ? (exits.find((x) => x.id === openId) ?? null) : null

  const columns: Column<ExitView>[] = [
    {
      key: 'name',
      head: t('exits.col.name'),
      primary: true,
      cell: (x) => (
        <div className="cell-name">
          <strong>{x.name}</strong>
          <div className="cell-tags">
            {x.kind === 'chain' ? <Tag tone="accent">{t('exits.kind.chain')}</Tag> : null}
            {x.ai ? <Tag tone="ok">{t('exits.ai')}</Tag> : null}
            {x.warning ? <Tag tone="warn">{x.warning}</Tag> : null}
          </div>
        </div>
      ),
    },
    { key: 'type', head: t('exits.col.type'), label: t('exits.col.type'), cell: (x) => <Tag>{x.label}</Tag> },
    {
      key: 'address',
      head: t('exits.col.address'),
      label: t('exits.col.address'),
      cell: (x) => (
        <span>
          {address(x)} <span className="dim">· {t(x.has_auth ? 'exits.auth' : 'exits.noAuth')}</span>
          {x.kind === 'chain' ? <span className="dim"> · {t('exits.via', { name: x.via_relay_name || x.via_address || '?' })}</span> : null}
        </span>
      ),
    },
    { key: 'path', head: t('exits.col.path'), label: t('exits.col.path'), cell: (x) => (x.path?.length ? <ExitRoute hops={x.path} /> : <span className="dim">–</span>) },
    {
      key: 'refs',
      head: t('exits.col.usedBy'),
      label: t('exits.col.usedBy'),
      cell: (x) =>
        x.refs === 0 ? (
          <span className="dim">{t('exits.unused')}</span>
        ) : (
          <span className="row" title={x.nodes.join(', ')}>
            <Tag tone="accent">{t('exits.refs', { n: x.refs })}</Tag>
            <span className="dim small">
              {[...x.nodes.slice(0, 2), ...(x.ai ? [t('exits.ai')] : [])].join(', ')}
              {x.nodes.length > 2 ? '…' : ''}
            </span>
          </span>
        ),
    },
    {
      key: 'actions',
      head: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (x) => (
        <Menu
          label={t('common.more')}
          items={[
            { label: t('nodes.action.test'), icon: 'play', onSelect: () => setOpenId(x.id) },
            { label: t('common.edit'), icon: 'edit', onSelect: () => setEditing(x) },
            { label: t('common.delete'), icon: 'trash', danger: true, disabled: x.refs > 0, onSelect: () => setDeleting(x) },
          ]}
        />
      ),
    },
  ]

  const createButton = (
    <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
      {t('exits.new')}
    </Button>
  )

  return (
    <>
      <Panel flush>
        <div className="toolbar">
          <Search id="exits-filter" value={query} onChange={setQuery} placeholder={t('exits.search')} label={t('common.search')} />
          <span className="toolbar__count dim small">{t('common.total', { n: shown.length })}</span>
          {createButton}
        </div>
        <DataTable
          caption={t('exits.tableCaption')}
          rows={shown}
          rowKey={(x) => x.id}
          columns={columns}
          onRowClick={(x) => setOpenId(x.id)}
          empty={
            exits.length === 0 ? (
              <Empty icon="globe" title={t('exits.empty')} action={createButton}>
                {t('exits.emptyHint')}
              </Empty>
            ) : (
              <Empty icon="search" title={t('common.noMatch')} />
            )
          }
        />
      </Panel>

      {creating || editing ? (
        <ExitForm
          exit={editing ?? undefined}
          onClose={() => {
            setCreating(false)
            setEditing(null)
          }}
          onSaved={async () => {
            setCreating(false)
            setEditing(null)
            await res.reload()
          }}
        />
      ) : null}

      {open ? (
        <Drawer title={open.name} onClose={() => setOpenId(null)}>
          <div className="stack">
            <div className="row">
              <Tag>{open.label}</Tag>
              {open.kind === 'chain' ? <Tag tone="accent">{t('exits.kind.chain')}</Tag> : open.kind === 'remote' ? <Tag>{t('exits.kind.remote')}</Tag> : null}
              {open.warning ? <Tag tone="warn">{open.warning}</Tag> : null}
            </div>
            {open.path?.length ? (
              <Section title={t('exits.detail.path')}>
                <ExitRoute hops={open.path} />
              </Section>
            ) : null}
            {open.ai_usable === false ? <Notice tone="warn">{t('exits.detail.aiBad', { why: open.ai_problem ?? '' })}</Notice> : open.ai_usable ? <p className="ok small">{t('exits.detail.aiOk')}</p> : null}
            <div className="row">
              <Button size="sm" icon="edit" onClick={() => setEditing(open)}>
                {t('common.edit')}
              </Button>
              <Button size="sm" variant="danger" icon="trash" onClick={() => setDeleting(open)} disabled={open.refs > 0}>
                {t('common.delete')}
              </Button>
            </div>
            {open.refs > 0 ? <Notice>{t('exits.deleteBlocked', { n: open.refs })}</Notice> : null}
            <KV
              rows={[
                { k: t('exits.col.address'), v: address(open) },
                { k: t('exits.col.type'), v: open.label },
                { k: t('relays.col.transport'), v: open.transport.toUpperCase() },
                { k: t('exits.auth'), v: t(open.has_auth ? 'common.yes' : 'common.no') },
                open.kind === 'chain' && { k: t('relays.path.relay'), v: open.via_relay_name || open.via_address || '–' },
              ]}
            />
            <Section title={t('exits.detail.nodes')}>
              {open.nodes.length === 0 && !open.ai ? (
                <p className="dim">{t('exits.unused')}</p>
              ) : (
                <ul className="stack stack--tight">
                  {open.nodes.map((n) => (
                    <li key={n}>
                      <Route
                        hops={[
                          { label: n, kind: 'entry' },
                          { label: open.name, kind: 'exit' },
                          { label: address(open), kind: 'target' },
                        ]}
                      />
                    </li>
                  ))}
                  {open.ai ? (
                    <li>
                      <Tag>{t('exits.ai')}</Tag>
                    </li>
                  ) : null}
                </ul>
              )}
            </Section>
            <Section title={t('exits.detail.test')}>
              <DiagRunner path={`/api/exits/${open.id}/test`} canFull={false} />
            </Section>
          </div>
        </Drawer>
      ) : null}

      {deleting ? (
        <Confirm
          danger
          title={t('exits.deleteTitle', { name: deleting.name })}
          message={t('exits.deleteMsg')}
          impact={[t('exits.deleteImpact')]}
          confirmLabel={t('common.delete')}
          onCancel={() => setDeleting(null)}
          onConfirm={async () => {
            const r = await act(() => guard(() => api.del(`/api/exits/${deleting.id}`)), { ok: t('exits.deleted') })
            if (r === undefined) return
            setDeleting(null)
            setOpenId(null)
            await res.reload()
          }}
        />
      ) : null}
    </>
  )
}

type Kind = 'socks5' | 'http' | 'https' | 'remote'

/** Creates an exit, or edits one. An exit's kind cannot change after creation. */
function ExitForm({ exit, onClose, onSaved }: { exit?: ExitView; onClose: () => void; onSaved: () => Promise<void> }) {
  const { t } = useI18n()
  const act = useAct()
  const [kind, setKind] = useState<Kind>('socks5')
  const [name, setName] = useState(exit?.name ?? '')
  const [host, setHost] = useState(exit?.host ?? '')
  const [port, setPort] = useState(exit ? String(exit.port) : '')
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [link, setLink] = useState('')
  const [tcpOnly, setTcpOnly] = useState(false)
  const [busy, setBusy] = useState(false)

  // A share-link exit: a new "remote" one, or an existing exit that is not a plain proxy.
  const byLink = exit ? !['socks5', 'http', 'https'].includes(exit.protocol) : kind === 'remote'
  const ready = byLink ? !!exit || link.trim() !== '' : host.trim() !== '' && isPort(port)

  const submit = async () => {
    setBusy(true)
    const r = exit
      ? await act(
          () =>
            api.patch(`/api/exits/${exit.id}`, {
              name: name.trim(),
              // Empty secrets and an empty link mean "keep what is stored".
              ...(byLink ? (link.trim() ? { link: link.trim() } : {}) : { host: host.trim(), port: Number(port), ...(user ? { username: user } : {}), ...(pass ? { password: pass } : {}) }),
            }),
          { ok: t('relays.edit.saved') },
        )
      : await act(
          () =>
            api.post('/api/exits', {
              name: name.trim(),
              protocol: kind,
              host: host.trim(),
              port: Number(port) || 0,
              username: user,
              password: pass,
              link: byLink ? link.trim() : '',
              remote_network: byLink && tcpOnly ? 'tcp' : '',
            }),
          { ok: t('exits.create.done') },
        )
    setBusy(false)
    if (r !== undefined) await onSaved()
  }

  return (
    <Dialog
      title={t(exit ? 'exits.edit.title' : 'exits.create.title')}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!ready}>
            {t(exit ? 'common.save' : 'common.create')}
          </Button>
        </>
      }
    >
      <div className="stack">
        {exit ? null : (
          <Field label={t('exits.create.type')}>
            {() => (
              <Segmented<Kind>
                label={t('exits.create.type')}
                value={kind}
                onChange={setKind}
                options={[
                  { value: 'socks5', label: t('exits.create.socks5') },
                  { value: 'http', label: t('exits.create.http') },
                  { value: 'https', label: t('exits.create.https') },
                  { value: 'remote', label: t('exits.create.remote') },
                ]}
              />
            )}
          </Field>
        )}
        <Field label={`${t('exits.create.name')} ${t('common.optional')}`}>{(id) => <Input id={id} data-autofocus maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
        {byLink ? (
          <>
            <Field label={t('exits.create.link')} hint={t(exit ? 'exits.create.linkKeep' : 'exits.create.linkHint')}>
              {(id, note) => <Textarea id={id} aria-describedby={note} rows={3} autoCapitalize="none" autoComplete="off" value={link} onChange={(e) => setLink(e.target.value)} placeholder="vless://… hy2://… tuic://…" />}
            </Field>
            {exit ? null : (
              <Checkbox checked={tcpOnly} onChange={setTcpOnly}>
                {t('exits.create.tcpOnly')}
              </Checkbox>
            )}
          </>
        ) : (
          <>
            <div className="cols-2">
              <Field label={t('exits.create.host')} required>
                {(id) => <Input id={id} value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="none" />}
              </Field>
              <Field label={t('exits.create.port')} required>
                {(id) => <Input id={id} inputMode="numeric" value={port} onChange={(e) => setPort(portDigits(e.target.value))} />}
              </Field>
            </div>
            <div className="cols-2">
              <Field label={`${t('exits.create.user')} ${t('common.optional')}`}>{(id) => <Input id={id} autoComplete="off" value={user} onChange={(e) => setUser(e.target.value)} />}</Field>
              <Field label={`${t('exits.create.pass')} ${t('common.optional')}`} hint={exit ? t('exits.create.passKeep') : undefined}>
                {(id, note) => <Input id={id} aria-describedby={note} type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />}
              </Field>
            </div>
          </>
        )}
      </div>
    </Dialog>
  )
}

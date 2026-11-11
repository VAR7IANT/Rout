import { useMemo, useState } from 'react'
import { api } from '../core/api'
import { bytes, date, parseSize, percent } from '../core/format'
import { useDebounced, useHotkey, useRemote } from '../core/hooks'
import { useI18n } from '../core/i18n'
import { useRouter } from '../core/router'
import { useAct, useReauth } from '../core/session'
import type { PlanView, SubItemView, SubscriptionList, SubscriptionView } from '../core/types'
import { LoadState, NameDialog, Reveal, SecretValue } from '../ui/domain'
import { Button, Empty, Field, Input, KV, Meter, Notice, PageHead, Panel, Search, Switch, Tabs, Tag, cx } from '../ui/kit'
import { Confirm, Dialog, Menu } from '../ui/overlay'
import { SourcesTab } from './sources'
import { SubscriptionEditor } from './subscription-editor'

type Tab = 'subscriptions' | 'sources'

export function SubscriptionsPage({ tab }: { tab: Tab }) {
  const { t } = useI18n()
  const { go } = useRouter()
  return (
    <div className="page">
      <PageHead title={t('subs.title')} sub={t('subs.subtitle')} />
      <Tabs<Tab>
        label={t('subs.title')}
        value={tab}
        onChange={(v) => go(v === 'subscriptions' ? '/subscriptions' : '/sources')}
        tabs={[
          { value: 'subscriptions', label: t('subs.tab.subscriptions') },
          { value: 'sources', label: t('subs.tab.sources') },
        ]}
      />
      {tab === 'subscriptions' ? <SubscriptionsTab /> : <SourcesTab />}
    </div>
  )
}

/** A node the subscription cannot hand out in at least one format. */
const troubled = (i: SubItemView) => i.status === 'skipped' || !i.base64_ok || !i.mihomo_ok

type Asking = { kind: 'links' | 'plan' | 'report' | 'rename' | 'rotate' | 'delete' | 'reset'; sub: SubscriptionView }

function SubscriptionsTab() {
  const { t } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const res = useRemote<SubscriptionList>('/api/subscriptions', { every: 15000 })
  const [query, setQuery] = useState('')
  const needle = useDebounced(query, 150).trim().toLowerCase()
  const [editing, setEditing] = useState<{ sub?: SubscriptionView } | null>(null)
  const [asking, setAsking] = useState<Asking | null>(null)

  useHotkey('/', (e) => {
    e.preventDefault()
    document.getElementById('subs-filter')?.focus()
  })

  const data = res.data
  const subs = useMemo(() => data?.subscriptions ?? [], [data])
  const shown = useMemo(() => subs.filter((s) => !needle || s.name.toLowerCase().includes(needle)), [subs, needle])
  if (!data) return <LoadState res={res} />

  const ask = (kind: Asking['kind'], sub: SubscriptionView) => setAsking({ kind, sub })
  const close = () => setAsking(null)
  const sub = asking?.sub
  const toggle = async (s: SubscriptionView, enabled: boolean) => {
    await act(() => api.patch(`/api/subscriptions/${s.id}`, { enabled }), { ok: t(enabled ? 'subs.enabledOn' : 'subs.enabledOff') })
    await res.reload()
  }
  const createButton = (
    <Button variant="primary" icon="plus" onClick={() => setEditing({})}>
      {t('subs.new')}
    </Button>
  )
  const urlMissing = !!data.server && !data.server.public_url_set

  return (
    <>
      {data.server && !data.server.enabled ? (
        <Notice tone="warn" title={t('subs.serverOff')}>
          {t('subs.serverOffHint')}
        </Notice>
      ) : urlMissing ? (
        <Notice tone="warn" title={t('subs.serverNoUrl')}>
          {t('subs.serverOffHint')}
        </Notice>
      ) : null}

      <div className="toolbar toolbar--bare">
        <Search id="subs-filter" value={query} onChange={setQuery} placeholder={t('subs.search')} label={t('common.search')} />
        <span className="toolbar__count dim small">{t('common.total', { n: shown.length })}</span>
        {createButton}
      </div>

      {subs.length === 0 ? (
        <Empty icon="sub" title={t('subs.empty')} action={createButton}>
          {t('subs.emptyHint')}
        </Empty>
      ) : shown.length === 0 ? (
        <Empty icon="search" title={t('common.noMatch')} />
      ) : (
        <div className="cards">
          {shown.map((s) => {
            const bad = s.items.filter(troubled).length
            const total = s.items.length
            return (
              <Panel
                key={s.id}
                className={cx(!s.enabled && 'is-off')}
                title={s.name}
                meta={<Tag tone={s.aggregate ? 'accent' : 'neutral'}>{t(s.aggregate ? 'subs.kind.aggregate' : 'subs.kind.standard')}</Tag>}
                actions={<Switch checked={s.enabled} onChange={(v) => void toggle(s, v)} label={`${t(s.enabled ? 'common.disable' : 'common.enable')}: ${s.name}`} />}
              >
                <div className="stack">
                  <div className="dim">{total === 0 ? t('subs.noNodes') : s.aggregate ? t('subs.counts', { local: s.local_count, remote: s.remote_count }) : t('subs.nodesN', { n: total })}</div>
                  {s.plan ? <PlanSummary plan={s.plan} /> : null}
                  {total === 0 ? null : (
                    <button type="button" className={cx('textlink', bad > 0 ? 'warn' : 'ok')} onClick={() => ask('report', s)}>
                      {bad > 0 ? `! ${t('subs.compat.issues', { n: bad })} — ${t('subs.compat.view')}` : `✓ ${t('subs.compat.ok')}`}
                    </button>
                  )}
                  <div className="row">
                    <Button size="sm" icon="qr" variant="primary" onClick={() => ask('links', s)}>
                      {t('subs.action.link')}
                    </Button>
                    <Button size="sm" icon="edit" onClick={() => setEditing({ sub: s })}>
                      {t('subs.action.nodes')}
                    </Button>
                    <Button size="sm" icon="pulse" onClick={() => ask('plan', s)}>
                      {t('subs.action.plan')}
                    </Button>
                    <Menu
                      label={`${t('common.more')}: ${s.name}`}
                      items={[
                        { label: t('common.rename'), icon: 'edit', onSelect: () => ask('rename', s) },
                        { label: t('subs.action.reset'), icon: 'refresh', hidden: !s.plan, onSelect: () => ask('reset', s) },
                        { label: t('subs.action.rotate'), icon: 'lock', onSelect: () => ask('rotate', s) },
                        { label: t('common.delete'), icon: 'trash', danger: true, onSelect: () => ask('delete', s) },
                      ]}
                    />
                  </div>
                </div>
              </Panel>
            )
          })}
        </div>
      )}

      {editing ? (
        <SubscriptionEditor
          sub={editing.sub}
          choices={data.nodes}
          onClose={() => setEditing(null)}
          onSaved={async (created) => {
            setEditing(null)
            await act(async () => null, { ok: t(created ? 'subs.created' : 'subs.saved') })
            await res.reload()
          }}
        />
      ) : null}

      {sub && asking.kind === 'links' ? <LinksDialog sub={sub} ready={!urlMissing} onClose={close} /> : null}
      {sub && asking.kind === 'report' ? <ReportDialog sub={sub} onClose={close} /> : null}
      {sub && asking.kind === 'plan' ? (
        <PlanDialog
          sub={sub}
          onClose={close}
          onSaved={async () => {
            close()
            await res.reload()
          }}
        />
      ) : null}
      {sub && asking.kind === 'rename' ? (
        <NameDialog
          title={t('subs.rename.title')}
          current={sub.name}
          maxLength={40}
          onClose={close}
          onSave={async (name) => {
            const r = await act(() => api.patch(`/api/subscriptions/${sub.id}`, { name }), { ok: t('nodes.renamed') })
            await res.reload()
            return r !== undefined
          }}
        />
      ) : null}
      {sub && asking.kind === 'reset' ? (
        <Confirm
          title={t('subs.plan.resetTitle', { name: sub.name })}
          impact={[t('subs.plan.resetImpact')]}
          confirmLabel={t('subs.action.reset')}
          onCancel={close}
          onConfirm={async () => {
            if ((await act(() => api.post(`/api/subscriptions/${sub.id}/reset-usage`), { ok: t('subs.plan.resetDone') })) === undefined) return
            close()
            await res.reload()
          }}
        />
      ) : null}
      {sub && asking.kind === 'rotate' ? (
        <Confirm
          danger
          title={t('subs.rotate.title', { name: sub.name })}
          message={t('subs.rotate.msg')}
          impact={[t('subs.rotate.i1'), t('subs.rotate.i2')]}
          confirmLabel={t('subs.action.rotate')}
          onCancel={close}
          onConfirm={async () => {
            if ((await act(() => guard(() => api.post(`/api/subscriptions/${sub.id}/rotate`)), { ok: t('subs.rotate.done') })) === undefined) return
            await res.reload()
            ask('links', sub) // the old links are dead: show the new ones straight away
          }}
        />
      ) : null}
      {sub && asking.kind === 'delete' ? (
        <Confirm
          danger
          title={t('subs.delete.title', { name: sub.name })}
          message={t('subs.delete.msg')}
          impact={[t('subs.delete.impact')]}
          confirmLabel={t('common.delete')}
          onCancel={close}
          onConfirm={async () => {
            if ((await act(() => guard(() => api.del(`/api/subscriptions/${sub.id}`)), { ok: t('subs.delete.done') })) === undefined) return
            close()
            await res.reload()
          }}
        />
      ) : null}
    </>
  )
}

function PlanSummary({ plan }: { plan: PlanView }) {
  const { t, locale } = useI18n()
  // An expiry date is valid through the end of that day.
  const expired = plan.expires ? new Date(`${plan.expires}T23:59:59`) < new Date() : false
  return (
    <div className="stack stack--tight">
      {plan.limit > 0 ? (
        <div className="between">
          <Meter value={percent(plan.used, plan.limit)} label={t('common.used')} width={16} />
          <span className="small">
            {bytes(plan.used)} / {bytes(plan.limit)} · {t('subs.leftBadge', { v: bytes(plan.left) })}
          </span>
        </div>
      ) : null}
      <div className="row dim small">
        {plan.next_reset ? <span>{t('common.resets', { d: date(plan.next_reset, locale) })}</span> : null}
        {plan.expires ? expired ? <Tag tone="error">{t('subs.expiredBadge')}</Tag> : <span>{t('common.expires', { d: plan.expires })}</span> : null}
      </div>
    </div>
  )
}

function LinksDialog({ sub, ready, onClose }: { sub: SubscriptionView; ready: boolean; onClose: () => void }) {
  const { t } = useI18n()
  return (
    <Dialog wide title={t('subs.link.title', { name: sub.name })} onClose={onClose} footer={<Button onClick={onClose}>{t('common.done')}</Button>}>
      {!ready ? (
        <Notice tone="warn" title={t('subs.serverNoUrl')}>
          {t('subs.serverOffHint')}
        </Notice>
      ) : !sub.can_reveal_url ? (
        <Notice tone="warn">{t('subs.link.cannot')}</Notice>
      ) : (
        <Reveal<{ base64_url: string; mihomo_url: string }> label={t('subs.link.hidden')} load={() => api.get(`/api/subscriptions/${sub.id}/url`)}>
          {(urls) => (
            <div className="stack">
              <SecretValue value={urls.base64_url} label={t('subs.link.base64')} rows={2} />
              <SecretValue value={urls.mihomo_url} label={t('subs.link.mihomo')} rows={2} />
            </div>
          )}
        </Reveal>
      )}
    </Dialog>
  )
}

/** Which nodes each output format cannot carry, and why. */
function ReportDialog({ sub, onClose }: { sub: SubscriptionView; onClose: () => void }) {
  const { t } = useI18n()
  const rows = sub.items.filter((i) => troubled(i) || (i.notes?.length ?? 0) > 0)
  const verdict = (i: SubItemView, ok: boolean) => (i.status === 'skipped' ? <Tag tone="warn">–</Tag> : ok ? <Tag tone="ok">✓</Tag> : <Tag tone="error">✗</Tag>)
  return (
    <Dialog wide title={t('subs.report.title', { name: sub.name })} onClose={onClose} footer={<Button onClick={onClose}>{t('common.done')}</Button>}>
      <div className="stack">
        <p className="dim">{t('subs.report.intro')}</p>
        {rows.length === 0 ? (
          <Notice tone="ok">{t('subs.report.allOk')}</Notice>
        ) : (
          <div className="grid-wrap">
            <table className="grid">
              <thead>
                <tr>
                  <th scope="col">{t('subs.report.node')}</th>
                  <th scope="col">{t('subs.fmt.base64')}</th>
                  <th scope="col">{t('subs.fmt.mihomo')}</th>
                  <th scope="col">{t('subs.report.reason')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((i, n) => (
                  <tr key={`${i.kind}-${i.node_id}-${n}`}>
                    <td className="grid__primary">
                      <strong>{i.name}</strong>
                      <div className="dim small">
                        {(i.protocol ?? '').toUpperCase()} {i.source ? `· ${i.source}` : ''}
                      </div>
                    </td>
                    <td data-label={t('subs.fmt.base64')}>{verdict(i, i.base64_ok)}</td>
                    <td data-label={t('subs.fmt.mihomo')}>{verdict(i, i.mihomo_ok)}</td>
                    <td data-label={t('subs.report.reason')} className="small">
                      <div>
                        {i.skipped ? <div>{t('subs.report.skipped', { why: i.skipped })}</div> : null}
                        {!i.base64_ok && i.base64_why ? <div>Base64: {i.base64_why}</div> : null}
                        {!i.mihomo_ok && i.mihomo_why ? <div>Mihomo: {i.mihomo_why}</div> : null}
                        {(i.notes ?? []).map((note) => (
                          <div key={note} className="dim">
                            {note}
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Dialog>
  )
}

/** The shared data allowance of a subscription: size, monthly reset day and expiry date. */
function PlanDialog({ sub, onClose, onSaved }: { sub: SubscriptionView; onClose: () => void; onSaved: () => Promise<void> }) {
  const { t } = useI18n()
  const act = useAct()
  const plan = sub.plan
  const [limit, setLimit] = useState(plan && plan.limit > 0 ? bytes(plan.limit, 2).replace(' ', '') : '0')
  const [day, setDay] = useState(String(plan?.billing_day || 1))
  const [zone, setZone] = useState(plan?.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
  const [expires, setExpires] = useState(plan?.expires ?? '')
  const [busy, setBusy] = useState(false)
  const limitBytes = parseSize(limit)
  const dayNumber = Number(day)
  const dayOK = dayNumber >= 1 && dayNumber <= 28 // a day every month has

  const save = async () => {
    if (limitBytes === null || !dayOK) return
    setBusy(true)
    const r = await act(() => api.put(`/api/subscriptions/${sub.id}/plan`, { limit_bytes: limitBytes, billing_day: dayNumber, timezone: zone.trim(), expires }), { ok: t('subs.plan.saved') })
    setBusy(false)
    if (r !== undefined) await onSaved()
  }

  return (
    <Dialog
      title={t('subs.plan.title', { name: sub.name })}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void save()} busy={busy} disabled={limitBytes === null || !dayOK}>
            {t('common.save')}
          </Button>
        </>
      }
    >
      <div className="stack">
        {plan ? <KV rows={[{ k: t('subs.plan.used'), v: `${bytes(plan.used)}${plan.incomplete ? ' *' : ''}` }]} /> : null}
        <Field label={t('subs.plan.limit')} hint={t('subs.plan.limitHint')} error={limitBytes === null ? t('subs.plan.limitBad') : null}>
          {(id, note) => <Input id={id} aria-describedby={note} data-autofocus value={limit} onChange={(e) => setLimit(e.target.value)} inputMode="decimal" />}
        </Field>
        <div className="cols-2">
          <Field label={t('subs.plan.day')} hint={t('subs.plan.dayHint')} error={dayOK ? null : t('subs.plan.dayHint')}>
            {(id, note) => <Input id={id} aria-describedby={note} inputMode="numeric" value={day} onChange={(e) => setDay(e.target.value.replace(/\D/g, '').slice(0, 2))} />}
          </Field>
          <Field label={t('subs.plan.tz')}>{(id) => <Input id={id} value={zone} onChange={(e) => setZone(e.target.value)} autoCapitalize="none" />}</Field>
        </div>
        <Field label={`${t('subs.plan.expires')} ${t('common.optional')}`}>{(id) => <Input id={id} type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />}</Field>
        <p className="dim small">{t('subs.plan.noTraffic')}</p>
      </div>
    </Dialog>
  )
}

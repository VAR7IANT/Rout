import { useMemo, useState } from 'react'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatDate, formatPercent, parseSize } from '../lib/format'
import { useDebounced, useResource } from '../lib/hooks'
import { useRouter } from '../lib/router'
import { Cancelled, useReauth, useRunner } from '../lib/session'
import { useToast } from '../lib/toast'
import type { SubscriptionList, SubscriptionView } from '../lib/types'
import { ConfirmDialog, Menu, Modal } from '../components/overlay'
import { Reveal, SecretValue } from '../components/shared'
import { Badge, Button, Card, EmptyState, Field, Input, KV, Meter, Notice, PageHead, SearchInput, Spinner, Switch, Tabs } from '../components/ui'
import { SourcesTab } from './Sources'
import { SubscriptionEditor } from './SubscriptionEditor'

export function SubscriptionsPage({ tab }: { tab: 'subscriptions' | 'sources' }) {
  const { t } = useI18n()
  const { navigate } = useRouter()
  return (
    <div className="page">
      <PageHead title={t('subs.title')} subtitle={t('subs.subtitle')} />
      <Tabs label={t('subs.title')} value={tab} onChange={(v) => navigate(v === 'subscriptions' ? '/subscriptions' : '/sources')} tabs={[{ value: 'subscriptions', label: t('subs.tab.subscriptions') }, { value: 'sources', label: t('subs.tab.sources') }]} />
      {tab === 'subscriptions' ? <SubscriptionsTab /> : <SourcesTab />}
    </div>
  )
}

function SubscriptionsTab() {
  const { t, locale } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const { guard } = useReauth()
  const res = useResource<SubscriptionList>('/api/subscriptions', { interval: 15000 })
  const [query, setQuery] = useState('')
  const q = useDebounced(query, 150).trim().toLowerCase()
  const [editor, setEditor] = useState<{ sub?: SubscriptionView } | null>(null)
  const [links, setLinks] = useState<SubscriptionView | null>(null)
  const [plan, setPlan] = useState<SubscriptionView | null>(null)
  const [report, setReport] = useState<SubscriptionView | null>(null)
  const [rename, setRename] = useState<SubscriptionView | null>(null)
  const [rotate, setRotate] = useState<SubscriptionView | null>(null)
  const [del, setDel] = useState<SubscriptionView | null>(null)
  const [resetUse, setResetUse] = useState<SubscriptionView | null>(null)

  const data = res.data
  const subs = data?.subscriptions ?? []
  const filtered = useMemo(() => subs.filter((s) => !q || s.name.toLowerCase().includes(q)), [subs, q])

  if (res.loading && !data) return <Spinner label={t('common.loading')} />
  if (!data) {
    return (
      <EmptyState icon="warn" title={t('common.loadFailed')} action={<Button onClick={() => void res.reload()}>{t('common.retry')}</Button>}>
        {res.error?.message}
      </EmptyState>
    )
  }

  const toggle = async (s: SubscriptionView, enabled: boolean) => {
    await run(() => api.patch(`/api/subscriptions/${s.id}`, { enabled }), { ok: enabled ? t('subs.enabledOn') : t('subs.enabledOff') })
    await res.reload()
  }

  return (
    <>
      {data.server && !data.server.enabled ? (
        <Notice tone="warn" title={t('subs.serverOff')}>
          {t('subs.serverOffHint')}
        </Notice>
      ) : data.server && !data.server.public_url_set ? (
        <Notice tone="warn" title={t('subs.serverNoUrl')}>
          {t('subs.serverOffHint')}
        </Notice>
      ) : null}

      <div className="toolbar toolbar-plain">
        <SearchInput value={query} onChange={setQuery} placeholder={t('subs.search')} label={t('common.search')} />
        <span className="toolbar-count muted small">{t('common.total', { n: filtered.length })}</span>
        <Button variant="primary" icon="plus" onClick={() => setEditor({})}>
          {t('subs.new')}
        </Button>
      </div>

      {subs.length === 0 ? (
        <Card>
          <EmptyState icon="sub" title={t('subs.empty')} action={<Button variant="primary" icon="plus" onClick={() => setEditor({})}>{t('subs.new')}</Button>}>
            {t('subs.emptyHint')}
          </EmptyState>
        </Card>
      ) : filtered.length === 0 ? (
        <Card>
          <EmptyState icon="search" title={t('common.noMatch')} />
        </Card>
      ) : (
        <div className="sub-grid">
          {filtered.map((s) => {
            const bad = s.items.filter((i) => i.status === 'skipped' || !i.base64_ok || !i.mihomo_ok).length
            const total = s.items.length
            return (
              <Card
                key={s.id}
                className={`sub-card ${s.enabled ? '' : 'is-off'}`}
                title={
                  <span className="sub-title">
                    {s.name} <Badge tone={s.aggregate ? 'accent' : 'neutral'}>{s.aggregate ? t('subs.kind.aggregate') : t('subs.kind.standard')}</Badge>
                  </span>
                }
                actions={<Switch checked={s.enabled} onChange={(v) => void toggle(s, v)} label={s.enabled ? t('common.disable') : t('common.enable')} />}
              >
                <div className="stack">
                  <div className="muted">{total === 0 ? t('subs.noNodes') : s.aggregate ? t('subs.counts', { local: s.local_count, remote: s.remote_count }) : t('subs.nodesN', { n: total })}</div>
                  {s.plan ? <PlanSummary plan={s.plan} locale={locale} /> : null}
                  {bad > 0 ? (
                    <button type="button" className="link-button warn-text" onClick={() => setReport(s)}>
                      ▲ {t('subs.compat.issues', { n: bad })} — {t('subs.compat.view')}
                    </button>
                  ) : total > 0 ? (
                    <button type="button" className="link-button ok-text" onClick={() => setReport(s)}>
                      ✓ {t('subs.compat.ok')}
                    </button>
                  ) : null}
                  <div className="row-wrap">
                    <Button size="sm" icon="qr" variant="primary" onClick={() => setLinks(s)}>
                      {t('subs.action.link')}
                    </Button>
                    <Button size="sm" icon="edit" onClick={() => setEditor({ sub: s })}>
                      {t('subs.action.nodes')}
                    </Button>
                    <Button size="sm" icon="pulse" onClick={() => setPlan(s)}>
                      {t('subs.action.plan')}
                    </Button>
                    <Menu
                      label={t('common.more')}
                      items={[
                        { label: t('common.rename'), icon: 'edit', onSelect: () => setRename(s) },
                        { label: t('subs.action.reset'), icon: 'refresh', hidden: !s.plan, onSelect: () => setResetUse(s) },
                        { label: t('subs.action.rotate'), icon: 'key', onSelect: () => setRotate(s) },
                        { label: t('common.delete'), icon: 'trash', danger: true, onSelect: () => setDel(s) },
                      ]}
                    />
                  </div>
                </div>
              </Card>
            )
          })}
        </div>
      )}

      {editor ? (
        <SubscriptionEditor
          sub={editor.sub}
          choices={data.nodes}
          onClose={() => setEditor(null)}
          onSaved={async (created) => {
            setEditor(null)
            toast.push('ok', created ? t('subs.created') : t('subs.saved'))
            await res.reload()
          }}
        />
      ) : null}

      {links ? <LinksDialog sub={links} ready={!data.server || data.server.public_url_set} onClose={() => setLinks(null)} /> : null}
      {report ? <ReportDialog sub={report} onClose={() => setReport(null)} /> : null}
      {plan ? (
        <PlanDialog
          sub={plan}
          onClose={() => setPlan(null)}
          onSaved={async () => {
            setPlan(null)
            toast.push('ok', t('subs.plan.saved'))
            await res.reload()
          }}
        />
      ) : null}

      {rename ? (
        <RenameSub
          sub={rename}
          onClose={() => setRename(null)}
          onSaved={async () => {
            setRename(null)
            await res.reload()
          }}
        />
      ) : null}

      {resetUse ? (
        <ConfirmDialog
          title={t('subs.plan.resetTitle', { name: resetUse.name })}
          impact={[t('subs.plan.resetImpact')]}
          confirmLabel={t('subs.action.reset')}
          onCancel={() => setResetUse(null)}
          onConfirm={async () => {
            const r = await run(() => api.post(`/api/subscriptions/${resetUse.id}/reset-usage`), { ok: t('subs.plan.resetDone') })
            if (r !== undefined) {
              setResetUse(null)
              await res.reload()
            }
          }}
        />
      ) : null}

      {rotate ? (
        <ConfirmDialog
          title={t('subs.rotate.title', { name: rotate.name })}
          message={t('subs.rotate.msg')}
          impact={[t('subs.rotate.i1'), t('subs.rotate.i2')]}
          confirmLabel={t('subs.action.rotate')}
          danger
          onCancel={() => setRotate(null)}
          onConfirm={async () => {
            try {
              await guard(() => api.post(`/api/subscriptions/${rotate.id}/rotate`))
              const s = rotate
              setRotate(null)
              toast.push('ok', t('subs.rotate.done'))
              await res.reload()
              setLinks(s)
            } catch (e) {
              if (!(e instanceof Cancelled)) await run(() => Promise.reject(e))
            }
          }}
        />
      ) : null}

      {del ? (
        <ConfirmDialog
          title={t('subs.delete.title', { name: del.name })}
          message={t('subs.delete.msg')}
          impact={[t('subs.delete.impact')]}
          confirmLabel={t('common.delete')}
          danger
          onCancel={() => setDel(null)}
          onConfirm={async () => {
            try {
              await guard(() => api.del(`/api/subscriptions/${del.id}`))
              setDel(null)
              toast.push('ok', t('subs.delete.done'))
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

function PlanSummary({ plan, locale }: { plan: NonNullable<SubscriptionView['plan']>; locale: string }) {
  const { t } = useI18n()
  const expired = plan.expires ? new Date(plan.expires + 'T23:59:59') < new Date() : false
  return (
    <div className="plan">
      {plan.limit > 0 ? (
        <>
          <Meter percent={formatPercent(plan.used, plan.limit)} label={t('common.used')} />
          <div className="plan-line mono small">
            {formatBytes(plan.used)} / {formatBytes(plan.limit)} · {t('subs.leftBadge', { v: formatBytes(plan.left) })}
          </div>
        </>
      ) : null}
      <div className="row-wrap small muted">
        {plan.next_reset ? <span>{t('common.resets', { d: formatDate(plan.next_reset, locale) })}</span> : null}
        {plan.expires ? expired ? <Badge tone="error">{t('subs.expiredBadge')}</Badge> : <span>{t('common.expires', { d: plan.expires })}</span> : null}
      </div>
    </div>
  )
}

// ---- links -----------------------------------------------------------------------------

function LinksDialog({ sub, ready, onClose }: { sub: SubscriptionView; ready: boolean; onClose: () => void }) {
  const { t } = useI18n()
  return (
    <Modal title={t('subs.link.title', { name: sub.name })} onClose={onClose} wide footer={<Button onClick={onClose}>{t('common.done')}</Button>}>
      {!ready ? (
        <Notice tone="warn" title={t('subs.serverNoUrl')}>
          {t('subs.serverOffHint')}
        </Notice>
      ) : !sub.can_reveal_url ? (
        <Notice tone="warn">{t('subs.link.cannot')}</Notice>
      ) : (
        <Reveal<{ base64_url: string; mihomo_url: string }> label={t('subs.link.hidden')} load={() => api.get(`/api/subscriptions/${sub.id}/url`)}>
          {(v) => (
            <div className="stack">
              <SecretValue value={v.base64_url} label={t('subs.link.base64')} rows={2} />
              <SecretValue value={v.mihomo_url} label={t('subs.link.mihomo')} rows={2} />
            </div>
          )}
        </Reveal>
      )}
    </Modal>
  )
}

// ---- compatibility report --------------------------------------------------------------

function ReportDialog({ sub, onClose }: { sub: SubscriptionView; onClose: () => void }) {
  const { t } = useI18n()
  const bad = sub.items.filter((i) => i.status === 'skipped' || !i.base64_ok || !i.mihomo_ok || (i.notes?.length ?? 0) > 0)
  return (
    <Modal title={t('subs.report.title', { name: sub.name })} onClose={onClose} wide footer={<Button onClick={onClose}>{t('common.done')}</Button>}>
      <p className="muted">{t('subs.report.intro')}</p>
      {bad.length === 0 ? (
        <Notice tone="ok">{t('subs.report.allOk')}</Notice>
      ) : (
        <div className="table-wrap">
          <table className="table table-compact">
            <thead>
              <tr>
                <th>{t('subs.report.node')}</th>
                <th>{t('subs.fmt.base64')}</th>
                <th>{t('subs.fmt.mihomo')}</th>
                <th>{t('subs.report.reason')}</th>
              </tr>
            </thead>
            <tbody>
              {bad.map((i, n) => (
                <tr key={`${i.kind}-${i.node_id}-${n}`}>
                  <td data-label={t('subs.report.node')} className="cell-primary">
                    <strong>{i.name}</strong>
                    <div className="muted small">
                      {(i.protocol ?? '').toUpperCase()} {i.source ? `· ${i.source}` : ''}
                    </div>
                  </td>
                  <td data-label={t('subs.fmt.base64')}>{i.status === 'skipped' ? <Badge tone="warn">–</Badge> : i.base64_ok ? <Badge tone="ok">✓</Badge> : <Badge tone="error">✗</Badge>}</td>
                  <td data-label={t('subs.fmt.mihomo')}>{i.status === 'skipped' ? <Badge tone="warn">–</Badge> : i.mihomo_ok ? <Badge tone="ok">✓</Badge> : <Badge tone="error">✗</Badge>}</td>
                  <td data-label={t('subs.report.reason')} className="small">
                    {i.skipped ? <div>{t('subs.report.skipped', { why: i.skipped })}</div> : null}
                    {!i.base64_ok && i.base64_why ? <div>Base64: {i.base64_why}</div> : null}
                    {!i.mihomo_ok && i.mihomo_why ? <div>Mihomo: {i.mihomo_why}</div> : null}
                    {(i.notes ?? []).map((n2) => (
                      <div key={n2} className="muted">
                        {n2}
                      </div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  )
}

// ---- plan ------------------------------------------------------------------------------

function PlanDialog({ sub, onClose, onSaved }: { sub: SubscriptionView; onClose: () => void; onSaved: () => Promise<void> }) {
  const { t } = useI18n()
  const run = useRunner()
  const p = sub.plan
  const [limit, setLimit] = useState(p && p.limit > 0 ? formatBytes(p.limit, 2).replace(' ', '') : '0')
  const [day, setDay] = useState(String(p?.billing_day || 1))
  const [tz, setTz] = useState(p?.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
  const [expires, setExpires] = useState(p?.expires ?? '')
  const [busy, setBusy] = useState(false)
  const bytes = parseSize(limit)
  const dayNum = Number(day)
  const dayOK = Number.isInteger(dayNum) && dayNum >= 1 && dayNum <= 28

  const save = async () => {
    if (bytes === null || !dayOK) return
    setBusy(true)
    const r = await run(() => api.put(`/api/subscriptions/${sub.id}/plan`, { limit_bytes: bytes, billing_day: dayNum, timezone: tz.trim(), expires }))
    setBusy(false)
    if (r !== undefined) await onSaved()
  }

  return (
    <Modal
      title={t('subs.plan.title', { name: sub.name })}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={() => void save()} busy={busy} disabled={bytes === null || !dayOK}>
            {t('common.save')}
          </Button>
        </>
      }
    >
      <div className="stack">
        {p ? <KV items={[{ k: t('subs.plan.used'), v: `${formatBytes(p.used)}${p.incomplete ? ' *' : ''}`, mono: true }]} /> : null}
        <Field label={t('subs.plan.limit')} hint={t('subs.plan.limitHint')} error={bytes === null ? t('subs.plan.limitBad') : null}>
          {(id, d) => <Input id={id} aria-describedby={d} data-autofocus value={limit} onChange={(e) => setLimit(e.target.value)} inputMode="decimal" />}
        </Field>
        <div className="grid-fields">
          <Field label={t('subs.plan.day')} hint={t('subs.plan.dayHint')} error={dayOK ? null : t('subs.plan.dayHint')}>
            {(id, d) => <Input id={id} aria-describedby={d} inputMode="numeric" value={day} onChange={(e) => setDay(e.target.value.replace(/\D/g, '').slice(0, 2))} />}
          </Field>
          <Field label={t('subs.plan.tz')}>{(id) => <Input id={id} value={tz} onChange={(e) => setTz(e.target.value)} autoCapitalize="none" spellCheck={false} />}</Field>
        </div>
        <Field label={`${t('subs.plan.expires')} ${t('common.optional')}`}>{(id) => <Input id={id} type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />}</Field>
        <p className="muted small">{t('subs.plan.noTraffic')}</p>
      </div>
    </Modal>
  )
}

function RenameSub({ sub, onClose, onSaved }: { sub: SubscriptionView; onClose: () => void; onSaved: () => Promise<void> }) {
  const { t } = useI18n()
  const run = useRunner()
  const [name, setName] = useState(sub.name)
  const [busy, setBusy] = useState(false)
  return (
    <Modal
      title={t('subs.rename.title')}
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
            disabled={!name.trim() || name.trim() === sub.name}
            onClick={async () => {
              setBusy(true)
              const r = await run(() => api.patch(`/api/subscriptions/${sub.id}`, { name: name.trim() }), { ok: t('nodes.renamed') })
              setBusy(false)
              if (r !== undefined) await onSaved()
            }}
          >
            {t('common.save')}
          </Button>
        </>
      }
    >
      <Field label={t('common.name')}>{(id) => <Input id={id} data-autofocus value={name} maxLength={40} onChange={(e) => setName(e.target.value)} />}</Field>
    </Modal>
  )
}

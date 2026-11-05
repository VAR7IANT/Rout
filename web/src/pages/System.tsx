import { useEffect, useMemo, useRef, useState } from 'react'
import { useI18n, type TFn } from '../i18n'
import type { MessageKey } from '../i18n/catalog'
import { api, download, saveBlob } from '../lib/api'
import { formatBytes, formatDateTime, formatPercent, formatRelative, formatUptime, parseDate } from '../lib/format'
import { useNow, useResource } from '../lib/hooks'
import { Cancelled, useReauth, useRunner } from '../lib/session'
import { useToast } from '../lib/toast'
import type { ActivityEntry, HTTPSView, NetworkView, PermissionCheck, RestorePlan, ServiceItem, SessionInfo, SystemView, UpdateInfo } from '../lib/types'
import { ConfirmDialog } from '../components/overlay'
import { DataTable, type Column } from '../components/table'
import { StateBadge } from '../components/shared'
import { useRouter } from '../lib/router'
import { PanelHTTPSCard } from './PanelHTTPS'
import { Badge, Button, Card, EmptyState, Field, Input, KV, Meter, Notice, PageHead, Select, Spinner, Tabs, Textarea, Toggle } from '../components/ui'

type Section = 'overview' | 'services' | 'network' | 'security' | 'backup'
const MAX_BACKUP = 24 * 1024 * 1024

export function SystemPage() {
  const { t } = useI18n()
  const { query } = useRouter()
  const initial = query.get('tab')
  const [tab, setTab] = useState<Section>(initial === 'services' || initial === 'network' || initial === 'security' || initial === 'backup' ? initial : 'overview')
  const res = useResource<SystemView>('/api/system', { interval: 20000 })
  const [logUnit, setLogUnit] = useState<string>('')

  const openLogs = (unit: string) => {
    setLogUnit(unit)
    setTab('services')
  }

  return (
    <>
      <PageHead title={t('sys.title')} subtitle={t('sys.subtitle')} />
      <Tabs
        label={t('sys.tabs')}
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'overview', label: t('sys.tab.overview') },
          { value: 'services', label: t('sys.tab.services') },
          { value: 'network', label: t('sys.tab.network') },
          { value: 'security', label: t('sys.tab.security') },
          { value: 'backup', label: t('sys.tab.backup') },
        ]}
      />
      {res.loading && !res.data ? <Spinner label={t('common.loading')} /> : null}
      {!res.data && !res.loading ? (
        <EmptyState icon="warn" title={t('common.loadFailed')} action={<Button onClick={() => void res.reload()}>{t('common.retry')}</Button>}>
          {res.error?.message}
        </EmptyState>
      ) : null}
      {res.data ? (
        <div className="page-body">
          {tab === 'overview' ? <Overview sys={res.data} /> : null}
          {tab === 'services' ? <Services sys={res.data} reload={res.reload} logUnit={logUnit} setLogUnit={setLogUnit} /> : null}
          {tab === 'network' ? <NetworkTab sys={res.data} /> : null}
          {tab === 'security' ? <SecurityTab sys={res.data} reload={res.reload} openLogs={openLogs} /> : null}
          {tab === 'backup' ? <BackupTab /> : null}
        </div>
      ) : null}
    </>
  )
}

// ---- overview --------------------------------------------------------------------------

function Overview({ sys }: { sys: SystemView }) {
  const { t, locale } = useI18n()
  const run = useRunner()
  const now = useNow(30000)
  const [update, setUpdate] = useState<UpdateInfo>(sys.update)
  const [busy, setBusy] = useState(false)
  const s = sys.system

  const check = async () => {
    setBusy(true)
    const r = await run(() => api.post<UpdateInfo>('/api/system/update-check'))
    setBusy(false)
    if (r) setUpdate(r)
  }

  return (
    <div className="grid-2">
      <Card title={t('sys.versionCard')}>
        <div className="stack">
          <KV
            items={[
              { k: t('sys.current'), v: `v${sys.version}`, mono: true },
              { k: t('sys.latest'), v: update.latest ?? t('sys.updateNever'), mono: !!update.latest },
            ]}
          />
          {update.error ? (
            <Notice tone="warn">{t('sys.updateFailed', { why: update.error })}</Notice>
          ) : update.available ? (
            <Notice tone="accent">{t('sys.updateAvailable', { v: update.latest ?? '' })}</Notice>
          ) : update.latest ? (
            <Notice tone="ok">{t('sys.upToDate')}</Notice>
          ) : null}
          <div className="row-between">
            <span className="muted small">{update.checked_at ? t('sys.checkedAt', { v: formatRelative(update.checked_at, now, t) }) : ''}</span>
            <Button icon="refresh" busy={busy} onClick={() => void check()}>
              {t('sys.checkUpdate')}
            </Button>
          </div>
          <p className="muted small">{t('sys.updateHow')}</p>
        </div>
      </Card>

      <Card title={t('sys.runtime')}>
        <KV
          items={[
            { k: t('sys.os'), v: sys.runtime.os },
            { k: t('sys.arch'), v: sys.runtime.arch },
            { k: t('sys.go'), v: sys.runtime.go, mono: true },
            { k: t('sys.init'), v: sys.runtime.init && sys.runtime.init !== 'none' ? sys.runtime.init : t('sys.initNone') },
          ]}
        />
      </Card>

      <Card title={t('sys.host')} className="span-2">
        <div className="grid-3">
          <div className="stack-tight">
            <KV
              items={[
                { k: t('sys.hostname'), v: s.hostname || '–', mono: true },
                { k: t('sys.uptime'), v: formatUptime(s.uptime_sec, t) },
                { k: t('sys.cpuLoad'), v: `${s.cpu_percent.toFixed(0)}% · ${s.load1.toFixed(2)}` },
              ]}
            />
          </div>
          <div className="stack-tight">
            <div className="row-between small">
              <span>{t('sys.mem')}</span>
              <span className="muted">
                {formatBytes(s.mem_used)} / {formatBytes(s.mem_total)}
              </span>
            </div>
            <Meter percent={formatPercent(s.mem_used, s.mem_total)} label={t('sys.mem')} />
          </div>
          <div className="stack-tight">
            <div className="row-between small">
              <span>{t('sys.disk')}</span>
              <span className="muted">
                {formatBytes(s.disk_used)} / {formatBytes(s.disk_total)}
              </span>
            </div>
            <Meter percent={formatPercent(s.disk_used, s.disk_total)} label={t('sys.disk')} />
          </div>
        </div>
        <span className="sr-only">{locale}</span>
      </Card>
    </div>
  )
}

// ---- services and logs -----------------------------------------------------------------

function Services({ sys, reload, logUnit, setLogUnit }: { sys: SystemView; reload: () => Promise<void>; logUnit: string; setLogUnit: (u: string) => void }) {
  const { t } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const { guard } = useReauth()
  const [confirm, setConfirm] = useState<{ svc: ServiceItem; action: 'restart' | 'stop' } | null>(null)
  const [busyUnit, setBusyUnit] = useState<string | null>(null)
  const managed = sys.runtime.init === 'systemd' || sys.runtime.init === 'openrc'

  const act = async (svc: ServiceItem, action: 'start' | 'stop' | 'restart') => {
    setBusyUnit(svc.unit)
    try {
      await guard(() => api.post('/api/system/service', { unit: svc.unit, action }))
      toast.push('ok', t('sys.svc.done'))
      await reload()
      setConfirm(null)
    } catch (e) {
      if (!(e instanceof Cancelled)) await run(() => Promise.reject(e))
    } finally {
      setBusyUnit(null)
    }
  }

  const columns: Column<ServiceItem>[] = [
    {
      key: 'name',
      header: t('sys.svc.name'),
      primary: true,
      cell: (s) => <strong>{s.name}</strong>,
    },
    { key: 'kind', header: t('sys.svc.kind'), label: t('sys.svc.kind'), cell: (s) => <Badge>{t(`sys.svc.kind.${s.kind}` as 'sys.svc.kind.node')}</Badge> },
    { key: 'state', header: t('sys.svc.state'), label: t('sys.svc.state'), cell: (s) => <StateBadge state={s.state} /> },
    {
      key: 'actions',
      header: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (s) => (
        <div className="row-nowrap">
          {s.kind === 'subscription' ? (
            s.state === 'running' ? (
              <>
                <Button size="sm" icon="refresh" disabled={!managed || busyUnit === s.unit} onClick={() => setConfirm({ svc: s, action: 'restart' })}>
                  {t('sys.svc.restart')}
                </Button>
                <Button size="sm" icon="stop" disabled={!managed || busyUnit === s.unit} onClick={() => setConfirm({ svc: s, action: 'stop' })}>
                  {t('sys.svc.stop')}
                </Button>
              </>
            ) : (
              <Button size="sm" icon="play" busy={busyUnit === s.unit} disabled={!managed} onClick={() => void act(s, 'start')}>
                {t('sys.svc.start')}
              </Button>
            )
          ) : s.kind === 'node' || s.kind === 'relay' ? (
            <Button size="sm" icon="refresh" disabled={!managed || busyUnit === s.unit} onClick={() => setConfirm({ svc: s, action: 'restart' })}>
              {t('sys.svc.restart')}
            </Button>
          ) : null}
          <Button size="sm" variant="ghost" disabled={!managed} onClick={() => setLogUnit(s.unit)}>
            {t('sys.svc.logs')}
          </Button>
        </div>
      ),
    },
  ]

  const c = confirm
  return (
    <div className="stack-lg">
      {!managed ? <Notice tone="warn">{t('sys.svc.noInit')}</Notice> : null}
      <Card title={t('sys.svc.title')} flush>
        <DataTable
          caption={t('sys.svc.caption')}
          rows={sys.services}
          rowKey={(s) => s.unit}
          columns={columns}
          empty={<EmptyState icon="server" title={t('sys.svc.empty')} />}
        />
      </Card>
      {sys.services.some((s) => s.kind === 'web') ? <p className="muted small">{t('sys.svc.webNote')}</p> : null}

      <Card title={t('sys.sub.title')}>
        <KV
          items={[
            { k: t('sys.sub.port'), v: String(sys.subscription.port), mono: true },
            { k: t('sys.sub.public'), v: sys.subscription.public_url || t('sys.sub.publicNone'), mono: !!sys.subscription.public_url },
            { k: t('sys.svc.state'), v: sys.subscription.managed ? t('sys.sub.managed') : t('state.unmanaged') },
          ]}
        />
      </Card>

      <LogViewer services={sys.services} unit={logUnit} setUnit={setLogUnit} />

      {c ? (
        <ConfirmDialog
          title={c.action === 'stop' ? t('sys.svc.stopTitle') : t('sys.svc.restartTitle', { name: c.svc.name })}
          message={c.action === 'stop' ? t('sys.svc.stopMsg') : t('sys.svc.restartMsg')}
          impact={c.action === 'stop' ? [t('sys.svc.stopImpact1'), t('sys.svc.stopImpact2')] : [c.svc.kind === 'subscription' ? t('sys.svc.restartSub') : t('sys.svc.restartNode')]}
          confirmLabel={c.action === 'stop' ? t('sys.svc.stop') : t('sys.svc.restart')}
          danger={c.action === 'stop'}
          onCancel={() => setConfirm(null)}
          onConfirm={() => act(c.svc, c.action)}
        />
      ) : null}
    </div>
  )
}

function LogViewer({ services, unit, setUnit }: { services: ServiceItem[]; unit: string; setUnit: (u: string) => void }) {
  const { t } = useI18n()
  const [lines, setLines] = useState('100')
  const [text, setText] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const seq = useRef(0)
  const pre = useRef<HTMLPreElement>(null)
  const selected = services.find((s) => s.unit === unit)

  const load = async () => {
    if (!unit) return
    const mine = ++seq.current
    setBusy(true)
    setError(null)
    try {
      const r = await api.get<{ log: string }>(`/api/system/logs?unit=${encodeURIComponent(unit)}&lines=${lines}`)
      if (mine === seq.current) setText(r.log)
    } catch (e) {
      if (mine === seq.current) {
        setText(null)
        setError(e instanceof Error ? e.message : t('err.generic'))
      }
    } finally {
      if (mine === seq.current) setBusy(false)
    }
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => void load(), [unit, lines])
  useEffect(() => {
    if (pre.current) pre.current.scrollTop = pre.current.scrollHeight
  }, [text])

  return (
    <Card
      title={t('sys.log.title')}
      actions={
        <Button size="sm" icon="refresh" busy={busy} disabled={!unit} onClick={() => void load()}>
          {t('sys.log.reload')}
        </Button>
      }
    >
      <div className="stack">
        <div className="grid-fields">
          <Field label={t('sys.log.unit')}>
            {(id) => (
              <Select id={id} value={unit} onChange={(e) => setUnit(e.target.value)}>
                <option value="">{t('sys.log.pick')}</option>
                {services.map((s) => (
                  <option key={s.unit} value={s.unit}>
                    {s.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t('sys.log.lines')}>
            {(id) => (
              <Select id={id} value={lines} onChange={(e) => setLines(e.target.value)}>
                {['50', '100', '200', '500'].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        {error ? <Notice tone="error">{error}</Notice> : null}
        {unit ? (
          <pre ref={pre} className="log" tabIndex={0} aria-label={t('sys.log.aria', { name: selected?.name ?? unit })}>
            {text == null ? '' : text.trim() === '' ? t('sys.log.empty') : text}
          </pre>
        ) : (
          <p className="muted">{t('sys.log.pick')}</p>
        )}
        <p className="muted small">{t('sys.log.redacted')}</p>
      </div>
    </Card>
  )
}

// ---- network and HTTPS -----------------------------------------------------------------

function NetworkTab({ sys }: { sys: SystemView }) {
  const { t } = useI18n()
  const now = useNow(30000)
  const net = useResource<NetworkView>('/api/system/network')
  const [https, setHttps] = useState<HTTPSView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const ipText = (addr: string, local: boolean) => (addr ? addr : local ? t('sys.net.localOnly') : t('sys.net.none'))

  const runHTTPS = async () => {
    setBusy(true)
    setError(null)
    try {
      setHttps(await api.get<HTTPSView>('/api/system/https'))
    } catch (e) {
      setError(e instanceof Error ? e.message : t('err.generic'))
    } finally {
      setBusy(false)
    }
  }

  const yn = (ok: boolean) => <Badge tone={ok ? 'ok' : 'error'}>{ok ? t('sys.https.ok') : t('sys.https.fail')}</Badge>

  return (
    <div className="stack-lg">
      <Card
        title={t('sys.net.title')}
        actions={
          <Button size="sm" icon="refresh" busy={net.loading} onClick={() => void net.reload()}>
            {t('sys.net.recheck')}
          </Button>
        }
      >
        {net.loading && !net.data ? (
          <Spinner label={t('common.loading')} />
        ) : net.data ? (
          <KV
            items={[
              { k: t('sys.net.ipv4'), v: ipText(net.data.public_ips.ipv4, net.data.public_ips.local_ipv4), mono: !!net.data.public_ips.ipv4 },
              { k: t('sys.net.ipv6'), v: ipText(net.data.public_ips.ipv6, net.data.public_ips.local_ipv6), mono: !!net.data.public_ips.ipv6 },
              {
                k: t('sys.net.dns'),
                v: net.data.dns.ok ? <Badge tone="ok">{t('sys.net.dnsOk', { ms: net.data.dns.millis })}</Badge> : <Badge tone="error">{t('sys.net.dnsFail', { why: net.data.dns.error ?? '' })}</Badge>,
              },
              { k: t('sys.net.resolvers'), v: net.data.dns.servers.length ? net.data.dns.servers.join('、') : '–', mono: true },
            ]}
          />
        ) : (
          <Notice tone="error">{net.error?.message}</Notice>
        )}
        {net.data?.public_ips.checked_at ? <p className="muted small">{t('sys.net.checkedAt', { v: formatRelative(net.data.public_ips.checked_at, now, t) })}</p> : null}
      </Card>

      <PanelHTTPSCard secure={sys.web.secure_request} />

      <Card
        title={t('sys.https.title')}
        actions={
          <Button size="sm" variant="primary" busy={busy} onClick={() => void runHTTPS()}>
            {busy ? t('sys.https.running') : t('sys.https.run')}
          </Button>
        }
      >
        <div className="stack">
          <p className="muted">{t('sys.https.intro')}</p>
          {error ? <Notice tone="error">{error}</Notice> : null}
          {https ? (
            https.domain === '' ? (
              <Notice tone="neutral">{t('sys.https.none')}</Notice>
            ) : (
              <>
                <KV
                  items={[
                    { k: t('sys.https.domain'), v: https.domain, mono: true },
                    { k: t('sys.https.caddy'), v: <Badge tone={https.installed && https.running ? 'ok' : 'error'}>{!https.installed ? t('sys.https.notInstalled') : https.running ? t('sys.https.running2') : t('sys.https.stopped')}</Badge> },
                    {
                      k: t('sys.https.route'),
                      v: https.route_conflict ? <Badge tone="error">{t('sys.https.routeConflict')}</Badge> : https.route_ok ? <Badge tone="ok">{t('sys.https.routeOk')}</Badge> : <Badge tone="error">{https.route_found ? t('sys.https.routeBad') : t('sys.https.routeMissing')}</Badge>,
                    },
                    {
                      k: t('sys.https.dns'),
                      v: https.dns.proxied || https.dns.uncertain ? <Badge tone="warn">{t('sys.https.dnsProxied')}</Badge> : https.dns.matched ? <Badge tone="ok">{t('sys.https.dnsMatch')}</Badge> : <Badge tone="error">{t('sys.https.dnsMismatch')}</Badge>,
                    },
                    { k: t('sys.https.tls'), v: yn(https.verification.local_tls) },
                    { k: t('sys.https.public'), v: yn(https.verification.public_from_host) },
                    { k: t('sys.https.external'), v: yn(https.verification.external) },
                    {
                      k: t('sys.https.cert'),
                      v: https.verification.certificate_error ? <Badge tone="error">{t('sys.https.certError')}</Badge> : https.verification.expires ? t('sys.https.certExpires', { v: formatDateTime(https.verification.expires) }) : '–',
                    },
                  ]}
                />
                {https.issues.length > 0 ? (
                  <Notice tone="warn" title={t('sys.https.issues')}>
                    <ul className="plain-list">
                      {https.issues.map((x, i) => (
                        <li key={i}>{x}</li>
                      ))}
                    </ul>
                  </Notice>
                ) : (
                  <Notice tone="ok">{t('sys.https.allGood')}</Notice>
                )}
                {https.last_error ? <Notice tone="error">{https.last_error}</Notice> : null}
              </>
            )
          ) : null}
          <p className="muted small">{t('sys.https.howTo')}</p>
        </div>
      </Card>
    </div>
  )
}

// ---- security --------------------------------------------------------------------------

function SecurityTab({ sys, reload, openLogs }: { sys: SystemView; reload: () => Promise<void>; openLogs: (u: string) => void }) {
  void openLogs
  return (
    <div className="stack-lg">
      <SettingsCard sys={sys} reload={reload} />
      <SessionsCard />
      <ActivityCard />
      <PermissionsCard checks={sys.permissions} reload={reload} />
    </div>
  )
}

function SettingsCard({ sys, reload }: { sys: SystemView; reload: () => Promise<void> }) {
  const { t, locale } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const { guard } = useReauth()
  const w = sys.web
  const [port, setPort] = useState(String(w.port))
  const [hosts, setHosts] = useState(w.allowed_hosts.join('\n'))
  const [idle, setIdle] = useState(String(w.session_idle_min))
  const [max, setMax] = useState(String(w.session_max_hours))
  const [secure, setSecure] = useState(w.secure_cookie)
  const [busy, setBusy] = useState(false)
  const [confirmSecure, setConfirmSecure] = useState(false)

  const num = (s: string) => (/^\d+$/.test(s.trim()) ? Number(s) : NaN)
  const errors = {
    port: !(num(port) >= 1024 && num(port) <= 65535) ? t('sys.sec.badPort') : null,
    idle: !(num(idle) >= 5 && num(idle) <= 1440) ? t('sys.sec.badIdle') : null,
    max: !(num(max) >= 1 && num(max) <= 720) ? t('sys.sec.badMax') : null,
  }
  const invalid = !!(errors.port || errors.idle || errors.max)
  const dirty =
    port !== String(w.port) || idle !== String(w.session_idle_min) || max !== String(w.session_max_hours) || secure !== w.secure_cookie || hosts.trim() !== w.allowed_hosts.join('\n').trim()
  const risky = secure && !w.secure_cookie && !w.secure_request

  const save = async () => {
    setBusy(true)
    try {
      const body = {
        port: num(port),
        session_idle_min: num(idle),
        session_max_hours: num(max),
        secure_cookie: secure,
        allowed_hosts: hosts
          .split(/[\n,，\s]+/)
          .map((x) => x.trim())
          .filter(Boolean),
      }
      const r = await guard(() => api.patch<{ restart_required: boolean }>('/api/system/settings', body))
      toast.push('ok', r?.restart_required ? t('sys.sec.savedRestart') : t('sys.sec.saved'))
      setConfirmSecure(false)
      await reload()
    } catch (e) {
      if (!(e instanceof Cancelled)) await run(() => Promise.reject(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title={t('sys.sec.settings')}>
      <div className="stack">
        <p className="muted">{t('sys.sec.settingsIntro')}</p>
        <div className="grid-fields">
          <Field label={t('sys.sec.port')} hint={t('sys.sec.portHint')} error={errors.port}>
            {(id, d) => <Input id={id} aria-describedby={d} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, '').slice(0, 5))} />}
          </Field>
          <Field label={t('sys.sec.idle')} error={errors.idle}>
            {(id, d) => <Input id={id} aria-describedby={d} inputMode="numeric" value={idle} onChange={(e) => setIdle(e.target.value.replace(/\D/g, '').slice(0, 4))} />}
          </Field>
          <Field label={t('sys.sec.max')} error={errors.max}>
            {(id, d) => <Input id={id} aria-describedby={d} inputMode="numeric" value={max} onChange={(e) => setMax(e.target.value.replace(/\D/g, '').slice(0, 3))} />}
          </Field>
        </div>
        <Field label={t('sys.sec.hosts')} hint={t('sys.sec.hostsHint')}>
          {(id, d) => <Textarea id={id} aria-describedby={d} rows={3} className="mono" spellCheck={false} autoCapitalize="none" value={hosts} onChange={(e) => setHosts(e.target.value)} />}
        </Field>
        <Toggle checked={secure} onChange={setSecure} hint={t('sys.sec.secureHint')}>
          {t('sys.sec.secure')}
        </Toggle>
        {risky ? <Notice tone="warn">{t('sys.sec.secureWarn')}</Notice> : null}
        <div className="row-end">
          <Button variant="primary" disabled={!dirty || invalid} busy={busy} onClick={() => (risky ? setConfirmSecure(true) : void save())}>
            {t('common.save')}
          </Button>
        </div>
        <hr className="rule" />
        <KV
          items={[
            {
              k: t('sys.sec.password'),
              v: w.password_set ? t('sys.sec.passwordSet', { d: w.password_changed_at ? ` · ${formatDateTime(w.password_changed_at, locale)}` : '' }) : t('login.notConfigured'),
            },
          ]}
        />
        <p className="muted small">{t('sys.sec.passwordHow')}</p>
      </div>
      {confirmSecure ? (
        <ConfirmDialog title={t('sys.sec.secure')} message={t('sys.sec.secureWarn')} confirmLabel={t('common.save')} danger onCancel={() => setConfirmSecure(false)} onConfirm={save} />
      ) : null}
    </Card>
  )
}

function SessionsCard() {
  const { t, locale } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const now = useNow(30000)
  const res = useResource<{ sessions: SessionInfo[] }>('/api/sessions', { interval: 30000 })
  const [revoke, setRevoke] = useState<SessionInfo | null>(null)
  const [revokeOthers, setRevokeOthers] = useState(false)
  const sessions = res.data?.sessions ?? []

  const columns: Column<SessionInfo>[] = [
    {
      key: 'ip',
      header: t('sys.sec.ip'),
      primary: true,
      cell: (s) => (
        <span className="row-gap">
          <span className="mono">{s.ip}</span> {s.current ? <Badge tone="accent">{t('sys.sec.current')}</Badge> : null}
        </span>
      ),
    },
    { key: 'agent', header: t('sys.sec.agent'), label: t('sys.sec.agent'), cell: (s) => <span className="small clamp-2" title={s.agent}>{s.agent || '–'}</span> },
    { key: 'created', header: t('sys.sec.started'), label: t('sys.sec.started'), cell: (s) => formatDateTime(s.created_at, locale) },
    { key: 'seen', header: t('sys.sec.seen'), label: t('sys.sec.seen'), cell: (s) => formatRelative(s.last_seen, now, t) },
    {
      key: 'actions',
      header: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (s) => (s.current ? null : (
        <Button size="sm" variant="danger" onClick={() => setRevoke(s)}>
          {t('sys.sec.revoke')}
        </Button>
      )),
    },
  ]

  return (
    <Card
      title={t('sys.sec.sessions')}
      flush
      actions={
        <Button size="sm" disabled={sessions.filter((s) => !s.current).length === 0} onClick={() => setRevokeOthers(true)}>
          {t('sys.sec.revokeOthers')}
        </Button>
      }
    >
      <p className="muted small card-pad">{t('sys.sec.sessionsIntro')}</p>
      <DataTable caption={t('sys.sec.sessionsCaption')} rows={sessions} rowKey={(s) => s.id} columns={columns} empty={<EmptyState icon="shield" title={t('common.none')} />} />
      {revoke ? (
        <ConfirmDialog
          title={t('sys.sec.revokeTitle')}
          message={t('sys.sec.revokeMsg')}
          confirmLabel={t('sys.sec.revoke')}
          danger
          onCancel={() => setRevoke(null)}
          onConfirm={async () => {
            const r = await run(() => api.del(`/api/sessions/${revoke.id}`))
            if (r !== undefined) {
              toast.push('ok', t('sys.sec.revoked'))
              setRevoke(null)
              await res.reload()
            }
          }}
        />
      ) : null}
      {revokeOthers ? (
        <ConfirmDialog
          title={t('sys.sec.revokeOthersTitle')}
          message={t('sys.sec.revokeMsg')}
          confirmLabel={t('sys.sec.revokeOthers')}
          danger
          onCancel={() => setRevokeOthers(false)}
          onConfirm={async () => {
            const r = await run(() => api.post<{ revoked: number }>('/api/sessions/revoke-others'))
            if (r) {
              toast.push('ok', t('sys.sec.revokedN', { n: r.revoked }))
              setRevokeOthers(false)
              await res.reload()
            }
          }}
        />
      ) : null}
    </Card>
  )
}

function ActivityCard() {
  const { t, locale } = useI18n()
  const res = useResource<{ entries: ActivityEntry[] }>('/api/activity', { interval: 30000 })
  const entries = [...(res.data?.entries ?? [])].reverse()
  return (
    <Card title={t('sys.sec.activity')}>
      {entries.length === 0 ? (
        <p className="muted">{t('sys.sec.activityEmpty')}</p>
      ) : (
        <ul className="activity">
          {entries.map((e, i) => (
            <li key={`${e.at}-${i}`}>
              <time className="muted small" dateTime={e.at}>
                {formatDateTime(e.at, locale)}
              </time>
              <span className="mono small">{e.ip}</span>
              <span>{e.action}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="muted small">{t('sys.sec.activityNote')}</p>
    </Card>
  )
}

function PermissionsCard({ checks, reload }: { checks: PermissionCheck[]; reload: () => Promise<void> }) {
  const { t } = useI18n()
  const toast = useToast()
  const run = useRunner()
  const { guard } = useReauth()
  const [confirm, setConfirm] = useState(false)
  const bad = checks.filter((c) => !c.ok)

  const columns: Column<PermissionCheck>[] = [
    { key: 'path', header: t('sys.perm.path'), primary: true, cell: (c) => <span className="mono small">{c.path}</span> },
    { key: 'mode', header: t('sys.perm.mode'), label: t('sys.perm.mode'), cell: (c) => <span className="mono">{c.mode}</span> },
    { key: 'expected', header: t('sys.perm.expected'), label: t('sys.perm.expected'), cell: (c) => <span className="mono">{c.expected}</span> },
    { key: 'ok', header: t('common.status'), label: t('common.status'), cell: (c) => <Badge tone={c.ok ? 'ok' : 'error'}>{c.ok ? t('sys.https.ok') : t('sys.https.fail')}</Badge> },
  ]

  return (
    <Card
      title={t('sys.perm.title')}
      flush
      actions={
        bad.length > 0 ? (
          <Button size="sm" variant="primary" onClick={() => setConfirm(true)}>
            {t('sys.perm.fix')}
          </Button>
        ) : undefined
      }
    >
      <div className="card-pad">
        <p className="muted small">{t('sys.perm.intro')}</p>
        {bad.length === 0 ? <Notice tone="ok">{t('sys.perm.ok')}</Notice> : <Notice tone="warn">{t('sys.perm.bad', { n: bad.length })}</Notice>}
      </div>
      <DataTable caption={t('sys.perm.caption')} rows={checks} rowKey={(c) => c.path} columns={columns} />
      {confirm ? (
        <ConfirmDialog
          title={t('sys.perm.fixTitle')}
          message={t('sys.perm.fixMsg')}
          impact={bad.map((b) => `${b.path}: ${b.mode} → ${b.expected}`)}
          confirmLabel={t('sys.perm.fix')}
          onCancel={() => setConfirm(false)}
          onConfirm={async () => {
            try {
              const r = await guard(() => api.post<{ fixed: number }>('/api/system/permissions/fix'))
              toast.push('ok', t('sys.perm.fixed', { n: r?.fixed ?? 0 }))
              setConfirm(false)
              await reload()
            } catch (e) {
              if (!(e instanceof Cancelled)) await run(() => Promise.reject(e))
            }
          }}
        />
      ) : null}
    </Card>
  )
}

// ---- backup and restore ----------------------------------------------------------------

function BackupTab() {
  const { t } = useI18n()
  return (
    <div className="stack-lg">
      <BackupCard />
      <RestoreCard />
      <p className="sr-only">{t('sys.tab.backup')}</p>
    </div>
  )
}

function BackupCard() {
  const { t } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const { guard } = useReauth()
  const [busy, setBusy] = useState(false)
  const go = async () => {
    setBusy(true)
    const r = await run(() => guard(() => download('/api/system/backup')))
    setBusy(false)
    if (r) {
      saveBlob(r.blob, r.filename)
      toast.push('ok', t('sys.bk.downloaded'))
    }
  }
  return (
    <Card title={t('sys.bk.title')}>
      <div className="stack">
        <p>{t('sys.bk.intro')}</p>
        <Notice tone="warn">{t('sys.bk.warn')}</Notice>
        <div>
          <Button variant="primary" icon="download" busy={busy} onClick={() => void go()}>
            {t('sys.bk.download')}
          </Button>
        </div>
      </div>
    </Card>
  )
}

interface PlanResponse {
  plan: RestorePlan
  applied: boolean
  permissions_fixed?: number
}

function RestoreCard() {
  const { t, locale } = useI18n()
  const run = useRunner()
  const toast = useToast()
  const { guard } = useReauth()
  const input = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<{ name: string; size: number; data: unknown } | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [plan, setPlan] = useState<RestorePlan | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirm, setConfirm] = useState(false)

  const reset = () => {
    setFile(null)
    setPlan(null)
    setFileError(null)
    if (input.current) input.current.value = ''
  }

  const pick = async (f: File | undefined) => {
    setPlan(null)
    setFileError(null)
    setFile(null)
    if (!f) return
    if (f.size > MAX_BACKUP) return setFileError(t('sys.rs.tooBig', { max: formatBytes(MAX_BACKUP, 0) }))
    try {
      const data = JSON.parse(await f.text())
      if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new Error('shape')
      setFile({ name: f.name, size: f.size, data })
    } catch {
      setFileError(t('sys.rs.notJson'))
    }
  }

  const preview = async () => {
    if (!file) return
    setBusy(true)
    const r = await run(() => guard(() => api.post<PlanResponse>('/api/system/restore', { backup: file.data, dry_run: true })))
    setBusy(false)
    if (r) setPlan(r.plan)
  }

  const apply = async () => {
    if (!file) return
    try {
      const r = await guard(() => api.post<PlanResponse>('/api/system/restore', { backup: file.data, dry_run: false, confirm: 'RESTORE' }))
      toast.push('ok', r?.permissions_fixed ? t('sys.rs.doneFixed', { n: r.permissions_fixed }) : t('sys.rs.done'))
      setConfirm(false)
      reset()
    } catch (e) {
      if (!(e instanceof Cancelled)) await run(() => Promise.reject(e))
    }
  }

  const rows = useMemo(
    () =>
      plan
        ? ([
            ['nodes', plan.nodes],
            ['relays', plan.relays],
            ['exits', plan.exits],
            ['subs', plan.subscriptions],
            ['sources', plan.sources],
          ] as const)
        : [],
    [plan],
  )
  const created = parseDate(plan?.created_at)

  return (
    <Card title={t('sys.rs.title')}>
      <div className="stack">
        <p>{t('sys.rs.intro')}</p>
        <div className="row-gap">
          <input ref={input} type="file" accept="application/json,.json" className="sr-only" id="restore-file" onChange={(e) => void pick(e.target.files?.[0])} />
          <Button icon="upload" onClick={() => input.current?.click()}>
            {file ? t('sys.rs.reset') : t('sys.rs.choose')}
          </Button>
          {file ? (
            <span className="small">
              <strong>{file.name}</strong> <span className="muted">({formatBytes(file.size)})</span>
            </span>
          ) : null}
        </div>
        {fileError ? <Notice tone="error">{fileError}</Notice> : null}
        {file && !plan ? (
          <div>
            <Button variant="primary" busy={busy} onClick={() => void preview()}>
              {t('sys.rs.preview')}
            </Button>
          </div>
        ) : null}

        {plan ? (
          <div className="stack">
            <h3 className="h3">{t('sys.rs.plan')}</h3>
            <p className="muted small">
              {created ? t('sys.rs.meta', { d: created.toLocaleString(locale), v: plan.rout_version ?? '?' }) : null} <Badge>{plan.full ? t('sys.rs.kindFull') : t('sys.rs.kindPartial')}</Badge>
            </p>
            {plan.warnings.length > 0 ? (
              <Notice tone="warn" title={t('sys.rs.warnings')}>
                <ul className="plain-list">
                  {plan.warnings.map((w) => (
                    <li key={w}>{warningText(t, w)}</li>
                  ))}
                </ul>
              </Notice>
            ) : null}
            <div className="table-wrap">
              <table className="table plain table-keep">
                <thead>
                  <tr>
                    <th>{t('sys.rs.col.kind')}</th>
                    <th>{t('sys.rs.col.now')}</th>
                    <th>{t('sys.rs.col.backup')}</th>
                    <th>{t('sys.rs.col.removed')}</th>
                    <th>{t('sys.rs.col.added')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(([key, d]) => (
                    <tr key={key}>
                      <th scope="row">{t(`sys.rs.${key}` as 'sys.rs.nodes')}</th>
                      <td>{d.now}</td>
                      <td>{d.backup}</td>
                      <td className={d.removed.length ? 'err-text' : 'muted'}>{d.removed.length ? d.removed.join('、') : t('sys.rs.noChange')}</td>
                      <td className={d.added.length ? 'ok-text' : 'muted'}>{d.added.length ? d.added.join('、') : t('sys.rs.noChange')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="row-end">
              <Button variant="ghost" onClick={reset}>
                {t('common.cancel')}
              </Button>
              <Button variant="danger" onClick={() => setConfirm(true)}>
                {t('sys.rs.apply')}
              </Button>
            </div>
          </div>
        ) : null}
      </div>

      {confirm ? (
        <ConfirmDialog
          title={t('sys.rs.applyTitle')}
          message={t('sys.rs.applyMsg')}
          impact={[t('sys.rs.impact1'), t('sys.rs.impact2'), t('sys.rs.impact3'), t('sys.rs.impact4')]}
          confirmLabel={t('sys.rs.apply')}
          danger
          requireText="RESTORE"
          onCancel={() => setConfirm(false)}
          onConfirm={apply}
        />
      ) : null}
      <span className="sr-only">{formatDateTime(undefined)}</span>
    </Card>
  )
}

const RESTORE_WARNINGS = ['plain_state_backup', 'sources_kept', 'aggregate_without_sources', 'snapshots_omitted'] as const

function warningText(t: TFn, w: string): string {
  return (RESTORE_WARNINGS as readonly string[]).includes(w) ? t(`sys.rs.warn.${w}` as MessageKey) : w
}

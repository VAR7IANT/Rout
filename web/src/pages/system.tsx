// System: version, services and logs, network and HTTPS, panel security, backup and restore.
import { useCallback, useEffect, useRef, useState } from 'react'
import { api, saveAs } from '../core/api'
import { bytes, dateTime, percent, portDigits, relative, toDate, uptime } from '../core/format'
import { useNow, useRemote } from '../core/hooks'
import { useI18n, type MessageKey } from '../core/i18n'
import { useRouter } from '../core/router'
import { errorText, useAct, useReauth } from '../core/session'
import type { ActivityEntry, DiffSet, HTTPSView, NetworkView, PermissionCheck, RestorePlan, ServiceItem, SessionInfo, SystemView, UpdateInfo } from '../core/types'
import { LoadState, StateTag } from '../ui/domain'
import { Button, Checkbox, Empty, Field, Input, KV, Meter, Notice, PageHead, Panel, Select, Spinner, Tabs, Tag, Textarea } from '../ui/kit'
import { Confirm } from '../ui/overlay'
import { DataTable, type Column } from '../ui/table'
import { PanelHTTPSCard } from './panel-https'

const TABS = ['overview', 'services', 'network', 'security', 'backup'] as const
type Tab = (typeof TABS)[number]
const isTab = (v: string | null): v is Tab => (TABS as readonly string[]).includes(v ?? '')

export function SystemPage() {
  const { t } = useI18n()
  const { query, go } = useRouter()
  const wanted = query.get('tab')
  const tab: Tab = isTab(wanted) ? wanted : 'overview'
  // The tab lives in the URL (?tab=network) so links and Back land on it.
  const setTab = (next: Tab) => go(next === 'overview' ? '/system' : `/system?tab=${next}`, { replace: true })
  const res = useRemote<SystemView>('/api/system', { every: 20000 })
  const [logUnit, setLogUnit] = useState('')
  const sys = res.data

  return (
    <div className="page">
      <PageHead title={t('sys.title')} sub={t('sys.subtitle')} />
      <Tabs<Tab> label={t('sys.tabs')} value={tab} onChange={setTab} tabs={TABS.map((value) => ({ value, label: t(`sys.tab.${value}`) }))} />
      {!sys ? <LoadState res={res} /> : null}
      {sys && tab === 'overview' ? <OverviewTab sys={sys} /> : null}
      {sys && tab === 'services' ? <ServicesTab sys={sys} reload={res.reload} logUnit={logUnit} setLogUnit={setLogUnit} /> : null}
      {sys && tab === 'network' ? <NetworkTab sys={sys} /> : null}
      {sys && tab === 'security' ? <SecurityTab sys={sys} reload={res.reload} /> : null}
      {sys && tab === 'backup' ? <BackupTab /> : null}
    </div>
  )
}

// ---- overview --------------------------------------------------------------------------

function OverviewTab({ sys }: { sys: SystemView }) {
  const { t } = useI18n()
  const act = useAct()
  const now = useNow()
  const [update, setUpdate] = useState<UpdateInfo>(sys.update)
  const [checking, setChecking] = useState(false)
  const host = sys.system

  const check = async () => {
    setChecking(true)
    const r = await act(() => api.post<UpdateInfo>('/api/system/update-check'))
    setChecking(false)
    if (r) setUpdate(r)
  }

  return (
    <div className="stack">
      <div className="cols-2">
        <Panel
          title={t('sys.versionCard')}
          actions={
            <Button size="sm" icon="refresh" busy={checking} onClick={() => void check()}>
              {t('sys.checkUpdate')}
            </Button>
          }
        >
          <div className="stack">
            <KV
              rows={[
                { k: t('sys.current'), v: `v${sys.version}` },
                { k: t('sys.latest'), v: update.latest ?? t('sys.updateNever') },
              ]}
            />
            {update.error ? (
              <Notice tone="warn">{t('sys.updateFailed', { why: update.error })}</Notice>
            ) : update.available ? (
              <Notice tone="accent">{t('sys.updateAvailable', { v: update.latest ?? '' })}</Notice>
            ) : update.latest ? (
              <Notice tone="ok">{t('sys.upToDate')}</Notice>
            ) : null}
            {update.checked_at ? <p className="dim small">{t('sys.checkedAt', { v: relative(update.checked_at, now, t) })}</p> : null}
            <p className="dim small">{t('sys.updateHow')}</p>
          </div>
        </Panel>

        <Panel title={t('sys.runtime')}>
          <KV
            rows={[
              { k: t('sys.os'), v: sys.runtime.os },
              { k: t('sys.arch'), v: sys.runtime.arch },
              { k: t('sys.go'), v: sys.runtime.go },
              { k: t('sys.init'), v: sys.runtime.init && sys.runtime.init !== 'none' ? sys.runtime.init : t('sys.initNone') },
            ]}
          />
        </Panel>
      </div>

      <Panel title={t('sys.host')}>
        <KV
          rows={[
            { k: t('sys.hostname'), v: host.hostname || '–' },
            { k: t('sys.uptime'), v: uptime(host.uptime_sec, t) },
            { k: t('sys.cpuLoad'), v: `${host.cpu_percent.toFixed(0)}% · ${host.load1.toFixed(2)}` },
            {
              k: t('sys.mem'),
              v: (
                <span className="row">
                  <Meter value={percent(host.mem_used, host.mem_total)} label={t('sys.mem')} width={16} />
                  <span className="dim">
                    {bytes(host.mem_used)} / {bytes(host.mem_total)}
                  </span>
                </span>
              ),
            },
            {
              k: t('sys.disk'),
              v: (
                <span className="row">
                  <Meter value={percent(host.disk_used, host.disk_total)} label={t('sys.disk')} width={16} />
                  <span className="dim">
                    {bytes(host.disk_used)} / {bytes(host.disk_total)}
                  </span>
                </span>
              ),
            },
          ]}
        />
      </Panel>
    </div>
  )
}

// ---- services and logs -----------------------------------------------------------------

type ServiceAction = 'start' | 'stop' | 'restart'

function ServicesTab({ sys, reload, logUnit, setLogUnit }: { sys: SystemView; reload: () => Promise<void>; logUnit: string; setLogUnit: (u: string) => void }) {
  const { t } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const [asking, setAsking] = useState<{ service: ServiceItem; action: 'restart' | 'stop' } | null>(null)
  const [working, setWorking] = useState<string | null>(null)
  // Without an init system Rout cannot control services or read their logs.
  const managed = sys.runtime.init === 'systemd' || sys.runtime.init === 'openrc'

  const run = async (service: ServiceItem, action: ServiceAction) => {
    setWorking(service.unit)
    const r = await act(() => guard(() => api.post('/api/system/service', { unit: service.unit, action })), { ok: t('sys.svc.done') })
    setWorking(null)
    if (r === undefined) return
    setAsking(null)
    await reload()
  }

  const controls = (s: ServiceItem) => {
    const locked = !managed || working === s.unit
    const restart = (
      <Button size="sm" icon="refresh" disabled={locked} onClick={() => setAsking({ service: s, action: 'restart' })}>
        {t('sys.svc.restart')}
      </Button>
    )
    if (s.kind === 'node' || s.kind === 'relay') return restart
    if (s.kind !== 'subscription') return null // the panel cannot restart itself from here
    if (s.state !== 'running')
      return (
        <Button size="sm" icon="play" busy={working === s.unit} disabled={!managed} onClick={() => void run(s, 'start')}>
          {t('sys.svc.start')}
        </Button>
      )
    return (
      <>
        {restart}
        <Button size="sm" icon="stop" disabled={locked} onClick={() => setAsking({ service: s, action: 'stop' })}>
          {t('sys.svc.stop')}
        </Button>
      </>
    )
  }

  const columns: Column<ServiceItem>[] = [
    { key: 'name', head: t('sys.svc.name'), primary: true, cell: (s) => <strong>{s.name}</strong> },
    { key: 'kind', head: t('sys.svc.kind'), label: t('sys.svc.kind'), cell: (s) => <Tag>{t(`sys.svc.kind.${s.kind}` as MessageKey)}</Tag> },
    { key: 'state', head: t('sys.svc.state'), label: t('sys.svc.state'), cell: (s) => <StateTag state={s.state} /> },
    {
      key: 'actions',
      head: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (s) => (
        <span className="row row--end nowrap">
          {controls(s)}
          <Button size="sm" variant="ghost" disabled={!managed} onClick={() => setLogUnit(s.unit)}>
            {t('sys.svc.logs')}
          </Button>
        </span>
      ),
    },
  ]

  const stopping = asking?.action === 'stop'
  return (
    <div className="stack">
      {managed ? null : <Notice tone="warn">{t('sys.svc.noInit')}</Notice>}
      <Panel title={t('sys.svc.title')} flush>
        <DataTable caption={t('sys.svc.caption')} rows={sys.services} rowKey={(s) => s.unit} columns={columns} empty={<Empty icon="nodes" title={t('sys.svc.empty')} />} />
      </Panel>
      {sys.services.some((s) => s.kind === 'web') ? <p className="dim small">{t('sys.svc.webNote')}</p> : null}

      <Panel title={t('sys.sub.title')}>
        <KV
          rows={[
            { k: t('sys.sub.port'), v: String(sys.subscription.port) },
            { k: t('sys.sub.public'), v: sys.subscription.public_url || t('sys.sub.publicNone') },
            { k: t('sys.svc.state'), v: t(sys.subscription.managed ? 'sys.sub.managed' : 'state.unmanaged') },
          ]}
        />
      </Panel>

      <LogViewer services={sys.services} unit={logUnit} setUnit={setLogUnit} />

      {asking ? (
        <Confirm
          danger={stopping}
          title={stopping ? t('sys.svc.stopTitle') : t('sys.svc.restartTitle', { name: asking.service.name })}
          message={t(stopping ? 'sys.svc.stopMsg' : 'sys.svc.restartMsg')}
          impact={stopping ? [t('sys.svc.stopImpact1'), t('sys.svc.stopImpact2')] : [t(asking.service.kind === 'subscription' ? 'sys.svc.restartSub' : 'sys.svc.restartNode')]}
          confirmLabel={t(stopping ? 'sys.svc.stop' : 'sys.svc.restart')}
          onCancel={() => setAsking(null)}
          onConfirm={() => run(asking.service, asking.action)}
        />
      ) : null}
    </div>
  )
}

const LOG_LINES = ['50', '100', '200', '500']

function LogViewer({ services, unit, setUnit }: { services: ServiceItem[]; unit: string; setUnit: (u: string) => void }) {
  const { t } = useI18n()
  const [lines, setLines] = useState('100')
  const [text, setText] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const ticket = useRef(0)
  const pane = useRef<HTMLPreElement>(null)

  const load = useCallback(async () => {
    if (!unit) return
    const mine = ++ticket.current // only the latest request may write
    setBusy(true)
    setError(null)
    try {
      const r = await api.get<{ log: string }>(`/api/system/logs?unit=${encodeURIComponent(unit)}&lines=${lines}`)
      if (mine === ticket.current) setText(r.log)
    } catch (e) {
      if (mine !== ticket.current) return
      setText(null)
      setError(errorText(e, t))
    } finally {
      if (mine === ticket.current) setBusy(false)
    }
  }, [unit, lines, t])
  useEffect(() => void load(), [load])
  // Newest lines are at the bottom: keep them in view.
  useEffect(() => {
    if (pane.current) pane.current.scrollTop = pane.current.scrollHeight
  }, [text])

  return (
    <Panel
      title={t('sys.log.title')}
      actions={
        <Button size="sm" icon="refresh" busy={busy} disabled={!unit} onClick={() => void load()}>
          {t('sys.log.reload')}
        </Button>
      }
    >
      <div className="stack">
        <div className="cols-2">
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
                {LOG_LINES.map((n) => (
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
          <pre ref={pane} className="log" tabIndex={0} aria-label={t('sys.log.aria', { name: services.find((s) => s.unit === unit)?.name ?? unit })}>
            {text == null ? '' : text.trim() === '' ? t('sys.log.empty') : text}
          </pre>
        ) : (
          <p className="dim">{t('sys.log.pick')}</p>
        )}
        <p className="dim small">{t('sys.log.redacted')}</p>
      </div>
    </Panel>
  )
}

// ---- network and HTTPS -----------------------------------------------------------------

function NetworkTab({ sys }: { sys: SystemView }) {
  const { t, locale } = useI18n()
  const now = useNow()
  const net = useRemote<NetworkView>('/api/system/network')
  const [https, setHttps] = useState<HTTPSView | null>(null)
  const [httpsError, setHttpsError] = useState<string | null>(null)
  const [checking, setChecking] = useState(false)

  const address = (ip: string, local: boolean) => ip || <span className="dim">{t(local ? 'sys.net.localOnly' : 'sys.net.none')}</span>
  const passed = (ok: boolean) => <Tag tone={ok ? 'ok' : 'error'}>{t(ok ? 'sys.https.ok' : 'sys.https.fail')}</Tag>

  // Not loaded with the page: the check makes outside requests and takes a while.
  const checkHTTPS = async () => {
    setChecking(true)
    setHttpsError(null)
    try {
      setHttps(await api.get<HTTPSView>('/api/system/https'))
    } catch (e) {
      setHttpsError(errorText(e, t))
    } finally {
      setChecking(false)
    }
  }

  const ips = net.data?.public_ips
  const dns = net.data?.dns
  const v = https?.verification

  return (
    <div className="stack">
      <Panel
        title={t('sys.net.title')}
        actions={
          <Button size="sm" icon="refresh" busy={net.loading} onClick={() => void net.reload()}>
            {t('sys.net.recheck')}
          </Button>
        }
      >
        {ips && dns ? (
          <div className="stack stack--tight">
            <KV
              rows={[
                { k: t('sys.net.ipv4'), v: address(ips.ipv4, ips.local_ipv4) },
                { k: t('sys.net.ipv6'), v: address(ips.ipv6, ips.local_ipv6) },
                { k: t('sys.net.dns'), v: dns.ok ? <Tag tone="ok">{t('sys.net.dnsOk', { ms: dns.millis })}</Tag> : <Tag tone="error">{t('sys.net.dnsFail', { why: dns.error ?? '' })}</Tag> },
                { k: t('sys.net.resolvers'), v: dns.servers.length > 0 ? dns.servers.join(', ') : '–' },
              ]}
            />
            {ips.checked_at ? <p className="dim small">{t('sys.net.checkedAt', { v: relative(ips.checked_at, now, t) })}</p> : null}
          </div>
        ) : net.loading ? (
          <Spinner label={t('common.loading')} />
        ) : (
          <Notice tone="error">{net.error?.message}</Notice>
        )}
      </Panel>

      <PanelHTTPSCard secure={sys.web.secure_request} />

      <Panel
        title={t('sys.https.title')}
        actions={
          <Button size="sm" variant="primary" busy={checking} onClick={() => void checkHTTPS()}>
            {t(checking ? 'sys.https.running' : 'sys.https.run')}
          </Button>
        }
      >
        <div className="stack">
          <p className="dim small">{t('sys.https.intro')}</p>
          {httpsError ? <Notice tone="error">{httpsError}</Notice> : null}
          {https && v ? (
            https.domain === '' ? (
              <Notice>{t('sys.https.none')}</Notice>
            ) : (
              <>
                <KV
                  rows={[
                    { k: t('sys.https.domain'), v: https.domain },
                    { k: t('sys.https.caddy'), v: <Tag tone={https.installed && https.running ? 'ok' : 'error'}>{t(!https.installed ? 'sys.https.notInstalled' : https.running ? 'sys.https.running2' : 'sys.https.stopped')}</Tag> },
                    {
                      k: t('sys.https.route'),
                      v: https.route_conflict ? (
                        <Tag tone="error">{t('sys.https.routeConflict')}</Tag>
                      ) : https.route_ok ? (
                        <Tag tone="ok">{t('sys.https.routeOk')}</Tag>
                      ) : (
                        <Tag tone="error">{t(https.route_found ? 'sys.https.routeBad' : 'sys.https.routeMissing')}</Tag>
                      ),
                    },
                    {
                      k: t('sys.https.dns'),
                      v: https.dns.proxied || https.dns.uncertain ? <Tag tone="warn">{t('sys.https.dnsProxied')}</Tag> : <Tag tone={https.dns.matched ? 'ok' : 'error'}>{t(https.dns.matched ? 'sys.https.dnsMatch' : 'sys.https.dnsMismatch')}</Tag>,
                    },
                    { k: t('sys.https.tls'), v: passed(v.local_tls) },
                    { k: t('sys.https.public'), v: passed(v.public_from_host) },
                    { k: t('sys.https.external'), v: passed(v.external) },
                    { k: t('sys.https.cert'), v: v.certificate_error ? <Tag tone="error">{t('sys.https.certError')}</Tag> : v.expires ? t('sys.https.certExpires', { v: dateTime(v.expires, locale) }) : '–' },
                  ]}
                />
                {https.issues.length > 0 ? (
                  <Notice tone="warn" title={t('sys.https.issues')}>
                    <ul className="bullets">
                      {https.issues.map((issue, i) => (
                        <li key={i}>{issue}</li>
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
          <p className="dim small">{t('sys.https.howTo')}</p>
        </div>
      </Panel>
    </div>
  )
}

// ---- security --------------------------------------------------------------------------

function SecurityTab({ sys, reload }: { sys: SystemView; reload: () => Promise<void> }) {
  return (
    <div className="stack">
      <SettingsPanel sys={sys} reload={reload} />
      <SessionsPanel />
      <ActivityPanel />
      <PermissionsPanel checks={sys.permissions} reload={reload} />
    </div>
  )
}

/** A whole number inside [min, max], else NaN. */
const within = (text: string, min: number, max: number): number => {
  const n = /^\d+$/.test(text.trim()) ? Number(text) : NaN
  return n >= min && n <= max ? n : NaN
}
const digits = (typed: string, max: number) => typed.replace(/\D/g, '').slice(0, max)
const splitHosts = (text: string) => text.split(/[\n,，\s]+/).filter(Boolean)

function SettingsPanel({ sys, reload }: { sys: SystemView; reload: () => Promise<void> }) {
  const { t, locale } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const web = sys.web
  const [port, setPort] = useState(String(web.port))
  const [hosts, setHosts] = useState(web.allowed_hosts.join('\n'))
  const [idle, setIdle] = useState(String(web.session_idle_min))
  const [max, setMax] = useState(String(web.session_max_hours))
  const [secure, setSecure] = useState(web.secure_cookie)
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)

  const values = { port: within(port, 1024, 65535), idle: within(idle, 5, 1440), max: within(max, 1, 720) }
  const invalid = Object.values(values).some(Number.isNaN)
  const dirty = port !== String(web.port) || idle !== String(web.session_idle_min) || max !== String(web.session_max_hours) || secure !== web.secure_cookie || splitHosts(hosts).join('\n') !== web.allowed_hosts.join('\n')
  // Turning Secure cookies on while this very page is on plain HTTP locks the browser out.
  const lockout = secure && !web.secure_cookie && !web.secure_request

  const save = async () => {
    setBusy(true)
    const r = await act(() => guard(() => api.patch<{ restart_required: boolean }>('/api/system/settings', { port: values.port, session_idle_min: values.idle, session_max_hours: values.max, secure_cookie: secure, allowed_hosts: splitHosts(hosts) })))
    setBusy(false)
    if (r === undefined) return
    await act(async () => null, { ok: t(r?.restart_required ? 'sys.sec.savedRestart' : 'sys.sec.saved') })
    setConfirming(false)
    await reload()
  }

  return (
    <Panel title={t('sys.sec.settings')}>
      <div className="stack">
        <p className="dim small">{t('sys.sec.settingsIntro')}</p>
        <div className="cols-3">
          <Field label={t('sys.sec.port')} hint={t('sys.sec.portHint')} error={Number.isNaN(values.port) ? t('sys.sec.badPort') : null}>
            {(id, note) => <Input id={id} aria-describedby={note} inputMode="numeric" value={port} onChange={(e) => setPort(portDigits(e.target.value))} />}
          </Field>
          <Field label={t('sys.sec.idle')} error={Number.isNaN(values.idle) ? t('sys.sec.badIdle') : null}>
            {(id, note) => <Input id={id} aria-describedby={note} inputMode="numeric" value={idle} onChange={(e) => setIdle(digits(e.target.value, 4))} />}
          </Field>
          <Field label={t('sys.sec.max')} error={Number.isNaN(values.max) ? t('sys.sec.badMax') : null}>
            {(id, note) => <Input id={id} aria-describedby={note} inputMode="numeric" value={max} onChange={(e) => setMax(digits(e.target.value, 3))} />}
          </Field>
        </div>
        <Field label={t('sys.sec.hosts')} hint={t('sys.sec.hostsHint')}>
          {(id, note) => <Textarea id={id} aria-describedby={note} rows={3} autoCapitalize="none" value={hosts} onChange={(e) => setHosts(e.target.value)} />}
        </Field>
        <Checkbox checked={secure} onChange={setSecure} hint={t('sys.sec.secureHint')}>
          {t('sys.sec.secure')}
        </Checkbox>
        {lockout ? <Notice tone="warn">{t('sys.sec.secureWarn')}</Notice> : null}
        <div className="row row--end">
          <Button variant="primary" disabled={!dirty || invalid} busy={busy} onClick={() => (lockout ? setConfirming(true) : void save())}>
            {t('common.save')}
          </Button>
        </div>
        <hr className="rule" />
        <KV rows={[{ k: t('sys.sec.password'), v: web.password_set ? t('sys.sec.passwordSet', { d: web.password_changed_at ? ` · ${dateTime(web.password_changed_at, locale)}` : '' }) : t('login.notConfigured') }]} />
        <p className="dim small">{t('sys.sec.passwordHow')}</p>
      </div>
      {confirming ? <Confirm danger title={t('sys.sec.secure')} message={t('sys.sec.secureWarn')} confirmLabel={t('common.save')} onCancel={() => setConfirming(false)} onConfirm={save} /> : null}
    </Panel>
  )
}

function SessionsPanel() {
  const { t, locale } = useI18n()
  const act = useAct()
  const now = useNow()
  const res = useRemote<{ sessions: SessionInfo[] }>('/api/sessions', { every: 30000 })
  const [revoking, setRevoking] = useState<SessionInfo | 'others' | null>(null)
  const sessions = res.data?.sessions ?? []

  const columns: Column<SessionInfo>[] = [
    {
      key: 'ip',
      head: t('sys.sec.ip'),
      primary: true,
      cell: (s) => (
        <span className="row">
          {s.ip}
          {s.current ? <Tag tone="accent">{t('sys.sec.current')}</Tag> : null}
        </span>
      ),
    },
    { key: 'agent', head: t('sys.sec.agent'), label: t('sys.sec.agent'), cell: (s) => <span className="small clamp" title={s.agent}>{s.agent || '–'}</span> },
    { key: 'created', head: t('sys.sec.started'), label: t('sys.sec.started'), cell: (s) => dateTime(s.created_at, locale) },
    { key: 'seen', head: t('sys.sec.seen'), label: t('sys.sec.seen'), cell: (s) => relative(s.last_seen, now, t) },
    {
      key: 'actions',
      head: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (s) =>
        s.current ? null : (
          <Button size="sm" variant="danger" onClick={() => setRevoking(s)}>
            {t('sys.sec.revoke')}
          </Button>
        ),
    },
  ]

  const revoke = async () => {
    if (!revoking) return
    if (revoking === 'others') {
      const r = await act(() => api.post<{ revoked: number }>('/api/sessions/revoke-others'))
      if (!r) return
      await act(async () => null, { ok: t('sys.sec.revokedN', { n: r.revoked }) })
    } else if ((await act(() => api.del(`/api/sessions/${revoking.id}`), { ok: t('sys.sec.revoked') })) === undefined) return
    setRevoking(null)
    await res.reload()
  }

  return (
    <Panel
      flush
      title={t('sys.sec.sessions')}
      actions={
        <Button size="sm" disabled={sessions.every((s) => s.current)} onClick={() => setRevoking('others')}>
          {t('sys.sec.revokeOthers')}
        </Button>
      }
    >
      <p className="dim small pad">{t('sys.sec.sessionsIntro')}</p>
      <DataTable caption={t('sys.sec.sessionsCaption')} rows={sessions} rowKey={(s) => s.id} columns={columns} empty={<Empty icon="shield" title={t('common.none')} />} />
      {revoking ? (
        <Confirm
          danger
          title={t(revoking === 'others' ? 'sys.sec.revokeOthersTitle' : 'sys.sec.revokeTitle')}
          message={t('sys.sec.revokeMsg')}
          confirmLabel={t(revoking === 'others' ? 'sys.sec.revokeOthers' : 'sys.sec.revoke')}
          onCancel={() => setRevoking(null)}
          onConfirm={revoke}
        />
      ) : null}
    </Panel>
  )
}

/** The audit log, newest first, printed like a log file. */
function ActivityPanel() {
  const { t, locale } = useI18n()
  const res = useRemote<{ entries: ActivityEntry[] }>('/api/activity', { every: 30000 })
  const entries = [...(res.data?.entries ?? [])].reverse()
  return (
    <Panel title={t('sys.sec.activity')}>
      <div className="stack stack--tight">
        {entries.length === 0 ? (
          <p className="dim">{t('sys.sec.activityEmpty')}</p>
        ) : (
          <ul className="audit">
            {entries.map((e, i) => (
              <li key={`${e.at}-${i}`}>
                <time className="dim" dateTime={e.at}>
                  {dateTime(e.at, locale)}
                </time>
                <span className="audit__ip">{e.ip}</span>
                <span>{e.action}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="dim small">{t('sys.sec.activityNote')}</p>
      </div>
    </Panel>
  )
}

function PermissionsPanel({ checks, reload }: { checks: PermissionCheck[]; reload: () => Promise<void> }) {
  const { t } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const [confirming, setConfirming] = useState(false)
  const wrong = checks.filter((c) => !c.ok)

  const columns: Column<PermissionCheck>[] = [
    { key: 'path', head: t('sys.perm.path'), primary: true, cell: (c) => c.path },
    { key: 'mode', head: t('sys.perm.mode'), label: t('sys.perm.mode'), cell: (c) => c.mode },
    { key: 'expected', head: t('sys.perm.expected'), label: t('sys.perm.expected'), cell: (c) => c.expected },
    { key: 'ok', head: t('common.status'), label: t('common.status'), cell: (c) => <Tag tone={c.ok ? 'ok' : 'error'}>{t(c.ok ? 'sys.https.ok' : 'sys.https.fail')}</Tag> },
  ]

  return (
    <Panel
      flush
      title={t('sys.perm.title')}
      actions={
        wrong.length > 0 ? (
          <Button size="sm" variant="primary" onClick={() => setConfirming(true)}>
            {t('sys.perm.fix')}
          </Button>
        ) : undefined
      }
    >
      <div className="stack stack--tight pad">
        <p className="dim small">{t('sys.perm.intro')}</p>
        {wrong.length === 0 ? <Notice tone="ok">{t('sys.perm.ok')}</Notice> : <Notice tone="warn">{t('sys.perm.bad', { n: wrong.length })}</Notice>}
      </div>
      <DataTable caption={t('sys.perm.caption')} rows={checks} rowKey={(c) => c.path} columns={columns} />
      {confirming ? (
        <Confirm
          title={t('sys.perm.fixTitle')}
          message={t('sys.perm.fixMsg')}
          impact={wrong.map((c) => `${c.path}: ${c.mode} → ${c.expected}`)}
          confirmLabel={t('sys.perm.fix')}
          onCancel={() => setConfirming(false)}
          onConfirm={async () => {
            const r = await act(() => guard(() => api.post<{ fixed: number }>('/api/system/permissions/fix')))
            if (r === undefined) return
            await act(async () => null, { ok: t('sys.perm.fixed', { n: r?.fixed ?? 0 }) })
            setConfirming(false)
            await reload()
          }}
        />
      ) : null}
    </Panel>
  )
}

// ---- backup and restore ----------------------------------------------------------------

function BackupTab() {
  return (
    <div className="stack">
      <BackupPanel />
      <RestorePanel />
    </div>
  )
}

function BackupPanel() {
  const { t } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const [busy, setBusy] = useState(false)
  const download = async () => {
    setBusy(true)
    const file = await act(() => guard(() => api.file('/api/system/backup')), { ok: t('sys.bk.downloaded') })
    setBusy(false)
    if (file) saveAs(file.blob, file.filename)
  }
  return (
    <Panel title={t('sys.bk.title')}>
      <div className="stack">
        <p>{t('sys.bk.intro')}</p>
        <Notice tone="warn">{t('sys.bk.warn')}</Notice>
        <div>
          <Button variant="primary" icon="download" busy={busy} onClick={() => void download()}>
            {t('sys.bk.download')}
          </Button>
        </div>
      </div>
    </Panel>
  )
}

const MAX_BACKUP = 24 * 1024 * 1024 // the server refuses anything larger
const KNOWN_WARNINGS = new Set(['plain_state_backup', 'sources_kept', 'aggregate_without_sources', 'snapshots_omitted'])
const PLAN_ROWS: { key: 'nodes' | 'relays' | 'exits' | 'subs' | 'sources'; pick: (p: RestorePlan) => DiffSet }[] = [
  { key: 'nodes', pick: (p) => p.nodes },
  { key: 'relays', pick: (p) => p.relays },
  { key: 'exits', pick: (p) => p.exits },
  { key: 'subs', pick: (p) => p.subscriptions },
  { key: 'sources', pick: (p) => p.sources },
]

interface RestoreAnswer {
  plan: RestorePlan
  applied: boolean
  permissions_fixed?: number
}

/** Restore in three steps: choose a file, read the dry-run comparison, type RESTORE. */
function RestorePanel() {
  const { t, locale } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const input = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<{ name: string; size: number; data: unknown } | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [plan, setPlan] = useState<RestorePlan | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)

  const reset = () => {
    setFile(null)
    setPlan(null)
    setFileError(null)
    if (input.current) input.current.value = ''
  }

  const choose = async (picked: File | undefined) => {
    setFile(null)
    setPlan(null)
    setFileError(null)
    if (!picked) return
    if (picked.size > MAX_BACKUP) return setFileError(t('sys.rs.tooBig', { max: bytes(MAX_BACKUP, 0) }))
    try {
      const data: unknown = JSON.parse(await picked.text())
      if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new Error('not an object')
      setFile({ name: picked.name, size: picked.size, data })
    } catch {
      setFileError(t('sys.rs.notJson'))
    }
  }

  const preview = async () => {
    if (!file) return
    setBusy(true)
    const r = await act(() => guard(() => api.post<RestoreAnswer>('/api/system/restore', { backup: file.data, dry_run: true })))
    setBusy(false)
    if (r) setPlan(r.plan)
  }

  const apply = async () => {
    if (!file) return
    const r = await act(() => guard(() => api.post<RestoreAnswer>('/api/system/restore', { backup: file.data, dry_run: false, confirm: 'RESTORE' })))
    if (r === undefined) return
    await act(async () => null, { ok: r?.permissions_fixed ? t('sys.rs.doneFixed', { n: r.permissions_fixed }) : t('sys.rs.done') })
    setConfirming(false)
    reset()
  }

  const created = toDate(plan?.created_at)
  const names = (list: string[]) => (list.length > 0 ? list.join(', ') : t('sys.rs.noChange'))

  return (
    <Panel title={t('sys.rs.title')}>
      <div className="stack">
        <p>{t('sys.rs.intro')}</p>
        <div className="row">
          <input ref={input} type="file" accept="application/json,.json" className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(e) => void choose(e.target.files?.[0])} />
          <Button icon="upload" onClick={() => input.current?.click()}>
            {t(file ? 'sys.rs.reset' : 'sys.rs.choose')}
          </Button>
          {file ? (
            <span className="small">
              <strong>{file.name}</strong> <span className="dim">({bytes(file.size)})</span>
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
          <>
            <div className="row">
              <strong>{t('sys.rs.plan')}</strong>
              <Tag>{t(plan.full ? 'sys.rs.kindFull' : 'sys.rs.kindPartial')}</Tag>
              {created ? <span className="dim small">{t('sys.rs.meta', { d: created.toLocaleString(locale), v: plan.rout_version ?? '?' })}</span> : null}
            </div>
            {plan.warnings.length > 0 ? (
              <Notice tone="warn" title={t('sys.rs.warnings')}>
                <ul className="bullets">
                  {plan.warnings.map((w) => (
                    <li key={w}>{KNOWN_WARNINGS.has(w) ? t(`sys.rs.warn.${w}` as MessageKey) : w}</li>
                  ))}
                </ul>
              </Notice>
            ) : null}
            <div className="grid-wrap">
              <table className="grid grid--keep">
                <thead>
                  <tr>
                    <th scope="col">{t('sys.rs.col.kind')}</th>
                    <th scope="col">{t('sys.rs.col.now')}</th>
                    <th scope="col">{t('sys.rs.col.backup')}</th>
                    <th scope="col">{t('sys.rs.col.removed')}</th>
                    <th scope="col">{t('sys.rs.col.added')}</th>
                  </tr>
                </thead>
                <tbody>
                  {PLAN_ROWS.map(({ key, pick }) => {
                    const diff = pick(plan)
                    return (
                      <tr key={key}>
                        <th scope="row">{t(`sys.rs.${key}`)}</th>
                        <td>{diff.now}</td>
                        <td>{diff.backup}</td>
                        <td className={diff.removed.length > 0 ? 'err' : 'dim'}>{names(diff.removed)}</td>
                        <td className={diff.added.length > 0 ? 'ok' : 'dim'}>{names(diff.added)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <div className="row row--end">
              <Button variant="ghost" onClick={reset}>
                {t('common.cancel')}
              </Button>
              <Button variant="danger" onClick={() => setConfirming(true)}>
                {t('sys.rs.apply')}
              </Button>
            </div>
          </>
        ) : null}
      </div>

      {confirming ? (
        <Confirm
          danger
          requireText="RESTORE"
          title={t('sys.rs.applyTitle')}
          message={t('sys.rs.applyMsg')}
          impact={[t('sys.rs.impact1'), t('sys.rs.impact2'), t('sys.rs.impact3'), t('sys.rs.impact4')]}
          confirmLabel={t('sys.rs.apply')}
          onCancel={() => setConfirming(false)}
          onConfirm={apply}
        />
      ) : null}
    </Panel>
  )
}

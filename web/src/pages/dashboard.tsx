import { useEffect, useState, type ReactNode } from 'react'
import { api } from '../core/api'
import { bytes, date, percent, rate, uptime } from '../core/format'
import { useRemote } from '../core/hooks'
import { useI18n, type TFn } from '../core/i18n'
import { Link } from '../core/router'
import type { AIView, Alert, CountSet, Overview, PanelHTTPSReport } from '../core/types'
import { Plot } from '../ui/chart'
import { LoadState } from '../ui/domain'
import { Button, Meter, Notice, PageHead, Panel, Stat, Tag, type Tone } from '../ui/kit'
import { loadPanelReport, panelHealth } from './panel-https'

const alertLinks: Record<string, string> = { nodes: '/nodes', relays: '/relays', subscriptions: '/subscriptions', sources: '/sources', system: '/system' }
const alertMark: Record<Alert['level'], { mark: string; tone: Tone }> = { error: { mark: '✗', tone: 'error' }, warn: { mark: '!', tone: 'warn' }, info: { mark: 'i', tone: 'neutral' } }

function countsLine(t: TFn, c: CountSet): string | undefined {
  if (c.total === 0) return undefined
  const parts = [t('dash.runningOf', { r: c.running, n: c.total })]
  if (c.stopped > 0) parts.push(t('dash.stoppedN', { n: c.stopped }))
  if (c.disabled > 0) parts.push(t('dash.disabledN', { n: c.disabled }))
  return parts.join(' · ')
}

export function Dashboard() {
  const { t, tc, locale } = useI18n()
  const res = useRemote<Overview>('/api/overview', { every: 5000 })
  const o = res.data
  if (!o) return <LoadState res={res} />

  const sys = o.system
  const history = sys.history ?? []
  const c = o.counts
  const alerts = o.alerts.filter((a) => a.code !== 'update_available') // has its own banner
  const sub = o.subscription_server
  const subTone: Tone = !sub.enabled || !sub.managed ? 'neutral' : sub.running ? 'ok' : 'error'
  const subText = !sub.enabled ? t('dash.serverOff') : !sub.managed ? t('dash.serverUnmanaged') : t(sub.running ? 'state.running' : 'state.stopped')

  return (
    <div className="page">
      <PageHead
        title={t('dash.title')}
        sub={t('dash.subtitle', { host: sys.hostname ?? 'rout', up: uptime(sys.uptime_sec, t) })}
        actions={
          <Button icon="refresh" size="sm" onClick={() => void res.reload()}>
            {t('common.refresh')}
          </Button>
        }
      />

      {o.update.available ? (
        <Notice tone="accent" title={t('dash.update', { v: o.update.latest ?? '' })}>
          {t('dash.updateHint')}
        </Notice>
      ) : null}

      <Panel title={t('dash.alerts')} meta={alerts.length > 0 ? String(alerts.length) : undefined} tone={alerts.some((a) => a.level === 'error') ? 'error' : alerts.length > 0 ? 'warn' : undefined}>
        {alerts.length === 0 ? (
          <p className="row">
            <Tag tone="ok">OK</Tag>
            <span className="dim">{t('dash.noAlerts')}</span>
          </p>
        ) : (
          <ul className="alerts">
            {alerts.map((a, i) => (
              <li key={`${a.code}-${a.subject ?? ''}-${i}`} className={`alerts__item alerts__item--${alertMark[a.level].tone}`}>
                <span className="alerts__mark" aria-hidden="true">
                  [{alertMark[a.level].mark}]
                </span>
                <div className="grow">
                  <strong>{tc(`alert.${a.code}`, a.code)}</strong>
                  {a.subject ? <span> {a.subject}</span> : null}
                  {a.detail ? <div className="dim small">{a.detail}</div> : null}
                </div>
                {a.link && alertLinks[a.link] ? <Link to={alertLinks[a.link]}>{t('common.details')} →</Link> : null}
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <div className="stats">
        <Stat label={t('dash.nodes')} value={c.nodes.total} sub={countsLine(t, c.nodes)} tone={c.nodes.stopped > 0 ? 'warn' : undefined} />
        <Stat label={t('dash.relays')} value={c.relays.total} sub={countsLine(t, c.relays)} tone={c.relays.stopped > 0 ? 'warn' : undefined} />
        <Stat label={t('dash.exits')} value={c.exits} />
        <Stat label={t('dash.subs')} value={c.subscriptions} sub={c.aggregates > 0 ? t('dash.aggregatesN', { n: c.aggregates }) : undefined} />
        <Stat
          label={t('dash.sources')}
          value={c.sources}
          sub={c.sources > 0 ? `${t('dash.sourcesOk', { ok: c.sources_ok, bad: c.sources_failed })} · ${t('dash.remoteNodes', { n: c.remote_nodes })}` : undefined}
          tone={c.sources_failed > 0 ? 'warn' : undefined}
        />
        <Stat
          label={t('dash.subServer')}
          value={
            <Tag tone={subTone} led>
              {subText}
            </Tag>
          }
        />
      </div>

      <div className="cols-2">
        <AITile />
        <WebTile />
      </div>

      <div className="cols-2">
        <Panel title={t('dash.resources')}>
          <div className="stack">
            <div className="gauges">
              <Gauge label={t('dash.cpu')} value={sys.cpu_percent} note={`${t('dash.cores', { n: sys.cores })} · ${t('dash.load', { v: sys.load1.toFixed(2) })}`} />
              <Gauge
                label={t('dash.memory')}
                value={percent(sys.mem_used, sys.mem_total)}
                note={`${bytes(sys.mem_used)} / ${bytes(sys.mem_total)}${sys.swap_total > 0 ? ` · ${t('dash.swap', { u: bytes(sys.swap_used), t: bytes(sys.swap_total) })}` : ''}`}
              />
              <Gauge label={t('dash.disk')} value={percent(sys.disk_used, sys.disk_total)} note={`${bytes(sys.disk_used)} / ${bytes(sys.disk_total)}`} />
            </div>
            <div className="cols-2">
              <figure className="figure">
                <figcaption>{t('dash.chartCpu')}</figcaption>
                <Plot label={t('dash.chartCpu')} max={100} series={[{ label: 'cpu', tone: 'a', values: history.map((p) => p.cpu) }]} />
              </figure>
              <figure className="figure">
                <figcaption>{t('dash.chartNet')}</figcaption>
                <Plot
                  label={t('dash.chartNet')}
                  series={[
                    { label: 'down', tone: 'a', values: history.map((p) => p.net_rx_rate) },
                    { label: 'up', tone: 'b', values: history.map((p) => p.net_tx_rate) },
                  ]}
                />
                <div className="legend">
                  <span className="legend__a">
                    ↓ {t('dash.down')} {rate(sys.net_rx_rate)}
                  </span>
                  <span className="legend__b">
                    ↑ {t('dash.up')} {rate(sys.net_tx_rate)}
                  </span>
                </div>
              </figure>
            </div>
          </div>
        </Panel>

        <div className="stack">
          <Panel title={t('dash.network')}>
            <div className="stack stack--tight">
              <Family name="IPv4" ip={o.network.ipv4} local={o.network.local_ipv4} checking={o.network.checking} />
              <Family name="IPv6" ip={o.network.ipv6} local={o.network.local_ipv6} checking={o.network.checking} />
            </div>
          </Panel>
          <Panel title={t('dash.certs')}>
            {o.certs.length === 0 ? (
              <p className="dim">{t('dash.certsNone')}</p>
            ) : (
              <ul className="stack stack--tight">
                {o.certs.map((cert) => (
                  <li key={cert.id} className="between">
                    <span>{cert.name}</span>
                    <span className="row">
                      {cert.self_signed ? <Tag>{t('dash.selfSigned')}</Tag> : null}
                      <Tag tone={cert.days < 0 ? 'error' : cert.days <= 14 ? 'warn' : 'ok'}>{cert.days < 0 ? t('dash.certExpired', { n: -cert.days }) : t('dash.certDays', { n: cert.days })}</Tag>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>

      <div className="cols-2">
        <Panel title={t('dash.traffic')}>
          <div className="stack">
            <Line label={t('dash.trafficLive')} value={`↓ ${rate(sys.net_rx_rate)} · ↑ ${rate(sys.net_tx_rate)}`} note={t('dash.since', { d: `↓ ${bytes(sys.net_rx_total)} · ↑ ${bytes(sys.net_tx_total)}` })} />
            {o.traffic.monitoring ? (
              <>
                <Line label={t('dash.trafficTotal')} value={bytes(o.traffic.total)} note={`↓ ${bytes(o.traffic.down)} · ↑ ${bytes(o.traffic.up)}`} />
                {o.traffic.top.length > 0 ? (
                  <figure className="figure">
                    <figcaption>{t('dash.topNodes')}</figcaption>
                    <ul className="ranks">
                      {o.traffic.top.map((n) => (
                        <li key={n.id}>
                          <span className="ranks__name">{n.name}</span>
                          <Meter value={percent(n.total, o.traffic.top[0]?.total || 1)} tone="accent" label={n.name} showValue={false} width={16} />
                          <span className="ranks__value">{bytes(n.total)}</span>
                        </li>
                      ))}
                    </ul>
                  </figure>
                ) : null}
              </>
            ) : (
              <Notice title={t('dash.trafficOff')}>{t('dash.trafficOffHint')}</Notice>
            )}
          </div>
        </Panel>

        <Panel title={t('dash.quotas')}>
          {o.quotas.length === 0 ? (
            <p className="dim">{t('dash.quotasNone')}</p>
          ) : (
            <ul className="stack">
              {o.quotas.map((q) => (
                <li key={`${q.kind}-${q.id}`} className="stack stack--tight">
                  <div className="between">
                    <span className="row">
                      <Tag>{t(q.kind === 'node' ? 'dash.quotaNode' : 'dash.quotaSub')}</Tag>
                      {q.name}
                    </span>
                    <span>
                      {bytes(q.used)} / {bytes(q.limit)}
                    </span>
                  </div>
                  <div className="between">
                    <Meter value={percent(q.used, q.limit)} label={q.name} width={24} />
                    {q.next_reset ? <span className="dim small">{t('common.resets', { d: date(q.next_reset, locale) })}</span> : null}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  )
}

function Gauge({ label, value, note }: { label: string; value: number; note: string }) {
  return (
    <div className="gauge">
      <span className="gauge__label">{label}</span>
      <Meter value={value} label={label} width={20} />
      <span className="dim small gauge__note">{note}</span>
    </div>
  )
}

function Line({ label, value, note }: { label: string; value: ReactNode; note?: string }) {
  return (
    <div className="line">
      <div className="dim small">{label}</div>
      <div className="line__value">{value}</div>
      {note ? <div className="dim small">{note}</div> : null}
    </div>
  )
}

function Family({ name, ip, local, checking }: { name: string; ip: string; local: boolean; checking: boolean }) {
  const { t } = useI18n()
  const tone: Tone = ip ? 'ok' : local ? 'warn' : 'neutral'
  const text = ip ? t('dash.netUsable') : checking ? t('dash.netChecking') : local ? t('dash.netLocalOnly') : t('dash.netNone')
  return (
    <div className="between">
      <span>
        <strong>{name}</strong> <span className={ip ? '' : 'dim'}>{ip || '–'}</span>
      </span>
      <Tag tone={tone} led>
        {text}
      </Tag>
    </div>
  )
}

/** Runs `load` once, shortly after the first paint, so slow extras never delay the dashboard. */
function useLate<T>(load: () => Promise<T>): { data: T | null; failed: boolean } {
  const [state, setState] = useState<{ data: T | null; failed: boolean }>({ data: null, failed: false })
  useEffect(() => {
    let mounted = true
    const timer = window.setTimeout(() => {
      load().then(
        (data) => mounted && setState({ data, failed: false }),
        () => mounted && setState({ data: null, failed: true }),
      )
    }, 250)
    return () => {
      mounted = false
      window.clearTimeout(timer)
    }
    // `load` is a fresh closure each render; it must run once only.
  }, [])
  return state
}

function Tile({ to, label, value, note }: { to: string; label: string; value: ReactNode; note?: ReactNode }) {
  return (
    <Link to={to} className="tile">
      <span className="tile__label">{label}</span>
      <span className="tile__value">{value}</span>
      <span className="tile__note">{note}</span>
      <span className="tile__go" aria-hidden="true">
        →
      </span>
    </Link>
  )
}

function AITile() {
  const { t } = useI18n()
  const { data, failed } = useLate(() => api.get<AIView>('/api/ai'))
  const bound = data?.nodes.filter((n) => n.bound).length ?? 0
  const tone: Tone = !data ? 'neutral' : data.problems.length > 0 ? 'warn' : data.enabled ? 'ok' : 'neutral'
  const note = data ? `${data.exit ? t('dash.aiExit', { name: data.exit.name }) : t('ai.noExit')}${data.problems.length > 0 ? ` · ${t('dash.aiProblems', { n: data.problems.length })}` : ''}` : ''
  return (
    <Tile
      to="/ai"
      label={t('dash.ai')}
      note={note}
      value={
        data ? (
          <Tag tone={tone} led>
            {data.enabled ? t('dash.aiOn', { n: bound }) : t('dash.aiOff')}
          </Tag>
        ) : failed ? (
          <Tag>{t('dash.webFailed')}</Tag>
        ) : (
          <span className="dim small">{t('common.loading')}</span>
        )
      }
    />
  )
}

function WebTile() {
  const { t } = useI18n()
  const { data, failed } = useLate<PanelHTTPSReport>(() => loadPanelReport())
  const health = data ? panelHealth(data) : null
  return (
    <Tile
      to="/system?tab=network"
      label={t('dash.web')}
      note={data?.url ?? data?.domain ?? ''}
      value={
        health ? (
          <Tag tone={health.tone} led>
            {t(health.key)}
          </Tag>
        ) : failed ? (
          <Tag>{t('dash.webFailed')}</Tag>
        ) : (
          <span className="dim small">{t('dash.webChecking')}</span>
        )
      }
    />
  )
}

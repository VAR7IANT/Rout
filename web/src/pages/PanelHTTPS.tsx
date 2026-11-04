import { useCallback, useEffect, useRef, useState } from 'react'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { formatDateTime } from '../lib/format'
import { Cancelled, errorText, useReauth } from '../lib/session'
import { useToast } from '../lib/toast'
import type { CheckLevel, PanelHTTPSReport, PanelRepairResult } from '../lib/types'
import { CopyButton } from '../components/copy'
import { Icon, type IconName } from '../components/icons'
import { Badge, Button, Card, KV, Notice, Spinner, type Tone } from '../components/ui'

// The panel's own HTTPS (Caddy in front of rout-web). The diagnosis can take several seconds,
// so the last answer is kept for a few minutes and shared by the dashboard tile and this card.

const CACHE_MS = 5 * 60 * 1000
let cached: { at: number; report: PanelHTTPSReport } | null = null
let inflight: Promise<PanelHTTPSReport> | null = null

/** Loads the panel HTTPS report, reusing a recent answer unless `fresh` is set. */
export function loadPanelReport(fresh = false): Promise<PanelHTTPSReport> {
  if (!fresh && cached && Date.now() - cached.at < CACHE_MS) return Promise.resolve(cached.report)
  if (inflight && !fresh) return inflight
  const p = api.get<PanelHTTPSReport>('/api/system/panel').then(
    (report) => {
      cached = { at: Date.now(), report }
      if (inflight === p) inflight = null
      return report
    },
    (e: unknown) => {
      if (inflight === p) inflight = null
      throw e
    },
  )
  inflight = p
  return p
}

/** For tests: forgets the cached report. */
export function resetPanelCache() {
  cached = null
  inflight = null
}

/** A one-word summary of the report: ok, pending, problem or not configured. */
export function panelHealth(r: PanelHTTPSReport): { tone: Tone; key: 'panel.health.ok' | 'panel.health.pending' | 'panel.health.fail' | 'panel.health.none' } {
  if (!r.domain) return { tone: 'neutral', key: 'panel.health.none' }
  if (r.checks.some((c) => c.level === 'fail') || r.verification.certificate_error) return { tone: 'error', key: 'panel.health.fail' }
  if (r.pending || !r.verification.public_https || !r.verification.login_page) return { tone: 'warn', key: 'panel.health.pending' }
  return { tone: 'ok', key: 'panel.health.ok' }
}

const levelIcon: Record<CheckLevel, IconName> = { ok: 'check', warn: 'warn', fail: 'close', info: 'pulse' }
const ownershipTone: Record<string, Tone> = { managed: 'ok', external: 'neutral', modified: 'warn', none: 'neutral' }

export function PanelHTTPSCard({ secure }: { secure?: boolean }) {
  const { t, locale } = useI18n()
  const toast = useToast()
  const { guard } = useReauth()
  const [report, setReport] = useState<PanelHTTPSReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [repairing, setRepairing] = useState(false)
  const [repair, setRepair] = useState<PanelRepairResult | null>(null)
  const alive = useRef(true)

  const load = useCallback(
    async (fresh: boolean) => {
      setLoading(true)
      setError(null)
      try {
        const r = await loadPanelReport(fresh)
        if (alive.current) setReport(r)
      } catch (e) {
        if (alive.current) setError(errorText(e, t))
      } finally {
        if (alive.current) setLoading(false)
      }
    },
    [t],
  )
  useEffect(() => {
    alive.current = true
    void load(false)
    return () => {
      alive.current = false
    }
  }, [load])

  const runRepair = async () => {
    setRepairing(true)
    setRepair(null)
    try {
      const r = await guard(() => api.post<PanelRepairResult>('/api/system/panel/repair'))
      if (!alive.current) return
      setRepair(r)
      toast.push(r.ok ? 'ok' : 'info', r.ok ? t('panel.repair.ok') : t('panel.repair.pending'))
      await load(true)
    } catch (e) {
      if (!(e instanceof Cancelled)) toast.push('error', errorText(e, t))
    } finally {
      if (alive.current) setRepairing(false)
    }
  }

  const v = report?.verification
  const health = report ? panelHealth(report) : null
  const net = report?.network
  const yn = (ok: boolean | undefined) => <Badge tone={ok ? 'ok' : 'error'}>{ok ? t('sys.https.ok') : t('sys.https.fail')}</Badge>

  return (
    <Card
      title={t('panel.title')}
      subtitle={t('panel.subtitle')}
      actions={
        <div className="row-wrap">
          <Button size="sm" icon="refresh" busy={loading} disabled={repairing} onClick={() => void load(true)}>
            {t('panel.recheck')}
          </Button>
          <Button size="sm" variant="primary" icon="shield" busy={repairing} disabled={loading || !report?.domain} onClick={() => void runRepair()}>
            {t('panel.repair')}
          </Button>
        </div>
      }
    >
      <div className="stack">
        {secure !== undefined ? secure ? <Notice tone="ok">{t('sys.https.panelSecure')}</Notice> : <Notice tone="warn">{t('sys.https.panelPlain')}</Notice> : null}
        {loading && !report ? <Spinner label={t('panel.checking')} /> : null}
        {error ? <Notice tone="error" title={t('panel.loadFailed')}>{error}</Notice> : null}
        {repair ? (
          <Notice tone={repair.ok ? 'ok' : repair.pending ? 'warn' : 'error'} title={repair.ok ? t('panel.repair.ok') : t('panel.repair.pending')}>
            {repair.diagnosis || null}
          </Notice>
        ) : null}
        {report && v && net && health ? (
          <>
            <div className="panel-head">
              <Badge tone={health.tone}>{t(health.key)}</Badge>
              {report.domain ? <Badge tone={ownershipTone[report.ownership] ?? 'neutral'}>{t(`panel.own.${['none', 'managed', 'external', 'modified'].includes(report.ownership) ? report.ownership : 'none'}` as 'panel.own.none')}</Badge> : null}
              {report.pending ? <Badge tone="warn">{t('panel.pending')}</Badge> : null}
            </div>
            <KV
              items={[
                {
                  k: t('panel.domain'),
                  v: report.domain ? (
                    <span className="wrap-any">
                      {report.url ? (
                        <a href={report.url} target="_blank" rel="noreferrer noopener" className="mono">
                          {report.url}
                        </a>
                      ) : (
                        <span className="mono">{report.domain}</span>
                      )}
                    </span>
                  ) : (
                    <span className="muted">{t('panel.noDomain')}</span>
                  ),
                },
                { k: 'IPv4', v: net.ipv4 ? <span className="mono">{net.ipv4}{net.ipv4_nat ? <> <Badge tone="warn">NAT</Badge></> : null}</span> : <span className="muted">{t('sys.net.none')}</span> },
                { k: 'IPv6', v: net.ipv6 ? <span className="mono">{net.ipv6}{net.ipv6_nat ? <> <Badge tone="warn">NAT</Badge></> : null}</span> : <span className="muted">{t('sys.net.none')}</span> },
                ...(net.ipv6_only ? [{ k: t('panel.netKind'), v: <Badge>{t('panel.ipv6Only')}</Badge> }] : []),
                ...(report.domain
                  ? [
                      { k: t('panel.v.local'), v: yn(v.local_service) },
                      { k: t('panel.v.host'), v: yn(v.host_allowed) },
                      { k: t('panel.v.tls'), v: yn(v.local_tls) },
                      { k: t('panel.v.public'), v: yn(v.public_https) },
                      { k: t('panel.v.login'), v: yn(v.login_page) },
                      {
                        k: t('panel.cert'),
                        v: v.certificate_error ? (
                          <Badge tone="error">{t('sys.https.certError')}</Badge>
                        ) : v.expires && formatDateTime(v.expires, locale) !== '–' ? (
                          <span>
                            {t('sys.https.certExpires', { v: formatDateTime(v.expires, locale) })}
                            {v.issuer ? <span className="muted small"> · {v.issuer}</span> : null}
                          </span>
                        ) : (
                          '–'
                        ),
                      },
                    ]
                  : []),
              ]}
            />
            {report.last_error ? <Notice tone="error" title={t('panel.lastError')}>{report.last_error}</Notice> : null}
            {report.records && report.records.length > 0 ? (
              <section className="stack-tight">
                <h3 className="section-title">{t('panel.records')}</h3>
                <p className="hint">{t('panel.recordsHint')}</p>
                <ul className="records">
                  {report.records.map((r) => (
                    <li key={r}>
                      <code className="mono">{r}</code>
                      <CopyButton text={r} compact />
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
            {report.checks.length > 0 ? (
              <section className="stack-tight">
                <h3 className="section-title">{t('panel.checks')}</h3>
                <ul className="checks">
                  {report.checks.map((c, i) => (
                    <li key={`${c.key}-${i}`} className={`diag-${c.level}`}>
                      <Icon name={levelIcon[c.level] ?? 'pulse'} size={15} />
                      <span className="sr-only">{t(`panel.level.${c.level}` as 'panel.level.ok')}</span>
                      <span>{c.text}</span>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
          </>
        ) : null}
        <p className="muted small">{t('panel.terminal')}</p>
      </div>
    </Card>
  )
}

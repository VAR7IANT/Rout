// The panel's own HTTPS entrance (Caddy in front of rout-web): diagnosis and repair.
import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../core/api'
import { DASH, dateTime } from '../core/format'
import { useI18n, type MessageKey } from '../core/i18n'
import { Cancelled, errorText, useReauth } from '../core/session'
import { useToast } from '../core/toast'
import type { CheckLevel, PanelHTTPSReport, PanelRepairResult } from '../core/types'
import { CopyButton } from '../ui/copy'
import { Section } from '../ui/domain'
import { Button, KV, Notice, Panel, Spinner, Tag, type Tone } from '../ui/kit'

// The diagnosis can take tens of seconds, so one answer is kept for a few minutes and shared
// by the dashboard tile and the System page.
const KEEP_MS = 5 * 60 * 1000
let kept: { at: number; report: PanelHTTPSReport } | null = null
let flying: Promise<PanelHTTPSReport> | null = null

export function loadPanelReport(fresh = false): Promise<PanelHTTPSReport> {
  if (!fresh && kept && Date.now() - kept.at < KEEP_MS) return Promise.resolve(kept.report)
  if (!fresh && flying) return flying
  const request: Promise<PanelHTTPSReport> = api
    .get<PanelHTTPSReport>('/api/system/panel')
    .then((report) => {
      kept = { at: Date.now(), report }
      return report
    })
    .finally(() => {
      if (flying === request) flying = null
    })
  flying = request
  return request
}

/** For tests: forget the kept report. */
export function forgetPanelReport() {
  kept = null
  flying = null
}

type HealthKey = 'panel.health.ok' | 'panel.health.pending' | 'panel.health.fail' | 'panel.health.none'

/** The report in one word: not set up, broken, not ready yet, or working. */
export function panelHealth(r: PanelHTTPSReport): { tone: Tone; key: HealthKey } {
  if (!r.domain) return { tone: 'neutral', key: 'panel.health.none' }
  if (r.verification.certificate_error || r.checks.some((c) => c.level === 'fail')) return { tone: 'error', key: 'panel.health.fail' }
  if (r.pending || !r.verification.public_https || !r.verification.login_page) return { tone: 'warn', key: 'panel.health.pending' }
  return { tone: 'ok', key: 'panel.health.ok' }
}

const ownTone: Record<string, Tone> = { managed: 'ok', modified: 'warn' }
const ownKnown = new Set(['none', 'managed', 'external', 'modified'])
const checkMark: Record<CheckLevel, string> = { ok: '✓', warn: '!', fail: '✗', info: '·' }
const checkClass: Record<CheckLevel, string> = { ok: 'ok', warn: 'warn', fail: 'fail', info: 'info' }

export function PanelHTTPSCard({ secure }: { secure?: boolean }) {
  const { t, locale } = useI18n()
  const toast = useToast()
  const { guard } = useReauth()
  const [report, setReport] = useState<PanelHTTPSReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [repairing, setRepairing] = useState(false)
  const [repair, setRepair] = useState<PanelRepairResult | null>(null)
  const mounted = useRef(true)

  const load = useCallback(
    async (fresh: boolean) => {
      setLoading(true)
      setError(null)
      try {
        const r = await loadPanelReport(fresh)
        if (mounted.current) setReport(r)
      } catch (e) {
        if (mounted.current) setError(errorText(e, t))
      } finally {
        if (mounted.current) setLoading(false)
      }
    },
    [t],
  )
  useEffect(() => {
    mounted.current = true
    void load(false)
    return () => {
      mounted.current = false
    }
  }, [load])

  const runRepair = async () => {
    setRepairing(true)
    setRepair(null)
    try {
      const r = await guard(() => api.post<PanelRepairResult>('/api/system/panel/repair'))
      if (!mounted.current) return
      setRepair(r)
      toast.push(r.ok ? 'ok' : 'info', t(r.ok ? 'panel.repair.ok' : 'panel.repair.pending'))
      await load(true)
    } catch (e) {
      if (!(e instanceof Cancelled)) toast.push('error', errorText(e, t))
    } finally {
      if (mounted.current) setRepairing(false)
    }
  }

  const passed = (ok: boolean) => <Tag tone={ok ? 'ok' : 'error'}>{t(ok ? 'sys.https.ok' : 'sys.https.fail')}</Tag>
  const address = (ip: string | undefined, nat: boolean) =>
    ip ? (
      <span className="row">
        {ip}
        {nat ? <Tag tone="warn">NAT</Tag> : null}
      </span>
    ) : (
      <span className="dim">{t('sys.net.none')}</span>
    )

  const v = report?.verification
  const expires = v?.expires ? dateTime(v.expires, locale) : DASH

  return (
    <Panel
      title={t('panel.title')}
      actions={
        <>
          <Button size="sm" icon="refresh" busy={loading} disabled={repairing} onClick={() => void load(true)}>
            {t('panel.recheck')}
          </Button>
          <Button size="sm" variant="primary" icon="shield" busy={repairing} disabled={loading || !report?.domain} onClick={() => void runRepair()}>
            {t('panel.repair')}
          </Button>
        </>
      }
    >
      <div className="stack">
        <p className="dim small">{t('panel.subtitle')}</p>
        {secure === undefined ? null : <Notice tone={secure ? 'ok' : 'warn'}>{t(secure ? 'sys.https.panelSecure' : 'sys.https.panelPlain')}</Notice>}
        {loading && !report ? <Spinner label={t('panel.checking')} /> : null}
        {error ? (
          <Notice tone="error" title={t('panel.loadFailed')}>
            {error}
          </Notice>
        ) : null}
        {repair ? (
          <Notice tone={repair.ok ? 'ok' : repair.pending ? 'warn' : 'error'} title={t(repair.ok ? 'panel.repair.ok' : 'panel.repair.pending')}>
            {repair.diagnosis || null}
          </Notice>
        ) : null}

        {report && v ? (
          <>
            <div className="row">
              <Tag tone={panelHealth(report).tone} led>
                {t(panelHealth(report).key)}
              </Tag>
              {report.domain ? <Tag tone={ownTone[report.ownership] ?? 'neutral'}>{t(`panel.own.${ownKnown.has(report.ownership) ? report.ownership : 'none'}` as MessageKey)}</Tag> : null}
              {report.pending ? <Tag tone="warn">{t('panel.pending')}</Tag> : null}
            </div>
            <KV
              rows={[
                {
                  k: t('panel.domain'),
                  v: !report.domain ? (
                    <span className="dim">{t('panel.noDomain')}</span>
                  ) : report.url ? (
                    <a href={report.url} target="_blank" rel="noreferrer noopener">
                      {report.url}
                    </a>
                  ) : (
                    report.domain
                  ),
                },
                { k: 'IPv4', v: address(report.network.ipv4, report.network.ipv4_nat) },
                { k: 'IPv6', v: address(report.network.ipv6, report.network.ipv6_nat) },
                report.network.ipv6_only && { k: t('panel.netKind'), v: <Tag>{t('panel.ipv6Only')}</Tag> },
                ...(report.domain
                  ? [
                      { k: t('panel.v.local'), v: passed(v.local_service) },
                      { k: t('panel.v.host'), v: passed(v.host_allowed) },
                      { k: t('panel.v.tls'), v: passed(v.local_tls) },
                      { k: t('panel.v.public'), v: passed(v.public_https) },
                      { k: t('panel.v.login'), v: passed(v.login_page) },
                      {
                        k: t('panel.cert'),
                        v: v.certificate_error ? (
                          <Tag tone="error">{t('sys.https.certError')}</Tag>
                        ) : expires === DASH ? (
                          DASH
                        ) : (
                          <span>
                            {t('sys.https.certExpires', { v: expires })}
                            {v.issuer ? <span className="dim small"> · {v.issuer}</span> : null}
                          </span>
                        ),
                      },
                    ]
                  : []),
              ]}
            />
            {report.last_error ? (
              <Notice tone="error" title={t('panel.lastError')}>
                {report.last_error}
              </Notice>
            ) : null}
            {report.records?.length ? (
              <Section title={t('panel.records')}>
                <p className="dim small">{t('panel.recordsHint')}</p>
                <ul className="stack stack--tight">
                  {report.records.map((record) => (
                    <li key={record} className="cmdline cmdline--plain">
                      <code>{record}</code>
                      <CopyButton text={record} compact />
                    </li>
                  ))}
                </ul>
              </Section>
            ) : null}
            {report.checks.length > 0 ? (
              <Section title={t('panel.checks')}>
                <ul className="checks">
                  {report.checks.map((c, i) => (
                    <li key={`${c.key}-${i}`} className={`diag__step diag__step--${checkClass[c.level] ?? 'info'}`}>
                      <span className="diag__mark" aria-hidden="true">
                        {checkMark[c.level] ?? '·'}
                      </span>
                      <span className="sr-only">{t(`panel.level.${c.level}` as MessageKey)}</span>
                      <span>{c.text}</span>
                    </li>
                  ))}
                </ul>
              </Section>
            ) : null}
          </>
        ) : null}
        <p className="dim small">{t('panel.terminal')}</p>
      </div>
    </Panel>
  )
}

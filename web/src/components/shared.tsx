import { Fragment, useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { formatBytes, formatDate, formatPercent } from '../lib/format'
import { useReauth, useRunner } from '../lib/session'
import type { DiagResult, TrafficView } from '../lib/types'
import { CopyButton } from './copy'
import { Icon } from './icons'
import { QRView } from './qr'
import { Badge, Button, Meter, Notice, type Tone } from './ui'

export function StateBadge({ state }: { state: string }) {
  const { t } = useI18n()
  const tone: Tone = state === 'running' ? 'ok' : state === 'stopped' ? 'error' : 'neutral'
  const known = ['running', 'stopped', 'disabled', 'unmanaged', 'unknown'].includes(state)
  return (
    <Badge tone={tone}>
      <span className={`dot dot-${tone}`} aria-hidden="true" />
      {known ? t(`state.${state}` as 'state.running') : state}
    </Badge>
  )
}

export function WarningBadges({ warnings }: { warnings: string[] }) {
  const { tc } = useI18n()
  return (
    <>
      {warnings
        .filter((w) => w !== 'service_down')
        .map((w) => (
          <Badge key={w} tone={w === 'cert_expired' || w === 'quota_reached' ? 'error' : 'warn'}>
            {tc(`warn.${w}`, w)}
          </Badge>
        ))}
    </>
  )
}

export function TrafficCell({ traffic }: { traffic?: TrafficView }) {
  const { t, locale } = useI18n()
  if (!traffic) return <span className="muted">–</span>
  if (!traffic.active) return <span className="muted">{traffic.limit > 0 ? `0 / ${formatBytes(traffic.limit)}` : t('common.unlimited')}</span>
  if (traffic.limit === 0)
    return (
      <span className="mono small" title={`▼ ${formatBytes(traffic.down)} · ▲ ${formatBytes(traffic.up)}`}>
        {formatBytes(traffic.total)} <span className="muted">· {t('common.unlimited')}</span>
      </span>
    )
  return (
    <div className="traffic-cell">
      <Meter percent={formatPercent(traffic.total, traffic.limit)} label={t('common.used')} tone={traffic.status === 'stopped_quota' ? 'error' : undefined} />
      <span className="mono small">
        {formatBytes(traffic.total)} / {formatBytes(traffic.limit)}
      </span>
      {traffic.next_reset ? <span className="muted small">{t('common.resets', { d: formatDate(traffic.next_reset, locale) })}</span> : null}
    </div>
  )
}

// ---- layered connection test -----------------------------------------------------------

/** Finds the IP addresses written in a piece of text (used to pick out an observed exit IP). */
export function findIPs(text: string): string[] {
  const out: string[] = []
  for (const raw of text.split(/[\s，、；;,()（）\[\]：]+/)) {
    const tok = raw.replace(/^[^0-9a-fA-F:]+|[^0-9a-fA-F:.]+$/g, '').replace(/\.$/, '')
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(tok) && tok.split('.').every((n) => Number(n) <= 255)) out.push(tok)
    else if (/^[0-9a-f:]+$/i.test(tok) && (tok.match(/:/g)?.length ?? 0) >= 2 && /[0-9a-f]/i.test(tok) && (tok.includes('::') || tok.split(':').length === 8)) out.push(tok)
  }
  return [...new Set(out)]
}

/** Renders text with the given strings emphasised. */
export function Marked({ text, marks }: { text: string; marks?: string[] }) {
  const list = (marks ?? []).filter(Boolean)
  if (list.length === 0) return <>{text}</>
  const esc = list.map((m) => m.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).sort((a, b) => b.length - a.length)
  const parts = text.split(new RegExp(`(${esc.join('|')})`, 'g'))
  return (
    <>
      {parts.map((p, i) =>
        list.includes(p) ? (
          <mark key={i} className="ip-mark mono">
            {p}
          </mark>
        ) : (
          <Fragment key={i}>{p}</Fragment>
        ),
      )}
    </>
  )
}

export function DiagResultView({ result, marks }: { result: DiagResult; marks?: string[] }) {
  const { t } = useI18n()
  const layers: number[] = []
  for (const s of result.steps) if (!layers.includes(s.layer)) layers.push(s.layer)
  return (
    <div className="diag" aria-live="polite">
      <Notice tone={result.ok ? 'ok' : 'error'} title={result.ok ? t('diag.ok') : t('diag.failed')} />
      {layers.map((layer) => {
        const steps = result.steps.filter((s) => s.layer === layer)
        return (
          <section key={layer} className="diag-layer">
            <h4>
              {layer}. {steps[0]?.layer_name}
            </h4>
            <ul>
              {steps.map((s, i) => (
                <li key={i} className={`diag-${s.level}`}>
                  <Icon name={s.level === 'ok' ? 'check' : s.level === 'fail' ? 'close' : s.level === 'warn' ? 'warn' : 'pulse'} size={15} />
                  <span>
                    <Marked text={s.text} marks={marks} />
                  </span>
                </li>
              ))}
            </ul>
          </section>
        )
      })}
    </div>
  )
}

// ---- traffic paths ---------------------------------------------------------------------

export type HopKind = 'entry' | 'relay' | 'target' | 'exit' | 'client' | 'net'

/** The route a connection takes: entry → relay → target. */
export function PathChain({ items, vertical }: { items: { label: ReactNode; kind: HopKind }[]; vertical?: boolean }) {
  return (
    <ol className={`path ${vertical ? 'path-stack' : ''}`}>
      {items.map((it, i) => (
        <Fragment key={i}>
          {i > 0 ? (
            <li className="path-arrow" aria-hidden="true">
              <Icon name="arrow" size={14} />
            </li>
          ) : null}
          <li className={`path-chip path-${it.kind}`}>{it.label}</li>
        </Fragment>
      ))}
    </ol>
  )
}

/** An exit's hop-by-hop path as the server words it (first hop: this server, last: the Internet). */
export function HopPath({ hops, vertical }: { hops: string[]; vertical?: boolean }) {
  return <PathChain vertical={vertical} items={hops.map((h, i) => ({ label: h, kind: i === 0 ? 'entry' : i === hops.length - 1 ? 'net' : i === hops.length - 2 ? 'exit' : 'relay' }))} />
}

/** Runs the layered test of a node, relay or exit and shows the result. */
export function DiagPanel({ path, canFull = true }: { path: string; canFull?: boolean }) {
  const { t } = useI18n()
  const run = useRunner()
  const [busy, setBusy] = useState<'quick' | 'full' | null>(null)
  const [result, setResult] = useState<DiagResult | null>(null)
  const start = async (full: boolean) => {
    setBusy(full ? 'full' : 'quick')
    setResult(null)
    const r = await run(() => api.post<DiagResult>(path, full ? { full: true } : canFull ? { full: false } : undefined))
    if (r) setResult(r)
    setBusy(null)
  }
  return (
    <div className="stack">
      <div className="row-wrap">
        <Button icon="test" onClick={() => void start(false)} busy={busy === 'quick'} disabled={busy !== null}>
          {t('diag.run')}
        </Button>
        {canFull ? (
          <Button icon="pulse" onClick={() => void start(true)} busy={busy === 'full'} disabled={busy !== null} title={t('diag.fullHint')}>
            {t('diag.runFull')}
          </Button>
        ) : null}
      </div>
      {busy ? <p className="muted small">{t('diag.running')}</p> : null}
      {result ? <DiagResultView result={result} /> : null}
    </div>
  )
}

// ---- values that stay hidden until the administrator re-enters the password ------------

/** A revealed secret: the text, a copy button and an on-demand QR code. */
export function SecretValue({ value, label, qr = true, qrLabel, rows = 3 }: { value: string; label: string; qr?: boolean; qrLabel?: string; rows?: number }) {
  const { t } = useI18n()
  const [showQR, setShowQR] = useState(false)
  return (
    <div className="secret-value">
      <div className="secret-head">
        <span className="muted small">{label}</span>
        <div className="row-wrap">
          <CopyButton text={value} />
          {qr ? (
            <Button size="sm" icon="qr" onClick={() => setShowQR((s) => !s)} aria-pressed={showQR}>
              {t('secret.qr')}
            </Button>
          ) : null}
        </div>
      </div>
      <textarea className="input textarea mono secret-text" readOnly value={value} rows={rows} onFocus={(e) => e.currentTarget.select()} aria-label={label} />
      {showQR ? (
        <div className="qr-box">
          <QRView text={value} label={qrLabel ?? label} />
        </div>
      ) : null}
    </div>
  )
}

/** Fetches a secret behind a recent-password check, keeps it in memory only and hides it again
 *  after a minute. `render` receives the revealed value. */
export function Reveal<T>({ load, label, children }: { load: () => Promise<T>; label: string; children: (value: T) => ReactNode }) {
  const { t } = useI18n()
  const run = useRunner()
  const { guard } = useReauth()
  const [value, setValue] = useState<{ v: T } | null>(null)
  const [busy, setBusy] = useState(false)
  const timer = useRef<number | null>(null)

  const hide = useCallback(() => {
    setValue(null)
    if (timer.current) window.clearTimeout(timer.current)
  }, [])
  useEffect(
    () => () => {
      if (timer.current) window.clearTimeout(timer.current)
    },
    [],
  )
  const reveal = async () => {
    setBusy(true)
    const v = await run(() => guard(load))
    setBusy(false)
    if (v === undefined) return
    setValue({ v })
    if (timer.current) window.clearTimeout(timer.current)
    timer.current = window.setTimeout(hide, 60000)
  }

  if (value == null) {
    return (
      <div className="secret secret-hidden">
        <span className="muted">{label}</span>
        <Button size="sm" icon="eye" onClick={() => void reveal()} busy={busy}>
          {t('secret.reveal')}
        </Button>
      </div>
    )
  }
  return (
    <div className="secret">
      {children(value.v)}
      <div className="row-between">
        <p className="hint">{t('secret.autoHide')}</p>
        <Button size="sm" variant="ghost" icon="eyeoff" onClick={hide}>
          {t('common.hide')}
        </Button>
      </div>
    </div>
  )
}

export function SecretBox({ load, label, qr = true, qrLabel }: { load: () => Promise<string>; label: string; qr?: boolean; qrLabel?: string }) {
  return <Reveal load={load} label={label}>{(v) => <SecretValue value={v} label={label} qr={qr} qrLabel={qrLabel} />}</Reveal>
}

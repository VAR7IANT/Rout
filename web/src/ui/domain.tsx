// Pieces that know about Rout's data (states, traffic, layered tests, secrets) and are used
// by more than one page.
import { Fragment, useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { api } from '../core/api'
import { bytes, date, percent } from '../core/format'
import { useI18n, type MessageKey } from '../core/i18n'
import { useAct, useReauth } from '../core/session'
import type { DiagResult, DiagStep, TrafficView } from '../core/types'
import { CopyButton } from './copy'
import type { Remote } from '../core/hooks'
import { Button, Empty, Field, Input, Meter, Notice, Segmented, Spinner, Tag, type Tone } from './kit'
import { Dialog } from './overlay'
import { QR } from './qr'

// ---- service state ---------------------------------------------------------------------

const stateTone: Record<string, Tone> = { running: 'ok', stopped: 'error' }
const knownStates = new Set(['running', 'stopped', 'disabled', 'unmanaged', 'unknown'])

export function StateTag({ state }: { state: string }) {
  const { t } = useI18n()
  return (
    <Tag tone={stateTone[state] ?? 'neutral'} led>
      {knownStates.has(state) ? t(`state.${state}` as MessageKey) : state}
    </Tag>
  )
}

const severe = new Set(['cert_expired', 'quota_reached'])

/** Warning codes of a node as tags. "service_down" is left out: the state tag already says it. */
export function WarningTags({ warnings }: { warnings: string[] }) {
  const { tc } = useI18n()
  return (
    <>
      {warnings
        .filter((w) => w !== 'service_down')
        .map((w) => (
          <Tag key={w} tone={severe.has(w) ? 'error' : 'warn'}>
            {tc(`warn.${w}`, w)}
          </Tag>
        ))}
    </>
  )
}

export function Traffic({ traffic }: { traffic?: TrafficView }) {
  const { t, locale } = useI18n()
  if (!traffic) return <span className="dim">–</span>
  if (!traffic.active) return <span className="dim">{traffic.limit > 0 ? `0 / ${bytes(traffic.limit)}` : t('common.unlimited')}</span>
  if (traffic.limit === 0)
    return (
      <span title={`↓ ${bytes(traffic.down)} · ↑ ${bytes(traffic.up)}`}>
        {bytes(traffic.total)} <span className="dim">· {t('common.unlimited')}</span>
      </span>
    )
  return (
    <span className="traffic">
      <Meter value={percent(traffic.total, traffic.limit)} label={t('common.used')} tone={traffic.status === 'stopped_quota' ? 'error' : undefined} showValue={false} width={8} />
      <span>
        {bytes(traffic.total)} / {bytes(traffic.limit)}
      </span>
      {traffic.next_reset ? <span className="dim small">{t('common.resets', { d: date(traffic.next_reset, locale) })}</span> : null}
    </span>
  )
}

// ---- layered connection test -----------------------------------------------------------

/** The IP addresses mentioned in a sentence (to highlight the observed exit address). */
export function findIPs(text: string): string[] {
  const found = new Set<string>()
  for (const word of text.split(/[\s，、；;,()（）[\]：]+/)) {
    const token = word.replace(/^[^0-9a-fA-F:]+|[^0-9a-fA-F:.]+$/g, '').replace(/\.$/, '')
    const v4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(token) && token.split('.').every((n) => Number(n) <= 255)
    const colons = token.match(/:/g)?.length ?? 0
    const v6 = /^[0-9a-f:]+$/i.test(token) && colons >= 2 && /[0-9a-f]/i.test(token) && (token.includes('::') || colons === 7)
    if (v4 || v6) found.add(token)
  }
  return [...found]
}

/** `text` with every occurrence of the given strings emphasised. */
export function Marked({ text, marks = [] }: { text: string; marks?: string[] }) {
  const wanted = marks.filter(Boolean)
  if (wanted.length === 0) return <>{text}</>
  const pattern = [...wanted]
    .sort((a, b) => b.length - a.length)
    .map((m) => m.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|')
  return (
    <>
      {text.split(new RegExp(`(${pattern})`, 'g')).map((part, i) => (wanted.includes(part) ? <mark key={i}>{part}</mark> : <Fragment key={i}>{part}</Fragment>))}
    </>
  )
}

const stepMark: Record<DiagStep['level'], string> = { ok: '✓', fail: '✗', warn: '!', info: '·' }

/** A test report printed like command output: one block per layer, one marked line per step. */
export function DiagReport({ result, marks }: { result: DiagResult; marks?: string[] }) {
  const { t } = useI18n()
  const layers = [...new Set(result.steps.map((s) => s.layer))]
  return (
    <div className="diag" aria-live="polite">
      <Notice tone={result.ok ? 'ok' : 'error'} title={t(result.ok ? 'diag.ok' : 'diag.failed')} />
      {layers.map((layer) => {
        const steps = result.steps.filter((s) => s.layer === layer)
        return (
          <section key={layer} className="diag__layer">
            <h4>
              {String(layer).padStart(2, '0')} {steps[0]?.layer_name}
            </h4>
            <ul>
              {steps.map((s, i) => (
                <li key={i} className={`diag__step diag__step--${s.level}`}>
                  <span className="diag__mark" aria-hidden="true">
                    {stepMark[s.level]}
                  </span>
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

/** Buttons that run the layered test of a node, relay or exit, and the report below them. */
export function DiagRunner({ path, canFull = true }: { path: string; canFull?: boolean }) {
  const { t } = useI18n()
  const act = useAct()
  const [running, setRunning] = useState<'quick' | 'full' | null>(null)
  const [result, setResult] = useState<DiagResult | null>(null)
  const start = async (full: boolean) => {
    setRunning(full ? 'full' : 'quick')
    setResult(null)
    // Exits take no options; nodes and relays choose between the quick and the full run.
    const r = await act(() => api.post<DiagResult>(path, canFull ? { full } : undefined))
    if (r) setResult(r)
    setRunning(null)
  }
  return (
    <div className="stack">
      <div className="row">
        <Button icon="play" onClick={() => void start(false)} busy={running === 'quick'} disabled={running !== null}>
          {t('diag.run')}
        </Button>
        {canFull ? (
          <Button icon="pulse" onClick={() => void start(true)} busy={running === 'full'} disabled={running !== null} title={t('diag.fullHint')}>
            {t('diag.runFull')}
          </Button>
        ) : null}
      </div>
      {running ? <p className="dim small">{t('diag.running')}</p> : null}
      {result ? <DiagReport result={result} /> : null}
    </div>
  )
}

// ---- traffic routes --------------------------------------------------------------------

export type HopKind = 'entry' | 'relay' | 'target' | 'exit' | 'client' | 'net'

/** The route a connection takes, drawn as `a → b → c`; `vertical` stacks the hops. */
export function Route({ hops, vertical }: { hops: { label: ReactNode; kind: HopKind }[]; vertical?: boolean }) {
  return (
    <ol className={`route${vertical ? ' route--vertical' : ''}`}>
      {hops.map((hop, i) => (
        <li key={i} className={`route__hop route__hop--${hop.kind}`}>
          {hop.label}
        </li>
      ))}
    </ol>
  )
}

/** An exit's hops as the server words them: first is this server, last is the Internet. */
export function ExitRoute({ hops, vertical }: { hops: string[]; vertical?: boolean }) {
  const kind = (i: number): HopKind => (i === 0 ? 'entry' : i === hops.length - 1 ? 'net' : i === hops.length - 2 ? 'exit' : 'relay')
  return <Route vertical={vertical} hops={hops.map((label, i) => ({ label, kind: kind(i) }))} />
}

// ---- secrets ---------------------------------------------------------------------------

/** A revealed secret: selectable text, a copy button and a QR code on demand. */
export function SecretValue({ value, label, qr = true, qrLabel, rows = 3 }: { value: string; label: string; qr?: boolean; qrLabel?: string; rows?: number }) {
  const { t } = useI18n()
  const [showQR, setShowQR] = useState(false)
  return (
    <div className="secret__value">
      <div className="between">
        <span className="dim small">{label}</span>
        <div className="row">
          <CopyButton text={value} />
          {qr ? (
            <Button size="sm" icon="qr" onClick={() => setShowQR((s) => !s)} aria-pressed={showQR}>
              {t('secret.qr')}
            </Button>
          ) : null}
        </div>
      </div>
      <textarea className="input input--area secret__text" readOnly value={value} rows={rows} onFocus={(e) => e.currentTarget.select()} aria-label={label} />
      {showQR ? (
        <div className="secret__qr">
          <QR text={value} label={qrLabel ?? label} />
        </div>
      ) : null}
    </div>
  )
}

const HIDE_AFTER = 60_000

/**
 * Fetches a secret behind the recent-password check, keeps it in component memory only and
 * forgets it after a minute (or on Hide, or when the component goes away).
 */
export function Reveal<T>({ load, label, children }: { load: () => Promise<T>; label: string; children: (value: T) => ReactNode }) {
  const { t } = useI18n()
  const act = useAct()
  const { guard } = useReauth()
  const [shown, setShown] = useState<{ value: T } | null>(null)
  const [busy, setBusy] = useState(false)
  const timer = useRef<number | undefined>(undefined)

  const hide = useCallback(() => {
    window.clearTimeout(timer.current)
    setShown(null)
  }, [])
  useEffect(() => () => window.clearTimeout(timer.current), [])

  const reveal = async () => {
    setBusy(true)
    const value = await act(() => guard(load))
    setBusy(false)
    if (value === undefined) return
    setShown({ value })
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(hide, HIDE_AFTER)
  }

  if (!shown)
    return (
      <div className="secret secret--hidden">
        <span className="dim">{label}</span>
        <Button size="sm" icon="eye" onClick={() => void reveal()} busy={busy}>
          {t('secret.reveal')}
        </Button>
      </div>
    )
  return (
    <div className="secret">
      {children(shown.value)}
      <div className="between">
        <p className="dim small">{t('secret.autoHide')}</p>
        <Button size="sm" variant="ghost" icon="eyeoff" onClick={hide}>
          {t('common.hide')}
        </Button>
      </div>
    </div>
  )
}

/** The common case of Reveal: one string shown with copy and QR. */
export function SecretBox({ load, label, qr = true, qrLabel }: { load: () => Promise<string>; label: string; qr?: boolean; qrLabel?: string }) {
  return (
    <Reveal load={load} label={label}>
      {(value) => <SecretValue value={value} label={label} qr={qr} qrLabel={qrLabel} />}
    </Reveal>
  )
}

// ---- page plumbing ---------------------------------------------------------------------

/** What a page shows while its data is missing: the activity marker, or the error with Retry. */
export function LoadState({ res }: { res: Pick<Remote<unknown>, 'loading' | 'error' | 'reload'> }) {
  const { t } = useI18n()
  if (res.loading) return <Spinner label={t('common.loading')} />
  return (
    <Empty icon="warn" title={t('common.loadFailed')} action={<Button onClick={() => void res.reload()}>{t('common.retry')}</Button>}>
      {res.error?.message}
    </Empty>
  )
}

/** A one-field dialog for naming or renaming something. `onSave` resolves true when it worked. */
export function NameDialog({ title, current = '', maxLength = 64, onClose, onSave }: { title: string; current?: string; maxLength?: number; onClose: () => void; onSave: (name: string) => Promise<boolean> }) {
  const { t } = useI18n()
  const [name, setName] = useState(current)
  const [busy, setBusy] = useState(false)
  const clean = name.trim()
  const save = async () => {
    setBusy(true)
    const ok = await onSave(clean)
    setBusy(false)
    if (ok) onClose()
  }
  return (
    <Dialog title={title} onClose={onClose} busy={busy}>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault()
          if (clean && clean !== current) void save()
        }}
      >
        <Field label={t('common.name')}>{(id) => <Input id={id} data-autofocus value={name} maxLength={maxLength} onChange={(e) => setName(e.target.value)} />}</Field>
        <div className="row row--end">
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" busy={busy} disabled={!clean || clean === current}>
            {t('common.save')}
          </Button>
        </div>
      </form>
    </Dialog>
  )
}

/** A titled block inside a drawer or panel. */
export function Section({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <section className="section">
      <h3 className="section__title">{title}</h3>
      {children}
    </section>
  )
}

export type Inbound = '' | 'ipv4' | 'ipv6' | 'dual'

/** Which address family clients reach an entry on; families the host lacks are disabled with the reason. */
export function InboundPicker({ label, value, onChange, host }: { label: string; value: Inbound; onChange: (v: Inbound) => void; host: { ipv4: boolean; ipv6: boolean } }) {
  const { t } = useI18n()
  const dual = host.ipv4 && host.ipv6
  return (
    <Segmented<Inbound>
      label={label}
      value={value}
      onChange={onChange}
      options={[
        { value: '', label: t('common.auto') },
        { value: 'ipv4', label: 'IPv4', disabled: !host.ipv4, title: host.ipv4 ? undefined : t('nodes.create.noV4') },
        { value: 'ipv6', label: 'IPv6', disabled: !host.ipv6, title: host.ipv6 ? undefined : t('nodes.create.noV6') },
        { value: 'dual', label: t('family.dual'), disabled: !dual, title: dual ? undefined : t('nodes.create.dualNeeds') },
      ]}
    />
  )
}

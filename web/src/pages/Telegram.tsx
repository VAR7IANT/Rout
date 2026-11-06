import { useCallback, useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { useI18n, type TFn } from '../i18n'
import type { MessageKey } from '../i18n/catalog'
import { ApiError, api } from '../lib/api'
import { formatDateTime, formatRelative } from '../lib/format'
import { useNow } from '../lib/hooks'
import { Cancelled, errorText, useReauth } from '../lib/session'
import { useToast } from '../lib/toast'
import type { TelegramBindRequest, TelegramConnState, TelegramPatch, TelegramPending, TelegramProbe, TelegramServer, TelegramStatus, TelegramTestResult } from '../lib/types'
import { CopyButton } from '../components/copy'
import { Icon, type IconName } from '../components/icons'
import { ConfirmDialog, Overlay } from '../components/overlay'
import { DataTable, type Column } from '../components/table'
import { Badge, Button, Card, Dot, Field, Input, Notice, Spinner, Toggle, type Tone } from '../components/ui'

// Telegram Bot remote management. The bot token is write-only: it lives in the state of the
// wizard / edit dialog while the administrator types it and is dropped as soon as the dialog
// closes. No call ever returns it, and it is never put in browser storage.

const POLL_MS = 5000
const TOKEN_RE = /^\d+:\S{8,}$/
const CHAT_RE = /^[1-9]\d{0,18}$/
const NAME_MAX = 60

const connTone: Record<TelegramConnState, Tone> = { unbound: 'neutral', starting: 'warn', connected: 'ok', connecting: 'warn', pending: 'warn', revoked: 'error', error: 'error', stopped: 'error' }
const connLabel: Record<TelegramConnState, MessageKey> = {
  unbound: 'telegram.state.unbound',
  starting: 'telegram.state.starting',
  connected: 'telegram.state.connected',
  connecting: 'telegram.state.connecting',
  pending: 'telegram.state.pending',
  revoked: 'telegram.state.revoked',
  error: 'telegram.state.error',
  stopped: 'telegram.state.stopped',
}
const stepIcon: Record<string, IconName> = { ok: 'check', fail: 'close', warn: 'warn', info: 'pulse' }

// ---- data ------------------------------------------------------------------------------

/** Loads the status and refreshes it every few seconds while the tab is visible. `apply` stores
 *  an answer a mutation returned and discards any older poll still in flight. */
function useTelegramStatus() {
  const [data, setData] = useState<TelegramStatus | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(true)
  const seq = useRef(0)
  const alive = useRef(true)

  const load = useCallback(async () => {
    const mine = ++seq.current
    try {
      const r = await api.get<TelegramStatus>('/api/telegram')
      if (!alive.current || mine !== seq.current) return
      setData(r)
      setError(null)
    } catch (e) {
      if (!alive.current || mine !== seq.current) return
      setError(e instanceof ApiError ? e : new ApiError(0, 'network', 'network'))
    } finally {
      if (alive.current && mine === seq.current) setLoading(false)
    }
  }, [])

  const apply = useCallback((next: TelegramStatus) => {
    seq.current++
    setData(next)
    setError(null)
    setLoading(false)
  }, [])

  useEffect(() => {
    alive.current = true
    void load()
    const id = window.setInterval(() => {
      if (!document.hidden) void load()
    }, POLL_MS)
    const visible = () => {
      if (!document.hidden) void load()
    }
    document.addEventListener('visibilitychange', visible)
    return () => {
      alive.current = false
      window.clearInterval(id)
      document.removeEventListener('visibilitychange', visible)
    }
  }, [load])

  return { data, error, loading, reload: load, apply }
}

type Outcome<T> = { ok: true; value: T } | { ok: false; error: string } | null

/** Runs a mutating call behind the password re-check. null: the administrator cancelled the
 *  prompt; otherwise the value or the message to show. */
function useAct() {
  const { t } = useI18n()
  const { guard } = useReauth()
  return useCallback(
    async <T,>(fn: () => Promise<T>): Promise<Outcome<T>> => {
      try {
        return { ok: true, value: await guard(fn) }
      } catch (e) {
        if (e instanceof Cancelled) return null
        return { ok: false, error: errorText(e, t) }
      }
    },
    [guard, t],
  )
}

/** Makes sure a server message can never echo the token back into the page. */
function scrub(message: string, secret: string): string {
  const s = secret.trim()
  return s.length >= 8 ? message.split(s).join('•••') : message
}

function chatProblem(value: string, t: TFn): string | null {
  const s = value.trim()
  if (!s) return null
  if (s.startsWith('-')) return t('telegram.chat.negative')
  return CHAT_RE.test(s) ? null : t('telegram.chat.bad')
}

// ---- small pieces ----------------------------------------------------------------------

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="tg-fact">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  )
}

function Endpoints({ list }: { list: string[] }) {
  return (
    <ul className="tg-lines">
      {list.map((e) => (
        <li key={e} className="mono">
          {e}
        </li>
      ))}
    </ul>
  )
}

function Section({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <section className="tg-section">
      <div className="stack-tight">
        <h3>{title}</h3>
        {hint ? <p className="muted small">{hint}</p> : null}
      </div>
      {children}
    </section>
  )
}

function Facts() {
  const { t } = useI18n()
  return (
    <ul className="plain-list tg-points">
      <li>{t('telegram.fact.hub')}</li>
      <li>{t('telegram.fact.approve')}</li>
      <li>{t('telegram.fact.firewall')}</li>
      <li>{t('telegram.fact.token')}</li>
    </ul>
  )
}

function ConnBadge({ state }: { state: TelegramConnState }) {
  const { t } = useI18n()
  const tone = connTone[state] ?? 'neutral'
  return (
    <Badge tone={tone}>
      <Dot tone={tone} />
      {connLabel[state] ? t(connLabel[state]) : state}
    </Badge>
  )
}

// ---- the card --------------------------------------------------------------------------

export function TelegramCard() {
  const { t } = useI18n()
  const toast = useToast()
  const st = useTelegramStatus()
  const [wizard, setWizard] = useState(false)
  const s = st.data

  let body: ReactNode
  if (!s) {
    body = st.loading ? (
      <Spinner label={t('common.loading')} />
    ) : (
      <Notice
        tone="error"
        title={t('telegram.loadFailed')}
        action={
          <Button size="sm" onClick={() => void st.reload()}>
            {t('common.retry')}
          </Button>
        }
      >
        {st.error ? errorText(st.error, t) : null}
      </Notice>
    )
  } else if (!s.bound) {
    body = <Unbound onBind={() => setWizard(true)} />
  } else {
    body = <Bound s={s} apply={st.apply} reload={st.reload} />
  }

  return (
    <Card className="tg-card" title={t('telegram.title')} subtitle={t('telegram.subtitle')}>
      <div className="stack-lg">
        {s && st.error ? <Notice tone="warn">{t('telegram.refreshFailed', { why: errorText(st.error, t) })}</Notice> : null}
        {body}
      </div>
      {wizard ? (
        <BindWizard
          onClose={() => setWizard(false)}
          onBound={(next) => {
            setWizard(false)
            st.apply(next)
            toast.push('ok', t('telegram.bound'))
          }}
        />
      ) : null}
    </Card>
  )
}

function Unbound({ onBind }: { onBind: () => void }) {
  const { t } = useI18n()
  return (
    <div className="stack">
      <div className="row-wrap">
        <Badge>{t('telegram.notBound')}</Badge>
      </div>
      <p>{t('telegram.intro')}</p>
      <Facts />
      <div className="row-wrap tg-actions">
        <Button variant="primary" icon="link" onClick={onBind}>
          {t('telegram.bind')}
        </Button>
      </div>
    </div>
  )
}

// ---- bound -----------------------------------------------------------------------------

function Bound({ s, apply, reload }: { s: TelegramStatus; apply: (s: TelegramStatus) => void; reload: () => Promise<void> }) {
  const { t, locale } = useI18n()
  const toast = useToast()
  const act = useAct()
  const now = useNow(30000)
  const [edit, setEdit] = useState(false)
  const [unbind, setUnbind] = useState(false)
  const [revoke, setRevoke] = useState<TelegramServer | null>(null)
  const [testing, setTesting] = useState(false)
  const [test, setTest] = useState<{ result?: TelegramTestResult; error?: string } | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const hub = s.role === 'hub'
  const conn = s.connection
  const others = s.servers.filter((x) => !x.self).length

  const runTest = async () => {
    setTesting(true)
    setTest(null)
    try {
      setTest({ result: await api.post<TelegramTestResult>('/api/telegram/test') })
    } catch (e) {
      setTest({ error: errorText(e, t) })
    } finally {
      setTesting(false)
    }
  }

  const decide = async (p: TelegramPending, what: 'approve' | 'reject') => {
    setBusy(`${what}:${p.id}`)
    const r = await act(() => api.post<TelegramStatus>(`/api/telegram/pending/${encodeURIComponent(p.id)}/${what}`))
    setBusy(null)
    if (!r) return
    if (!r.ok) {
      toast.push('error', r.error)
      return
    }
    apply(r.value)
    toast.push('ok', t(what === 'approve' ? 'telegram.approved' : 'telegram.rejected', { name: p.name }))
  }

  const columns: Column<TelegramServer>[] = [
    {
      key: 'name',
      header: t('telegram.col.server'),
      primary: true,
      cell: (x) => (
        <div className="tg-cell tg-cell-name">
          <span className="tg-server-name">
            <strong>{x.name}</strong>
            {x.self ? <Badge tone="accent">{t('telegram.self')}</Badge> : null}
          </span>
          {x.version ? <span className="muted small">v{x.version.replace(/^v/i, '')}</span> : null}
        </div>
      ),
    },
    {
      key: 'status',
      header: t('common.status'),
      label: t('common.status'),
      cell: (x) => (
        <div className="tg-cell">
          <Badge tone={x.online ? 'ok' : 'warn'}>
            <Dot tone={x.online ? 'ok' : 'warn'} />
            {x.online ? t('telegram.online') : t('telegram.offline')}
          </Badge>
          {x.last_seen ? (
            <span className="muted small" title={formatDateTime(x.last_seen, locale)}>
              {t('telegram.lastSeen', { when: formatRelative(x.last_seen, now, t) })}
            </span>
          ) : null}
        </div>
      ),
    },
    {
      key: 'ai',
      header: t('telegram.col.ai'),
      label: t('telegram.col.ai'),
      cell: (x) =>
        x.ai_enabled === undefined ? (
          <span className="muted">–</span>
        ) : (
          <div className="tg-cell">
            <Badge tone={x.ai_enabled ? 'ok' : 'neutral'}>{x.ai_enabled ? t('common.enabled') : t('common.disabled')}</Badge>
            {x.exit_name ? <span className="muted small">{t('ai.exitIs', { name: x.exit_name })}</span> : null}
          </div>
        ),
    },
    {
      key: 'fp',
      header: t('telegram.col.fp'),
      label: t('telegram.col.fp'),
      className: 'col-fp',
      cell: (x) => <span className="tg-fp">{x.fingerprint}</span>,
    },
    {
      key: 'actions',
      header: <span className="sr-only">{t('common.actions')}</span>,
      className: 'col-actions',
      cell: (x) =>
        x.self ? null : (
          <Button size="sm" variant="danger" icon="close" aria-label={t('telegram.revokeName', { name: x.name })} disabled={busy !== null} onClick={() => setRevoke(x)}>
            {t('telegram.revoke')}
          </Button>
        ),
    },
  ]

  return (
    <>
      <div className="stack">
        {!s.service.running ? (
          <Notice tone="warn" title={t('telegram.svc.stopped')}>
            {t('telegram.svc.stoppedDetail')}
          </Notice>
        ) : null}
        {!s.service.managed ? (
          <Notice tone="warn" title={t('telegram.svc.unmanaged')}>
            {t('telegram.svc.unmanagedDetail')}
          </Notice>
        ) : null}
        {!hub && conn.state === 'pending' ? (
          <Notice tone="accent" title={t('telegram.state.pending')}>
            {t('telegram.pending.agent')}
          </Notice>
        ) : null}
        {!hub && conn.state === 'revoked' ? <Notice tone="error">{t('telegram.revoked.notice')}</Notice> : null}
        {hub && s.hub && !s.hub.multi_server ? <Notice tone="neutral">{t('telegram.noMulti')}</Notice> : null}

        <div className="tg-head">
          <Badge tone={hub ? 'accent' : 'neutral'}>{hub ? t('telegram.role.hub') : t('telegram.role.agent')}</Badge>
          <ConnBadge state={conn.state} />
          {s.bot_username ? <strong className="tg-bot">@{s.bot_username}</strong> : null}
        </div>
        {conn.detail ? <p className={`small wrap-any ${connTone[conn.state] === 'error' ? 'err-text' : 'muted'}`}>{conn.detail}</p> : null}

        <dl className="tg-facts">
          {s.server_name ? <Fact label={t('telegram.f.name')}>{s.server_name}</Fact> : null}
          {s.chat_id_masked ? (
            <Fact label={t('telegram.f.chat')}>
              <span className="mono">{s.chat_id_masked}</span>
            </Fact>
          ) : null}
          {s.server_id ? (
            <Fact label={t('telegram.f.id')}>
              <span className="mono">{s.server_id}</span>
            </Fact>
          ) : null}
          {s.fingerprint ? (
            <Fact label={t('telegram.f.fp')}>
              <div className="tg-fpline">
                <span className="tg-fp">{s.fingerprint}</span>
                <CopyButton text={s.fingerprint} compact />
              </div>
            </Fact>
          ) : null}
          {hub && s.hub ? (
            <>
              <Fact label={t('telegram.f.hubAddr')}>{s.hub.endpoints.length ? <Endpoints list={s.hub.endpoints} /> : <span className="muted">–</span>}</Fact>
              <Fact label={t('telegram.f.hubPort')}>
                <span className="mono">{s.hub.port}</span>
              </Fact>
              <Fact label={t('telegram.f.multi')}>{s.hub.multi_server ? t('telegram.multi.on') : t('telegram.multi.off')}</Fact>
            </>
          ) : null}
          {!hub && s.follows ? (
            <>
              <Fact label={t('telegram.f.follows')}>{s.follows.endpoints.length ? <Endpoints list={s.follows.endpoints} /> : <span className="muted">–</span>}</Fact>
              <Fact label={t('telegram.f.followsFp')}>
                <span className="tg-fp">{s.follows.fingerprint}</span>
              </Fact>
            </>
          ) : null}
          <Fact label={t('telegram.f.last')}>
            {conn.last_ok ? `${formatDateTime(conn.last_ok, locale)} (${formatRelative(conn.last_ok, now, t)})` : t('common.never')}
          </Fact>
        </dl>

        <div className="row-wrap tg-actions">
          <Button icon="test" busy={testing} disabled={testing} onClick={() => void runTest()}>
            {t('telegram.test')}
          </Button>
          <Button icon="edit" disabled={testing} onClick={() => setEdit(true)}>
            {t('common.edit')}
          </Button>
          <Button variant="danger" icon="logout" disabled={testing} onClick={() => setUnbind(true)}>
            {t('telegram.unbind')}
          </Button>
        </div>

        {testing ? (
          <div className="progress-line" role="status">
            <span className="progress-bar" aria-hidden="true" />
            <span className="muted small">{t('telegram.test.running')}</span>
          </div>
        ) : null}
        {test?.error ? <Notice tone="error">{test.error}</Notice> : null}
        {test?.result ? (
          <div className="diag" aria-live="polite">
            <Notice tone={test.result.ok ? 'ok' : 'error'} title={test.result.ok ? t('telegram.test.ok') : t('telegram.test.fail')} />
            <section className="diag-layer">
              <ul>
                {test.result.steps.map((step, i) => (
                  <li key={i} className={`diag-${step.level}`}>
                    <Icon name={stepIcon[step.level] ?? 'pulse'} size={15} />
                    <span>{step.text}</span>
                  </li>
                ))}
              </ul>
            </section>
          </div>
        ) : null}
      </div>

      {hub && s.servers.length > 0 ? (
        <Section title={t('telegram.servers')} hint={t('telegram.servers.hint')}>
          <div className="tg-table">
            <DataTable caption={t('telegram.servers.caption')} rows={s.servers} rowKey={(x) => x.id} columns={columns} />
          </div>
        </Section>
      ) : null}

      {s.pending.length > 0 ? (
        <Section title={t('telegram.pending')} hint={t('telegram.pending.hint')}>
          <ul className="tg-pending">
            {s.pending.map((p) => (
              <li key={p.id}>
                <div className="tg-pending-main">
                  <strong>{p.name}</strong>
                  <span className="tg-fp">{p.fingerprint}</span>
                  <span className="muted small" title={formatDateTime(p.requested_at, locale)}>
                    {t('telegram.pending.requested', { when: formatRelative(p.requested_at, now, t) })}
                  </span>
                </div>
                <div className="tg-pending-actions">
                  <Button variant="primary" icon="check" aria-label={t('telegram.approveName', { name: p.name })} busy={busy === `approve:${p.id}`} disabled={busy !== null} onClick={() => void decide(p, 'approve')}>
                    {t('telegram.approve')}
                  </Button>
                  <Button variant="danger" icon="close" aria-label={t('telegram.rejectName', { name: p.name })} busy={busy === `reject:${p.id}`} disabled={busy !== null} onClick={() => void decide(p, 'reject')}>
                    {t('telegram.reject')}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </Section>
      ) : null}

      <details className="disclosure tg-audit">
        <summary>
          <Icon name="chevron" size={15} />
          {t('telegram.audit', { n: s.audit.length })}
        </summary>
        {s.audit.length === 0 ? (
          <p className="muted small">{t('telegram.audit.empty')}</p>
        ) : (
          <ul className="tg-audit-list">
            {s.audit.slice(0, 100).map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        )}
      </details>

      <details className="disclosure tg-audit">
        <summary>
          <Icon name="chevron" size={15} />
          {t('telegram.how')}
        </summary>
        <Facts />
      </details>

      {edit ? (
        <EditDialog
          s={s}
          onClose={() => setEdit(false)}
          onSaved={(next) => {
            setEdit(false)
            apply(next)
            toast.push('ok', t('telegram.edit.saved'))
          }}
        />
      ) : null}

      {unbind ? (
        <ConfirmDialog
          title={t('telegram.unbind.title')}
          message={hub ? t('telegram.unbind.hub') : t('telegram.unbind.agent')}
          impact={[t('telegram.unbind.impactKeep'), ...(hub && others > 0 ? [t('telegram.unbind.impactOthers', { n: others })] : [])]}
          confirmLabel={t('telegram.unbind')}
          danger
          onCancel={() => setUnbind(false)}
          onConfirm={async () => {
            const r = await act(() => api.post('/api/telegram/unbind'))
            if (!r) return
            if (!r.ok) {
              toast.push('error', r.error)
              return
            }
            setUnbind(false)
            setTest(null)
            toast.push('ok', t('telegram.unbound'))
            apply({ bound: false, service: s.service, connection: { state: 'unbound' }, servers: [], pending: [], audit: [] })
            void reload()
          }}
        />
      ) : null}

      {revoke ? (
        <ConfirmDialog
          title={t('telegram.revoke.title', { name: revoke.name })}
          message={t('telegram.revoke.msg')}
          impact={[t('telegram.revoke.impact')]}
          confirmLabel={t('telegram.revoke')}
          danger
          onCancel={() => setRevoke(null)}
          onConfirm={async () => {
            const target = revoke
            const r = await act(() => api.del<TelegramStatus>(`/api/telegram/servers/${encodeURIComponent(target.id)}`))
            if (!r) return
            if (!r.ok) {
              toast.push('error', r.error)
              return
            }
            setRevoke(null)
            apply(r.value)
            toast.push('ok', t('telegram.revoked', { name: target.name }))
          }}
        />
      ) : null}
    </>
  )
}

// ---- edit ------------------------------------------------------------------------------

function EditDialog({ s, onClose, onSaved }: { s: TelegramStatus; onClose: () => void; onSaved: (s: TelegramStatus) => void }) {
  const { t } = useI18n()
  const act = useAct()
  const formId = useId()
  // What the form started from; polling may change `s` underneath without touching the fields.
  const [base] = useState(() => ({ name: s.server_name ?? '', multi: s.hub?.multi_server ?? false }))
  const hub = s.role === 'hub'
  const [name, setName] = useState(base.name)
  const [token, setToken] = useState('')
  const [chat, setChat] = useState('')
  const [multi, setMulti] = useState(base.multi)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const patch: TelegramPatch = {}
  const n = name.trim()
  if (n !== base.name) patch.server_name = n
  if (token.trim()) patch.token = token.trim()
  if (chat.trim()) patch.chat_id = chat.trim()
  if (hub && multi !== base.multi) patch.multi_server = multi
  const changed = Object.keys(patch).length > 0

  const nameOK = n.length >= 1 && n.length <= NAME_MAX
  const tokenBad = token.trim() !== '' && !TOKEN_RE.test(token.trim())
  const chatErr = chatProblem(chat, t)
  const valid = nameOK && !tokenBad && !chatErr

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!changed || !valid || busy) return
    setBusy(true)
    setError(null)
    const sent = token
    const r = await act(() => api.patch<TelegramStatus>('/api/telegram', patch))
    setBusy(false)
    if (!r) return
    if (!r.ok) {
      setError(scrub(r.error, sent))
      return
    }
    setToken('')
    onSaved(r.value)
  }

  return (
    <Overlay
      title={t('telegram.edit.title')}
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" form={formId} variant="primary" busy={busy} disabled={!changed || !valid}>
            {t('common.save')}
          </Button>
        </>
      }
    >
      <form id={formId} className="stack" onSubmit={(e) => void submit(e)} autoComplete="off">
        <Field label={t('telegram.name')} hint={t('telegram.name.hint')} required>
          {(id, d) => <Input id={id} aria-describedby={d} data-autofocus maxLength={NAME_MAX} value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />}
        </Field>
        <Field label={t('telegram.edit.token')} hint={t('telegram.edit.tokenHint')} error={tokenBad ? t('telegram.token.bad') : null}>
          {(id, d) => <Input id={id} aria-describedby={d} type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} data-lpignore="true" data-1p-ignore />}
        </Field>
        <Field label={t('telegram.edit.chat')} hint={t('telegram.edit.chatHint', { masked: s.chat_id_masked ?? '–' })} error={chatErr}>
          {(id, d) => <Input id={id} aria-describedby={d} inputMode="numeric" value={chat} onChange={(e) => setChat(e.target.value.replace(/\s/g, ''))} autoComplete="off" spellCheck={false} placeholder={s.chat_id_masked} />}
        </Field>
        {hub ? (
          <div className="tg-toggle">
            <Toggle checked={multi} onChange={setMulti} hint={!multi && base.multi ? t('telegram.edit.multiOff') : t('telegram.hub.multiHint')}>
              {t('telegram.hub.multi')}
            </Toggle>
          </div>
        ) : null}
        {error ? <Notice tone="error">{error}</Notice> : null}
      </form>
    </Overlay>
  )
}

// ---- bind wizard -----------------------------------------------------------------------

function BindWizard({ onClose, onBound }: { onClose: () => void; onBound: (s: TelegramStatus) => void }) {
  const { t } = useI18n()
  const act = useAct()
  const formId = useId()
  const [token, setToken] = useState('')
  const [chat, setChat] = useState('')
  const [touched, setTouched] = useState(false)
  const [probe, setProbe] = useState<TelegramProbe | null>(null)
  const [name, setName] = useState('')
  const [verified, setVerified] = useState(false)
  const [multi, setMulti] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const tk = token.trim()
  const cid = chat.trim()
  const tokenBad = touched && tk !== '' && !TOKEN_RE.test(tk)
  const chatErr = chatProblem(chat, t)
  const step1OK = TOKEN_RE.test(tk) && CHAT_RE.test(cid)

  const hubInfo = probe && probe.hub.found ? probe.hub : null
  const agent = !!hubInfo
  const nameOK = name.trim().length >= 1 && name.trim().length <= NAME_MAX
  const step2OK = !!probe && nameOK && (agent ? verified : !probe.webhook_active)

  const doProbe = async () => {
    setBusy(true)
    setError(null)
    const r = await act(() => api.post<TelegramProbe>('/api/telegram/probe', { token: tk, chat_id: cid }))
    setBusy(false)
    if (!r) return
    if (!r.ok) {
      setError(scrub(r.error, tk))
      return
    }
    setProbe(r.value)
    setName((r.value.suggested_name ?? '').slice(0, NAME_MAX))
    setVerified(false)
    setMulti(true)
  }

  const doBind = async () => {
    if (!probe || !step2OK) return
    const body: TelegramBindRequest = hubInfo
      ? { token: tk, chat_id: cid, server_name: name.trim(), role: 'agent', trust_hub_fp: hubInfo.fingerprint }
      : { token: tk, chat_id: cid, server_name: name.trim(), role: 'hub', multi_server: multi }
    setBusy(true)
    setError(null)
    const r = await act(() => api.post<TelegramStatus>('/api/telegram/bind', body))
    setBusy(false)
    if (!r) return
    if (!r.ok) {
      setError(scrub(r.error, tk))
      return
    }
    // The secret is no longer needed: drop it before anything else happens.
    setToken('')
    setChat('')
    onBound(r.value)
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (busy) return
    if (!probe) {
      setTouched(true)
      if (step1OK) void doProbe()
    } else void doBind()
  }

  const back = () => {
    setProbe(null)
    setError(null)
  }

  return (
    <Overlay
      title={t('telegram.bind')}
      description={probe ? t('telegram.wiz.step2') : t('telegram.wiz.step1')}
      onClose={onClose}
      busy={busy}
      footer={
        probe ? (
          <>
            <Button variant="ghost" onClick={back} disabled={busy}>
              {t('telegram.back')}
            </Button>
            <Button type="submit" form={formId} variant="primary" icon="link" busy={busy} disabled={!step2OK}>
              {t('telegram.bindNow')}
            </Button>
          </>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" form={formId} variant="primary" busy={busy} disabled={!step1OK}>
              {t('telegram.check')}
            </Button>
          </>
        )
      }
    >
      <form id={formId} className="stack" onSubmit={submit} autoComplete="off">
        {!probe ? (
          <>
            <Field label={t('telegram.token')} hint={t('telegram.token.hint')} required error={tokenBad ? t('telegram.token.bad') : null}>
              {(id, d) => (
                <Input
                  id={id}
                  aria-describedby={d}
                  data-autofocus
                  type="password"
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  data-lpignore="true"
                  data-1p-ignore
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  onBlur={() => setTouched(true)}
                />
              )}
            </Field>
            <Field label={t('telegram.chat')} hint={t('telegram.chat.hint')} required error={chatErr}>
              {(id, d) => <Input id={id} aria-describedby={d} inputMode="numeric" autoComplete="off" spellCheck={false} value={chat} onChange={(e) => setChat(e.target.value.replace(/\s/g, ''))} />}
            </Field>
          </>
        ) : (
          <>
            <p className="tg-botline">
              <Icon name="check" size={16} />
              <span className="muted">{t('telegram.bot')}</span>
              <strong className="tg-bot">@{probe.bot_username}</strong>
            </p>

            {hubInfo ? (
              <>
                <Notice tone="accent" title={t('telegram.agent.title')}>
                  {t('telegram.agent.after')}
                </Notice>
                <dl className="tg-facts">
                  {hubInfo.hub_name ? <Fact label={t('telegram.agent.hubName')}>{hubInfo.hub_name}</Fact> : null}
                  <Fact label={t('telegram.agent.endpoints')}>
                    <Endpoints list={hubInfo.endpoints} />
                  </Fact>
                </dl>
                <div className="stack-tight">
                  <span className="muted small">{t('telegram.agent.fingerprint')}</span>
                  <div className="tg-fpbox">{hubInfo.fingerprint}</div>
                </div>
                <Notice tone="warn">{t('telegram.agent.verify')}</Notice>
                <div className="tg-toggle">
                  <Toggle checked={verified} onChange={setVerified}>
                    {t('telegram.agent.confirm')}
                  </Toggle>
                </div>
              </>
            ) : (
              <>
                <Notice tone="neutral" title={t('telegram.hub.title')}>
                  {t('telegram.hub.detail')}
                </Notice>
                <div className="tg-toggle">
                  <Toggle checked={multi} onChange={setMulti} hint={t('telegram.hub.multiHint')}>
                    {t('telegram.hub.multi')}
                  </Toggle>
                </div>
                {probe.webhook_active ? (
                  <Notice tone="error" title={t('telegram.webhook.title')}>
                    {t('telegram.webhook.detail')}
                  </Notice>
                ) : null}
              </>
            )}

            <Field label={t('telegram.name')} hint={t('telegram.name.hint')} required>
              {(id, d) => <Input id={id} aria-describedby={d} maxLength={NAME_MAX} value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />}
            </Field>
          </>
        )}
        {error ? <Notice tone="error">{error}</Notice> : null}
      </form>
    </Overlay>
  )
}

import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { useI18n, type TFn } from '../i18n'
import { ApiError, api } from '../lib/api'
import { useResource } from '../lib/hooks'
import { errorText, useRunner } from '../lib/session'
import { useToast } from '../lib/toast'
import { Link } from '../lib/router'
import type { AIRoute, AISimulation, AIView, ChainProtocol, ChainSpec, DiagResult, ExitView, RelayView } from '../lib/types'
import { DiagResultView, HopPath, PathChain, findIPs, type HopKind } from '../components/shared'
import { Badge, Button, Card, EmptyState, Field, Input, Notice, PageHead, Segmented, Select, Spinner, Switch, Textarea, type Tone } from '../components/ui'
import { Icon } from '../components/icons'

type Mode = 'existing' | 'relay' | 'remote' | 'forwarder'

export function AIPage() {
  const { t } = useI18n()
  const res = useResource<AIView>('/api/ai')
  const v = res.data

  if (res.loading && !v) return <Spinner label={t('common.loading')} />
  if (!v) {
    return (
      <EmptyState icon="warn" title={t('common.loadFailed')} action={<Button onClick={() => void res.reload()}>{t('common.retry')}</Button>}>
        {res.error?.message}
      </EmptyState>
    )
  }
  const update = (next: AIView) => res.setData(next)

  return (
    <div className="page ai-page">
      <PageHead title={t('ai.title')} subtitle={t('ai.subtitle')} />
      <StatusCard view={v} onChange={update} />
      <LanesCard view={v} />
      <div className="ai-grid">
        <NodesCard view={v} onChange={update} />
        <ExitCard view={v} onChange={update} reload={res.reload} />
      </div>
      <TestCard view={v} />
      <SimulateCard />
      <LimitsCard view={v} />
    </div>
  )
}

// ---- status ----------------------------------------------------------------------------

function StatusCard({ view, onChange }: { view: AIView; onChange: (v: AIView) => void }) {
  const { t } = useI18n()
  const run = useRunner()
  const [busy, setBusy] = useState<'toggle' | 'apply' | null>(null)
  const outOfSync = view.nodes.filter((n) => !n.in_sync)
  const bound = view.nodes.filter((n) => n.bound).length

  const toggle = async (on: boolean) => {
    setBusy('toggle')
    const r = await run(() => api.post<AIView>('/api/ai/enabled', { enabled: on }), { ok: on ? t('ai.enabledOk') : t('ai.disabledOk') })
    setBusy(null)
    if (r) onChange(r)
  }
  const apply = async () => {
    setBusy('apply')
    const r = await run(() => api.post<AIView>('/api/ai/apply'), { ok: t('ai.applied') })
    setBusy(null)
    if (r) onChange(r)
  }

  return (
    <Card>
      <div className="ai-status">
        <div className="ai-status-main">
          <Switch checked={view.enabled} onChange={(on) => void toggle(on)} label={t('ai.enable')} disabled={busy !== null} />
          <div className="stack-tight">
            <strong>{view.enabled ? t('ai.on') : t('ai.off')}</strong>
            <span className="muted small">{view.enabled ? t('ai.onHint', { n: bound }) : t('ai.offHint')}</span>
          </div>
        </div>
        <div className="row-wrap ai-status-meta">
          <Badge>{t('ai.ruleSet', { v: view.rule_set })}</Badge>
          {view.rule_set_available > view.rule_set ? <Badge tone="accent">{t('ai.ruleSetNew', { v: view.rule_set_available })}</Badge> : null}
          {view.exit ? <Badge tone={view.exit.ai_usable === false ? 'error' : 'ok'}>{t('ai.exitIs', { name: view.exit.name })}</Badge> : <Badge tone="warn">{t('ai.noExit')}</Badge>}
        </div>
      </div>
      {view.problems.length > 0 || outOfSync.length > 0 ? (
        <div className="stack ai-status-notes">
          {view.problems.map((p, i) => (
            <Notice key={i} tone="warn">
              {p}
            </Notice>
          ))}
          {outOfSync.length > 0 ? (
            <Notice
              tone="accent"
              title={t('ai.unsynced')}
              action={
                <Button size="sm" variant="primary" icon="refresh" busy={busy === 'apply'} disabled={busy !== null} onClick={() => void apply()}>
                  {t('ai.apply')}
                </Button>
              }
            >
              {t('ai.unsyncedDetail', { names: outOfSync.map((n) => n.name).join('、') })}
            </Notice>
          ) : null}
        </div>
      ) : null}
    </Card>
  )
}

// ---- path preview ----------------------------------------------------------------------

function routeName(exit: string, t: TFn) {
  return exit === 'direct' ? t('ai.lane.direct') : exit
}

function LanesCard({ view }: { view: AIView }) {
  const { t } = useI18n()
  const bound = view.nodes.filter((n) => n.bound)
  const inbound = bound.length ? bound.map((n) => n.name).join('、') : t('ai.lane.noNodes')
  const ordinary = [...new Set((bound.length ? bound : view.nodes).map((n) => routeName(n.exit, t)))]
  const normal: { label: string; kind: HopKind }[] = [
    { label: t('ai.lane.client'), kind: 'client' },
    { label: inbound, kind: 'entry' },
    { label: ordinary.length ? ordinary.join(' / ') : t('ai.lane.direct'), kind: 'exit' },
    { label: t('ai.lane.internet'), kind: 'net' },
  ]
  const hops = view.exit?.path?.length ? view.exit.path.slice(1) : []
  const ai: { label: string; kind: HopKind }[] = [
    { label: t('ai.lane.client'), kind: 'client' },
    { label: inbound, kind: 'entry' },
    ...(hops.length
      ? hops.map((h, i): { label: string; kind: HopKind } => ({ label: h, kind: i === hops.length - 1 ? 'net' : i === hops.length - 2 ? 'exit' : 'relay' }))
      : [{ label: t('ai.noExit'), kind: 'target' as HopKind }]),
  ]
  return (
    <Card title={t('ai.lanes')} subtitle={t('ai.lanesHint')}>
      <div className="lanes">
        <div className="lane">
          <div className="lane-head">
            <span className="lane-dot lane-dot-normal" aria-hidden="true" />
            <strong>{t('ai.lane.normal')}</strong>
            <span className="muted small">{t('ai.lane.normalHint')}</span>
          </div>
          <PathChain items={normal} />
        </div>
        <div className="lane lane-ai">
          <div className="lane-head">
            <span className="lane-dot lane-dot-ai" aria-hidden="true" />
            <strong>{t('ai.lane.ai')}</strong>
            <span className="muted small">{view.enabled ? t('ai.lane.aiHint') : t('ai.lane.aiOff')}</span>
          </div>
          <PathChain items={ai} />
        </div>
      </div>
    </Card>
  )
}

// ---- inbound nodes ---------------------------------------------------------------------

function sameSet(a: Set<string>, b: Set<string>) {
  if (a.size !== b.size) return false
  for (const x of a) if (!b.has(x)) return false
  return true
}

function NodesCard({ view, onChange }: { view: AIView; onChange: (v: AIView) => void }) {
  const { t } = useI18n()
  const run = useRunner()
  const server = useMemo(() => new Set(view.nodes.filter((n) => n.bound).map((n) => n.id)), [view.nodes])
  const [sel, setSel] = useState<Set<string>>(server)
  const [busy, setBusy] = useState(false)
  // Follow the server whenever it reports a different binding (after a save or a reload).
  const key = [...server].sort().join(',')
  const seen = useRef(key)
  useEffect(() => {
    if (seen.current !== key) {
      seen.current = key
      setSel(new Set(server))
    }
  }, [key, server])

  const dirty = !sameSet(sel, server)
  const save = async () => {
    setBusy(true)
    const ids = view.nodes.filter((n) => sel.has(n.id)).map((n) => n.id)
    const r = await run(() => api.put<AIView>('/api/ai/bindings', { ids }), { ok: t('ai.nodes.saved') })
    setBusy(false)
    if (r) onChange(r)
  }
  const flip = (id: string, on: boolean) => {
    const next = new Set(sel)
    if (on) next.add(id)
    else next.delete(id)
    setSel(next)
  }

  return (
    <Card
      title={t('ai.nodes')}
      subtitle={t('ai.nodesHint')}
      actions={
        <Button size="sm" variant="primary" icon="check" busy={busy} disabled={!dirty} onClick={() => void save()}>
          {t('common.save')}
        </Button>
      }
    >
      {view.nodes.length === 0 ? (
        <p className="muted">
          {t('ai.nodes.empty')} <Link to="/nodes">{t('nav.nodes')} →</Link>
        </p>
      ) : (
        <ul className="ai-nodes">
          {view.nodes.map((n) => {
            const on = sel.has(n.id)
            return (
              <li key={n.id} className={`${on ? 'on' : ''} ${n.eligible ? '' : 'is-off'}`}>
                <label className="ai-node">
                  <input type="checkbox" className="check" checked={on} disabled={!n.eligible || busy} onChange={(e) => flip(n.id, e.target.checked)} aria-describedby={`ai-node-${n.id}`} />
                  <span className="ai-node-main">
                    <span className="ai-node-title">
                      <strong>{n.name}</strong>
                      <Badge>{n.protocol}</Badge>
                    </span>
                    <span id={`ai-node-${n.id}`} className="ai-node-sub">
                      <span className="muted small">{n.running}</span>
                      {n.bound && !n.in_sync ? <Badge tone="warn">{t('ai.nodes.unsynced')}</Badge> : null}
                      <span className="muted small">{t('ai.nodes.route', { exit: routeName(n.exit, t) })}</span>
                      {n.note ? <span className={`small ${n.eligible ? 'muted' : 'warn-text'}`}>{n.eligible ? n.note : t('ai.nodes.ineligible', { why: n.note })}</span> : !n.eligible ? <span className="small warn-text">{t('ai.nodes.ineligibleBare')}</span> : null}
                    </span>
                  </span>
                </label>
              </li>
            )
          })}
        </ul>
      )}
      {dirty ? <p className="hint ai-nodes-dirty">{t('ai.nodes.dirty')}</p> : null}
    </Card>
  )
}

// ---- AI exit ---------------------------------------------------------------------------

function ExitCard({ view, onChange, reload }: { view: AIView; onChange: (v: AIView) => void; reload: () => Promise<void> }) {
  const { t } = useI18n()
  const [mode, setMode] = useState<Mode>('existing')
  const run = useRunner()
  const toast = useToast()

  /** Makes `id` the AI exit; used by every mode once the exit exists. */
  const choose = async (id: string, created?: boolean) => {
    const r = await run(() => api.put<AIView>('/api/ai/exit', { exit_id: id }))
    if (r) {
      onChange(r)
      toast.push('ok', created ? t('ai.exit.createdUsed') : t('ai.exit.used'))
      setMode('existing')
    } else if (created) await reload()
    return !!r
  }

  return (
    <Card title={t('ai.exit')} subtitle={t('ai.exitHint')}>
      <div className="stack">
        <div className="mode-scroll">
          <Segmented<Mode>
            label={t('ai.exit')}
            value={mode}
            onChange={setMode}
            options={[
              { value: 'existing', label: t('ai.mode.existing') },
              { value: 'relay', label: t('ai.mode.relay') },
              { value: 'remote', label: t('ai.mode.remote') },
              { value: 'forwarder', label: t('ai.mode.forwarder') },
            ]}
          />
        </div>
        {mode === 'existing' ? <ExistingExits view={view} choose={choose} /> : null}
        {mode === 'relay' ? <ChainForm kind="relay" relays={view.relays} choose={choose} /> : null}
        {mode === 'forwarder' ? <ChainForm kind="forwarder" relays={[]} choose={choose} /> : null}
        {mode === 'remote' ? <RemoteForm choose={choose} /> : null}
      </div>
    </Card>
  )
}

function exitKindBadge(x: ExitView, t: TFn) {
  return x.kind === 'chain' ? <Badge tone="accent">{t('exits.kind.chain')}</Badge> : x.kind === 'remote' ? <Badge>{t('exits.kind.remote')}</Badge> : <Badge>{x.label}</Badge>
}

function ExistingExits({ view, choose }: { view: AIView; choose: (id: string) => Promise<boolean> }) {
  const { t } = useI18n()
  const [pick, setPick] = useState(view.exit_id ?? '')
  const [busy, setBusy] = useState(false)
  useEffect(() => setPick(view.exit_id ?? ''), [view.exit_id])
  if (view.exits.length === 0) return <p className="muted">{t('ai.exit.none')}</p>
  return (
    <div className="stack">
      <ul className="exit-picks" role="radiogroup" aria-label={t('ai.mode.existing')}>
        {view.exits.map((x) => {
          const usable = x.ai_usable !== false
          return (
            <li key={x.id} className={`${pick === x.id ? 'on' : ''} ${usable ? '' : 'is-off'}`}>
              <label className="exit-pick">
                <input type="radio" name="ai-exit" className="check" value={x.id} checked={pick === x.id} disabled={!usable || busy} onChange={() => setPick(x.id)} />
                <span className="exit-pick-main">
                  <span className="ai-node-title">
                    <strong>{x.name}</strong>
                    {exitKindBadge(x, t)}
                    {view.exit_id === x.id ? <Badge tone="ok">{t('ai.exit.current')}</Badge> : null}
                  </span>
                  {x.path?.length ? <HopPath hops={x.path} /> : null}
                  {!usable ? <span className="small err-text">{x.ai_problem || t('ai.exit.unusable')}</span> : null}
                  {x.warning ? <span className="small warn-text">{x.warning}</span> : null}
                </span>
              </label>
            </li>
          )
        })}
      </ul>
      <div className="row-end">
        <Button
          variant="primary"
          busy={busy}
          disabled={!pick || pick === view.exit_id}
          onClick={async () => {
            setBusy(true)
            await choose(pick)
            setBusy(false)
          }}
        >
          {t('ai.exit.use')}
        </Button>
      </div>
    </div>
  )
}

function PlaintextWarning({ protocol }: { protocol: string }) {
  const { t } = useI18n()
  if (protocol !== 'socks5' && protocol !== 'http') return null
  return <Notice tone="warn" title={t('ai.plain.title')}>{t('ai.plain.detail')}</Notice>
}

function hostPortOK(s: string) {
  const v = s.trim()
  const m = /^(\[[0-9a-fA-F:.]+\]|[^\s:[\]]+):(\d{1,5})$/.exec(v)
  return !!m && Number(m[2]) >= 1 && Number(m[2]) <= 65535
}

function ChainForm({ kind, relays, choose }: { kind: 'relay' | 'forwarder'; relays: RelayView[]; choose: (id: string, created?: boolean) => Promise<boolean> }) {
  const { t } = useI18n()
  const run = useRunner()
  const [relayId, setRelayId] = useState(relays[0]?.id ?? '')
  const relay = relays.find((r) => r.id === relayId)
  const [protocol, setProtocol] = useState<ChainProtocol>(relay?.target_kind ? 'node' : 'socks5')
  const [via, setVia] = useState('')
  const [name, setName] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [link, setLink] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (kind === 'relay') setProtocol(relay?.target_kind ? 'node' : 'socks5')
  }, [kind, relay?.id, relay?.target_kind])

  if (kind === 'relay' && relays.length === 0) {
    return (
      <Notice tone="neutral" title={t('ai.chain.noRelays')}>
        {t('ai.chain.noRelaysHint')} <Link to="/relays">{t('nav.relays')} →</Link>
      </Notice>
    )
  }

  const proxy = protocol !== 'node'
  const portNum = Number(port)
  const portOK = port === '' || (Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535)
  const hostGiven = host.trim() !== '' || port !== ''
  // Through one of this server's relays the relay target is the default proxy address; through
  // another server's forwarder the proxy address must be given.
  const proxyReady = kind === 'relay' ? (!hostGiven || (host.trim() !== '' && port !== '' && portOK)) : host.trim() !== '' && port !== '' && portOK
  const linkReady = link.trim() !== '' || (kind === 'relay' && !!relay?.target_kind)
  const viaReady = kind === 'relay' ? !!relay : hostPortOK(via)
  const ready = viaReady && (proxy ? proxyReady : linkReady)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!ready) return
    setBusy(true)
    const spec: ChainSpec = { name: name.trim() || undefined, protocol }
    if (kind === 'relay') spec.via_relay = relayId
    else spec.via_address = via.trim()
    if (proxy) {
      if (host.trim()) spec.host = host.trim()
      if (port) spec.port = portNum
      if (user) spec.username = user
      if (pass) spec.password = pass
    } else if (link.trim()) spec.link = link.trim()
    const r = await run(() => api.post<{ exit: ExitView }>('/api/exits/chain', spec))
    if (r?.exit) {
      if (await choose(r.exit.id, true)) {
        setPass('')
        setLink('')
      }
    }
    setBusy(false)
  }

  return (
    <form className="stack" onSubmit={(e) => void submit(e)}>
      <p className="muted small">{kind === 'relay' ? t('ai.chain.relayIntro') : t('ai.chain.forwarderIntro')}</p>
      {kind === 'relay' ? (
        <Field label={t('ai.chain.relay')} hint={relay ? t('ai.chain.relayTarget', { target: relay.target }) : undefined}>
          {(id, d) => (
            <Select id={id} aria-describedby={d} value={relayId} onChange={(e) => setRelayId(e.target.value)}>
              {relays.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} — {r.target}
                </option>
              ))}
            </Select>
          )}
        </Field>
      ) : (
        <Field label={t('ai.chain.via')} hint={t('ai.chain.viaHint')} required error={via && !hostPortOK(via) ? t('ai.chain.viaBad') : null}>
          {(id, d) => <Input id={id} aria-describedby={d} value={via} onChange={(e) => setVia(e.target.value)} placeholder="203.0.113.7:20001" autoCapitalize="none" autoComplete="off" spellCheck={false} className="mono" />}
        </Field>
      )}
      {relay && kind === 'relay' ? <PathChain items={[{ label: t('ai.lane.inbound'), kind: 'entry' }, { label: relay.name, kind: 'relay' }, { label: <span className="mono">{relay.target}</span>, kind: 'target' }, { label: t('ai.lane.internet'), kind: 'net' }]} /> : null}
      <Field label={t('ai.chain.end')}>
        {() => (
          <div className="mode-scroll">
            <Segmented<ChainProtocol>
              label={t('ai.chain.end')}
              value={protocol}
              onChange={setProtocol}
              options={[
                { value: 'socks5', label: 'SOCKS5' },
                { value: 'http', label: 'HTTP CONNECT' },
                { value: 'https', label: 'HTTPS CONNECT' },
                { value: 'node', label: t('ai.chain.node') },
              ]}
            />
          </div>
        )}
      </Field>
      {proxy ? (
        <>
          <div className="grid-fields">
            <Field label={kind === 'relay' ? `${t('exits.create.host')} ${t('common.optional')}` : t('exits.create.host')} required={kind !== 'relay'} hint={kind === 'relay' ? t('ai.chain.hostDefault') : t('ai.chain.hostHint')}>
              {(id, d) => <Input id={id} aria-describedby={d} value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="none" autoComplete="off" spellCheck={false} />}
            </Field>
            <Field label={kind === 'relay' ? `${t('exits.create.port')} ${t('common.optional')}` : t('exits.create.port')} required={kind !== 'relay'} error={portOK ? null : t('ai.chain.portBad')}>
              {(id) => <Input id={id} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, '').slice(0, 5))} />}
            </Field>
          </div>
          <div className="grid-fields">
            <Field label={`${t('exits.create.user')} ${t('common.optional')}`}>{(id) => <Input id={id} autoComplete="off" autoCapitalize="none" spellCheck={false} value={user} onChange={(e) => setUser(e.target.value)} />}</Field>
            <Field label={`${t('exits.create.pass')} ${t('common.optional')}`}>{(id) => <Input id={id} type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />}</Field>
          </div>
        </>
      ) : (
        <Field label={t('exits.create.link')} hint={kind === 'relay' && relay?.target_kind ? t('ai.chain.linkDefault', { kind: relay.target_kind }) : t('ai.chain.linkHint')} required={!(kind === 'relay' && relay?.target_kind)}>
          {(id, d) => <Textarea id={id} aria-describedby={d} rows={3} className="mono" spellCheck={false} autoCapitalize="none" autoComplete="off" value={link} onChange={(e) => setLink(e.target.value)} placeholder="vless://… hy2://… tuic://…" />}
        </Field>
      )}
      <PlaintextWarning protocol={protocol} />
      <Field label={`${t('exits.create.name')} ${t('common.optional')}`} hint={t('relays.create.nameHint')}>
        {(id, d) => <Input id={id} aria-describedby={d} maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}
      </Field>
      <div className="row-end">
        <Button type="submit" variant="primary" icon="plus" busy={busy} disabled={!ready}>
          {t('ai.chain.create')}
        </Button>
      </div>
    </form>
  )
}

function RemoteForm({ choose }: { choose: (id: string, created?: boolean) => Promise<boolean> }) {
  const { t } = useI18n()
  const run = useRunner()
  const [name, setName] = useState('')
  const [link, setLink] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!link.trim()) return
    setBusy(true)
    const r = await run(() => api.post<{ exit: ExitView }>('/api/exits', { name: name.trim(), protocol: 'remote', link: link.trim() }))
    if (r?.exit && (await choose(r.exit.id, true))) setLink('')
    setBusy(false)
  }
  return (
    <form className="stack" onSubmit={(e) => void submit(e)}>
      <p className="muted small">{t('ai.remote.intro')}</p>
      <Field label={t('exits.create.link')} required hint={t('exits.create.linkHint')}>
        {(id, d) => <Textarea id={id} aria-describedby={d} rows={3} className="mono" spellCheck={false} autoCapitalize="none" autoComplete="off" value={link} onChange={(e) => setLink(e.target.value)} placeholder="vless://… hy2://… tuic://…" />}
      </Field>
      <Field label={`${t('exits.create.name')} ${t('common.optional')}`}>{(id) => <Input id={id} maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
      <div className="row-end">
        <Button type="submit" variant="primary" icon="plus" busy={busy} disabled={!link.trim()}>
          {t('ai.chain.create')}
        </Button>
      </div>
    </form>
  )
}

// ---- end-to-end test -------------------------------------------------------------------

/** The exit addresses a passing test observed (layer 6). */
export function observedExitIPs(r: DiagResult): string[] {
  return [...new Set(r.steps.filter((s) => s.layer === 6 && s.level !== 'fail').flatMap((s) => findIPs(s.text)))]
}

function TestCard({ view }: { view: AIView }) {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [result, setResult] = useState<DiagResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!busy) return
    const start = Date.now()
    setElapsed(0)
    const id = window.setInterval(() => setElapsed(Math.round((Date.now() - start) / 1000)), 1000)
    return () => window.clearInterval(id)
  }, [busy])

  const start = async () => {
    setBusy(true)
    setResult(null)
    setError(null)
    try {
      setResult(await api.post<DiagResult>('/api/ai/test'))
    } catch (e) {
      setError(e instanceof ApiError && e.status === 429 ? t('ai.test.busy') : errorText(e, t))
    } finally {
      setBusy(false)
    }
  }
  const ips = result ? observedExitIPs(result) : []

  return (
    <Card
      title={t('ai.test')}
      subtitle={t('ai.testHint')}
      actions={
        <Button variant="primary" icon="test" busy={busy} disabled={!view.exit_id} onClick={() => void start()}>
          {t('ai.test.run')}
        </Button>
      }
    >
      <div className="stack">
        {!view.exit_id ? <p className="muted">{t('ai.test.noExit')}</p> : null}
        {busy ? (
          <div className="progress-line" role="status">
            <span className="progress-bar" aria-hidden="true" />
            <span className="muted small">{t('ai.test.running', { s: elapsed })}</span>
          </div>
        ) : null}
        {error ? <Notice tone="error">{error}</Notice> : null}
        {result ? (
          <>
            {ips.length > 0 ? (
              <div className="exit-ip">
                <span className="muted small">{t('ai.test.exitIP')}</span>
                <div className="exit-ip-list">
                  {ips.map((ip) => (
                    <strong key={ip} className="mono">
                      {ip}
                    </strong>
                  ))}
                </div>
              </div>
            ) : null}
            <DiagResultView result={result} marks={ips} />
          </>
        ) : null}
      </div>
    </Card>
  )
}

// ---- rule simulation -------------------------------------------------------------------

const routeTone: Record<AIRoute, Tone> = { ai: 'accent', original: 'neutral', blocked: 'error' }

function SimulateCard() {
  const { t } = useI18n()
  const run = useRunner()
  const [host, setHost] = useState('chat.openai.com')
  const [busy, setBusy] = useState(false)
  const [sim, setSim] = useState<AISimulation | null>(null)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!host.trim()) return
    setBusy(true)
    const r = await run(() => api.post<AISimulation>('/api/ai/simulate', { host: host.trim() }))
    setBusy(false)
    if (r) setSim(r)
  }
  return (
    <Card title={t('ai.sim')} subtitle={t('ai.simHint')}>
      <div className="stack">
        <form className="sim-form" onSubmit={(e) => void submit(e)}>
          <Input aria-label={t('ai.sim.host')} value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="none" autoComplete="off" spellCheck={false} inputMode="url" className="mono" />
          <Button type="submit" icon="search" busy={busy} disabled={!host.trim()}>
            {t('ai.sim.run')}
          </Button>
        </form>
        {sim ? (
          <div className="stack">
            <p className="small">
              <Badge>{t('ai.sim.badge')}</Badge> <span className="mono">{sim.host}</span>
            </p>
            {sim.nodes.length === 0 ? (
              <p className="muted">{t('ai.sim.noNodes')}</p>
            ) : (
              <ul className="sim-list">
                {sim.nodes.map((n) => (
                  <li key={n.id}>
                    <span className="sim-name">{n.name}</span>
                    <Badge tone={routeTone[n.route] ?? 'neutral'}>{t(`ai.route.${n.route}` as 'ai.route.ai')}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : null}
      </div>
    </Card>
  )
}

// ---- limits ----------------------------------------------------------------------------

function LimitsCard({ view }: { view: AIView }) {
  const { t } = useI18n()
  return (
    <Card title={t('ai.limits')}>
      <div className="stack">
        <ul className="plain-list">
          {view.limits.map((l, i) => (
            <li key={i}>{l}</li>
          ))}
        </ul>
        <details className="disclosure">
          <summary>
            <Icon name="chevron" size={15} />
            {t('ai.services', { n: view.services.length, v: view.rule_set })}
          </summary>
          <ul className="service-list">
            {view.services.map((s) => (
              <li key={s.name}>
                <strong>{s.name}</strong>
                <span className="mono small muted">{s.suffixes.join('  ')}</span>
              </li>
            ))}
          </ul>
        </details>
      </div>
    </Card>
  )
}

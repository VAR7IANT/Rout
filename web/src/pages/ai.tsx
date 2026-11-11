// AI smart routing: which inbound nodes send AI-service domains to a dedicated exit.
import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { ApiError, api } from '../core/api'
import { isPort, portDigits } from '../core/format'
import { useRemote } from '../core/hooks'
import { useI18n, type MessageKey, type TFn } from '../core/i18n'
import { Link } from '../core/router'
import { errorText, useAct } from '../core/session'
import type { AIRoute, AISimulation, AIView, ChainProtocol, ChainSpec, DiagResult, ExitView, RelayView } from '../core/types'
import { DiagReport, ExitRoute, LoadState, Route, findIPs, type HopKind } from '../ui/domain'
import { Button, Checkbox, Field, Input, Notice, PageHead, Panel, Segmented, Select, Switch, Tag, Textarea, cx, type Tone } from '../ui/kit'

type Hop = { label: string; kind: HopKind }
/** Called once an exit should become the AI exit; resolves true when the server accepted it. */
type Choose = (id: string, created?: boolean) => Promise<boolean>

const laneName = (exit: string, t: TFn) => (exit === 'direct' ? t('ai.lane.direct') : exit)
const LINK_PLACEHOLDER = 'vless://… hy2://… tuic://…'

export function AIPage() {
  const { t } = useI18n()
  const res = useRemote<AIView>('/api/ai')
  const view = res.data
  if (!view) return <LoadState res={res} />
  // Every write answers with the whole new view, so the page never needs a second request.
  const update = (next: AIView) => res.set(next)
  return (
    <div className="page">
      <PageHead title={t('ai.title')} sub={t('ai.subtitle')} />
      <StatusPanel view={view} onChange={update} />
      <LanesPanel view={view} />
      <div className="cols-2">
        <NodesPanel view={view} onChange={update} />
        <ExitPanel view={view} onChange={update} reload={res.reload} />
      </div>
      <TestPanel view={view} />
      <SimulatePanel />
      <LimitsPanel view={view} />
    </div>
  )
}

// ---- status ----------------------------------------------------------------------------

function StatusPanel({ view, onChange }: { view: AIView; onChange: (v: AIView) => void }) {
  const { t } = useI18n()
  const act = useAct()
  const [busy, setBusy] = useState<'toggle' | 'apply' | null>(null)
  const stale = view.nodes.filter((n) => !n.in_sync)
  const bound = view.nodes.filter((n) => n.bound).length

  const send = async (what: 'toggle' | 'apply', call: () => Promise<AIView>, ok: string) => {
    setBusy(what)
    const next = await act(call, { ok })
    setBusy(null)
    if (next) onChange(next)
  }

  return (
    <Panel tone={view.problems.length > 0 ? 'warn' : undefined}>
      <div className="stack">
        <div className="between">
          <div className="row">
            <Switch checked={view.enabled} label={t('ai.enable')} disabled={busy !== null} onChange={(on) => void send('toggle', () => api.post<AIView>('/api/ai/enabled', { enabled: on }), t(on ? 'ai.enabledOk' : 'ai.disabledOk'))} />
            <div>
              <strong className={view.enabled ? 'ok' : undefined}>{t(view.enabled ? 'ai.on' : 'ai.off')}</strong>
              <div className="dim small">{view.enabled ? t('ai.onHint', { n: bound }) : t('ai.offHint')}</div>
            </div>
          </div>
          <div className="row">
            <Tag>{t('ai.ruleSet', { v: view.rule_set })}</Tag>
            {view.rule_set_available > view.rule_set ? <Tag tone="accent">{t('ai.ruleSetNew', { v: view.rule_set_available })}</Tag> : null}
            {view.exit ? <Tag tone={view.exit.ai_usable === false ? 'error' : 'ok'}>{t('ai.exitIs', { name: view.exit.name })}</Tag> : <Tag tone="warn">{t('ai.noExit')}</Tag>}
          </div>
        </div>
        {view.problems.map((problem, i) => (
          <Notice key={i} tone="warn">
            {problem}
          </Notice>
        ))}
        {stale.length > 0 ? (
          <Notice
            tone="accent"
            title={t('ai.unsynced')}
            action={
              <Button size="sm" variant="primary" icon="refresh" busy={busy === 'apply'} disabled={busy !== null} onClick={() => void send('apply', () => api.post<AIView>('/api/ai/apply'), t('ai.applied'))}>
                {t('ai.apply')}
              </Button>
            }
          >
            {t('ai.unsyncedDetail', { names: stale.map((n) => n.name).join(', ') })}
          </Notice>
        ) : null}
      </div>
    </Panel>
  )
}

// ---- the two paths ---------------------------------------------------------------------

function LanesPanel({ view }: { view: AIView }) {
  const { t } = useI18n()
  const bound = view.nodes.filter((n) => n.bound)
  const inbound = bound.length > 0 ? bound.map((n) => n.name).join(', ') : t('ai.lane.noNodes')
  const ordinary = [...new Set((bound.length > 0 ? bound : view.nodes).map((n) => laneName(n.exit, t)))]
  const start: Hop[] = [
    { label: t('ai.lane.client'), kind: 'client' },
    { label: inbound, kind: 'entry' },
  ]
  // The exit's path starts with "this server", which the inbound hop already shows.
  const exitHops = view.exit?.path?.slice(1) ?? []
  const aiTail: Hop[] =
    exitHops.length > 0 ? exitHops.map((label, i) => ({ label, kind: i === exitHops.length - 1 ? 'net' : i === exitHops.length - 2 ? 'exit' : 'relay' })) : [{ label: t('ai.noExit'), kind: 'target' }]
  return (
    <Panel title={t('ai.lanes')}>
      <div className="stack">
        <p className="dim small">{t('ai.lanesHint')}</p>
        <div className="lane">
          <div className="lane__head">
            <strong>{t('ai.lane.normal')}</strong>
            <span className="dim small">{t('ai.lane.normalHint')}</span>
          </div>
          <Route
            hops={[
              ...start,
              { label: ordinary.length > 0 ? ordinary.join(' / ') : t('ai.lane.direct'), kind: 'exit' },
              { label: t('ai.lane.internet'), kind: 'net' },
            ]}
          />
        </div>
        <div className="lane lane--ai">
          <div className="lane__head">
            <strong>{t('ai.lane.ai')}</strong>
            <span className="dim small">{t(view.enabled ? 'ai.lane.aiHint' : 'ai.lane.aiOff')}</span>
          </div>
          <Route hops={[...start, ...aiTail]} />
        </div>
      </div>
    </Panel>
  )
}

// ---- inbound nodes ---------------------------------------------------------------------

function NodesPanel({ view, onChange }: { view: AIView; onChange: (v: AIView) => void }) {
  const { t } = useI18n()
  const act = useAct()
  // What the server has, as a stable string; the checklist restarts from it whenever it changes.
  const saved = useMemo(
    () =>
      view.nodes
        .filter((n) => n.bound)
        .map((n) => n.id)
        .sort()
        .join(','),
    [view.nodes],
  )
  const [picked, setPicked] = useState<Set<string>>(() => new Set(saved ? saved.split(',') : []))
  const [busy, setBusy] = useState(false)
  useEffect(() => setPicked(new Set(saved ? saved.split(',') : [])), [saved])

  const dirty = [...picked].sort().join(',') !== saved
  const save = async () => {
    setBusy(true)
    const ids = view.nodes.filter((n) => picked.has(n.id)).map((n) => n.id) // keep the server's order
    const next = await act(() => api.put<AIView>('/api/ai/bindings', { ids }), { ok: t('ai.nodes.saved') })
    setBusy(false)
    if (next) onChange(next)
  }
  const flip = (id: string, on: boolean) =>
    setPicked((old) => {
      const next = new Set(old)
      if (on) next.add(id)
      else next.delete(id)
      return next
    })

  return (
    <Panel
      title={t('ai.nodes')}
      actions={
        <Button size="sm" variant="primary" icon="check" busy={busy} disabled={!dirty} onClick={() => void save()}>
          {t('common.save')}
        </Button>
      }
    >
      <div className="stack">
        <p className="dim small">{t('ai.nodesHint')}</p>
        {view.nodes.length === 0 ? (
          <p className="dim">
            {t('ai.nodes.empty')} <Link to="/nodes">{t('nav.nodes')} →</Link>
          </p>
        ) : (
          <ul className="picks">
            {view.nodes.map((n) => (
              <li key={n.id} className={cx('picks__item', picked.has(n.id) && 'is-on', !n.eligible && 'is-off')}>
                <Checkbox checked={picked.has(n.id)} disabled={!n.eligible || busy} onChange={(on) => flip(n.id, on)}>
                  <span className="row">
                    <strong>{n.name}</strong>
                    <Tag>{n.protocol}</Tag>
                    {n.bound && !n.in_sync ? <Tag tone="warn">{t('ai.nodes.unsynced')}</Tag> : null}
                  </span>
                  <span className="dim small">
                    {n.running} · {t('ai.nodes.route', { exit: laneName(n.exit, t) })}
                  </span>
                  {n.eligible ? n.note ? <span className="dim small">{n.note}</span> : null : <span className="warn small">{n.note ? t('ai.nodes.ineligible', { why: n.note }) : t('ai.nodes.ineligibleBare')}</span>}
                </Checkbox>
              </li>
            ))}
          </ul>
        )}
        {dirty ? <p className="warn small">{t('ai.nodes.dirty')}</p> : null}
      </div>
    </Panel>
  )
}

// ---- the AI exit -----------------------------------------------------------------------

type Mode = 'existing' | 'relay' | 'remote' | 'forwarder'

function ExitPanel({ view, onChange, reload }: { view: AIView; onChange: (v: AIView) => void; reload: () => Promise<void> }) {
  const { t } = useI18n()
  const act = useAct()
  const [mode, setMode] = useState<Mode>('existing')

  const choose: Choose = async (id, created) => {
    const next = await act(() => api.put<AIView>('/api/ai/exit', { exit_id: id }), { ok: t(created ? 'ai.exit.createdUsed' : 'ai.exit.used') })
    if (next) {
      onChange(next)
      setMode('existing')
    } else if (created) await reload() // the exit exists even though it could not be selected
    return !!next
  }

  return (
    <Panel title={t('ai.exit')}>
      <div className="stack">
        <p className="dim small">{t('ai.exitHint')}</p>
        <div className="scroll-x">
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
        {mode === 'relay' ? <ChainForm via="relay" relays={view.relays} choose={choose} /> : null}
        {mode === 'forwarder' ? <ChainForm via="forwarder" relays={[]} choose={choose} /> : null}
        {mode === 'remote' ? <RemoteForm choose={choose} /> : null}
      </div>
    </Panel>
  )
}

function ExistingExits({ view, choose }: { view: AIView; choose: Choose }) {
  const { t } = useI18n()
  const [pick, setPick] = useState(view.exit_id ?? '')
  const [busy, setBusy] = useState(false)
  useEffect(() => setPick(view.exit_id ?? ''), [view.exit_id])
  if (view.exits.length === 0) return <p className="dim">{t('ai.exit.none')}</p>
  const use = async () => {
    setBusy(true)
    await choose(pick)
    setBusy(false)
  }
  const kindTag = (x: ExitView) => (x.kind === 'chain' ? <Tag tone="accent">{t('exits.kind.chain')}</Tag> : x.kind === 'remote' ? <Tag>{t('exits.kind.remote')}</Tag> : <Tag>{x.label}</Tag>)
  return (
    <div className="stack">
      <ul className="picks" role="radiogroup" aria-label={t('ai.mode.existing')}>
        {view.exits.map((x) => {
          const usable = x.ai_usable !== false
          return (
            <li key={x.id} className={cx('picks__item', pick === x.id && 'is-on', !usable && 'is-off')}>
              <label className="radio">
                <input type="radio" name="ai-exit" value={x.id} checked={pick === x.id} disabled={!usable || busy} onChange={() => setPick(x.id)} />
                <span className="radio__mark" aria-hidden="true" />
                <span className="check__text">
                  <span className="row">
                    <strong>{x.name}</strong>
                    {kindTag(x)}
                    {view.exit_id === x.id ? <Tag tone="ok">{t('ai.exit.current')}</Tag> : null}
                  </span>
                  {x.path?.length ? <ExitRoute hops={x.path} /> : null}
                  {usable ? null : <span className="err small">{x.ai_problem || t('ai.exit.unusable')}</span>}
                  {x.warning ? <span className="warn small">{x.warning}</span> : null}
                </span>
              </label>
            </li>
          )
        })}
      </ul>
      <div className="row row--end">
        <Button variant="primary" busy={busy} disabled={!pick || pick === view.exit_id} onClick={() => void use()}>
          {t('ai.exit.use')}
        </Button>
      </div>
    </div>
  )
}

/** "host:port" or "[v6]:port" with a usable port. */
export function isHostPort(text: string): boolean {
  const m = /^(\[[0-9a-fA-F:.]+\]|[^\s:[\]]+):(\d{1,5})$/.exec(text.trim())
  return !!m && isPort(m[2])
}

/** A relay that carries a node link or UDP ends in a node; anything else in a SOCKS5 proxy. */
const defaultEnd = (relay: RelayView | undefined): ChainProtocol => (relay?.target_kind || relay?.transport === 'udp' ? 'node' : 'socks5')

/**
 * A relay-chain exit: the real proxy (or remote node) at the end of a forward. The hop is
 * either one of this server's relays, or a forwarder on another server given as host:port.
 */
function ChainForm({ via, relays, choose }: { via: 'relay' | 'forwarder'; relays: RelayView[]; choose: Choose }) {
  const { t } = useI18n()
  const act = useAct()
  const [relayId, setRelayId] = useState(relays[0]?.id ?? '')
  const relay = relays.find((r) => r.id === relayId)
  const [end, setEnd] = useState<ChainProtocol>(() => defaultEnd(relay))
  const [forwarder, setForwarder] = useState('')
  const [name, setName] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [link, setLink] = useState('')
  const [busy, setBusy] = useState(false)
  const throughRelay = via === 'relay'

  // Picking another relay re-suggests what sits at its end.
  useEffect(() => {
    if (throughRelay) setEnd(defaultEnd(relay))
    // Only the relay's identity and shape matter, not the object.
  }, [throughRelay, relay?.id, relay?.target_kind, relay?.transport])

  if (throughRelay && relays.length === 0)
    return (
      <Notice title={t('ai.chain.noRelays')}>
        {t('ai.chain.noRelaysHint')} <Link to="/relays">{t('nav.relays')} →</Link>
      </Notice>
    )

  const proxy = end !== 'node'
  const portOK = port === '' || isPort(port)
  const addressGiven = host.trim() !== '' && port !== '' && portOK
  // Through a local relay the relay's own target is the default proxy address (and node link);
  // through someone else's forwarder both must be spelled out.
  const proxyReady = throughRelay ? addressGiven || (host.trim() === '' && port === '') : addressGiven
  const linkReady = link.trim() !== '' || (throughRelay && !!relay?.target_kind)
  const ready = (throughRelay ? !!relay : isHostPort(forwarder)) && (proxy ? proxyReady : linkReady)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!ready) return
    setBusy(true)
    const spec: ChainSpec = { name: name.trim() || undefined, protocol: end }
    if (throughRelay) spec.via_relay = relayId
    else spec.via_address = forwarder.trim()
    if (!proxy) {
      if (link.trim()) spec.link = link.trim()
    } else {
      if (host.trim()) spec.host = host.trim()
      if (port) spec.port = Number(port)
      if (user) spec.username = user
      if (pass) spec.password = pass
    }
    const made = await act(() => api.post<{ exit: ExitView }>('/api/exits/chain', spec))
    if (made?.exit && (await choose(made.exit.id, true))) {
      setPass('')
      setLink('')
    }
    setBusy(false)
  }

  const optional = (key: MessageKey) => (throughRelay ? `${t(key)} ${t('common.optional')}` : t(key))

  return (
    <form className="stack" onSubmit={(e) => void submit(e)}>
      <p className="dim small">{t(throughRelay ? 'ai.chain.relayIntro' : 'ai.chain.forwarderIntro')}</p>
      {throughRelay ? (
        <Field label={t('ai.chain.relay')} hint={relay ? t('ai.chain.relayTarget', { target: relay.target }) : undefined}>
          {(id, note) => (
            <Select id={id} aria-describedby={note} value={relayId} onChange={(e) => setRelayId(e.target.value)}>
              {relays.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} — {r.target}
                </option>
              ))}
            </Select>
          )}
        </Field>
      ) : (
        <Field label={t('ai.chain.via')} hint={t('ai.chain.viaHint')} required error={forwarder && !isHostPort(forwarder) ? t('ai.chain.viaBad') : null}>
          {(id, note) => <Input id={id} aria-describedby={note} value={forwarder} onChange={(e) => setForwarder(e.target.value)} placeholder="203.0.113.7:20001" autoCapitalize="none" autoComplete="off" />}
        </Field>
      )}
      {throughRelay && relay ? (
        <Route
          hops={[
            { label: t('ai.lane.inbound'), kind: 'entry' },
            { label: relay.name, kind: 'relay' },
            { label: relay.target, kind: 'target' },
            { label: t('ai.lane.internet'), kind: 'net' },
          ]}
        />
      ) : null}
      <Field label={t('ai.chain.end')}>
        {() => (
          <div className="scroll-x">
            <Segmented<ChainProtocol>
              label={t('ai.chain.end')}
              value={end}
              onChange={setEnd}
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
          <div className="cols-2">
            <Field label={optional('exits.create.host')} required={!throughRelay} hint={t(throughRelay ? 'ai.chain.hostDefault' : 'ai.chain.hostHint')}>
              {(id, note) => <Input id={id} aria-describedby={note} value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="none" autoComplete="off" />}
            </Field>
            <Field label={optional('exits.create.port')} required={!throughRelay} error={portOK ? null : t('ai.chain.portBad')}>
              {(id) => <Input id={id} inputMode="numeric" value={port} onChange={(e) => setPort(portDigits(e.target.value))} />}
            </Field>
          </div>
          <div className="cols-2">
            <Field label={`${t('exits.create.user')} ${t('common.optional')}`}>{(id) => <Input id={id} autoComplete="off" autoCapitalize="none" value={user} onChange={(e) => setUser(e.target.value)} />}</Field>
            <Field label={`${t('exits.create.pass')} ${t('common.optional')}`}>{(id) => <Input id={id} type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />}</Field>
          </div>
        </>
      ) : (
        <Field label={t('exits.create.link')} required={!(throughRelay && relay?.target_kind)} hint={throughRelay && relay?.target_kind ? t('ai.chain.linkDefault', { kind: relay.target_kind }) : t('ai.chain.linkHint')}>
          {(id, note) => <Textarea id={id} aria-describedby={note} rows={3} autoCapitalize="none" autoComplete="off" value={link} onChange={(e) => setLink(e.target.value)} placeholder={LINK_PLACEHOLDER} />}
        </Field>
      )}
      {end === 'socks5' || end === 'http' ? (
        <Notice tone="warn" title={t('ai.plain.title')}>
          {t('ai.plain.detail')}
        </Notice>
      ) : null}
      <Field label={`${t('exits.create.name')} ${t('common.optional')}`} hint={t('relays.create.nameHint')}>
        {(id, note) => <Input id={id} aria-describedby={note} maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}
      </Field>
      <div className="row row--end">
        <Button type="submit" variant="primary" icon="plus" busy={busy} disabled={!ready}>
          {t('ai.chain.create')}
        </Button>
      </div>
    </form>
  )
}

/** A node on another server, by share link, as the AI exit. */
function RemoteForm({ choose }: { choose: Choose }) {
  const { t } = useI18n()
  const act = useAct()
  const [name, setName] = useState('')
  const [link, setLink] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!link.trim()) return
    setBusy(true)
    const made = await act(() => api.post<{ exit: ExitView }>('/api/exits', { name: name.trim(), protocol: 'remote', link: link.trim() }))
    if (made?.exit && (await choose(made.exit.id, true))) setLink('')
    setBusy(false)
  }
  return (
    <form className="stack" onSubmit={(e) => void submit(e)}>
      <p className="dim small">{t('ai.remote.intro')}</p>
      <Field label={t('exits.create.link')} required hint={t('exits.create.linkHint')}>
        {(id, note) => <Textarea id={id} aria-describedby={note} rows={3} autoCapitalize="none" autoComplete="off" value={link} onChange={(e) => setLink(e.target.value)} placeholder={LINK_PLACEHOLDER} />}
      </Field>
      <Field label={`${t('exits.create.name')} ${t('common.optional')}`}>{(id) => <Input id={id} maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
      <div className="row row--end">
        <Button type="submit" variant="primary" icon="plus" busy={busy} disabled={!link.trim()}>
          {t('ai.chain.create')}
        </Button>
      </div>
    </form>
  )
}

// ---- end-to-end test -------------------------------------------------------------------

const EXIT_LAYER = 6 // the layer that reports the address requests really left from

/** The exit addresses a test observed, taken from the non-failing steps of the exit layer. */
export function observedExitIPs(r: DiagResult): string[] {
  return [...new Set(r.steps.filter((s) => s.layer === EXIT_LAYER && s.level !== 'fail').flatMap((s) => findIPs(s.text)))]
}

function TestPanel({ view }: { view: AIView }) {
  const { t } = useI18n()
  const [running, setRunning] = useState(false)
  const [seconds, setSeconds] = useState(0)
  const [result, setResult] = useState<DiagResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!running) return
    const began = Date.now()
    setSeconds(0)
    const timer = window.setInterval(() => setSeconds(Math.round((Date.now() - began) / 1000)), 1000)
    return () => window.clearInterval(timer)
  }, [running])

  const start = async () => {
    setRunning(true)
    setResult(null)
    setError(null)
    try {
      setResult(await api.post<DiagResult>('/api/ai/test'))
    } catch (e) {
      // 429 here means another test is still running, not a login lock-out.
      setError(e instanceof ApiError && e.status === 429 ? t('ai.test.busy') : errorText(e, t))
    } finally {
      setRunning(false)
    }
  }
  const ips = result ? observedExitIPs(result) : []

  return (
    <Panel
      title={t('ai.test')}
      actions={
        <Button size="sm" variant="primary" icon="play" busy={running} disabled={!view.exit_id} onClick={() => void start()}>
          {t('ai.test.run')}
        </Button>
      }
    >
      <div className="stack">
        <p className="dim small">{t('ai.testHint')}</p>
        {view.exit_id ? null : <p className="dim">{t('ai.test.noExit')}</p>}
        {running ? (
          <p className="dim small" role="status">
            {t('ai.test.running', { s: seconds })}
            <span className="cursor" />
          </p>
        ) : null}
        {error ? <Notice tone="error">{error}</Notice> : null}
        {result ? (
          <>
            {ips.length > 0 ? (
              <div className="exit-ip">
                <span className="dim small">{t('ai.test.exitIP')}</span>
                {ips.map((ip) => (
                  <strong key={ip}>{ip}</strong>
                ))}
              </div>
            ) : null}
            <DiagReport result={result} marks={ips} />
          </>
        ) : null}
      </div>
    </Panel>
  )
}

// ---- rule simulation -------------------------------------------------------------------

const routeTone: Record<AIRoute, Tone> = { ai: 'accent', original: 'neutral', blocked: 'error' }

function SimulatePanel() {
  const { t } = useI18n()
  const act = useAct()
  const [host, setHost] = useState('chat.openai.com')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<AISimulation | null>(null)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!host.trim()) return
    setBusy(true)
    const r = await act(() => api.post<AISimulation>('/api/ai/simulate', { host: host.trim() }))
    setBusy(false)
    if (r) setResult(r)
  }
  return (
    <Panel title={t('ai.sim')}>
      <div className="stack">
        <p className="dim small">{t('ai.simHint')}</p>
        <form className="inline-form" onSubmit={(e) => void submit(e)}>
          <Input aria-label={t('ai.sim.host')} value={host} onChange={(e) => setHost(e.target.value)} autoCapitalize="none" autoComplete="off" inputMode="url" />
          <Button type="submit" icon="search" busy={busy} disabled={!host.trim()}>
            {t('ai.sim.run')}
          </Button>
        </form>
        {result ? (
          <div className="stack stack--tight">
            <p className="row">
              <Tag>{t('ai.sim.badge')}</Tag>
              {result.host}
            </p>
            {result.nodes.length === 0 ? (
              <p className="dim">{t('ai.sim.noNodes')}</p>
            ) : (
              <ul className="stack stack--tight">
                {result.nodes.map((n) => (
                  <li key={n.id} className="between">
                    <span>{n.name}</span>
                    <Tag tone={routeTone[n.route] ?? 'neutral'}>{t(`ai.route.${n.route}` as MessageKey)}</Tag>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : null}
      </div>
    </Panel>
  )
}

// ---- limits ----------------------------------------------------------------------------

function LimitsPanel({ view }: { view: AIView }) {
  const { t } = useI18n()
  return (
    <Panel title={t('ai.limits')}>
      <div className="stack">
        <ul className="bullets">
          {view.limits.map((limit, i) => (
            <li key={i}>{limit}</li>
          ))}
        </ul>
        <details className="fold">
          <summary>{t('ai.services', { n: view.services.length, v: view.rule_set })}</summary>
          <ul className="services">
            {view.services.map((s) => (
              <li key={s.name}>
                <strong>{s.name}</strong>
                <span className="dim small">{s.suffixes.join('  ')}</span>
              </li>
            ))}
          </ul>
        </details>
      </div>
    </Panel>
  )
}

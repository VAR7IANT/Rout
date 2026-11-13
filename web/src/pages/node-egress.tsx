// The outbound IP family of a node: the selector (used when creating nodes and in the node
// drawer) and the egress test. The policy itself lives on the server and is the same setting
// the terminal menu edits; this file only asks and shows.
import { useState } from 'react'
import { api } from '../core/api'
import { useI18n, type MessageKey, type TFn } from '../core/i18n'
import { useAct } from '../core/session'
import type { EgressCheck, EgressReport, NodeView, PolicyChoice } from '../core/types'
import { Button, Checkbox, Notice, Select, Tag, type Tone } from '../ui/kit'

const ALL: PolicyChoice[] = (['auto', 'ipv4_first', 'ipv6_first', 'ipv4_only', 'ipv6_only'] as const).map((policy) => ({ policy, available: true }))

export const policyLabel = (t: TFn, policy: string | undefined): string => t(`egress.policy.${policy || 'auto'}` as MessageKey)

/** True when the chosen policy needs a family this host cannot route and that is not yet acknowledged. */
export function needsConfirm(choices: PolicyChoice[] | undefined, value: string, confirmed: boolean): boolean {
  const choice = choices?.find((c) => c.policy === value)
  return !!choice && !choice.available && !confirmed
}

interface PickerProps {
  id?: string
  describedBy?: string
  value: string
  onChange: (v: string) => void
  /** What the server says this host can do; all five policies when it did not say. */
  choices?: PolicyChoice[]
  confirmed: boolean
  onConfirm: (v: boolean) => void
}

/** The policy list, what the chosen one means, and the acknowledgement an unusable one needs. */
export function PolicyPicker({ id, describedBy, value, onChange, choices, confirmed, onConfirm }: PickerProps) {
  const { t } = useI18n()
  const list = choices?.length ? choices : ALL
  const chosen = list.find((c) => c.policy === value)
  return (
    <div className="stack stack--tight">
      <Select
        id={id}
        aria-describedby={describedBy}
        value={value}
        onChange={(e) => {
          onChange(e.target.value)
          onConfirm(false) // an acknowledgement belongs to one choice
        }}
      >
        {list.map((c) => (
          <option key={c.policy} value={c.policy}>
            {policyLabel(t, c.policy)}
            {c.missing ? ` — ${t('egress.missing', { family: c.missing })}` : ''}
          </option>
        ))}
      </Select>
      <p className="dim small">{t(`egress.desc.${value || 'auto'}` as MessageKey)}</p>
      {chosen?.missing ? <p className="warn small">{t('egress.missing', { family: chosen.missing })}</p> : null}
      {chosen && !chosen.available ? (
        <Checkbox checked={confirmed} onChange={onConfirm}>
          {t('egress.confirm', { family: chosen.missing ?? '' })}
        </Checkbox>
      ) : null}
    </div>
  )
}

/** One node's policy: the current value, changing it, and the egress test. */
export function EgressSection({ node, choices, onChanged }: { node: NodeView; choices?: PolicyChoice[]; onChanged: () => Promise<void> }) {
  const { t } = useI18n()
  const act = useAct()
  const current = node.outbound_policy || 'auto'
  const [value, setValue] = useState(current)
  const [confirmed, setConfirmed] = useState(false)
  const [saving, setSaving] = useState(false)

  const save = async () => {
    setSaving(true)
    const r = await act(() => api.put(`/api/nodes/${node.id}/outbound-policy`, { policy: value, force: confirmed }), { ok: t('egress.saved') })
    setSaving(false)
    if (r === undefined) return
    setConfirmed(false)
    await onChanged()
  }

  return (
    <div className="stack">
      <div className="row">
        <span className="dim small">{t('egress.current')}</span>
        <Tag tone={current === 'auto' ? 'neutral' : 'accent'}>{policyLabel(t, current)}</Tag>
        {current !== 'auto' ? <Tag tone={node.outbound_enforced ? 'ok' : 'warn'}>{t(node.outbound_enforced ? 'egress.enforced' : 'egress.notEnforced')}</Tag> : null}
      </div>
      {node.outbound_note ? <p className="dim small">{node.outbound_note}</p> : null}
      <PolicyPicker value={value} onChange={setValue} choices={choices} confirmed={confirmed} onConfirm={setConfirmed} />
      <div className="row">
        <Button variant="primary" size="sm" onClick={() => void save()} busy={saving} disabled={value === current || needsConfirm(choices, value, confirmed)}>
          {t('egress.save')}
        </Button>
      </div>
      <p className="dim small">{t('egress.saveHint')}</p>
      <EgressTest node={node} />
    </div>
  )
}

function EgressTest({ node }: { node: NodeView }) {
  const { t } = useI18n()
  const act = useAct()
  const [running, setRunning] = useState<'test' | 'ip' | null>(null)
  const [report, setReport] = useState<EgressReport | null>(null)
  const start = async (quick: boolean) => {
    setRunning(quick ? 'ip' : 'test')
    setReport(null)
    const r = await act(() => api.post<EgressReport>(`/api/nodes/${node.id}/egress-test`, { quick }))
    if (r) setReport(r)
    setRunning(null)
  }
  const blocked = running !== null || !node.enabled
  return (
    <div className="stack">
      <div className="row">
        <Button icon="play" onClick={() => void start(false)} busy={running === 'test'} disabled={blocked}>
          {t('egress.test')}
        </Button>
        <Button icon="pulse" onClick={() => void start(true)} busy={running === 'ip'} disabled={blocked}>
          {t('egress.testIp')}
        </Button>
      </div>
      <p className="dim small">{t('egress.testHint')}</p>
      {running ? <p className="dim small">{t('egress.running')}</p> : null}
      {report ? <EgressResult report={report} /> : null}
    </div>
  )
}

const checkLook: Record<EgressCheck['status'], { mark: string; cls: string }> = {
  pass: { mark: '✓', cls: 'ok' },
  fail: { mark: '✗', cls: 'fail' },
  inconclusive: { mark: '!', cls: 'warn' },
  info: { mark: '·', cls: 'info' },
}
const verdictTone: Record<string, Tone> = { pass: 'ok', fail: 'error' }

/**
 * What the host itself measured and what was measured through the node are separate, labelled
 * blocks, so one is never mistaken for the other. A quick look ("show outbound IPs") carries
 * no verdict unless it could not even finish.
 */
export function EgressResult({ report }: { report: EgressReport }) {
  const { t } = useI18n()
  const has = (b: boolean) => t(b ? 'egress.have' : 'egress.none')
  const listing = report.quick && !report.result
  return (
    <div className="diag" aria-live="polite">
      <Notice tone={listing ? 'neutral' : (verdictTone[report.result] ?? 'warn')} title={listing ? t('egress.result.quick') : t(`egress.result.${report.result || 'inconclusive'}` as MessageKey)} />
      <section className="diag__layer">
        <h4>{t('egress.host.title')}</h4>
        <ul>
          {(['v4', 'v6'] as const).map((f) => (
            <li key={f} className="diag__step diag__step--info">
              <span className="diag__mark" aria-hidden="true">
                ·
              </span>
              <span>
                <strong>{f === 'v4' ? 'IPv4' : 'IPv6'}</strong> · {t('egress.route')} {has(report.host[f].route)} · {t('egress.dns')} {has(report.host[f].dns)} · {t('egress.hostIp')} {report.host[f].ip || t('egress.unavailable')}
              </span>
            </li>
          ))}
        </ul>
      </section>
      <section className="diag__layer">
        <h4>{t('egress.node.title')}</h4>
        <ul>
          {report.checks.map((c) => (
            <li key={c.key} className={`diag__step diag__step--${checkLook[c.status].cls}`}>
              <span className="diag__mark" aria-hidden="true">
                {checkLook[c.status].mark}
              </span>
              <span>{c.text}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}

import { useState } from 'react'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { useRunner } from '../lib/session'
import type { EgressReport, NodeView, PolicyChoice } from '../lib/types'
import { Badge, Button, Notice, Select, Toggle } from '../components/ui'
import { Icon } from '../components/icons'

// The outbound IP family of a node: one selector used by "new nodes" and by the node drawer, and
// the egress test. The policy itself lives on the server (the same setting the terminal menu
// edits); this file only asks and shows.

const FALLBACK: PolicyChoice[] = (['auto', 'ipv4_first', 'ipv6_first', 'ipv4_only', 'ipv6_only'] as const).map((policy) => ({ policy, available: true }))

export function policyLabel(t: ReturnType<typeof useI18n>['t'], policy: string | undefined): string {
  return t(`egress.policy.${policy || 'auto'}` as 'egress.policy.auto')
}

/** The policy list with its explanation, and the confirmation an unusable choice needs. */
export function PolicyPicker({
  id,
  value,
  onChange,
  choices,
  confirmed,
  onConfirm,
  describedBy,
}: {
  id?: string
  value: string
  onChange: (v: string) => void
  choices?: PolicyChoice[]
  confirmed: boolean
  onConfirm: (v: boolean) => void
  describedBy?: string
}) {
  const { t } = useI18n()
  const list = choices && choices.length > 0 ? choices : FALLBACK
  const chosen = list.find((c) => c.policy === value)
  const blocked = !!chosen && !chosen.available
  return (
    <div className="stack-tight">
      <Select
        id={id}
        aria-describedby={describedBy}
        value={value}
        onChange={(e) => {
          onChange(e.target.value)
          onConfirm(false)
        }}
      >
        {list.map((c) => (
          <option key={c.policy} value={c.policy}>
            {policyLabel(t, c.policy)}
            {c.missing ? ` — ${t('egress.missing', { family: c.missing })}` : ''}
          </option>
        ))}
      </Select>
      <p className="muted small">{t(`egress.desc.${value || 'auto'}` as 'egress.desc.auto')}</p>
      {chosen?.missing ? <p className="warn-text small">{t('egress.missing', { family: chosen.missing })}</p> : null}
      {blocked ? (
        <Toggle checked={confirmed} onChange={onConfirm}>
          {t('egress.confirm', { family: chosen!.missing ?? '' })}
        </Toggle>
      ) : null}
    </div>
  )
}

/** True when the picked policy needs the confirmation and has not got it. */
export function policyNeedsConfirm(choices: PolicyChoice[] | undefined, value: string, confirmed: boolean): boolean {
  const c = (choices ?? []).find((x) => x.policy === value)
  return !!c && !c.available && !confirmed
}

/** The policy of one node: current value, change, and the egress test. */
export function EgressSection({ node, choices, onChanged }: { node: NodeView; choices?: PolicyChoice[]; onChanged: () => Promise<void> }) {
  const { t } = useI18n()
  const run = useRunner()
  const current = node.outbound_policy || 'auto'
  const [value, setValue] = useState(current)
  const [confirmed, setConfirmed] = useState(false)
  const [saving, setSaving] = useState(false)
  const dirty = value !== current

  const save = async () => {
    setSaving(true)
    const r = await run(() => api.put(`/api/nodes/${node.id}/outbound-policy`, { policy: value, force: confirmed }), { ok: t('egress.saved') })
    setSaving(false)
    if (r !== undefined) {
      setConfirmed(false)
      await onChanged()
    }
  }

  return (
    <div className="stack">
      <div className="row-wrap">
        <span className="muted small">{t('egress.current')}</span>
        <Badge tone={current === 'auto' ? 'neutral' : 'accent'}>{policyLabel(t, current)}</Badge>
        {current !== 'auto' ? <Badge tone={node.outbound_enforced ? 'ok' : 'warn'}>{node.outbound_enforced ? t('egress.enforced') : t('egress.notEnforced')}</Badge> : null}
      </div>
      {node.outbound_note ? <p className="muted small">{node.outbound_note}</p> : null}
      <PolicyPicker value={value} onChange={setValue} choices={choices} confirmed={confirmed} onConfirm={setConfirmed} />
      <div className="row-wrap">
        <Button variant="primary" size="sm" onClick={() => void save()} busy={saving} disabled={!dirty || policyNeedsConfirm(choices, value, confirmed)}>
          {t('egress.save')}
        </Button>
      </div>
      <p className="muted small">{t('egress.saveHint')}</p>
      <EgressTest node={node} />
    </div>
  )
}

function EgressTest({ node }: { node: NodeView }) {
  const { t } = useI18n()
  const run = useRunner()
  const [busy, setBusy] = useState<'test' | 'ip' | null>(null)
  const [report, setReport] = useState<EgressReport | null>(null)
  const start = async (quick: boolean) => {
    setBusy(quick ? 'ip' : 'test')
    setReport(null)
    const r = await run(() => api.post<EgressReport>(`/api/nodes/${node.id}/egress-test`, { quick }))
    if (r) setReport(r)
    setBusy(null)
  }
  return (
    <div className="stack">
      <div className="row-wrap">
        <Button icon="test" onClick={() => void start(false)} busy={busy === 'test'} disabled={busy !== null || !node.enabled}>
          {t('egress.test')}
        </Button>
        <Button icon="pulse" onClick={() => void start(true)} busy={busy === 'ip'} disabled={busy !== null || !node.enabled}>
          {t('egress.testIp')}
        </Button>
      </div>
      <p className="muted small">{t('egress.testHint')}</p>
      {busy ? <p className="muted small">{t('egress.running')}</p> : null}
      {report ? <EgressReportView report={report} /> : null}
    </div>
  )
}

const mark = { pass: 'check', fail: 'close', inconclusive: 'warn', info: 'pulse' } as const

/** Host measurements and node measurements are shown in separate, labelled blocks, so one is
 *  never mistaken for the other. */
export function EgressReportView({ report }: { report: EgressReport }) {
  const { t } = useI18n()
  const yn = (b: boolean) => (b ? t('egress.have') : t('egress.none'))
  // a quick look carries no verdict, unless it could not even finish
  const quickView = report.quick && !report.result
  const tone = quickView ? 'neutral' : report.result === 'pass' ? 'ok' : report.result === 'fail' ? 'error' : 'warn'
  const title = quickView ? t('egress.result.quick') : t(`egress.result.${report.result || 'inconclusive'}` as 'egress.result.pass')
  return (
    <div className="diag" aria-live="polite">
      <Notice tone={tone} title={title} />
      <section className="diag-layer">
        <h4>{t('egress.host.title')}</h4>
        <ul>
          {(
            [
              ['IPv4', report.host.v4],
              ['IPv6', report.host.v6],
            ] as const
          ).map(([label, f]) => (
            <li key={label} className="diag-info">
              <Icon name="pulse" size={15} />
              <span>
                <strong>{label}</strong> · {t('egress.route')} {yn(f.route)} · {t('egress.dns')} {yn(f.dns)} · {t('egress.hostIp')} <span className="mono">{f.ip || t('egress.unavailable')}</span>
              </span>
            </li>
          ))}
        </ul>
      </section>
      <section className="diag-layer">
        <h4>{t('egress.node.title')}</h4>
        <ul>
          {report.checks.map((c) => (
            <li key={c.key} className={`diag-${c.status === 'pass' ? 'ok' : c.status === 'fail' ? 'fail' : c.status === 'inconclusive' ? 'warn' : 'info'}`}>
              <Icon name={mark[c.status]} size={15} />
              <span>{c.text}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}

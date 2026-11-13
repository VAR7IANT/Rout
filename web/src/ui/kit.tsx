// The panel's building blocks. Everything here is presentation only: no API calls, no routing.
import { useEffect, useId, useRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react'
import { blocks } from '../core/format'
import { Icon, type IconName } from './icons'

export type Tone = 'neutral' | 'ok' | 'warn' | 'error' | 'accent'

const cx = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).join(' ')

// ---- actions ---------------------------------------------------------------------------

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
  size?: 'sm' | 'md'
  icon?: IconName
  /** Shows the activity marker and blocks further clicks. */
  busy?: boolean
}

export function Button({ variant = 'default', size = 'md', icon, busy, disabled, className, children, type = 'button', ...rest }: ButtonProps) {
  return (
    <button type={type} className={cx('btn', `btn--${variant}`, `btn--${size}`, busy && 'is-busy', className)} disabled={disabled || busy} aria-busy={busy || undefined} {...rest}>
      {busy ? <Activity /> : icon ? <Icon name={icon} size={size === 'sm' ? 14 : 16} /> : null}
      {children != null ? <span className="btn__label">{children}</span> : null}
    </button>
  )
}

/** A button that shows only an icon; `label` is what assistive technology and the tooltip say. */
export function IconButton({ icon, label, size = 'md', className, busy, disabled, type = 'button', ...rest }: Omit<ButtonProps, 'children' | 'variant'> & { icon: IconName; label: string }) {
  return (
    <button type={type} className={cx('btn', 'btn--ghost', 'btn--icon', `btn--${size}`, className)} aria-label={label} title={label} disabled={disabled || busy} {...rest}>
      {busy ? <Activity /> : <Icon name={icon} size={size === 'sm' ? 14 : 16} />}
    </button>
  )
}

/** Three bars rising in turn: the panel's "working" marker. */
export function Activity() {
  return (
    <span className="activity" aria-hidden="true">
      <i />
      <i />
      <i />
    </span>
  )
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="spinner" role="status">
      <Activity />
      {label ? <span>{label}</span> : null}
    </span>
  )
}

// ---- status ----------------------------------------------------------------------------

export function Led({ tone }: { tone: Tone }) {
  return <span className={`led led--${tone}`} aria-hidden="true" />
}

/** A bracketed status word: `[● running]`. */
export function Tag({ tone = 'neutral', led, title, children }: { tone?: Tone; led?: boolean; title?: string; children: ReactNode }) {
  return (
    <span className={`tag tag--${tone}`} title={title}>
      {led ? <Led tone={tone} /> : null}
      {children}
    </span>
  )
}

const noticeIcon: Record<Tone, IconName> = { neutral: 'info', accent: 'info', ok: 'check', warn: 'warn', error: 'warn' }

export function Notice({ tone = 'neutral', title, children, action }: { tone?: Tone; title?: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className={`notice notice--${tone}`} role={tone === 'error' ? 'alert' : undefined}>
      <Icon name={noticeIcon[tone]} />
      <div className="notice__text">
        {title ? <strong>{title}</strong> : null}
        {children ? <div>{children}</div> : null}
      </div>
      {action ? <div className="notice__action">{action}</div> : null}
    </div>
  )
}

export function Empty({ title, children, action, icon = 'terminal' }: { title: string; children?: ReactNode; action?: ReactNode; icon?: IconName }) {
  return (
    <div className="empty">
      <Icon name={icon} size={28} />
      <p className="empty__title">{title}</p>
      {children ? <p className="empty__text">{children}</p> : null}
      {action}
    </div>
  )
}

/** A text meter, `[████░░░░░░] 40%`, exposed as a progress bar. */
export function Meter({ value, tone, label, width = 10, showValue = true }: { value: number; tone?: Tone; label?: string; width?: number; showValue?: boolean }) {
  const pct = Math.round(Math.min(100, Math.max(0, value)))
  const auto: Tone = pct >= 90 ? 'error' : pct >= 75 ? 'warn' : 'accent'
  const bar = blocks(pct, width)
  const cut = bar.indexOf('░') < 0 ? bar.length : bar.indexOf('░')
  return (
    <span className={`meter meter--${tone ?? auto}`} role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label={label}>
      <span aria-hidden="true">
        [<b>{bar.slice(0, cut)}</b>
        <i>{bar.slice(cut)}</i>]
      </span>
      {showValue ? <span className="meter__pct">{pct}%</span> : null}
    </span>
  )
}

// ---- layout ----------------------------------------------------------------------------

export function PageHead({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {sub ? <p className="page-head__sub">{sub}</p> : null}
      </div>
      {actions ? <div className="page-head__actions">{actions}</div> : null}
    </header>
  )
}

/** A bordered box with its title set into the top edge. */
export function Panel({ title, meta, actions, children, flush, className, tone }: { title?: ReactNode; meta?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; className?: string; tone?: Tone }) {
  return (
    <section className={cx('panel', flush && 'panel--flush', tone && `panel--${tone}`, className)}>
      {title || actions ? (
        <header className="panel__head">
          <div className="panel__heading">
            {title ? <h2 className="panel__title">{title}</h2> : null}
            {meta ? <span className="panel__meta">{meta}</span> : null}
          </div>
          {actions ? <div className="panel__actions">{actions}</div> : null}
        </header>
      ) : null}
      <div className="panel__body">{children}</div>
    </section>
  )
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: Tone }) {
  return (
    <div className={cx('stat', tone && `stat--${tone}`)}>
      <div className="stat__label">{label}</div>
      <div className="stat__value">{value}</div>
      {sub ? <div className="stat__sub">{sub}</div> : null}
    </div>
  )
}

/** Aligned `key  value` rows, like the output of a status command. */
export function KV({ rows }: { rows: ({ k: string; v: ReactNode } | null | false | undefined | '')[] }) {
  return (
    <dl className="kv">
      {rows.map((row) =>
        row ? (
          <div key={row.k} className="kv__row">
            <dt>{row.k}</dt>
            <dd>{row.v}</dd>
          </div>
        ) : null,
      )}
    </dl>
  )
}

// ---- form controls ---------------------------------------------------------------------

/**
 * A labelled control. `children` receives the id to put on the control and the id of the
 * hint/error text for aria-describedby.
 */
export function Field({ label, hint, error, required, children }: { label: string; hint?: ReactNode; error?: string | null; required?: boolean; children: (id: string, describedBy?: string) => ReactNode }) {
  const id = useId()
  const note = error || hint ? `${id}-note` : undefined
  return (
    <div className={cx('field', error && 'field--error')}>
      <label htmlFor={id}>
        {label}
        {required ? (
          <span className="field__req" aria-hidden="true">
            *
          </span>
        ) : null}
      </label>
      {children(id, note)}
      {error ? (
        <p id={note} className="field__error" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p id={note} className="field__hint">
          {hint}
        </p>
      ) : null}
    </div>
  )
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx('input', className)} spellCheck={false} {...rest} />
}
export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cx('input', 'input--area', className)} spellCheck={false} {...rest} />
}
export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cx('input', 'input--select', className)} {...rest}>
      {children}
    </select>
  )
}

/** A search box that looks like a prompt: `/ filter…`. */
export function Search({ value, onChange, placeholder, label, id }: { value: string; onChange: (v: string) => void; placeholder: string; label: string; id?: string }) {
  return (
    <label className="search">
      <span className="search__prompt" aria-hidden="true">
        /
      </span>
      <span className="sr-only">{label}</span>
      <input id={id} type="search" className="input" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} spellCheck={false} autoComplete="off" />
    </label>
  )
}

/** An on/off control that takes effect immediately. */
export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" className="switch" aria-checked={checked} aria-label={label} title={label} disabled={disabled} onClick={() => onChange(!checked)}>
      <span className="switch__knob" aria-hidden="true" />
    </button>
  )
}

/** `[x]` / `[ ]` / `[-]`. With `children` the text is visible; otherwise `label` is read out only. */
export function Checkbox({ checked, onChange, label, indeterminate, disabled, children, hint }: { checked: boolean; onChange: (v: boolean) => void; label?: string; indeterminate?: boolean; disabled?: boolean; children?: ReactNode; hint?: ReactNode }) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = !!indeterminate && !checked
  }, [indeterminate, checked])
  return (
    <label className={cx('check', disabled && 'is-disabled', children != null && 'check--text')}>
      <input ref={ref} type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} aria-label={children == null ? label : undefined} />
      <span className="check__box" aria-hidden="true" />
      {children != null ? (
        <span className="check__text">
          {children}
          {hint ? <span className="check__hint">{hint}</span> : null}
        </span>
      ) : null}
    </label>
  )
}

export interface Option<T extends string> {
  value: T
  label: ReactNode
  disabled?: boolean
  title?: string
  count?: number
}

/** A small set of mutually exclusive choices shown side by side. */
export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: Option<T>[]; label: string }) {
  return (
    <div className="seg" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" role="radio" aria-checked={o.value === value} className={cx('seg__item', o.value === value && 'is-on')} disabled={o.disabled} title={o.title} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  )
}

/** Page-level views. Left/Right move between tabs, as the ARIA pattern expects. */
export function Tabs<T extends string>({ value, onChange, tabs, label }: { value: T; onChange: (v: T) => void; tabs: Option<T>[]; label: string }) {
  const step = (dir: 1 | -1) => {
    const i = tabs.findIndex((x) => x.value === value)
    onChange(tabs[(i + dir + tabs.length) % tabs.length].value)
  }
  return (
    <div
      className="tabs"
      role="tablist"
      aria-label={label}
      onKeyDown={(e) => {
        if (e.key === 'ArrowRight') step(1)
        else if (e.key === 'ArrowLeft') step(-1)
      }}
    >
      {tabs.map((x) => (
        <button key={x.value} type="button" role="tab" aria-selected={x.value === value} tabIndex={x.value === value ? 0 : -1} className={cx('tabs__tab', x.value === value && 'is-on')} onClick={() => onChange(x.value)}>
          {x.label}
          {x.count != null ? <span className="tabs__count">{x.count}</span> : null}
        </button>
      ))}
    </div>
  )
}

export { cx }

import { useId, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react'
import { Icon, type IconName } from './icons'

export type Tone = 'neutral' | 'ok' | 'warn' | 'error' | 'accent'

// ---- buttons ---------------------------------------------------------------------------

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
  icon?: IconName
  busy?: boolean
}

export function Button({ variant = 'secondary', size = 'md', icon, busy, children, className = '', disabled, type = 'button', ...rest }: ButtonProps) {
  return (
    <button type={type} className={`btn btn-${variant} btn-${size} ${className}`} disabled={disabled || busy} aria-busy={busy || undefined} {...rest}>
      {busy ? <span className="spinner" aria-hidden="true" /> : icon ? <Icon name={icon} size={size === 'sm' ? 15 : 17} /> : null}
      {children != null && children !== false ? <span className="btn-label">{children}</span> : null}
    </button>
  )
}

export function IconButton({ icon, label, size = 'md', ...rest }: Omit<ButtonProps, 'children' | 'variant'> & { icon: IconName; label: string }) {
  return (
    <button type="button" className={`icon-btn icon-btn-${size}`} aria-label={label} title={label} {...rest}>
      <Icon name={icon} size={size === 'sm' ? 15 : 18} />
    </button>
  )
}

// ---- status ----------------------------------------------------------------------------

export function Badge({ tone = 'neutral', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {children}
    </span>
  )
}

export function Dot({ tone }: { tone: Tone }) {
  return <span className={`dot dot-${tone}`} aria-hidden="true" />
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="loading" role="status">
      <span className="spinner spinner-lg" aria-hidden="true" />
      {label ? <span>{label}</span> : null}
    </span>
  )
}

export function EmptyState({ icon = 'nodes', title, children, action }: { icon?: IconName; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-mark">
        <Icon name={icon} size={26} />
      </div>
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  )
}

export function Notice({ tone = 'neutral', title, children, action }: { tone?: Tone; title?: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className={`notice notice-${tone}`} role={tone === 'error' ? 'alert' : undefined}>
      <Icon name={tone === 'ok' ? 'check' : tone === 'neutral' ? 'pulse' : 'warn'} size={18} />
      <div className="notice-text">
        {title ? <strong>{title}</strong> : null}
        {children ? <div>{children}</div> : null}
      </div>
      {action}
    </div>
  )
}

// ---- layout ----------------------------------------------------------------------------

export function Card({ title, actions, children, className = '', flush, subtitle }: { title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={`card ${className}`}>
      {title || actions ? (
        <header className="card-head">
          <div className="card-titles">
            {title ? <h2>{title}</h2> : null}
            {subtitle ? <p className="muted small">{subtitle}</p> : null}
          </div>
          {actions ? <div className="card-actions">{actions}</div> : null}
        </header>
      ) : null}
      <div className={flush ? 'card-body card-body-flush' : 'card-body'}>{children}</div>
    </section>
  )
}

export function PageHead({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {subtitle ? <p className="muted">{subtitle}</p> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </div>
  )
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: Tone }) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ''}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub ? <div className="stat-sub">{sub}</div> : null}
    </div>
  )
}

export function Meter({ percent, tone, label }: { percent: number; tone?: Tone; label?: string }) {
  const p = Math.max(0, Math.min(100, percent))
  const t = tone ?? (p >= 90 ? 'error' : p >= 75 ? 'warn' : 'accent')
  return (
    <div className={`meter meter-${t}`} role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(p)} aria-label={label}>
      <div className="meter-fill" style={{ width: `${p}%` }} />
    </div>
  )
}

export function KV({ items }: { items: { k: string; v: ReactNode; mono?: boolean }[] }) {
  return (
    <dl className="kv">
      {items.map((it) => (
        <div key={it.k} className="kv-row">
          <dt>{it.k}</dt>
          <dd className={it.mono ? 'mono' : undefined}>{it.v}</dd>
        </div>
      ))}
    </dl>
  )
}

// ---- forms -----------------------------------------------------------------------------

export function Field({ label, hint, error, children, inline, required }: { label: string; hint?: ReactNode; error?: string | null; children: (id: string, describedBy?: string) => ReactNode; inline?: boolean; required?: boolean }) {
  const id = useId()
  const hid = `${id}-hint`
  const eid = `${id}-err`
  const described = [hint ? hid : '', error ? eid : ''].filter(Boolean).join(' ') || undefined
  return (
    <div className={`field ${inline ? 'field-inline' : ''} ${error ? 'field-error' : ''}`}>
      <label htmlFor={id}>
        {label}
        {required ? <span className="req" aria-hidden="true"> *</span> : null}
      </label>
      {children(id, described)}
      {hint ? (
        <p id={hid} className="hint">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={eid} className="err" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`input ${props.className ?? ''}`} />
}
export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={`input textarea ${props.className ?? ''}`} />
}
export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={`input select ${props.className ?? ''}`} />
}

export function SearchInput({ value, onChange, placeholder, label }: { value: string; onChange: (v: string) => void; placeholder: string; label: string }) {
  return (
    <div className="search">
      <Icon name="search" size={16} />
      <input type="search" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={label} />
    </div>
  )
}

export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} title={label} disabled={disabled} className={`switch ${checked ? 'switch-on' : ''}`} onClick={() => onChange(!checked)}>
      <span className="switch-knob" />
    </button>
  )
}

export function Check({ checked, onChange, label, indeterminate, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; indeterminate?: boolean; disabled?: boolean }) {
  return (
    <input
      type="checkbox"
      className="check"
      aria-label={label}
      checked={checked}
      disabled={disabled}
      ref={(el) => {
        if (el) el.indeterminate = !!indeterminate && !checked
      }}
      onChange={(e) => onChange(e.target.checked)}
    />
  )
}

export function Toggle({ checked, onChange, children, hint }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode; hint?: ReactNode }) {
  const id = useId()
  return (
    <div className="toggle-row">
      <input id={id} type="checkbox" className="check" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <label htmlFor={id}>
        <span>{children}</span>
        {hint ? <span className="hint">{hint}</span> : null}
      </label>
    </div>
  )
}

export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: ReactNode; disabled?: boolean; title?: string }[]; label: string }) {
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" role="radio" aria-checked={value === o.value} disabled={o.disabled} title={o.title} className={value === o.value ? 'on' : ''} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  )
}

export function Tabs<T extends string>({ value, onChange, tabs, label }: { value: T; onChange: (v: T) => void; tabs: { value: T; label: ReactNode; count?: number }[]; label: string }) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button key={t.value} type="button" role="tab" aria-selected={value === t.value} className={value === t.value ? 'on' : ''} onClick={() => onChange(t.value)}>
          {t.label}
          {t.count != null ? <span className="tab-count">{t.count}</span> : null}
        </button>
      ))}
    </div>
  )
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className="mono">{children}</span>
}

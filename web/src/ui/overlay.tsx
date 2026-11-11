import { useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { useT } from '../core/i18n'
import { Icon, type IconName } from './icons'
import { Button, IconButton, Notice, cx } from './kit'

// Layers that are open, innermost last. Escape closes only the top one, so a password prompt
// over a drawer does not take the drawer down with it.
const open: symbol[] = []

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'
const FIRST_FIELD = 'input:not([disabled]),select:not([disabled]),textarea:not([disabled]),button:not([disabled])'

interface LayerProps {
  title: string
  description?: string
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  /** While a request runs, Escape, the backdrop and the close button are inert. */
  busy?: boolean
  wide?: boolean
}

function Layer({ kind, title, description, onClose, children, footer, busy, wide }: LayerProps & { kind: 'dialog' | 'drawer' }) {
  const t = useT()
  const id = useId()
  const box = useRef<HTMLDivElement>(null)
  const live = useRef({ onClose, busy })
  live.current = { onClose, busy }

  useEffect(() => {
    const me = Symbol(kind)
    open.push(me)
    const returnTo = document.activeElement as HTMLElement | null
    const node = box.current
    // The first control of the body, not the close button in the title bar.
    ;(node?.querySelector<HTMLElement>('[data-autofocus]') ?? node?.querySelector('.layer__body')?.querySelector<HTMLElement>(FIRST_FIELD) ?? node)?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || open[open.length - 1] !== me || live.current.busy) return
      e.stopPropagation()
      live.current.onClose()
    }
    document.addEventListener('keydown', onKey)
    document.body.classList.add('is-locked')
    return () => {
      document.removeEventListener('keydown', onKey)
      open.splice(open.indexOf(me), 1)
      if (open.length === 0) document.body.classList.remove('is-locked')
      returnTo?.focus?.()
    }
  }, [kind])

  // Keep Tab inside the layer.
  const cycle = (e: ReactKeyboardEvent) => {
    if (e.key !== 'Tab' || !box.current) return
    const stops = Array.from(box.current.querySelectorAll<HTMLElement>(FOCUSABLE))
    if (stops.length === 0) return
    const first = stops[0]
    const last = stops[stops.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }

  return createPortal(
    <div className={`layer layer--${kind}`} onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div ref={box} className={cx('layer__box', wide && 'layer__box--wide')} role="dialog" aria-modal="true" aria-labelledby={`${id}-title`} aria-describedby={description ? `${id}-desc` : undefined} tabIndex={-1} onKeyDown={cycle}>
        <header className="layer__head">
          <h2 id={`${id}-title`}>{title}</h2>
          <IconButton icon="close" label={t('common.close')} onClick={onClose} disabled={busy} />
        </header>
        {description ? (
          <p id={`${id}-desc`} className="layer__desc">
            {description}
          </p>
        ) : null}
        <div className="layer__body">{children}</div>
        {footer ? <footer className="layer__foot">{footer}</footer> : null}
      </div>
    </div>,
    document.body,
  )
}

/** A centred modal for a short question or form. */
export function Dialog(props: LayerProps) {
  return <Layer kind="dialog" {...props} />
}
/** A side sheet for looking at, or editing, one item while the list stays behind it. */
export function Drawer(props: LayerProps) {
  return <Layer kind="drawer" {...props} />
}

// ---- confirmation ----------------------------------------------------------------------

interface ConfirmProps {
  title: string
  /** One sentence: what will happen. */
  message?: ReactNode
  /** Consequences to read before agreeing. */
  impact?: string[]
  confirmLabel: string
  danger?: boolean
  /** The button stays disabled until this text is typed (restore, mass delete). */
  requireText?: string
  onConfirm: () => Promise<void> | void
  onCancel: () => void
}

export function Confirm({ title, message, impact, confirmLabel, danger, requireText, onConfirm, onCancel }: ConfirmProps) {
  const t = useT()
  const id = useId()
  const [busy, setBusy] = useState(false)
  const [typed, setTyped] = useState('')
  const armed = !requireText || typed.trim() === requireText
  const go = async () => {
    setBusy(true)
    try {
      await onConfirm()
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog
      title={title}
      onClose={onCancel}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant={danger ? 'danger' : 'primary'} onClick={() => void go()} busy={busy} disabled={!armed}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="stack">
        {message ? <p>{message}</p> : null}
        {impact && impact.length > 0 ? (
          <Notice tone={danger ? 'error' : 'warn'} title={t('confirm.impact')}>
            <ul className="bullets">
              {impact.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </Notice>
        ) : null}
        {requireText ? (
          <div className="field">
            <label htmlFor={id}>{t('confirm.type', { text: requireText })}</label>
            <input id={id} data-autofocus className="input" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
          </div>
        ) : null}
      </div>
    </Dialog>
  )
}

// ---- row menu --------------------------------------------------------------------------

export interface MenuEntry {
  label: string
  icon?: IconName
  onSelect: () => void
  danger?: boolean
  disabled?: boolean
  hidden?: boolean
}

/** The "more actions" menu of a row. Up/Down move, Escape and outside clicks close it. */
export function Menu({ items, label }: { items: MenuEntry[]; label: string }) {
  const [shown, setShown] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const entries = items.filter((i) => !i.hidden)

  useEffect(() => {
    if (!shown) return
    const outside = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setShown(false)
    }
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setShown(false)
        root.current?.querySelector<HTMLElement>('button')?.focus()
        return
      }
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
      const stops = Array.from(root.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') ?? [])
      if (stops.length === 0) return
      e.preventDefault()
      const at = stops.indexOf(document.activeElement as HTMLElement)
      stops[(at + (e.key === 'ArrowDown' ? 1 : -1) + stops.length) % stops.length].focus()
    }
    document.addEventListener('mousedown', outside)
    document.addEventListener('keydown', key)
    return () => {
      document.removeEventListener('mousedown', outside)
      document.removeEventListener('keydown', key)
    }
  }, [shown])

  if (entries.length === 0) return null
  return (
    <div className="menu" ref={root} onClick={(e) => e.stopPropagation()}>
      <IconButton icon="more" label={label} aria-haspopup="menu" aria-expanded={shown} onClick={() => setShown((s) => !s)} />
      {shown ? (
        <div className="menu__list" role="menu">
          {entries.map((it) => (
            <button
              key={it.label}
              type="button"
              role="menuitem"
              className={cx('menu__item', it.danger && 'is-danger')}
              disabled={it.disabled}
              onClick={() => {
                setShown(false)
                it.onSelect()
              }}
            >
              {it.icon ? <Icon name={it.icon} size={14} /> : <span className="menu__gap" />}
              {it.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )
}

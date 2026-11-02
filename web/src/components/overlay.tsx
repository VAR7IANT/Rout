import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { useT } from '../i18n'
import { Button, IconButton, Notice } from './ui'
import { Icon } from './icons'

// Open overlays, innermost last: Escape closes only the top one (a password prompt over a drawer).
const stack: symbol[] = []

const focusable = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'

interface OverlayProps {
  title: string
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  /** Blocks Escape and backdrop clicks while a request is running. */
  busy?: boolean
  variant?: 'modal' | 'drawer'
  wide?: boolean
  description?: string
}

export function Overlay({ title, onClose, children, footer, busy, variant = 'modal', wide, description }: OverlayProps) {
  const t = useT()
  const id = useId()
  const box = useRef<HTMLDivElement>(null)
  const token = useRef(Symbol('overlay'))
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  const busyRef = useRef(busy)
  busyRef.current = busy

  useEffect(() => {
    const me = token.current
    stack.push(me)
    const previous = document.activeElement as HTMLElement | null
    const node = box.current
    const first = node?.querySelector<HTMLElement>('[data-autofocus]') ?? node?.querySelector<HTMLElement>(focusable.replace('a[href],', ''))
    ;(first ?? node)?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && stack[stack.length - 1] === me && !busyRef.current) {
        e.stopPropagation()
        closeRef.current()
      }
    }
    document.addEventListener('keydown', onKey)
    document.body.classList.add('no-scroll')
    return () => {
      document.removeEventListener('keydown', onKey)
      const i = stack.indexOf(me)
      if (i >= 0) stack.splice(i, 1)
      if (stack.length === 0) document.body.classList.remove('no-scroll')
      previous?.focus?.()
    }
  }, [])

  const trap = (e: ReactKeyboardEvent) => {
    if (e.key !== 'Tab' || !box.current) return
    const items = Array.from(box.current.querySelectorAll<HTMLElement>(focusable)).filter((el) => el.offsetParent !== null || el === document.activeElement)
    if (items.length === 0) return
    const first = items[0]
    const last = items[items.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }

  return createPortal(
    <div className={`overlay overlay-${variant}`} onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div ref={box} className={`sheet ${wide ? 'sheet-wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby={`${id}-t`} aria-describedby={description ? `${id}-d` : undefined} tabIndex={-1} onKeyDown={trap}>
        <header className="sheet-head">
          <h2 id={`${id}-t`}>{title}</h2>
          <IconButton icon="close" label={t('common.close')} onClick={onClose} disabled={busy} />
        </header>
        {description ? (
          <p id={`${id}-d`} className="sheet-desc muted">
            {description}
          </p>
        ) : null}
        <div className="sheet-body">{children}</div>
        {footer ? <footer className="sheet-foot">{footer}</footer> : null}
      </div>
    </div>,
    document.body,
  )
}

export const Modal = Overlay
export function Drawer(props: Omit<OverlayProps, 'variant'>) {
  return <Overlay {...props} variant="drawer" />
}

// ---- confirmation ----------------------------------------------------------------------

interface ConfirmProps {
  title: string
  /** What the operation does, in one sentence. */
  message?: ReactNode
  /** The consequences the administrator should read before agreeing. */
  impact?: string[]
  confirmLabel: string
  danger?: boolean
  /** The administrator must type this text before the button enables (restore, delete). */
  requireText?: string
  onConfirm: () => Promise<void> | void
  onCancel: () => void
}

export function ConfirmDialog({ title, message, impact, confirmLabel, danger, requireText, onConfirm, onCancel }: ConfirmProps) {
  const t = useT()
  const [busy, setBusy] = useState(false)
  const [typed, setTyped] = useState('')
  const ok = !requireText || typed.trim() === requireText
  const run = async () => {
    setBusy(true)
    try {
      await onConfirm()
    } finally {
      setBusy(false)
    }
  }
  return (
    <Overlay
      title={title}
      onClose={onCancel}
      busy={busy}
      footer={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant={danger ? 'danger' : 'primary'} onClick={run} busy={busy} disabled={!ok}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      {message ? <p>{message}</p> : null}
      {impact && impact.length > 0 ? (
        <Notice tone={danger ? 'error' : 'warn'} title={t('confirm.impact')}>
          <ul className="plain-list">
            {impact.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </Notice>
      ) : null}
      {requireText ? (
        <div className="field">
          <label htmlFor="confirm-text">{t('confirm.type', { text: requireText })}</label>
          <input id="confirm-text" data-autofocus className="input mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
        </div>
      ) : null}
    </Overlay>
  )
}

// ---- dropdown menu ---------------------------------------------------------------------

export interface MenuItem {
  label: string
  icon?: Parameters<typeof Icon>[0]['name']
  onSelect: () => void
  danger?: boolean
  disabled?: boolean
  hidden?: boolean
}

export function Menu({ items, label }: { items: MenuItem[]; label: string }) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const visible = items.filter((i) => !i.hidden)
  const close = useCallback(() => setOpen(false), [])
  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) close()
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close()
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open, close])
  if (visible.length === 0) return null
  return (
    <div className="menu" ref={root}>
      <IconButton icon="more" label={label} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)} />
      {open ? (
        <div className="menu-list" role="menu">
          {visible.map((it) => (
            <button
              key={it.label}
              type="button"
              role="menuitem"
              className={it.danger ? 'danger' : ''}
              disabled={it.disabled}
              onClick={() => {
                close()
                it.onSelect()
              }}
            >
              {it.icon ? <Icon name={it.icon} size={16} /> : <span className="menu-gap" />}
              {it.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )
}

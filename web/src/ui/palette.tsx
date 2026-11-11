import { useEffect, useMemo, useRef, useState } from 'react'
import { useT } from '../core/i18n'
import { Icon, type IconName } from './icons'
import { cx } from './kit'
import { Dialog } from './overlay'

export interface Command {
  id: string
  /** "Go to" or "Run": shown dimmed before the title. */
  verb: string
  title: string
  icon: IconName
  /** Extra words the filter matches (the path, English names). */
  keywords?: string
  run: () => void
}

/** Every space-separated word of the query must occur somewhere in the command's text. */
export function matchCommands(commands: Command[], query: string): Command[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean)
  if (words.length === 0) return commands
  return commands.filter((c) => {
    const text = `${c.verb} ${c.title} ${c.keywords ?? ''}`.toLowerCase()
    return words.every((w) => text.includes(w))
  })
}

/** Ctrl/Cmd+K: type to filter, arrows to move, Enter to run. */
export function Palette({ commands, onClose }: { commands: Command[]; onClose: () => void }) {
  const t = useT()
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)
  const list = useRef<HTMLUListElement>(null)
  const hits = useMemo(() => matchCommands(commands, query), [commands, query])
  const at = Math.min(cursor, Math.max(0, hits.length - 1))

  useEffect(() => {
    list.current?.querySelector('[aria-selected="true"]')?.scrollIntoView?.({ block: 'nearest' })
  }, [at])

  const run = (c: Command | undefined) => {
    if (!c) return
    onClose()
    c.run()
  }

  return (
    <Dialog title={t('term.palette')} onClose={onClose}>
      <div className="palette">
        <label className="palette__prompt">
          <span aria-hidden="true">&gt;</span>
          <span className="sr-only">{t('term.palette')}</span>
          <input
            data-autofocus
            className="input"
            value={query}
            placeholder={t('term.palettePlaceholder')}
            autoComplete="off"
            spellCheck={false}
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={hits[at] ? `palette-${hits[at].id}` : undefined}
            onChange={(e) => {
              setQuery(e.target.value)
              setCursor(0)
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault()
                setCursor((at + 1) % Math.max(1, hits.length))
              } else if (e.key === 'ArrowUp') {
                e.preventDefault()
                setCursor((at - 1 + hits.length) % Math.max(1, hits.length))
              } else if (e.key === 'Enter') {
                e.preventDefault()
                run(hits[at])
              }
            }}
          />
        </label>
        {hits.length === 0 ? (
          <p className="dim palette__empty">{t('term.paletteEmpty')}</p>
        ) : (
          <ul id="palette-list" ref={list} className="palette__list" role="listbox" aria-label={t('term.palette')}>
            {hits.map((c, i) => (
              <li key={c.id} id={`palette-${c.id}`} role="option" aria-selected={i === at} className={cx('palette__item', i === at && 'is-on')} onMouseEnter={() => setCursor(i)} onClick={() => run(c)}>
                <Icon name={c.icon} size={14} />
                <span className="dim">{c.verb}</span>
                <span>{c.title}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="dim small palette__hint">{t('term.paletteHint')}</p>
      </div>
    </Dialog>
  )
}

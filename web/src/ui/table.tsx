import type { ReactNode } from 'react'
import { Checkbox, cx } from './kit'

export interface Column<T> {
  key: string
  head: ReactNode
  cell: (row: T) => ReactNode
  /** Label shown before the value when the row is drawn as a card on a phone. */
  label?: string
  /** The card's first line on a phone (no label). */
  primary?: boolean
  className?: string
}

interface Props<T> {
  /** Read out as the table's caption. */
  caption: string
  rows: T[]
  rowKey: (row: T) => string
  columns: Column<T>[]
  /** Shown instead of the table when there are no rows. */
  empty?: ReactNode
  onRowClick?: (row: T) => void
  /** Selection: pass both to get the checkbox column. */
  selected?: Set<string>
  onSelect?: (next: Set<string>) => void
  selectLabel?: (row: T) => string
  selectAllLabel?: string
}

/**
 * One DOM for both layouts: a dense table on wide screens, and (purely in CSS) a stack of
 * cards on phones where each cell is prefixed by its column label.
 */
export function DataTable<T>({ caption, rows, rowKey, columns, empty, onRowClick, selected, onSelect, selectLabel, selectAllLabel = '' }: Props<T>) {
  if (rows.length === 0 && empty) return <>{empty}</>
  const picking = selected != null && onSelect != null
  const keys = rows.map(rowKey)
  const all = picking && keys.length > 0 && keys.every((k) => selected.has(k))
  const some = picking && keys.some((k) => selected.has(k))

  const mark = (which: string[], on: boolean) => {
    if (!picking) return
    const next = new Set(selected)
    for (const k of which) {
      if (on) next.add(k)
      else next.delete(k)
    }
    onSelect(next)
  }

  return (
    <div className="grid-wrap">
      <table className="grid">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {picking ? (
              <th className="grid__pick">
                <Checkbox checked={all} indeterminate={some} onChange={(on) => mark(keys, on)} label={selectAllLabel} />
              </th>
            ) : null}
            {columns.map((c) => (
              <th key={c.key} className={c.className} scope="col">
                {c.head}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const k = rowKey(row)
            const on = picking && selected.has(k)
            return (
              <tr
                key={k}
                className={cx(onRowClick && 'is-clickable', on && 'is-selected')}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                tabIndex={onRowClick ? 0 : undefined}
                onKeyDown={
                  onRowClick
                    ? (e) => {
                        if (e.key === 'Enter' && e.target === e.currentTarget) onRowClick(row)
                      }
                    : undefined
                }
              >
                {picking ? (
                  <td className="grid__pick" onClick={(e) => e.stopPropagation()}>
                    <Checkbox checked={on} onChange={(v) => mark([k], v)} label={selectLabel?.(row) ?? ''} />
                  </td>
                ) : null}
                {columns.map((c) => (
                  <td key={c.key} className={cx(c.className, c.primary && 'grid__primary')} data-label={c.primary ? undefined : c.label}>
                    {c.cell(row)}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

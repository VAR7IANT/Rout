import type { ReactNode } from 'react'
import { Check } from './ui'

export interface Column<T> {
  key: string
  header: ReactNode
  cell: (row: T) => ReactNode
  /** Shown as the label above the value in the stacked phone layout. */
  label?: string
  className?: string
  /** The first line of a phone card (no label). */
  primary?: boolean
}

interface Props<T> {
  rows: T[]
  rowKey: (row: T) => string
  columns: Column<T>[]
  selected?: Set<string>
  onSelect?: (next: Set<string>) => void
  selectLabel?: string
  selectAllLabel?: string
  onRowClick?: (row: T) => void
  empty?: ReactNode
  caption: string
}

/** A table on wide screens and a stack of cards on phones (CSS only: the same DOM). */
export function DataTable<T>({ rows, rowKey, columns, selected, onSelect, selectLabel = '', selectAllLabel = '', onRowClick, empty, caption }: Props<T>) {
  const selectable = !!selected && !!onSelect
  const allKeys = rows.map(rowKey)
  const allOn = selectable && allKeys.length > 0 && allKeys.every((k) => selected!.has(k))
  const some = selectable && allKeys.some((k) => selected!.has(k))
  const toggleAll = (on: boolean) => {
    if (!onSelect || !selected) return
    const next = new Set(selected)
    for (const k of allKeys) {
      if (on) next.add(k)
      else next.delete(k)
    }
    onSelect(next)
  }
  if (rows.length === 0 && empty) return <>{empty}</>
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {selectable ? (
              <th className="col-check">
                <Check checked={allOn} indeterminate={some} onChange={toggleAll} label={selectAllLabel} />
              </th>
            ) : null}
            {columns.map((c) => (
              <th key={c.key} className={c.className}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const k = rowKey(r)
            return (
              <tr key={k} className={`${onRowClick ? 'clickable' : ''} ${selected?.has(k) ? 'selected' : ''}`} onClick={onRowClick ? () => onRowClick(r) : undefined}>
                {selectable ? (
                  <td className="col-check" onClick={(e) => e.stopPropagation()}>
                    <Check
                      checked={selected!.has(k)}
                      label={selectLabel}
                      onChange={(on) => {
                        const next = new Set(selected)
                        if (on) next.add(k)
                        else next.delete(k)
                        onSelect!(next)
                      }}
                    />
                  </td>
                ) : null}
                {columns.map((c) => (
                  <td key={c.key} data-label={c.primary ? undefined : c.label} className={`${c.className ?? ''} ${c.primary ? 'cell-primary' : ''}`}>
                    {c.cell(r)}
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

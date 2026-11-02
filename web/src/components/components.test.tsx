import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useState } from 'react'
import { renderApp } from '../test-utils'
import { ConfirmDialog, Overlay } from './overlay'
import { DataTable, type Column } from './table'
import { QRView, qrPath } from './qr'
import { Tabs, Switch } from './ui'

afterEach(() => vi.restoreAllMocks())

describe('ConfirmDialog', () => {
  it('lists the impact and keeps the button disabled until the word is typed', async () => {
    const onConfirm = vi.fn()
    renderApp(<ConfirmDialog title="Restore" impact={['Things are deleted']} confirmLabel="Go" danger requireText="RESTORE" onConfirm={onConfirm} onCancel={() => undefined} />)
    expect(screen.getByText('Things are deleted')).toBeInTheDocument()
    const go = screen.getByRole('button', { name: 'Go' })
    expect(go).toBeDisabled()
    await userEvent.type(screen.getByRole('textbox'), 'restore')
    expect(go).toBeDisabled()
    await userEvent.clear(screen.getByRole('textbox'))
    await userEvent.type(screen.getByRole('textbox'), 'RESTORE')
    expect(go).toBeEnabled()
    await userEvent.click(go)
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })
  it('is a labelled modal dialog', () => {
    renderApp(<ConfirmDialog title="Delete it" confirmLabel="Delete" onConfirm={() => undefined} onCancel={() => undefined} />)
    expect(screen.getByRole('dialog', { name: 'Delete it' })).toHaveAttribute('aria-modal', 'true')
  })
})

describe('Overlay', () => {
  it('closes only the top overlay on Escape', async () => {
    const outer = vi.fn()
    const inner = vi.fn()
    renderApp(
      <>
        <Overlay title="Outer" onClose={outer}>
          <p>outer body</p>
        </Overlay>
        <Overlay title="Inner" onClose={inner}>
          <p>inner body</p>
        </Overlay>
      </>,
    )
    await userEvent.keyboard('{Escape}')
    expect(inner).toHaveBeenCalledTimes(1)
    expect(outer).not.toHaveBeenCalled()
  })
  it('ignores Escape and backdrop clicks while busy', async () => {
    const close = vi.fn()
    renderApp(
      <Overlay title="Busy" busy onClose={close}>
        <p>x</p>
      </Overlay>,
    )
    await userEvent.keyboard('{Escape}')
    fireEvent.mouseDown(document.querySelector('.overlay')!)
    expect(close).not.toHaveBeenCalled()
  })
  it('keeps keyboard focus inside the dialog', async () => {
    renderApp(
      <>
        <button>behind</button>
        <Overlay title="Trap" onClose={() => undefined}>
          <button>one</button>
          <button>two</button>
        </Overlay>
      </>,
    )
    const buttons = ['Close', 'one', 'two']
    for (let i = 0; i < 6; i++) {
      await userEvent.tab()
      expect(buttons).toContain(document.activeElement?.getAttribute('aria-label') ?? document.activeElement?.textContent)
    }
  })
})

interface Row {
  id: string
  name: string
  proto: string
}
const rows: Row[] = [
  { id: 'a', name: 'alpha', proto: 'vless' },
  { id: 'b', name: 'bravo', proto: 'ss' },
]
const columns: Column<Row>[] = [
  { key: 'name', header: 'Name', primary: true, cell: (r) => r.name },
  { key: 'proto', header: 'Protocol', label: 'Protocol', cell: (r) => r.proto },
]

describe('DataTable', () => {
  it('renders a semantic table with phone labels on the cells', () => {
    renderApp(<DataTable caption="Nodes" rows={rows} rowKey={(r) => r.id} columns={columns} />)
    expect(screen.getByRole('table', { name: 'Nodes' })).toBeInTheDocument()
    expect(screen.getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Name', 'Protocol'])
    const cell = screen.getByText('vless').closest('td')!
    expect(cell).toHaveAttribute('data-label', 'Protocol')
    expect(screen.getByText('alpha').closest('td')).not.toHaveAttribute('data-label')
  })
  it('selects rows and all rows', async () => {
    function Harness() {
      const [sel, setSel] = useState<Set<string>>(new Set())
      return (
        <>
          <DataTable caption="n" rows={rows} rowKey={(r) => r.id} columns={columns} selected={sel} onSelect={setSel} selectLabel="pick" selectAllLabel="all" />
          <output data-testid="sel">{[...sel].sort().join(',')}</output>
        </>
      )
    }
    renderApp(<Harness />)
    await userEvent.click(screen.getAllByLabelText('pick')[0]!)
    expect(screen.getByTestId('sel')).toHaveTextContent('a')
    await userEvent.click(screen.getByLabelText('all'))
    expect(screen.getByTestId('sel')).toHaveTextContent('a,b')
    await userEvent.click(screen.getByLabelText('all'))
    expect(screen.getByTestId('sel')).toHaveTextContent('')
  })
  it('opens a row on click but not when its checkbox is clicked', async () => {
    const open = vi.fn()
    renderApp(<DataTable caption="n" rows={rows} rowKey={(r) => r.id} columns={columns} selected={new Set()} onSelect={() => undefined} selectLabel="pick" onRowClick={open} />)
    await userEvent.click(screen.getByText('bravo'))
    expect(open).toHaveBeenCalledWith(rows[1])
    open.mockClear()
    await userEvent.click(screen.getAllByLabelText('pick')[0]!)
    expect(open).not.toHaveBeenCalled()
  })
  it('shows the empty state instead of an empty table', () => {
    renderApp(<DataTable caption="n" rows={[]} rowKey={(r: Row) => r.id} columns={columns} empty={<p>Nothing here</p>} />)
    expect(screen.getByText('Nothing here')).toBeInTheDocument()
    expect(screen.queryByRole('table')).toBeNull()
  })
})

describe('QR code', () => {
  it('draws a non-empty square matrix for a share link', () => {
    const q = qrPath('vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality#alpha')
    expect(q).not.toBeNull()
    expect(q!.size).toBeGreaterThanOrEqual(21)
    expect(q!.d.startsWith('M')).toBe(true)
  })
  it('gives up quietly on data too large for a QR code', () => {
    expect(qrPath('x'.repeat(5000))).toBeNull()
    renderApp(<QRView text={'x'.repeat(5000)} label="qr" />)
    expect(screen.queryByRole('img')).toBeNull()
  })
  it('is an accessible image drawn locally', () => {
    renderApp(<QRView text="hello" label="Link QR" />)
    const img = screen.getByRole('img', { name: 'Link QR' })
    expect(img.tagName.toLowerCase()).toBe('svg')
  })
})

describe('form controls', () => {
  it('Switch reports its state to assistive technology and toggles', async () => {
    const on = vi.fn()
    renderApp(<Switch checked={false} onChange={on} label="Enable" />)
    const sw = screen.getByRole('switch', { name: 'Enable' })
    expect(sw).toHaveAttribute('aria-checked', 'false')
    await userEvent.click(sw)
    expect(on).toHaveBeenCalledWith(true)
  })
  it('Tabs mark the selected tab', async () => {
    const change = vi.fn()
    renderApp(<Tabs label="t" value="a" onChange={change} tabs={[{ value: 'a', label: 'A' }, { value: 'b', label: 'B' }]} />)
    expect(screen.getByRole('tab', { name: 'A' })).toHaveAttribute('aria-selected', 'true')
    await userEvent.click(screen.getByRole('tab', { name: 'B' }))
    await waitFor(() => expect(change).toHaveBeenCalledWith('b'))
  })
})

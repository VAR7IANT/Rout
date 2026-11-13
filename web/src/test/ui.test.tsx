import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { findIPs, Marked } from '../ui/domain'
import { Checkbox, Meter, Tabs } from '../ui/kit'
import { Confirm, Dialog, Menu } from '../ui/overlay'
import { matchCommands, Palette, type Command } from '../ui/palette'
import { qrShape } from '../ui/qr'
import { DataTable } from '../ui/table'
import { mount } from './harness'

describe('Dialog', () => {
  it('is a labelled modal that focuses its first field and returns focus on close', async () => {
    function Demo() {
      const [open, setOpen] = useState(false)
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            open
          </button>
          {open ? (
            <Dialog title="Rename" description="Pick a name" onClose={() => setOpen(false)}>
              <input aria-label="name" />
            </Dialog>
          ) : null}
        </>
      )
    }
    mount(<Demo />)
    const opener = screen.getByRole('button', { name: 'open' })
    await userEvent.click(opener)
    const dialog = screen.getByRole('dialog', { name: 'Rename' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveAccessibleDescription('Pick a name')
    expect(screen.getByLabelText('name')).toHaveFocus()
    await userEvent.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(opener).toHaveFocus()
  })

  it('closes only the top layer on Escape, and nothing while that layer is busy', async () => {
    const outer = vi.fn()
    function Demo() {
      const [inner, setInner] = useState<'idle' | 'busy' | null>(null)
      return (
        <Dialog title="outer" onClose={outer}>
          <button type="button" onClick={() => setInner('busy')}>
            ask
          </button>
          {inner ? (
            <Dialog title="inner" onClose={() => setInner(null)} busy={inner === 'busy'}>
              <button type="button" onClick={() => setInner('idle')}>
                finish
              </button>
            </Dialog>
          ) : null}
        </Dialog>
      )
    }
    mount(<Demo />)
    await userEvent.click(screen.getByRole('button', { name: 'ask' }))
    await userEvent.keyboard('{Escape}') // the inner layer is busy: nothing closes
    expect(screen.getByRole('dialog', { name: 'inner' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'finish' }))
    await userEvent.keyboard('{Escape}') // closes the inner layer only
    expect(screen.queryByRole('dialog', { name: 'inner' })).not.toBeInTheDocument()
    expect(outer).not.toHaveBeenCalled()
    await userEvent.keyboard('{Escape}')
    expect(outer).toHaveBeenCalledTimes(1)
  })

  it('keeps Tab inside', async () => {
    mount(
      <Dialog title="t" onClose={() => undefined}>
        <input aria-label="only" />
      </Dialog>,
    )
    const close = screen.getByRole('button', { name: /close/i })
    expect(screen.getByLabelText('only')).toHaveFocus()
    await userEvent.tab()
    expect(close).toHaveFocus() // wrapped from the last stop to the first
    await userEvent.tab({ shift: true })
    expect(screen.getByLabelText('only')).toHaveFocus()
  })
})

describe('Confirm', () => {
  it('lists the consequences and arms only after the word is typed', async () => {
    const onConfirm = vi.fn()
    mount(<Confirm danger title="Restore" impact={['All nodes are replaced']} confirmLabel="Apply" requireText="RESTORE" onConfirm={onConfirm} onCancel={() => undefined} />)
    const apply = screen.getByRole('button', { name: 'Apply' })
    expect(screen.getByText('All nodes are replaced')).toBeInTheDocument()
    expect(apply).toBeDisabled()
    await userEvent.type(screen.getByRole('textbox'), 'restore')
    expect(apply).toBeDisabled() // case matters
    await userEvent.clear(screen.getByRole('textbox'))
    await userEvent.type(screen.getByRole('textbox'), 'RESTORE')
    await userEvent.click(apply)
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })
})

describe('Menu', () => {
  it('opens, hides hidden entries, runs the choice and closes', async () => {
    const edit = vi.fn()
    mount(
      <Menu
        label="More"
        items={[
          { label: 'Edit', onSelect: edit },
          { label: 'Secret', onSelect: () => undefined, hidden: true },
          { label: 'Delete', onSelect: () => undefined, disabled: true },
        ]}
      />,
    )
    const trigger = screen.getByRole('button', { name: 'More' })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    await userEvent.click(trigger)
    expect(screen.queryByRole('menuitem', { name: 'Secret' })).not.toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Delete' })).toBeDisabled()
    await userEvent.click(screen.getByRole('menuitem', { name: 'Edit' }))
    expect(edit).toHaveBeenCalled()
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })
  it('renders nothing when every entry is hidden', () => {
    const { container } = render(<Menu label="More" items={[{ label: 'x', onSelect: () => undefined, hidden: true }]} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('DataTable', () => {
  const rows = [
    { id: 'a', name: 'Alpha' },
    { id: 'b', name: 'Beta' },
  ]
  function Demo({ onOpen }: { onOpen: (id: string) => void }) {
    const [selected, setSelected] = useState<Set<string>>(new Set())
    return (
      <>
        <output>{[...selected].sort().join(',')}</output>
        <DataTable caption="things" rows={rows} rowKey={(r) => r.id} columns={[{ key: 'n', head: 'Name', primary: true, cell: (r) => r.name }]} selected={selected} onSelect={setSelected} selectLabel={(r) => `pick ${r.name}`} selectAllLabel="pick all" onRowClick={(r) => onOpen(r.id)} />
      </>
    )
  }
  it('selects rows without opening them, and all rows at once', async () => {
    const onOpen = vi.fn()
    render(<Demo onOpen={onOpen} />)
    await userEvent.click(screen.getByRole('checkbox', { name: 'pick Beta' }))
    expect(screen.getByRole('status')).toHaveTextContent('b')
    expect(onOpen).not.toHaveBeenCalled()
    expect(screen.getByRole('checkbox', { name: 'pick all' })).toHaveProperty('indeterminate', true)
    await userEvent.click(screen.getByRole('checkbox', { name: 'pick all' }))
    expect(screen.getByRole('status')).toHaveTextContent('a,b')
    await userEvent.click(screen.getByRole('checkbox', { name: 'pick all' }))
    expect(screen.getByRole('status')).toHaveTextContent('')
  })
  it('opens a row on click and on Enter', async () => {
    const onOpen = vi.fn()
    render(<Demo onOpen={onOpen} />)
    await userEvent.click(screen.getByText('Alpha'))
    screen.getByText('Beta').closest('tr')!.focus()
    await userEvent.keyboard('{Enter}')
    expect(onOpen.mock.calls).toEqual([['a'], ['b']])
  })
  it('shows the empty state instead of an empty table', () => {
    render(<DataTable caption="things" rows={[]} rowKey={() => ''} columns={[]} empty={<p>nothing here</p>} />)
    expect(screen.getByText('nothing here')).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })
})

describe('small controls', () => {
  it('Meter is a progress bar whose colour follows how full it is', () => {
    render(<Meter value={93.4} label="Disk" />)
    const bar = screen.getByRole('progressbar', { name: 'Disk' })
    expect(bar).toHaveAttribute('aria-valuenow', '93')
    expect(bar.className).toContain('meter--error')
    expect(bar).toHaveTextContent('93%')
  })
  it('Checkbox reports changes and shows its hint', async () => {
    const onChange = vi.fn()
    render(
      <Checkbox checked={false} onChange={onChange} hint="TCP + UDP">
        Shadowsocks
      </Checkbox>,
    )
    await userEvent.click(screen.getByRole('checkbox', { name: /Shadowsocks/ }))
    expect(onChange).toHaveBeenCalledWith(true)
    expect(screen.getByText('TCP + UDP')).toBeInTheDocument()
  })
  it('Tabs mark the current tab and move with the arrow keys', async () => {
    const onChange = vi.fn()
    render(
      <Tabs
        label="views"
        value="a"
        onChange={onChange}
        tabs={[
          { value: 'a', label: 'A' },
          { value: 'b', label: 'B' },
        ]}
      />,
    )
    expect(screen.getByRole('tab', { name: 'A' })).toHaveAttribute('aria-selected', 'true')
    screen.getByRole('tab', { name: 'A' }).focus()
    await userEvent.keyboard('{ArrowRight}')
    await userEvent.keyboard('{ArrowLeft}')
    expect(onChange.mock.calls).toEqual([['b'], ['b']]) // from A, left wraps round to B as well
  })
})

describe('command palette', () => {
  const commands: Command[] = [
    { id: 'nodes', verb: 'Go to', title: 'Nodes', icon: 'nodes', keywords: '/nodes', run: vi.fn() },
    { id: 'system', verb: 'Go to', title: 'System', icon: 'system', keywords: '/system', run: vi.fn() },
    { id: 'logout', verb: 'Run', title: 'Sign out', icon: 'logout', keywords: 'logout exit', run: vi.fn() },
  ]
  it('matches every typed word against title, verb and keywords', () => {
    expect(matchCommands(commands, '').map((c) => c.id)).toEqual(['nodes', 'system', 'logout'])
    expect(matchCommands(commands, 'go sys').map((c) => c.id)).toEqual(['system'])
    expect(matchCommands(commands, 'EXIT').map((c) => c.id)).toEqual(['logout'])
    expect(matchCommands(commands, 'nodes system')).toEqual([])
  })
  it('runs the highlighted command with the keyboard and closes', async () => {
    const onClose = vi.fn()
    mount(<Palette commands={commands} onClose={onClose} />)
    const box = screen.getByRole('combobox')
    expect(box).toHaveFocus()
    await userEvent.keyboard('{ArrowDown}')
    expect(within(screen.getByRole('listbox')).getByRole('option', { selected: true })).toHaveTextContent('System')
    await userEvent.keyboard('{Enter}')
    expect(commands[1].run).toHaveBeenCalled()
    expect(onClose).toHaveBeenCalled()
  })
  it('says so when nothing matches', async () => {
    mount(<Palette commands={commands} onClose={() => undefined} />)
    await userEvent.type(screen.getByRole('combobox'), 'zzz')
    expect(screen.getByText(/no matching command/i)).toBeInTheDocument()
  })
})

describe('helpers', () => {
  it('qrShape draws short text and gives up on text that cannot fit', () => {
    const small = qrShape('vless://abc@example.com:443')
    expect(small?.size).toBeGreaterThanOrEqual(21)
    expect(small?.d.startsWith('M')).toBe(true)
    expect(qrShape('x'.repeat(5000))).toBeNull()
  })
  it('findIPs picks addresses out of prose in either script', () => {
    expect(findIPs('Exit IP 203.0.113.7 (HTTP 200), also 2001:db8::1.')).toEqual(['203.0.113.7', '2001:db8::1'])
    expect(findIPs('出口地址：198.51.100.4，耗时 12:30')).toEqual(['198.51.100.4'])
    expect(findIPs('version 1.2.3 and 999.1.1.1')).toEqual([])
  })
  it('Marked emphasises exactly the given strings', () => {
    const { container } = render(<Marked text="left via 203.0.113.7 not 203.0.113.70" marks={['203.0.113.70', '203.0.113.7']} />)
    expect([...container.querySelectorAll('mark')].map((m) => m.textContent)).toEqual(['203.0.113.7', '203.0.113.70'])
  })
})

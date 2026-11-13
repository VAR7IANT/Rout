// A small stroke icon set drawn on a 24-unit grid with square caps, to sit next to monospace
// text without looking rounded. Icons are decorative: the control that holds one names itself.
const shapes = {
  dashboard: 'M4 4h7v9H4zM13 4h7v5h-7zM13 11h7v9h-7zM4 15h7v5H4z',
  nodes: 'M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01',
  relay: 'M4 8h13m0 0-3-3m3 3-3 3M20 16H7m0 0 3-3m-3 3 3 3',
  ai: 'M8 8h8v8H8zM10 4v4M14 4v4M10 16v4M14 16v4M4 10h4M4 14h4M16 10h4M16 14h4',
  sub: 'M5 6h14M5 12h14M5 18h9',
  system: 'M4 7h9M17 7h3M4 17h3M11 17h9M13 5v4h4V5zM7 15v4h4v-4z',
  plus: 'M12 5v14M5 12h14',
  close: 'M6 6l12 12M18 6 6 18',
  check: 'M5 12.5 10 17l9-10',
  warn: 'M12 4 3 20h18zM12 10v5M12 17.4v.2',
  info: 'M4 4h16v16H4zM12 11v6M12 7.4v.2',
  copy: 'M9 9h11v11H9zM5 15V4h11',
  more: 'M6 12h.01M12 12h.01M18 12h.01',
  refresh: 'M20 12a8 8 0 1 1-2.6-5.9M20 4v5h-5',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM16 16l4 4',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z',
  eyeoff: 'M4 4l16 16M10 5.2A9.4 9.4 0 0 1 12 5c6 0 10 7 10 7a17 17 0 0 1-3 3.8M6.4 6.6C3.7 8.4 2 12 2 12s4 7 10 7c1.6 0 3-.4 4.2-1',
  qr: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM19 14h1M14 19h2M19 18v2',
  play: 'M7 5l12 7-12 7z',
  stop: 'M6 6h12v12H6z',
  pulse: 'M3 12h4l3-7 4 14 3-7h4',
  arrow: 'M5 12h14m0 0-5-5m5 5-5 5',
  up: 'M12 19V5m0 0-5 5m5-5 5 5',
  down: 'M12 5v14m0 0-5-5m5 5 5-5',
  chevron: 'M9 6l6 6-6 6',
  logout: 'M10 4H5v16h5M9 12h11m0 0-4-4m4 4-4 4',
  sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2',
  moon: 'M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z',
  menu: 'M4 7h16M4 12h16M4 17h16',
  trash: 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v5M14 11v5',
  edit: 'M4 20h4L19 9l-4-4L4 16zM13 7l4 4',
  download: 'M12 4v11m0 0-4-4m4 4 4-4M5 19h14',
  upload: 'M12 16V5m0 0-4 4m4-4 4 4M5 19h14',
  link: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3A4 4 0 0 0 11 18.7l1-1',
  lock: 'M6 11h12v9H6zM9 11V8a3 3 0 0 1 6 0v3',
  power: 'M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0',
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  terminal: 'M4 5h16v14H4zM7 9l3 3-3 3M12 15h5',
  clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2',
  grip: 'M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01',
} as const

export type IconName = keyof typeof shapes
export const iconNames = Object.keys(shapes) as IconName[]

export function Icon({ name, size = 16, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg className={`icon${className ? ` ${className}` : ''}`} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true" focusable="false">
      <path d={shapes[name]} />
    </svg>
  )
}

// A small geometric icon set: 24px grid, 1.75px strokes, square caps. Inline so the build has
// no icon dependency and nothing is fetched at run time.

const paths = {
  dashboard: 'M4 4h7v9H4zM13 4h7v5h-7zM13 11h7v9h-7zM4 15h7v5H4z',
  nodes: 'M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12l8-4.5M12 12v9M12 12L4 7.5',
  relay: 'M3 12h6m6 0h6M9 7l6 5-6 5z',
  sub: 'M5 5h14v4H5zM5 11h14v4H5zM5 17h9v2H5z',
  system: 'M4 6h16M4 12h16M4 18h16M8 4v4M15 10v4M10 16v4',
  plus: 'M12 5v14M5 12h14',
  search: 'M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM15.5 15.5L20 20',
  more: 'M5 12h.01M12 12h.01M19 12h.01',
  copy: 'M9 9h10v11H9zM5 5h10v2M5 5v11h2',
  qr: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2v2h-2zM14 18h2v2h-2zM18 18h2v2h-2z',
  refresh: 'M20 5v5h-5M4 19v-5h5M5.6 9A8 8 0 0 1 20 10M18.4 15A8 8 0 0 1 4 14',
  trash: 'M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13M10 11v6M14 11v6',
  edit: 'M4 20h4L19 9l-4-4L4 16zM13 7l4 4',
  play: 'M7 5l12 7-12 7z',
  stop: 'M6 6h12v12H6z',
  close: 'M6 6l12 12M18 6L6 18',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  warn: 'M12 4l9 16H3zM12 10v5M12 17.5v.01',
  sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9L7 7M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1',
  moon: 'M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z',
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  logout: 'M10 4H5v16h5M14 8l4 4-4 4M18 12H9',
  chevron: 'M9 6l6 6-6 6',
  down: 'M6 9l6 6 6-6',
  up: 'M6 15l6-6 6 6',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  eyeoff: 'M3 3l18 18M10 6.2A9 9 0 0 1 12 6c6 0 10 6 10 6a17 17 0 0 1-3.2 3.7M6.3 7.8C3.6 9.6 2 12 2 12s4 6 10 6a9 9 0 0 0 3.7-.8',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  link: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1',
  download: 'M12 4v11M7 11l5 5 5-5M5 20h14',
  upload: 'M12 16V5M7 9l5-5 5 5M5 20h14',
  key: 'M8 14a4 4 0 1 1 3.4-6H21v4h-3v3h-3v-3h-3.6A4 4 0 0 1 8 14z',
  menu: 'M4 7h16M4 12h16M4 17h16',
  pulse: 'M3 12h4l3-7 4 14 3-7h4',
  server: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  test: 'M9 3v6L4.5 18a2 2 0 0 0 1.8 3h11.4a2 2 0 0 0 1.8-3L15 9V3M8 3h8M7.5 15h9',
  tag: 'M3 3h9l9 9-9 9-9-9zM8 8h.01',
  ai: 'M3 12h6l4-6h5M9 12l4 6h5M16 3l3 3-3 3M16 15l3 3-3 3',
  drag: 'M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01',
} as const

export type IconName = keyof typeof paths

export function Icon({ name, size = 18, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true" focusable="false">
      <path d={paths[name]} />
    </svg>
  )
}

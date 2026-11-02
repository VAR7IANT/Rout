import { useEffect, useState, type ReactNode } from 'react'
import { languages, useI18n, type Lang } from './i18n'
import { Link, useRouter } from './lib/router'
import { useSession } from './lib/session'
import { useTheme, type ThemeChoice } from './lib/theme'
import { Icon, type IconName } from './components/icons'
import { Overlay } from './components/overlay'
import { Button, IconButton, Notice, Segmented } from './components/ui'

interface NavItem {
  to: string
  match: string[]
  icon: IconName
  label: 'nav.dashboard' | 'nav.nodes' | 'nav.relays' | 'nav.subscriptions' | 'nav.system'
  short?: 'nav.relaysShort'
}

export const navItems: NavItem[] = [
  { to: '/', match: ['/'], icon: 'dashboard', label: 'nav.dashboard' },
  { to: '/nodes', match: ['/nodes'], icon: 'nodes', label: 'nav.nodes' },
  { to: '/relays', match: ['/relays', '/exits'], icon: 'relay', label: 'nav.relays', short: 'nav.relaysShort' },
  { to: '/subscriptions', match: ['/subscriptions', '/sources'], icon: 'sub', label: 'nav.subscriptions' },
  { to: '/system', match: ['/system'], icon: 'system', label: 'nav.system' },
]

export function Preferences() {
  const { t, lang, setLang } = useI18n()
  const { theme, setTheme } = useTheme()
  return (
    <div className="prefs">
      <label className="prefs-lang">
        <Icon name="globe" size={16} />
        <span className="sr-only">{t('shell.language')}</span>
        <select className="input select" value={lang} onChange={(e) => setLang(e.target.value as Lang)} aria-label={t('shell.language')}>
          {languages.map((l) => (
            <option key={l.id} value={l.id}>
              {l.label}
            </option>
          ))}
        </select>
      </label>
      <Segmented<ThemeChoice>
        label={t('shell.theme')}
        value={theme}
        onChange={setTheme}
        options={[
          { value: 'system', label: <Icon name="system" size={15} />, title: t('shell.theme.system') },
          { value: 'light', label: <Icon name="sun" size={15} />, title: t('shell.theme.light') },
          { value: 'dark', label: <Icon name="moon" size={15} />, title: t('shell.theme.dark') },
        ]}
      />
    </div>
  )
}

function isLoopback(host: string): boolean {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1'
}

/** True when the page itself was loaded over plain HTTP from a non-local address. */
export function usingPlainHTTP(loc: Pick<Location, 'protocol' | 'hostname'> = window.location): boolean {
  return loc.protocol === 'http:' && !isLoopback(loc.hostname)
}

export function Shell({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const { path } = useRouter()
  const { logout, version } = useSession()
  const [prefs, setPrefs] = useState(false)
  const active = (n: NavItem) => n.match.includes(path)

  useEffect(() => {
    window.scrollTo?.(0, 0)
  }, [path])

  return (
    <div className="app">
      <a className="skip" href="#main">
        {t('nav.skip')}
      </a>
      <aside className="side">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">Rout</span>
        </div>
        <nav aria-label={t('nav.main')} className="side-nav">
          {navItems.map((n) => (
            <Link key={n.to} to={n.to} className={active(n) ? 'on' : ''} aria-current={active(n) ? 'page' : undefined}>
              <Icon name={n.icon} />
              <span>{t(n.label)}</span>
            </Link>
          ))}
        </nav>
        <div className="side-foot">
          <Preferences />
          <Button variant="ghost" size="sm" icon="logout" onClick={() => void logout()}>
            {t('shell.logout')}
          </Button>
          <div className="side-version mono">{version ? t('shell.version', { v: version }) : ''}</div>
        </div>
      </aside>

      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">Rout</span>
        </div>
        <IconButton icon="menu" label={t('shell.settings')} onClick={() => setPrefs(true)} />
      </header>

      <main id="main" className="main" tabIndex={-1}>
        {usingPlainHTTP() ? <Notice tone="error" title={t('shell.insecure')}>{t('shell.insecureDetail')}</Notice> : null}
        {children}
      </main>

      <nav className="tabbar" aria-label={t('nav.main')}>
        {navItems.map((n) => (
          <Link key={n.to} to={n.to} className={active(n) ? 'on' : ''} aria-current={active(n) ? 'page' : undefined}>
            <Icon name={n.icon} size={20} />
            <span>{t(n.short ?? n.label)}</span>
          </Link>
        ))}
      </nav>

      {prefs ? (
        <Overlay title={t('shell.settings')} onClose={() => setPrefs(false)}>
          <div className="stack">
            <Preferences />
            <Button icon="logout" onClick={() => void logout()}>
              {t('shell.logout')}
            </Button>
            <div className="muted small mono">{version ? t('shell.version', { v: version }) : ''}</div>
          </div>
        </Overlay>
      ) : null}
    </div>
  )
}

import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { clock } from './core/format'
import { useHotkey, useNow } from './core/hooks'
import { languages, useI18n, type Lang, type MessageKey } from './core/i18n'
import { Link, useRouter } from './core/router'
import { useSession } from './core/session'
import { useTheme, type Theme } from './core/theme'
import { Icon, type IconName } from './ui/icons'
import { Button, IconButton, Notice, Segmented, cx } from './ui/kit'
import { Dialog } from './ui/overlay'
import { Palette, type Command } from './ui/palette'

interface Destination {
  to: string
  /** Paths that light this entry up (a page and its sibling tab share one entry). */
  paths: string[]
  icon: IconName
  label: MessageKey
  /** Shorter wording for the phone tab bar, where six entries share 320px. */
  short?: MessageKey
}

export const destinations: Destination[] = [
  { to: '/', paths: ['/'], icon: 'dashboard', label: 'nav.dashboard', short: 'nav.dashboardShort' },
  { to: '/nodes', paths: ['/nodes'], icon: 'nodes', label: 'nav.nodes' },
  { to: '/relays', paths: ['/relays', '/exits'], icon: 'relay', label: 'nav.relays', short: 'nav.relaysShort' },
  { to: '/ai', paths: ['/ai'], icon: 'ai', label: 'nav.ai', short: 'nav.aiShort' },
  { to: '/subscriptions', paths: ['/subscriptions', '/sources'], icon: 'sub', label: 'nav.subscriptions', short: 'nav.subscriptionsShort' },
  { to: '/system', paths: ['/system'], icon: 'system', label: 'nav.system' },
]

/** True when the page was loaded over plain HTTP from somewhere other than this machine. */
export function overPlainHTTP(loc: Pick<Location, 'protocol' | 'hostname'> = window.location): boolean {
  const local = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(loc.hostname)
  return loc.protocol === 'http:' && !local
}

const LOGO = String.raw`
 ___  ___  _   _ _____
| _ \/ _ \| | | |_   _|
|   / (_) | |_| | | |
|_|_\\___/ \___/  |_|`.slice(1)

export function Logo({ compact }: { compact?: boolean }) {
  if (compact)
    return (
      <span className="logo logo--compact">
        <span className="logo__block" aria-hidden="true">
          ▌
        </span>
        ROUT
      </span>
    )
  return (
    <span className="logo" role="img" aria-label="Rout">
      <pre aria-hidden="true">{LOGO}</pre>
    </span>
  )
}

/** Language and appearance: in the sidebar, the phone sheet and on the sign-in screen. */
export function Preferences() {
  const { t, lang, setLang } = useI18n()
  const { theme, setTheme } = useTheme()
  return (
    <div className="prefs">
      <Segmented<Lang> label={t('shell.language')} value={lang} onChange={setLang} options={languages.map((l) => ({ value: l.id, label: l.short, title: l.label }))} />
      <Segmented<Theme>
        label={t('shell.theme')}
        value={theme}
        onChange={setTheme}
        options={[
          { value: 'dark', label: <Icon name="moon" size={14} />, title: t('term.themeDark') },
          { value: 'light', label: <Icon name="sun" size={14} />, title: t('term.themeLight') },
        ]}
      />
    </div>
  )
}

function useCommands(): Command[] {
  const { t, lang, setLang } = useI18n()
  const { go } = useRouter()
  const { theme, setTheme } = useTheme()
  const { logout } = useSession()
  return useMemo(() => {
    const page = (id: string, to: string, title: string, icon: IconName): Command => ({ id, verb: t('term.goto'), title, icon, keywords: to, run: () => go(to) })
    const list: Command[] = [
      ...destinations.map((d) => page(`go${d.to}`, d.to, t(d.label), d.icon)),
      page('go/exits', '/exits', t('term.exits'), 'relay'),
      page('go/sources', '/sources', t('term.sources'), 'sub'),
    ]
    const other: Theme = theme === 'dark' ? 'light' : 'dark'
    list.push({ id: 'theme', verb: t('term.run'), title: t('term.useTheme', { name: t(other === 'dark' ? 'term.themeDark' : 'term.themeLight') }), icon: other === 'dark' ? 'moon' : 'sun', keywords: 'theme dark light', run: () => setTheme(other) })
    for (const l of languages) {
      if (l.id !== lang) list.push({ id: `lang-${l.id}`, verb: t('term.run'), title: t('term.useLang', { name: l.label }), icon: 'globe', keywords: `language ${l.id}`, run: () => setLang(l.id) })
    }
    list.push({ id: 'logout', verb: t('term.run'), title: t('shell.logout'), icon: 'logout', keywords: 'logout sign out exit', run: () => void logout() })
    return list
  }, [t, lang, setLang, go, theme, setTheme, logout])
}

function Nav({ className, compact }: { className: string; compact?: boolean }) {
  const { t } = useI18n()
  const { path } = useRouter()
  return (
    <nav className={className} aria-label={t('nav.main')}>
      {destinations.map((d) => {
        const on = d.paths.includes(path)
        return (
          <Link key={d.to} to={d.to} className={cx('nav__item', on && 'is-on')} aria-current={on ? 'page' : undefined}>
            <Icon name={d.icon} size={compact ? 18 : 16} />
            <span>{t(compact ? (d.short ?? d.label) : d.label)}</span>
          </Link>
        )
      })}
    </nav>
  )
}

function Clock() {
  const now = useNow(1000)
  return <time className="status__clock">{clock(now)}</time>
}

export function Shell({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const { path } = useRouter()
  const { logout, version, secure } = useSession()
  const [palette, setPalette] = useState(false)
  const [sheet, setSheet] = useState(false)
  const commands = useCommands()

  useHotkey('mod+k', (e) => {
    e.preventDefault()
    setPalette(true)
  })
  useEffect(() => {
    window.scrollTo?.(0, 0)
  }, [path])

  const mac = /Mac|iPhone|iPad/.test(navigator.platform)

  return (
    <div className="shell">
      <a className="skip" href="#main">
        {t('nav.skip')}
      </a>

      <aside className="side">
        <Logo />
        <Nav className="nav" />
        <div className="side__foot">
          <Preferences />
          <Button variant="ghost" size="sm" icon="logout" onClick={() => void logout()}>
            {t('shell.logout')}
          </Button>
          <div className="dim small">{version ? t('shell.version', { v: version }) : ''}</div>
        </div>
      </aside>

      <header className="status">
        <span className="status__brand">
          <Logo compact />
        </span>
        <span className="status__path" aria-hidden="true">
          <span className="status__user">admin@{window.location.hostname}</span>:<b>{path}</b>
          <span className="cursor" />
        </span>
        <span className="status__right">
          <span className={cx('status__link', secure ? 'is-ok' : 'is-warn')} title={t(secure ? 'term.secure' : 'term.insecure')}>
            <Icon name="lock" size={13} />
            <span className="sr-only">{t(secure ? 'term.secure' : 'term.insecure')}</span>
          </span>
          <button type="button" className="status__palette" onClick={() => setPalette(true)} aria-label={t('term.paletteOpen')} title={t('term.paletteOpen')}>
            <Icon name="search" size={13} />
            <kbd>{mac ? '⌘K' : 'Ctrl K'}</kbd>
          </button>
          <Clock />
          <IconButton className="status__menu" icon="menu" label={t('shell.settings')} onClick={() => setSheet(true)} />
        </span>
      </header>

      <main id="main" className="main" tabIndex={-1}>
        {overPlainHTTP() ? (
          <Notice tone="error" title={t('shell.insecure')}>
            {t('shell.insecureDetail')}
          </Notice>
        ) : null}
        {children}
      </main>

      <Nav className="tabbar" compact />

      {palette ? <Palette commands={commands} onClose={() => setPalette(false)} /> : null}
      {sheet ? (
        <Dialog title={t('shell.settings')} onClose={() => setSheet(false)}>
          <div className="stack">
            <Preferences />
            <Button icon="logout" onClick={() => void logout()}>
              {t('shell.logout')}
            </Button>
            <div className="dim small">{version ? t('shell.version', { v: version }) : ''}</div>
          </div>
        </Dialog>
      ) : null}
    </div>
  )
}

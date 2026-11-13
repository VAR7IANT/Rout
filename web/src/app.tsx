import type { ReactNode } from 'react'
import { I18nProvider, useT } from './core/i18n'
import { Link, RouterProvider, useRouter } from './core/router'
import { ReauthProvider, SessionProvider, useSession } from './core/session'
import { ThemeProvider } from './core/theme'
import { ToastProvider } from './core/toast'
import { AIPage } from './pages/ai'
import { Dashboard } from './pages/dashboard'
import { Login } from './pages/login'
import { NodesPage } from './pages/nodes'
import { RelaysPage } from './pages/relays'
import { SubscriptionsPage } from './pages/subscriptions'
import { SystemPage } from './pages/system'
import { Shell } from './shell'
import { Button, Empty, Spinner } from './ui/kit'
import { ReauthDialog } from './ui/reauth'

function Page() {
  const { path } = useRouter()
  const t = useT()
  switch (path) {
    case '/':
      return <Dashboard />
    case '/nodes':
      return <NodesPage />
    case '/relays':
      return <RelaysPage tab="relays" />
    case '/exits':
      return <RelaysPage tab="exits" />
    case '/ai':
      return <AIPage />
    case '/subscriptions':
      return <SubscriptionsPage tab="subscriptions" />
    case '/sources':
      return <SubscriptionsPage tab="sources" />
    case '/system':
      return <SystemPage />
    default:
      return (
        <Empty
          icon="warn"
          title={`404 · ${t('shell.notFound')}`}
          action={
            <Link to="/" className="btn btn--default btn--md">
              {t('shell.backHome')}
            </Link>
          }
        />
      )
  }
}

/** Decides between the boot screen, the sign-in form and the panel. */
function Gate() {
  const { phase, refresh } = useSession()
  const t = useT()
  if (phase === 'booting')
    return (
      <div className="splash">
        <Spinner label={t('shell.loading')} />
      </div>
    )
  if (phase === 'offline')
    return (
      <div className="splash">
        <Empty icon="warn" title={t('shell.unreachable')} action={<Button onClick={() => void refresh()}>{t('common.retry')}</Button>}>
          {t('shell.unreachableDetail')}
        </Empty>
      </div>
    )
  if (phase === 'guest') return <Login />
  return (
    <ReauthProvider prompt={(done) => <ReauthDialog done={done} />}>
      <Shell>
        <Page />
      </Shell>
    </ReauthProvider>
  )
}

export function Providers({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider>
      <I18nProvider>
        <ToastProvider>
          <RouterProvider>
            <SessionProvider>{children}</SessionProvider>
          </RouterProvider>
        </ToastProvider>
      </I18nProvider>
    </ThemeProvider>
  )
}

export default function App() {
  return (
    <Providers>
      <Gate />
    </Providers>
  )
}

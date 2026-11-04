import type { ReactNode } from 'react'
import { I18nProvider, useI18n } from './i18n'
import { ThemeProvider } from './lib/theme'
import { ToastProvider } from './lib/toast'
import { RouterProvider, useRouter, Link } from './lib/router'
import { ReauthProvider, SessionProvider, useSession } from './lib/session'
import { Shell } from './Shell'
import { Login } from './pages/Login'
import { Dashboard } from './pages/Dashboard'
import { NodesPage } from './pages/Nodes'
import { RelaysPage } from './pages/Relays'
import { SubscriptionsPage } from './pages/Subscriptions'
import { SystemPage } from './pages/System'
import { AIPage } from './pages/AI'
import { Button, EmptyState, Spinner } from './components/ui'

function Routes() {
  const { path } = useRouter()
  const { t } = useI18n()
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
        <EmptyState icon="warn" title={t('shell.notFound')} action={<Link to="/" className="btn btn-secondary btn-md">{t('shell.backHome')}</Link>} />
      )
  }
}

function Gate() {
  const { phase, refresh } = useSession()
  const { t } = useI18n()
  if (phase === 'loading')
    return (
      <div className="splash">
        <Spinner label={t('shell.loading')} />
      </div>
    )
  if (phase === 'unreachable')
    return (
      <div className="splash">
        <EmptyState icon="warn" title={t('shell.unreachable')} action={<Button onClick={() => void refresh()}>{t('common.retry')}</Button>}>
          {t('shell.unreachableDetail')}
        </EmptyState>
      </div>
    )
  if (phase === 'anonymous') return <Login />
  return (
    <ReauthProvider>
      <Shell>
        <Routes />
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

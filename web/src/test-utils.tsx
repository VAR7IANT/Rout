import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { I18nProvider, type Lang } from './i18n'
import { RouterProvider } from './lib/router'
import { ReauthProvider } from './lib/session'
import { ThemeProvider } from './lib/theme'
import { ToastProvider } from './lib/toast'

export function renderApp(ui: ReactElement, lang: Lang = 'en') {
  return render(
    <I18nProvider initial={lang}>
      <ThemeProvider>
      <ToastProvider>
        <RouterProvider>
          <ReauthProvider>{ui}</ReauthProvider>
        </RouterProvider>
      </ToastProvider>
      </ThemeProvider>
    </I18nProvider>,
  )
}

/** A fetch double that answers by "METHOD /path" and records every call. */
export interface Call {
  method: string
  path: string
  headers: Record<string, string>
  body: unknown
}
export function mockFetch(routes: Record<string, (call: Call) => { status?: number; body?: unknown; headers?: Record<string, string> } | undefined>) {
  const calls: Call[] = []
  const impl = async (input: RequestInfo | URL, init?: RequestInit) => {
    const method = (init?.method ?? 'GET').toUpperCase()
    const path = String(input)
    const headers = Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>))
    const call: Call = { method, path, headers, body: init?.body ? JSON.parse(String(init.body)) : undefined }
    calls.push(call)
    const handler = routes[`${method} ${path}`] ?? routes[`${method} ${path.split('?')[0]}`]
    const r = handler?.(call) ?? { status: 404, body: { error: { code: 'error', message: 'not found' } } }
    const status = r.status ?? 200
    return new Response(r.body === undefined ? '' : JSON.stringify(r.body), { status, headers: { 'Content-Type': 'application/json', ...(r.headers ?? {}) } })
  }
  return { calls, impl }
}

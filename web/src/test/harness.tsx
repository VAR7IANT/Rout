// Shared test plumbing: a fetch double keyed by "METHOD /path", and a render helper that
// mounts a component inside the providers the pages expect.
import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { vi } from 'vitest'
import { I18nProvider, type Lang } from '../core/i18n'
import { RouterProvider } from '../core/router'
import { ReauthProvider } from '../core/session'
import { ThemeProvider } from '../core/theme'
import { ToastProvider } from '../core/toast'
import { ReauthDialog } from '../ui/reauth'

export interface Call {
  method: string
  path: string
  headers: Record<string, string>
  body: unknown
}
type Answer = { status?: number; body?: unknown; headers?: Record<string, string> } | undefined
export type Routes = Record<string, (call: Call) => Answer>

/** Installs a fetch that answers from `routes` (query strings are ignored when matching) and records every call. */
export function serve(routes: Routes): Call[] {
  const calls: Call[] = []
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const method = (init?.method ?? 'GET').toUpperCase()
    const path = String(input)
    const call: Call = { method, path, headers: { ...((init?.headers ?? {}) as Record<string, string>) }, body: init?.body ? JSON.parse(String(init.body)) : undefined }
    calls.push(call)
    const handler = routes[`${method} ${path}`] ?? routes[`${method} ${path.split('?')[0]}`]
    const answer = handler?.(call) ?? { status: 404, body: { error: { code: 'error', message: `no route for ${method} ${path}` } } }
    return new Response(answer.body === undefined ? '' : JSON.stringify(answer.body), { status: answer.status ?? 200, headers: { 'Content-Type': 'application/json', ...(answer.headers ?? {}) } })
  })
  return calls
}

/** The calls made with `method` to `path`. */
export const sent = (calls: Call[], method: string, path: string) => calls.filter((c) => c.method === method && c.path.split('?')[0] === path)

export function mount(ui: ReactElement, lang: Lang = 'en') {
  return render(
    <ThemeProvider>
      <I18nProvider initial={lang}>
        <ToastProvider>
          <RouterProvider>
            <ReauthProvider prompt={(done) => <ReauthDialog done={done} />}>{ui}</ReauthProvider>
          </RouterProvider>
        </ToastProvider>
      </I18nProvider>
    </ThemeProvider>,
  )
}

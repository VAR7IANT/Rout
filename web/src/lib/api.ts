// The only place that talks to the panel API. Credentials never reach JavaScript: the session
// is an HttpOnly cookie. The CSRF token the server issues is kept in memory only (never in
// localStorage), and is sent on every request together with the interface language.

export class ApiError extends Error {
  status: number
  code: string
  retryAfter?: number
  constructor(status: number, code: string, message: string, retryAfter?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.retryAfter = retryAfter
  }
}

let csrfToken = ''
let apiLang = 'zh-CN'
let sessionLost: (() => void) | null = null

export function setCsrf(token: string) {
  csrfToken = token
}
export function getCsrf() {
  return csrfToken
}
export function setApiLang(lang: string) {
  apiLang = lang
}
/** Registers the function called when the server says the session has ended. */
export function onSessionLost(fn: (() => void) | null) {
  sessionLost = fn
}

interface Options {
  signal?: AbortSignal
}

// Calls that must not be treated as "the session ended" when they answer 401.
const anonymousPaths = new Set(['/api/login', '/api/state', '/api/health'])

async function send(method: string, path: string, body: unknown, opts: Options = {}): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json', 'X-Rout-Lang': apiLang }
  let payload: BodyInit | undefined
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  if (method !== 'GET' && method !== 'HEAD') {
    headers['X-CSRF-Token'] = csrfToken
    // Some write routes (restart, refresh) take no body; the server still insists on JSON.
    if (payload === undefined) headers['Content-Type'] = 'application/json'
  }
  let res: Response
  try {
    res = await fetch(path, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store', signal: opts.signal })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e
    throw new ApiError(0, 'network', 'network')
  }
  if (res.ok) return res
  let code = 'error'
  let message = res.statusText
  let retry: number | undefined
  try {
    const data = await res.json()
    if (data && data.error) {
      code = String(data.error.code ?? code)
      message = String(data.error.message ?? message)
      if (typeof data.error.retry_after === 'number') retry = data.error.retry_after
    }
  } catch {
    // A proxy error page or an empty body: keep the status text.
    code = res.status >= 500 ? 'server' : code
  }
  if (res.status === 401 && code === 'unauthenticated' && !anonymousPaths.has(path)) sessionLost?.()
  throw new ApiError(res.status, code, message, retry)
}

export async function request<T>(method: string, path: string, body?: unknown, opts?: Options): Promise<T> {
  const res = await send(method, path, body, opts)
  const text = await res.text()
  if (!text) return null as T
  return JSON.parse(text) as T
}

export const api = {
  get: <T>(path: string, opts?: Options) => request<T>('GET', path, undefined, opts),
  post: <T = unknown>(path: string, body?: unknown, opts?: Options) => request<T>('POST', path, body, opts),
  put: <T = unknown>(path: string, body?: unknown, opts?: Options) => request<T>('PUT', path, body, opts),
  patch: <T = unknown>(path: string, body?: unknown, opts?: Options) => request<T>('PATCH', path, body, opts),
  del: <T = unknown>(path: string, opts?: Options) => request<T>('DELETE', path, undefined, opts),
}

/** Downloads a file produced by the server (the backup) as a Blob. */
export async function download(path: string): Promise<{ blob: Blob; filename: string }> {
  const res = await send('GET', path, undefined)
  const blob = await res.blob()
  const cd = res.headers.get('Content-Disposition') ?? ''
  const m = /filename="?([^";]+)"?/.exec(cd)
  return { blob, filename: m?.[1] ?? 'rout-backup.json' }
}

export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function isReauthRequired(e: unknown): boolean {
  return e instanceof ApiError && e.code === 'reauth_required'
}

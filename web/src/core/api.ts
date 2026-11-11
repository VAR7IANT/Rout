// The panel's only door to the server. The session lives in an HttpOnly cookie that script
// cannot read; the CSRF token is held in this module's memory and nowhere else (no storage),
// so a reload simply asks /api/state for a fresh one.

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly retryAfter?: number
  constructor(status: number, code: string, message: string, retryAfter?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.retryAfter = retryAfter
  }
}

const wire = {
  csrf: '',
  lang: 'zh-CN',
  expired: null as (() => void) | null,
}

export const transport = {
  setCsrf(token: string) {
    wire.csrf = token
  },
  csrf: () => wire.csrf,
  setLang(lang: string) {
    wire.lang = lang
  },
  /** Called once when an authenticated call is answered with "unauthenticated". */
  onExpired(fn: (() => void) | null) {
    wire.expired = fn
  },
}

// A 401 from these means "not signed in yet", not "the session ended".
const preAuth = new Set(['/api/login', '/api/state', '/api/health'])

export interface CallOptions {
  signal?: AbortSignal
}

function isAbort(e: unknown): boolean {
  return e instanceof DOMException && e.name === 'AbortError'
}

async function failure(res: Response, path: string): Promise<ApiError> {
  let code = 'error'
  let message = res.statusText
  let retryAfter: number | undefined
  try {
    const body = (await res.json()) as { error?: { code?: unknown; message?: unknown; retry_after?: unknown } }
    if (body?.error) {
      code = String(body.error.code ?? code)
      message = String(body.error.message ?? message)
      if (typeof body.error.retry_after === 'number') retryAfter = body.error.retry_after
    }
  } catch {
    // Not JSON: a reverse proxy's error page or an empty body.
    if (res.status >= 500) code = 'server'
  }
  if (res.status === 401 && code === 'unauthenticated' && !preAuth.has(path)) wire.expired?.()
  return new ApiError(res.status, code, message, retryAfter)
}

async function exchange(method: string, path: string, body: unknown, opts: CallOptions = {}): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json', 'X-Rout-Lang': wire.lang }
  const writes = method !== 'GET' && method !== 'HEAD'
  if (writes) {
    headers['X-CSRF-Token'] = wire.csrf
    // The server requires JSON on every state-changing call, including the ones without a body.
    headers['Content-Type'] = 'application/json'
  }
  let res: Response
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
      cache: 'no-store',
      signal: opts.signal,
    })
  } catch (e) {
    if (isAbort(e)) throw e
    throw new ApiError(0, 'network', 'network')
  }
  if (!res.ok) throw await failure(res, path)
  return res
}

async function json<T>(method: string, path: string, body?: unknown, opts?: CallOptions): Promise<T> {
  const res = await exchange(method, path, body, opts)
  const text = await res.text()
  return (text ? JSON.parse(text) : null) as T
}

export const api = {
  get: <T>(path: string, opts?: CallOptions) => json<T>('GET', path, undefined, opts),
  post: <T = unknown>(path: string, body?: unknown, opts?: CallOptions) => json<T>('POST', path, body, opts),
  put: <T = unknown>(path: string, body?: unknown, opts?: CallOptions) => json<T>('PUT', path, body, opts),
  patch: <T = unknown>(path: string, body?: unknown, opts?: CallOptions) => json<T>('PATCH', path, body, opts),
  del: <T = unknown>(path: string, opts?: CallOptions) => json<T>('DELETE', path, undefined, opts),
  /** A server-produced file (the backup) with the name the server suggests. */
  async file(path: string): Promise<{ blob: Blob; filename: string }> {
    const res = await exchange('GET', path, undefined)
    const name = /filename="?([^";]+)"?/.exec(res.headers.get('Content-Disposition') ?? '')?.[1]
    return { blob: await res.blob(), filename: name ?? 'rout-backup.json' }
  },
}

/** Hands a Blob to the browser's download flow. */
export function saveAs(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const needsReauth = (e: unknown): boolean => e instanceof ApiError && e.code === 'reauth_required'
export const isAborted = isAbort

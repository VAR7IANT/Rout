import { useState, type FormEvent } from 'react'
import { useI18n } from '../i18n'
import { useSession, errorText } from '../lib/session'
import { ApiError } from '../lib/api'
import { Button, Field, Input, Notice } from '../components/ui'
import { Preferences } from '../Shell'
import { CopyButton } from '../components/copy'

export function Login() {
  const { t } = useI18n()
  const { login, configured } = useSession()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!password) return
    setBusy(true)
    setError(null)
    try {
      await login(password)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'invalid_credentials') setError(t('login.invalid'))
      else setError(errorText(err, t))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login">
      <div className="login-card">
        <div className="brand brand-lg">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">Rout</span>
        </div>
        <h1>{t('login.title')}</h1>
        <p className="muted">{t('login.subtitle')}</p>
        {!configured ? (
          <Notice tone="warn" title={t('login.notConfigured')}>
            <p>{t('login.notConfiguredDetail')}</p>
            <div className="codeline">
              <code>rout web passwd --generate</code>
              <CopyButton text="rout web passwd --generate" compact />
            </div>
          </Notice>
        ) : (
          <form onSubmit={submit} className="stack" noValidate>
            <Field label={t('login.password')} error={error}>
              {(id, d) => <Input id={id} aria-describedby={d} data-autofocus autoFocus type="password" name="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />}
            </Field>
            <Button type="submit" variant="primary" busy={busy} disabled={!password}>
              {t('login.submit')}
            </Button>
            <p className="hint">{t('login.lockedHint')}</p>
            <p className="hint">{t('login.forgot')}</p>
          </form>
        )}
      </div>
      <div className="login-prefs">
        <Preferences />
      </div>
    </main>
  )
}

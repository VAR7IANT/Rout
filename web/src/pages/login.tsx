import { useState, type FormEvent } from 'react'
import { ApiError } from '../core/api'
import { useT } from '../core/i18n'
import { errorText, useSession } from '../core/session'
import { Logo, Preferences } from '../shell'
import { CopyButton } from '../ui/copy'
import { Button, Field, Input, Notice } from '../ui/kit'

const SET_PASSWORD = 'rout web passwd --generate'

export function Login() {
  const t = useT()
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
      setError(err instanceof ApiError && err.code === 'invalid_credentials' ? t('login.invalid') : errorText(err, t))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login">
      <div className="login__box">
        <Logo />
        <h1>{t('login.title')}</h1>
        <p className="dim">{t('login.subtitle')}</p>
        {configured ? (
          <form className="stack" onSubmit={(e) => void submit(e)} noValidate>
            <Field label={t('login.password')} error={error}>
              {(id, note) => <Input id={id} aria-describedby={note} autoFocus type="password" name="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />}
            </Field>
            <Button type="submit" variant="primary" busy={busy} disabled={!password}>
              {t('login.submit')}
            </Button>
            <p className="dim small">{t('login.lockedHint')}</p>
            <p className="dim small">{t('login.forgot')}</p>
          </form>
        ) : (
          <Notice tone="warn" title={t('login.notConfigured')}>
            <p>{t('login.notConfiguredDetail')}</p>
            <div className="cmdline">
              <code>{SET_PASSWORD}</code>
              <CopyButton text={SET_PASSWORD} compact />
            </div>
          </Notice>
        )}
      </div>
      <Preferences />
    </main>
  )
}

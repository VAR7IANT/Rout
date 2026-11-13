import { useState, type FormEvent } from 'react'
import { api } from '../core/api'
import { useT } from '../core/i18n'
import { errorText } from '../core/session'
import { Button, Field, Input } from './kit'
import { Dialog } from './overlay'

/** The password prompt the server demands before a dangerous operation. */
export function ReauthDialog({ done }: { done: (ok: boolean) => void }) {
  const t = useT()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.post('/api/reauth', { password })
      done(true)
    } catch (err) {
      setError(errorText(err, t))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog title={t('reauth.title')} description={t('reauth.desc')} onClose={() => done(false)} busy={busy}>
      <form className="stack" onSubmit={(e) => void submit(e)}>
        <Field label={t('login.password')} error={error}>
          {(id, note) => <Input id={id} aria-describedby={note} data-autofocus type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />}
        </Field>
        <div className="row row--end">
          <Button variant="ghost" onClick={() => done(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" busy={busy} disabled={password === ''}>
            {t('reauth.confirm')}
          </Button>
        </div>
      </form>
    </Dialog>
  )
}

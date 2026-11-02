import { useState } from 'react'
import { useT } from '../i18n'
import { useToast } from '../lib/toast'
import { Button, IconButton } from './ui'

export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // Fall through to the legacy path (insecure origins have no clipboard API).
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  } catch {
    return false
  }
}

export function CopyButton({ text, label, compact }: { text: string; label?: string; compact?: boolean }) {
  const t = useT()
  const toast = useToast()
  const [done, setDone] = useState(false)
  const click = async () => {
    const ok = await copyText(text)
    if (ok) {
      setDone(true)
      toast.push('ok', t('common.copied'))
      window.setTimeout(() => setDone(false), 1500)
    } else toast.push('error', t('common.copyFailed'))
  }
  if (compact) return <IconButton icon={done ? 'check' : 'copy'} label={label ?? t('common.copy')} onClick={click} size="sm" />
  return (
    <Button size="sm" icon={done ? 'check' : 'copy'} onClick={click}>
      {label ?? t('common.copy')}
    </Button>
  )
}

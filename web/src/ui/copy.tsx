import { useState } from 'react'
import { useT } from '../core/i18n'
import { useToast } from '../core/toast'
import { Button, IconButton } from './kit'

/**
 * Copies text. The async clipboard API only exists on secure origins; over plain HTTP (an IP
 * address, before HTTPS is set up) it falls back to a hidden textarea and execCommand.
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // Permission denied or insecure origin: try the legacy path.
  }
  try {
    const scratch = document.createElement('textarea')
    scratch.value = text
    scratch.readOnly = true
    scratch.style.position = 'fixed'
    scratch.style.opacity = '0'
    document.body.appendChild(scratch)
    scratch.select()
    const ok = document.execCommand('copy')
    scratch.remove()
    return ok
  } catch {
    return false
  }
}

export function CopyButton({ text, label, compact }: { text: string; label?: string; compact?: boolean }) {
  const t = useT()
  const toast = useToast()
  const [done, setDone] = useState(false)
  const copy = async () => {
    if (!(await copyText(text))) {
      toast.push('error', t('common.copyFailed'))
      return
    }
    setDone(true)
    toast.push('ok', t('common.copied'))
    window.setTimeout(() => setDone(false), 1500)
  }
  const icon = done ? 'check' : 'copy'
  if (compact) return <IconButton icon={icon} label={label ?? t('common.copy')} size="sm" onClick={() => void copy()} />
  return (
    <Button size="sm" icon={icon} onClick={() => void copy()}>
      {label ?? t('common.copy')}
    </Button>
  )
}

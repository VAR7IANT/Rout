import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'
import { transport } from '../core/api'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  transport.setCsrf('')
  transport.setLang('zh-CN')
  transport.onExpired(null)
  localStorage.clear()
})

// jsdom implements neither of these.
window.scrollTo = () => undefined
Element.prototype.scrollIntoView = () => undefined

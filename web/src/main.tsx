import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './app'
import './styles/theme.css'
import './styles/base.css'
import './styles/kit.css'
import './styles/shell.css'
import './styles/pages.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

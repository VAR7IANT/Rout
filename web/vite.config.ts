/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The production build is written next to the Go package that embeds it.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: false, // scripts/clean-dist.mjs keeps the tracked .gitkeep
    sourcemap: false,
    target: 'es2022',
    chunkSizeWarningLimit: 600,
  },
  server: {
    port: 5173,
    // `rout web` listens on 127.0.0.1:8790; the dev server forwards API calls to it.
    proxy: { '/api': { target: 'http://127.0.0.1:8790', changeOrigin: false } },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    css: false,
    restoreMocks: true,
  },
})

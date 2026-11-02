// Empties internal/webui/dist before a build but keeps the tracked .gitkeep, so a build never
// leaves stale hashed assets behind (the Go side embeds the whole directory).
import { readdirSync, rmSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const dist = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'internal', 'webui', 'dist')
mkdirSync(dist, { recursive: true })
for (const name of readdirSync(dist)) {
  if (name === '.gitkeep') continue
  rmSync(join(dist, name), { recursive: true, force: true })
}

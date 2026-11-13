// Every interface string as [简体中文, 繁體中文, English]. The three sit side by side so a
// missing translation is visible in review, and src/test/catalog.test.ts checks every entry.
import { ai } from './messages/ai'
import { common } from './messages/common'
import { dashboard } from './messages/dashboard'
import { nodes } from './messages/nodes'
import { panel } from './messages/panel'
import { relays } from './messages/relays'
import { shell } from './messages/shell'
import { sources } from './messages/sources'
import { subs } from './messages/subs'
import { system } from './messages/system'
import { term } from './messages/term'

export type Entry = readonly [string, string, string]

export const catalog = { ...common, ...shell, ...dashboard, ...nodes, ...relays, ...subs, ...sources, ...system, ...ai, ...panel, ...term } as const
export type MessageKey = keyof typeof catalog
